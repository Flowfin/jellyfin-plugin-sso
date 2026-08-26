// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using Jellyfin.Plugin.SSO_Auth.Api.Routing;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for the rate-limit and provider-name classifications: every sensitive route is throttled or declared exempt, and every provider-named entry point registers the name or is declared exempt.
/// </content>
public partial class ArchitectureConformanceTests
{
    // Routes whose action MUST call RateLimitCheck (#928 U2): the anonymous login-path endpoints
    // (challenge / callback / auth for both protocols, SP metadata, inbound SAML logout) and the
    // admin endpoints that drive an OUTBOUND fetch (the OpenID connection tester and SAML metadata
    // import - an authenticated admin must not be able to spin the outbound probe unthrottled), plus
    // the account-link and unregister mutations. Adding a route here without wiring the gate fails the
    // test; the reverse - an unclassified NEW route - fails EverySensitiveRoute_IsClassified below.
    private static readonly string[] MustThrottleRoutes =
    {
        "OID/r/{provider}", "OID/redirect/{provider}", "OID/p/{provider}", "OID/start/{provider}",
        "OID/Test/{provider}", "OID/Auth/{provider}", "OID/backchannel-logout/{provider}",
        "SAML/p/{provider}", "SAML/post/{provider}", "SAML/start/{provider}", "SAML/metadata/{provider}",
        "SAML/Logout/{provider}", "SAML/ImportMetadata", "SAML/Auth/{provider}",
        "Unregister/{username}", "{mode}/Link/{provider}/{jellyfinUserId}",
        "{mode}/Link/{provider}/{jellyfinUserId}/{canonicalName}",
        // The per-subject link export (#1091): elevation-gated and read-only, but it answers per user id,
        // so an unthrottled one is a user-table enumeration an administrator can drive in a loop.
        "Links/Export/{jellyfinUserId}",
        // The link-backup restore (#1129): the same config-XML persist under the global lock as the two
        // link writes above, in bulk, and its refusal names usernames this instance does not hold, which
        // an unthrottled caller could drive in a loop as a user-table oracle.
        "Config/Links/Import",
        // The pre-provision link write (#1133): a config-XML persist under the global lock, and its 404 is
        // an existence answer about a user id, so it is throttled for both reasons the two neighbours are.
        "Links/Preprovision/{mode}/{provider}/{jellyfinUserId}",
    };

    // Routes deliberately NOT rate-limited, each with the reason it is safe: an elevation-gated admin
    // operation with no outbound fetch, an authenticated user action, or a purely local (no-I/O) probe.
    // Kept as an explicit allowlist so a NEW endpoint cannot be silently exempted - it must be added to
    // one of the two lists, which is the classification decision this conformance test forces.
    private static readonly string[] RateLimitExemptRoutes =
    {
        "OID/logout/{provider}", "SAML/logout/{provider}", // [Authorize] user logout, no fetch
        "OID/Add/{provider}", "SAML/Add/{provider}", "OID/Del/{provider}", "SAML/Del/{provider}", // elevated config CRUD
        "OID/Get", "SAML/Get", "OID/GetNames", "SAML/GetNames", "OID/States", // read-only listings
        "SAML/Test/{provider}", // LOCAL certificate parse - no outbound fetch (unlike OID/Test)
        // Elevated read of a stored provider's redirect_uri for the admin page (#1303): pure string
        // composition over the config already in memory, no outbound fetch and no write. Its 404 answers
        // whether a PROVIDER exists, which the elevation-gated OID/Get already lists in full, so it is
        // not the per-user-id enumeration surface that made the two Links routes throttled neighbours.
        "OID/RedirectUri/{provider}",
        "Config/Export", "Config/Import", // elevated config transfer
        // Elevated read-only report of which providers a declarative source decided (#1102): process
        // state settled during plugin construction, so it reads no provider, takes no outbound fetch and
        // writes nothing. It answers with NAMES the elevation-gated Config/Export already lists in full,
        // so repeating it discloses nothing that route does not, and it takes no caller-supplied id.
        "Config/Managed",
        // Elevated read-only aggregate configuration check (#1084): it evaluates the configuration already
        // in memory against the same rules the save path uses, makes NO outbound request of its own, writes
        // nothing and takes no caller-supplied id. Its whole design point is that it does not fan out to the
        // provider Test routes - those are throttled, share one bucket, and a fan-out would empty it - so
        // throttling this one would guard a surface that spends nothing.
        "Config/Check",
        // Elevated read-only counter exposition (#1139): in-memory tallies rendered to text, no outbound
        // fetch and no write. Exempt for a reason the neighbours above do not have - a scraper is SUPPOSED to
        // poll this route, every fifteen seconds forever, so a throttle here would break the one caller it
        // exists for, and would break it silently as a gap in a graph rather than as an error anybody sees.
        // What it discloses is provider names the elevation-gated OID/Get already lists in full plus counts
        // about the caller's own server, and it takes no caller-supplied id.
        "Metrics",
        "SSO-Only/Status", "SSO-Only/Enable", "SSO-Only/Disable", "SSO-Only/BreakGlassAdmin", // elevated mode control
        "Config/Links/Export", // elevated read-only link snapshot (#1126), in-memory, no outbound fetch
        "Links/Roster", // elevated read-only link roster (#1119), in-memory, no outbound fetch, takes no caller-supplied id
        "saml/links/{jellyfinUserId}", "oid/links/{jellyfinUserId}", // authenticated link listings
        "SSO-Managed/Status/{jellyfinUserId}", // elevated read-only account report (#1136), in-memory, no outbound fetch
        "{viewName}", // SSOViewsController: read-only embedded static asset (ETag/304), no I/O, no login path
        "i18n", // SSOViewsController: anonymous read-only UI-string catalog (#913), in-memory, no I/O, no login path
    };

    [Fact]
    public void EveryMustThrottleEndpoint_CallsTheRateLimitGate()
    {
        // #928 U2 - the structural half of "does every rate-limited endpoint actually rate-limit". The
        // per-endpoint 429 response-shape tests prove the wiring behaves; this proves the wiring EXISTS on
        // every endpoint that must have it, so the class of "a new login-path/outbound endpoint forgot the
        // RateLimitCheck call" is a red build, not a review miss.
        var actions = ControllerActionBlocks();
        var missing = new List<string>();
        foreach (var route in MustThrottleRoutes)
        {
            var block = actions.FirstOrDefault(a => a.Routes.Contains(route, StringComparer.Ordinal));
            Assert.True(block.Routes is not null, $"MustThrottleRoutes lists '{route}', but no controller action declares that route - a route was renamed; update the list (#928).");
            if (!block.Body.Contains("RateLimitCheck(SsoRateLimitClass.", StringComparison.Ordinal))
            {
                missing.Add(route);
            }
        }

        Assert.True(
            missing.Count == 0,
            "These endpoints must call RateLimitCheck(SsoRateLimitClass.…) and do not: " + string.Join(", ", missing));
    }

    [Fact]
    public void EverySensitiveRoute_IsClassified_AsThrottledOrExplicitlyExempt()
    {
        // The completeness guard: every controller route is in exactly one of the two lists. A NEW endpoint
        // therefore cannot land without a deliberate decision on whether it needs rate limiting - the whole
        // point of #928 U2's "no forgotten gate". Also fails on a stale list entry (a route no longer in
        // the controller), so the lists cannot drift out of sync with the surface.
        var declared = ControllerActionBlocks().SelectMany(a => a.Routes).ToList();
        Assert.NotEmpty(declared);

        var classified = MustThrottleRoutes.Concat(RateLimitExemptRoutes).ToHashSet(StringComparer.Ordinal);

        var unclassified = declared.Where(r => !classified.Contains(r)).ToList();
        Assert.True(
            unclassified.Count == 0,
            "These controller routes are in neither MustThrottleRoutes nor RateLimitExemptRoutes - classify each (does it need rate limiting?): " + string.Join(", ", unclassified));

        var declaredSet = declared.ToHashSet(StringComparer.Ordinal);
        var stale = classified.Where(r => !declaredSet.Contains(r)).ToList();
        Assert.True(
            stale.Count == 0,
            "These routes are listed in a rate-limit classification list but no longer exist on the controller - remove them: " + string.Join(", ", stale));
    }

    // Every controller action as (its route templates, its method-body text): the body runs from an action's
    // HTTP-attribute cluster to the next action's cluster, which is enough to see whether the (always-first)
    // RateLimitCheck statement is present. Stacked route attributes on one method (consecutive lines) are one
    // action. Route-template source scan, in the ControllerSourceFiles idiom (#388) so a controller split
    // cannot hide an endpoint.
    private static IReadOnlyList<(IReadOnlyList<string> Routes, string Body)> ControllerActionBlocks()
    {
        var attr = new Regex(
            @"^\s*\[Http(?:Get|Post|Put|Delete)\(""(?<route>[^""]*)""\)\]");
        var results = new List<(IReadOnlyList<string>, string)>();

        foreach (var path in ControllerSourceFiles())
        {
            var lines = File.ReadAllLines(path);
            var hits = new List<(int Line, string Route)>();
            for (var i = 0; i < lines.Length; i++)
            {
                var m = attr.Match(lines[i]);
                if (m.Success)
                {
                    hits.Add((i, m.Groups["route"].Value));
                }
            }

            // Group consecutive attribute lines (a method's stacked routes) into one action cluster.
            for (var i = 0; i < hits.Count;)
            {
                var routes = new List<string> { hits[i].Route };
                var last = i;
                while (last + 1 < hits.Count && hits[last + 1].Line == hits[last].Line + 1)
                {
                    routes.Add(hits[last + 1].Route);
                    last++;
                }

                var bodyStart = hits[last].Line;
                var bodyEnd = last + 1 < hits.Count ? hits[last + 1].Line : lines.Length;
                var body = string.Join("\n", lines.Skip(bodyStart).Take(bodyEnd - bodyStart));
                results.Add((routes, body));
                i = last + 1;
            }
        }

        return results;
    }

    // The entry points that REGISTER the provider name they are handed: the name becomes a new key in the
    // persisted provider map, which is the moment the callback-URL bytes handed to an identity provider are
    // fixed. Each must reach ProviderNameValidator.IsInvalid (#1160). The two Add routes carry the name in a
    // route segment; Config/Import carries it inside the document body, so it is listed here too and its
    // gate is reached through the config tier rather than through the controller's own wrapper.
    private static readonly string[] ProviderNameRegistrationRoutes =
    {
        "OID/Add/{provider}", "SAML/Add/{provider}", "Config/Import",
    };

    // The provider-named entry points that deliberately do NOT validate the name, with the reason each is
    // safe. All but the last LOOK a name UP and fail closed when it resolves to no provider, and that
    // exemption is argued in ProviderNameValidator's own summary - the bytes built from an already
    // registered name are exactly what its identity provider has registered, so revalidating at login would
    // strand a deployment whose name predates the rule (#336, #360). Kept as an exact-path allowlist so a
    // NEW provider-named endpoint cannot be silently exempted: it must be put in one of the two lists, which
    // is the classification decision this rule exists to force.
    private static readonly string[] ProviderNameExemptRoutes =
    {
        "OID/p/{provider}", "OID/start/{provider}", // OpenID challenge: resolves a stored provider
        "SAML/p/{provider}", "SAML/post/{provider}", "SAML/start/{provider}", // SAML challenge: resolves a stored provider
        "OID/r/{provider}", "OID/redirect/{provider}", "OID/Auth/{provider}", "SAML/Auth/{provider}", // callback/auth: the IdP is answering with a name it was already given
        "OID/logout/{provider}", "SAML/logout/{provider}", "SAML/Logout/{provider}", "OID/backchannel-logout/{provider}", // logout: resolves a stored provider
        "OID/Del/{provider}", "SAML/Del/{provider}", // removal: an already-stored name, or a no-op
        "OID/Test/{provider}", "SAML/Test/{provider}", // admin probe of a STORED provider, 404 on a miss
        "OID/RedirectUri/{provider}", // admin read of a STORED provider's redirect_uri, 404 on a miss (#1303)
        "SAML/metadata/{provider}", // SP metadata built for a stored provider
        "{mode}/Link/{provider}/{jellyfinUserId}", "{mode}/Link/{provider}/{jellyfinUserId}/{canonicalName}", // link write against a stored, enabled provider
        "Links/Preprovision/{mode}/{provider}/{jellyfinUserId}", // pre-provision write against a stored, enabled provider (#1133)

        // Not an SSO provider name at all: Unregister's body parameter happens to be called `provider` and
        // carries a JELLYFIN AuthenticationProviderId, written to the user record so the account falls back
        // to another auth provider. It never becomes a key in the OpenID/SAML provider maps and never
        // reaches a callback URL, so the round-trip predicate has nothing to say about it. The name
        // collision is the reason this surface is derived from the inventory rather than hand-listed.
        "Unregister/{username}",
    };

    [Fact]
    public void EveryProviderNamedEntryPoint_IsClassified_AsRegisteringOrDeclaredExempt()
    {
        // #1160. ProviderNameValidator gates NEWLY registered names only, and today that is one call site
        // against a provider name that reaches roughly two dozen entry points - so "gated" versus "exempt"
        // is a fact of the code with nothing asserting it was intended. This partitions the surface: a new
        // endpoint taking a provider name is in neither list and fails here, which is the case a fixed
        // battery of endpoint tests misses. The surface comes from the reflected inventory (#1159) rather
        // than a literal list, because the endpoint somebody forgot to list is the endpoint that skipped the
        // validator.
        var providerNamed = EntryPointInventory.OfThePlugin()
            .Where(e => e.Parameters.Any(p => string.Equals(p.Name, "provider", StringComparison.Ordinal)))
            .Select(e => e.Template)
            .ToList();

        // Config/Import takes the names inside its document rather than as an action parameter, so the
        // parameter walk cannot see it; it is named here for the same reason it is in the gated list.
        var surface = providerNamed.Append("Config/Import").ToList();

        Assert.True(
            providerNamed.Count >= 15,
            $"The provider-named entry-point walk found only {providerNamed.Count} routes; it has stopped seeing the real controllers and this rule would now pass over a surface too small to mean anything (#1159, #1160).");

        var classified = ProviderNameRegistrationRoutes.Concat(ProviderNameExemptRoutes).ToHashSet(StringComparer.Ordinal);

        var unclassified = surface.Where(r => !classified.Contains(r)).Distinct(StringComparer.Ordinal).ToList();
        Assert.True(
            unclassified.Count == 0,
            "These entry points take a provider name and are in neither ProviderNameRegistrationRoutes nor ProviderNameExemptRoutes - classify each (does it register the name, or look it up?): " + string.Join(", ", unclassified));

        var surfaceSet = surface.ToHashSet(StringComparer.Ordinal);
        var stale = classified.Where(r => !surfaceSet.Contains(r)).ToList();
        Assert.True(
            stale.Count == 0,
            "These routes are listed in a provider-name classification list but no entry point takes a provider name on them any more - remove them: " + string.Join(", ", stale));
    }

    [Fact]
    public void EveryProviderNameRegistrationRoute_ReachesTheSharedNamePredicate()
    {
        // The other half of #1160: classification alone would let a route sit in the gated list without the
        // guard. Deleting the RejectInvalidNewProviderName call from OID/Add fails here, and so does gutting
        // either throwing wrapper down to something that no longer consults the shared predicate.
        var predicate = ProviderNamePredicateToken();
        var actions = ControllerActionBlocks();

        foreach (var route in ProviderNameRegistrationRoutes)
        {
            var block = actions.FirstOrDefault(a => a.Routes.Contains(route, StringComparer.Ordinal));
            Assert.True(block.Routes is not null, $"ProviderNameRegistrationRoutes lists '{route}', but no controller action declares that route - a route was renamed; update the list (#1160).");
        }

        // Derived from the list rather than named again here: a fourth registration route added to the list
        // would otherwise be checked only for existing, which is the same forgotten-step this rule is about.
        // A registration route carrying the name in a route SEGMENT gates it at the controller; the ones that
        // carry it inside a body reach the config tier's gate instead and are covered by the rule below.
        foreach (var route in ProviderNameRegistrationRoutes.Where(r => r.Contains("{provider}", StringComparison.Ordinal)))
        {
            var block = actions.First(a => a.Routes.Contains(route, StringComparer.Ordinal));
            Assert.True(
                block.Body.Contains("RejectInvalidNewProviderName(", StringComparison.Ordinal),
                $"The '{route}' action must call RejectInvalidNewProviderName - it registers a NEW provider name, and the name it stores becomes part of the callback URL its identity provider is given (#336, #360, #1160).");
        }

        // The Add wrapper, and the config tier's parallel wrapper, both delegate to the one predicate. The
        // guard line is asserted verbatim because it also carries the new-name condition: a wrapper that
        // called the predicate unconditionally would strand every existing deployment behind a rename, which
        // is the failure the exemption above exists to avoid.
        var controllerSource = string.Join("\n", ControllerSourceFiles().Select(File.ReadAllText));
        Assert.Contains($"if (!providerExists && {predicate}provider))", controllerSource, StringComparison.Ordinal);

        var validatorSource = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Config", "ProviderConfigValidator.cs"));
        Assert.Contains($"if (isNew && {predicate}provider))", validatorSource, StringComparison.Ordinal);
    }

    [Fact]
    public void TheNonRouteRegistrationPaths_ReachTheGate_AndTheMetadataProbeRegistersNothing()
    {
        // Config/Import persists provider names that never appear in a route segment, so its gate is the
        // config tier's whole-document Validate rather than the controller's per-name wrapper. Both hops are
        // asserted, because the action calling Apply proves nothing if Apply stopped validating.
        var actions = ControllerActionBlocks();

        var import = actions.First(a => a.Routes.Contains("Config/Import", StringComparer.Ordinal));
        Assert.Contains("ConfigImport.Apply(", import.Body, StringComparison.Ordinal);

        var applySource = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Config", "ConfigImport.cs"));
        Assert.Contains("ProviderConfigValidator.Validate(", applySource, StringComparison.Ordinal);

        // SAML/ImportMetadata is the near neighbour that looks like a registration route and is not: it
        // parses metadata and RETURNS the values for an administrator to review, applying nothing. That is
        // the whole reason it needs no name gate, so it is asserted rather than assumed - the day it starts
        // persisting, this fails and the endpoint has to be classified.
        var importMetadata = actions.First(a => a.Routes.Contains("SAML/ImportMetadata", StringComparer.Ordinal));
        Assert.DoesNotContain("MutateConfiguration(", importMetadata.Body, StringComparison.Ordinal);
    }

    // The token the two source scans above look for, built from the real type and method rather than typed
    // out as a string. A rename therefore breaks this line (or fails the assertion below) instead of quietly
    // turning both scans into a search for a token nothing contains any more - a scan that matches nothing
    // passes, which is the shape #1160 asks to be pinned against.
    private static string ProviderNamePredicateToken()
    {
        var method = typeof(ProviderNameValidator).GetMethod(
            nameof(ProviderNameValidator.IsInvalid),
            BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);

        Assert.True(method is not null, "ProviderNameValidator.IsInvalid was renamed or removed; the provider-name gate rules scan for it by name (#1160).");
        Assert.Equal(typeof(bool), method!.ReturnType);
        Assert.Equal(typeof(string), Assert.Single(method.GetParameters()).ParameterType);

        // And it still decides: a predicate renamed back into place but gutted would satisfy every scan above.
        Assert.True((bool)method.Invoke(null, ["a/b"])!, "the pinned predicate no longer rejects a slash, which is the character that dead-ends the IdP redirect on a path no route matches (#336).");
        Assert.False((bool)method.Invoke(null, ["keycloak"])!, "the pinned predicate now rejects an ordinary name, which would strand every registration (#336).");

        return $"{nameof(ProviderNameValidator)}.{method.Name}(";
    }
}
