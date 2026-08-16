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
/// Conformance rules for the identity-construction lock and the outbound-connection guards: who may build a VerifiedIdentity, where the private-network relaxation may be selected, and the controller source scans.
/// </content>
public partial class ArchitectureConformanceTests
{
    [Fact]
    public void VerifiedIdentity_IsConstructedOnlyByProtocolValidators()
    {
        // Locked in by #473: VerifiedIdentity is the keystone the session-minting path is keyed on, and it
        // is unforgeable - its constructor is PRIVATE, so the only way to obtain one is a named factory that
        // stands for "this protocol's validation has completed". Two properties are pinned:
        //
        // 1. Reflection: NO declared instance constructor is reachable from outside the type - none is
        //    public, internal, or protected-internal. A sealed record's own compiler-generated copy
        //    constructor is emitted PRIVATE (protected only for unsealed records), so it too is excluded by
        //    this filter; the accessibility test is written to also exclude a plain `protected` ctor, which
        //    is unreachable on a sealed type anyway (no derived type could invoke it). The C# compiler
        //    guarantees such a constructor cannot be invoked outside the declaring type, so this alone
        //    proves `new VerifiedIdentity(...)` can appear only inside VerifiedIdentity.cs (the two
        //    factories) - no third construction path can compile. (An empty `with { }` on an existing
        //    instance clones a valid identity verbatim; every property is get-only, so it can neither
        //    mutate nor forge one.) A future `public`/`internal` ctor added to the type would reopen that
        //    hole and fail HERE.
        // 2. Source scan: each factory is INVOKED only from its protocol's validator. FromValidatedOidc
        //    belongs to the OpenID redeem path - built inside AuthorizeSession.Ready, which the store hands
        //    out only through the one-time atomic redeem - and FromValidatedSaml only at the SAML
        //    session-minting endpoint after full response validation. A call from anywhere else (a link
        //    endpoint, a new controller action) would mean an identity minted from something other than a
        //    completed validation, so it fails the scan.
        var ctors = typeof(VerifiedIdentity)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
        Assert.True(ctors.Length > 0, "VerifiedIdentity must declare an instance constructor to pin (it was removed or the type was renamed).");
        var reachable = ctors
            .Where(c => c.IsPublic || c.IsAssembly || c.IsFamilyOrAssembly)
            .Select(c => c.ToString())
            .ToList();
        Assert.True(
            reachable.Count == 0,
            "VerifiedIdentity's constructor(s) must not be reachable from outside the type (no public/internal/protected-internal ctor) so it is constructible only through its validation factories (#473): " + string.Join(", ", reachable));

        // Sentinel + call-site pins. The factory NAMES are the contract; require both to exist (a rename
        // must consciously update this rule), then confine each factory's invocation to the file(s) that own
        // its protocol's validation. AuthorizeSession is where the OpenID identity is built (from the
        // role-gate result); the SAML factory is invoked from the dedicated SamlAssertionValidator, the
        // single home the SAML inbound validation moved into (#496) - downstream of every gate, so the
        // "constructed only after complete validation" invariant is local to the validator.
        const string oidcFactory = "FromValidatedOidc";
        const string samlFactory = "FromValidatedSaml";
        var factoryMethods = typeof(VerifiedIdentity)
            .GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
            .Where(m => m.ReturnType == typeof(VerifiedIdentity))
            .Select(m => m.Name)
            .ToHashSet(StringComparer.Ordinal);
        Assert.True(
            factoryMethods.Contains(oidcFactory) && factoryMethods.Contains(samlFactory),
            $"VerifiedIdentity must expose the two named validation factories ({oidcFactory}, {samlFactory}); one was renamed, so update this rule and the source-scan allow-list with it (#473).");

        var oidcHome = SourceFilesDeclaring(new[] { typeof(AuthorizeSession) });
        var samlHome = SourceFilesDeclaring(new[] { typeof(SamlAssertionValidator) });
        AssertFactoryInvocationsConfinedTo("VerifiedIdentity." + oidcFactory + "(", oidcHome, "the OpenID redeem path (AuthorizeSession.Ready)");
        AssertFactoryInvocationsConfinedTo("VerifiedIdentity." + samlFactory + "(", samlHome, "the SAML assertion validator (SamlAssertionValidator)");
    }

    // Fails if the given factory-invocation token appears in any SSO-Auth source file outside the allowed
    // homes. Shared by the two #473 call-site pins; the allowed set is matched by absolute path so a file
    // rename that the reflection-driven home discovery already tracks flows through unchanged. This is a
    // qualified-call substring scan (belt-and-braces): the AIRTIGHT construction lock is the private-ctor
    // reflection assertion above - nothing outside VerifiedIdentity.cs can construct one at all, so a call
    // that this scan's substring might miss (a `using static` unqualified spelling, a line-split call) still
    // cannot forge an identity; this scan adds the sharper "constructed only by the RIGHT validator" signal
    // on top, keying on the qualified spelling the codebase actually uses.
    private static void AssertFactoryInvocationsConfinedTo(string invocationToken, IEnumerable<string> allowedFiles, string homeDescription)
    {
        var allowed = allowedFiles.Select(Path.GetFullPath).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var strays = Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Where(path => !allowed.Contains(Path.GetFullPath(path)))
            .Where(path => File.ReadAllText(path).Contains(invocationToken, StringComparison.Ordinal))
            .Select(Path.GetFileName)
            .ToList();

        Assert.True(
            strays.Count == 0,
            $"{invocationToken}...) may be invoked only from {homeDescription}; found outside it in: " + string.Join(", ", strays));
    }

    [Fact]
    public void OutboundConnectGuard_ResolvesTheHostOnce_AndConnectsToTheAddressItJudged()
    {
        // The guard is only worth anything if the address it judged is the address the socket reaches. A
        // second name resolution between the check and the connect, or a connect aimed at the host name
        // instead of the validated address, reopens DNS rebinding exactly: the attacker's name resolves to
        // a public address for the check and to an internal one for the connect. That property lives in
        // three lines of ConnectToAllowedAddressAsync and no runtime test can observe it without a
        // controllable resolver, so pin it at the source - the same way this file pins the other
        // call-level invariants.
        var source = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Net", "SsoHttp.cs"));

        // Exactly one resolution, and the host name is read only to perform it.
        Assert.Equal(1, CountOccurrences(source, "GetHostAddressesAsync"));
        Assert.Equal(1, CountOccurrences(source, "context.DnsEndPoint.Host"));

        // The value that is judged and the value that is connected to are the same local.
        Assert.Contains("IpAddressClassifier.IsBlockedAddress(address, policy)", source, StringComparison.Ordinal);
        Assert.Contains("socket.ConnectAsync(address, context.DnsEndPoint.Port", source, StringComparison.Ordinal);

        // The tier comes from the handler that captured it, never from the request, so a redirect hop is
        // judged under the tier the connection started on.
        Assert.Contains("ConnectToAllowedAddressAsync(context, policy, cancellationToken)", source, StringComparison.Ordinal);
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        for (var i = haystack.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = haystack.IndexOf(needle, i + needle.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }

    [Fact]
    public void PrivateNetworkRelaxation_NeverReachesTheAvatarFetchOrTheSamlMetadataImporter()
    {
        // #1179's stated failure mode is a leak of the private-network relaxation to a caller that never
        // opted in. Two files are named on the issue as out of scope for #1058 and must stay strict: the
        // avatar fetch, which builds its own handler and would otherwise let an IdP-supplied picture URL
        // reach the admin's LAN, and the SAML metadata importer, which resolves the named outbound client
        // and must keep resolving the strict one. SsoHttp's strict-by-default signature is what makes them
        // correct today, but a default protects nothing against someone later passing the flag explicitly -
        // so pin the call sites, not just the default. A source scan because this is a call-level property.
        foreach (var relativePath in new[]
        {
            Path.Combine("SSO-Auth", "Api", "Avatar", "AvatarService.cs"),
            Path.Combine("SSO-Auth", "Api", "Http", "SamlMetadataImporter.cs"),
        })
        {
            var source = File.ReadAllText(Path.Combine(RepoTree.Root, relativePath));

            Assert.DoesNotContain("PrivateNetworkPermitted", source, StringComparison.Ordinal);
            Assert.DoesNotContain("PrivateOutboundClientName", source, StringComparison.Ordinal);
            Assert.DoesNotContain("allowPrivateNetworkAddresses", source, StringComparison.Ordinal);
            Assert.DoesNotContain("AllowPrivateNetworkAddresses", source, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void PrivateNetworkRelaxation_IsSelectedOnlyByTheOidcBackchannelAndItsComposition()
    {
        // The other direction: enumerate every file that may name the relaxation at all, so a new caller
        // wiring itself to the private-permitted tier has to be added here deliberately rather than
        // arriving unnoticed. The roster is the OIDC backchannel (the login flow, the discovery reader and
        // the admin "Test connection" probe), the config surface that stores and audits the flag, and the
        // transport plus its composition root that define and register the two tiers.
        var allowed = new[]
        {
            "AddressPolicy.cs", "IpAddressClassifier.cs", "SsoHttp.cs", "SsoOnlyServiceRegistrator.cs",
            "OidcLoginService.cs", "OidcDiscoveryReader.cs", "ProviderConnectionTester.cs",
            "PluginConfiguration.cs", "OidcInsecureToggles.cs",
        }.ToHashSet(StringComparer.OrdinalIgnoreCase);

        var strays = Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Where(path => !allowed.Contains(Path.GetFileName(path)))
            .Where(path => File.ReadAllText(path).Contains("PrivateNetworkAddresses", StringComparison.Ordinal)
                || File.ReadAllText(path).Contains("PrivateNetworkPermitted", StringComparison.Ordinal)
                || File.ReadAllText(path).Contains("PrivateOutboundClientName", StringComparison.Ordinal))
            .Select(Path.GetFileName)
            .ToList();

        Assert.True(
            strays.Count == 0,
            "The private-network relaxation (#1058) must reach only the OIDC backchannel, its config surface and the transport; found named in: " + string.Join(", ", strays));
    }

    [Fact]
    public void Controller_NeverTouchesProviderLinkMaps()
    {
        // Locked in by the link/unlink admin-surface extraction (#372) and completed by #383: the two
        // legitimate homes for provider-CanonicalLinks access are CanonicalLinkService (the login/admin
        // link workflow, under the config lock) and ServerManagedFields.Preserve (the #157 re-injection
        // the config tier owns) - and the controller's two former inline re-injection statements now route
        // through that shared Preserve, so a CONTROLLER has ZERO direct CanonicalLinks access. This is a
        // call-level property, so it is a source scan rather than a reflection rule (the one exception to
        // the "call-level invariants stay with CodeQL" note in the class summary).
        //
        // Sentinel against a vacuous pass (#388): a zero-occurrence scan only means something while its
        // target token still names a link map. A property rename (CanonicalLinks -> anything) would make
        // the scan match nothing and pass for the wrong reason, so pin each property by reflection - a
        // rename fails HERE and forces a conscious update of the roster (and the scanned token with it).
        // BOTH server-managed link maps are guarded: the account-link map (ProviderConfigBase.CanonicalLinks,
        // #157) and its per-link issuer binding (OidConfig.CanonicalLinkIssuers, #186). Both are owned by
        // CanonicalLinkService and ServerManagedFields.Preserve; a controller must touch neither directly.
        var linkMapProperties = new[]
        {
            (Declaring: typeof(ProviderConfigBase), Name: "CanonicalLinks"),
            (Declaring: typeof(OidConfig), Name: "CanonicalLinkIssuers"),
        };
        foreach (var (declaring, name) in linkMapProperties)
        {
            Assert.True(
                declaring.GetProperty(name, BindingFlags.Public | BindingFlags.Instance) is not null,
                $"{declaring.Name}.{name} was renamed or removed; point this rule at the new provider link-map property so the scan keeps guarding it (#388).");
        }

        // The two tokens are disjoint substrings (".CanonicalLinkIssuers" does not contain ".CanonicalLinks"
        // - the char after "Link" is "I", not "s"), so scanning for both cannot cross-match.
        var tokens = linkMapProperties.Select(p => "." + p.Name).ToList();
        var linkMapLines = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => tokens.Any(t => l.Text.Contains(t, StringComparison.Ordinal)))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            linkMapLines.Count == 0,
            "A controller must not access a provider link map (CanonicalLinks / CanonicalLinkIssuers) directly; route link-map access through CanonicalLinkService and server-managed re-injection through ServerManagedFields.Preserve. Found: " + string.Join(" | ", linkMapLines));
    }

    [Fact]
    public void Controller_NeverTouchesRawSocketsOrDns()
    {
        // Locked in by the AvatarService extraction (#375): the raw-socket/DNS surface lives only in the
        // avatar tier (AvatarService, AvatarUrlValidator) and SsoRateLimiter - the controller orchestrates
        // flows over injected collaborators and never opens a network primitive itself. Same source scan as
        // the link-map rule above, over every controller source file (#388). Marker choice: any
        // Socket/NetworkStream use needs the System.Net.Sockets namespace in the file (using directive,
        // alias, or full qualification), so that one marker subsumes those type names; "NetworkStream" is
        // the belt-and-braces type-name catch on top; "SocketsHttpHandler" lives in System.Net.Http, which
        // the controller legitimately imports, so the namespace marker cannot cover it and it gets its own;
        // "Dns." catches System.Net.Dns call sites (which need no Sockets using) and "System.Net.Dns" the
        // static-import form. Bare "Socket"/"Dns" are deliberately NOT markers - they would false-positive
        // on prose in comments.
        var markers = new[] { "System.Net.Sockets", "SocketsHttpHandler", "NetworkStream", "Dns.", "System.Net.Dns" };
        var socketLines = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => markers.Any(m => l.Text.Contains(m, StringComparison.Ordinal)))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            socketLines.Count == 0,
            "A controller must not touch the raw socket/DNS surface (System.Net.Sockets, Socket, NetworkStream, Dns); outbound network primitives belong to AvatarService/AvatarUrlValidator and SsoRateLimiter. Found: " + string.Join(" | ", socketLines));

        // Sentinel against a vacuous pass (#444): unlike the link-map rule above, these markers are BCL
        // identifiers, not a token this codebase owns, so there is no single property to pin by
        // reflection. Instead pin the marker SET against reality: the raw socket/DNS surface's one
        // legitimate home is AvatarService/AvatarUrlValidator/SsoRateLimiter (#375), so at least one
        // marker must still match a real line there today. If a refactor ever changed how that tier
        // references sockets/DNS (a wrapping abstraction, a different BCL spelling) so that NONE of the
        // markers matched it any more, the zero-occurrence scan above would keep "passing" for the wrong
        // reason - this is the assertion that would actually catch it. Deliberately "at least one", not
        // "every" marker: "System.Net.Dns" is a defensive marker for the fully-qualified/static-import
        // spelling, which this codebase does not use anywhere today (Dns.GetHostAddressesAsync resolves
        // through the "using System.Net;" form instead, caught by the "Dns." marker) - that marker having
        // no live match is expected, not a liveness failure.
        var homeTypes = new[] { typeof(AvatarService), typeof(AvatarUrlValidator), typeof(SsoRateLimiter) };
        var homeFiles = SourceFilesDeclaring(homeTypes);
        Assert.True(
            homeFiles.Count == homeTypes.Length,
            "The raw socket/DNS surface's legitimate home (AvatarService/AvatarUrlValidator/SsoRateLimiter) was renamed or moved; point Controller_NeverTouchesRawSocketsOrDns's liveness check at its new location (#444).");

        var homeLines = homeFiles.SelectMany(File.ReadAllLines).ToList();
        Assert.True(
            markers.Any(m => homeLines.Any(l => l.Contains(m, StringComparison.Ordinal))),
            "None of the socket/DNS markers match any line in their legitimate home (AvatarService/AvatarUrlValidator/SsoRateLimiter); the zero-occurrence controller scan above would pass vacuously - update the markers to track how the socket/DNS surface is actually referenced (#444).");
    }
}
