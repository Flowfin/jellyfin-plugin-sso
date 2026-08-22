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
/// Conformance rules for the OIDC callback path and redirect_uri composition: one composition site, one builder fed a canonical base, and the admin page mirroring the server path.
/// </content>
public partial class ArchitectureConformanceTests
{
    // The path fragment that turns a base URL into an OpenID callback URL. RFC 6749 section 4.1.3 compares
    // redirect_uri byte-for-byte, so the authorization request and the token exchange have to hand out the
    // same string; a second place that composes this fragment is where the two would drift apart, and the
    // symptom lands at the identity provider as a refused login rather than anywhere a unit test looks.
    private const string OidcCallbackPathFragment = "/sso/OID/";

    // The one file allowed to compose it. Repo-relative and exact rather than a file name, for the reason
    // ParseSites() gives: two files can share a name and an allowlist keyed on the short one admits the
    // wrong file.
    private const string OidcRedirectUriCompositionSite = "SSO-Auth/Api/Oidc/OidcRedirectUriBuilder.cs";

    // Where a source text composes the OpenID callback path: the fragment inside a STRING LITERAL on a code
    // line. Reading literals rather than raw text is what keeps the five doc comments that quote the route
    // (LoginButton, OidcCallbackPath, ChallengePath, RouteSuffix) out of it, and the fixtures below pin both
    // directions. Its limit is the literal boundary - a site splitting the fragment across two literals is
    // not seen - and that residual is pinned rather than left to be discovered.
    private static IEnumerable<(int Number, string Text)> OidcCallbackPathCompositions(string source) =>
        CodeLinesOf(source)
            .Where(l => StringLiterals(l.Text).Any(literal => literal.Contains(OidcCallbackPathFragment, StringComparison.Ordinal)));

    [Fact]
    public void TheOidcCallbackPath_IsComposedInExactlyOnePlace()
    {
        // #1162. Two call sites hand out a redirect_uri, the challenge and the token exchange, and they must
        // produce identical bytes. Today both go through OidcRedirectUriBuilder; nothing refuses a third site
        // that concatenates the path itself, which is the edit that makes them differ.
        var root = RepoTree.Root;
        var offenders = Directory
            .EnumerateFiles(Path.Combine(root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Select(path => (Relative: Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/'), Path: path))
            .Where(file => !string.Equals(file.Relative, OidcRedirectUriCompositionSite, StringComparison.Ordinal))
            .SelectMany(file => OidcCallbackPathCompositions(File.ReadAllText(file.Path))
                .Select(l => $"{file.Relative}:{l.Number}: {l.Text}"))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"Only {OidcRedirectUriCompositionSite} may compose the OpenID callback path; a second site is how the challenge's redirect_uri and the token exchange's stop being the same bytes (#1162): " + string.Join(" | ", offenders));

        // Sentinel against a vacuous pass: the allowlisted file must still be the thing the scan is about. If
        // the composition moved out of it the loop above would find nothing and report a clean surface, which
        // is the shape this rule exists to refuse.
        Assert.True(
            OidcCallbackPathCompositions(File.ReadAllText(Path.Combine(root, OidcRedirectUriCompositionSite))).Any(),
            $"{OidcRedirectUriCompositionSite} no longer composes '{OidcCallbackPathFragment}', so this rule is now scanning for a fragment nothing in the tree holds and would pass over any hand-rolled site (#1162).");
    }

    [Fact]
    public void EveryOidcRedirectUriCallSite_FeedsTheOneBuilderACanonicalBase()
    {
        // The other half: the single builder is only single while every caller reaches it, and only correct
        // while every caller hands it the SAME base. A call site passing the raw request host instead of the
        // resolved canonical base produces a well-formed redirect_uri that the other leg does not match.
        var challenge = OidcRedirectUriBuilderMethod(nameof(OidcRedirectUriBuilder.ChallengeRedirectUri));
        var callback = OidcRedirectUriBuilderMethod(nameof(OidcRedirectUriBuilder.CallbackRedirectUri));

        var callSite = new Regex(
            $@"{nameof(OidcRedirectUriBuilder)}\.(?<method>\w+)\(\s*(?<base>[A-Za-z_][\w.]*)\(");

        var calls = Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .SelectMany(path => CodeLines(path).Select(l => (File: Path.GetFileName(path), l.Number, l.Text)))
            .Where(l => l.Text.Contains($"{nameof(OidcRedirectUriBuilder)}.", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            calls.Count >= 2,
            $"The redirect_uri call-site walk found {calls.Count} call(s) of {nameof(OidcRedirectUriBuilder)}; both the challenge and the token exchange must reach it, so a smaller number means the walk has stopped seeing the flow and this rule would pass over nothing (#1162).");

        var strays = calls
            .Select(l => (l.File, l.Number, l.Text, Match: callSite.Match(l.Text)))
            .Where(c => !c.Match.Success
                || !string.Equals(c.Match.Groups["base"].Value, OidcCanonicalBaseReader, StringComparison.Ordinal)
                || (c.Match.Groups["method"].Value != challenge.Name && c.Match.Groups["method"].Value != callback.Name))
            .Select(c => $"{c.File}:{c.Number}: {c.Text}")
            .ToList();

        Assert.True(
            strays.Count == 0,
            $"Every {nameof(OidcRedirectUriBuilder)} call must name one of its two methods and take {OidcCanonicalBaseReader}(...) as its base, so both legs are built over one canonical base (#1162, #242): " + string.Join(" | ", strays));

        Assert.Contains(challenge.Name, calls.Select(c => c.Text).Aggregate(string.Concat), StringComparison.Ordinal);
        Assert.Contains(callback.Name, calls.Select(c => c.Text).Aggregate(string.Concat), StringComparison.Ordinal);

        // And the base reader is the shared canonical decision rather than a local re-derivation of it, which
        // is the hop the two assertions above would otherwise take on trust.
        var flow = Assert.Single(SourceFilesDeclaring(new[] { typeof(OidcLoginService) }));
        var flowSource = File.ReadAllText(flow);
        Assert.Contains($"string {OidcCanonicalBaseReader}(HttpRequest request, OidConfig config) =>", flowSource, StringComparison.Ordinal);
        Assert.True(
            SourceCallsInCode(flowSource, $"{nameof(CanonicalBaseUrl)}.{nameof(CanonicalBaseUrl.Resolve)}("),
            $"{OidcCanonicalBaseReader} must resolve through {nameof(CanonicalBaseUrl)}.{nameof(CanonicalBaseUrl.Resolve)}; a local base derivation is how the redirect_uri stops matching the one the SAML side and the admin page compute (#242, #1162).");

        // One assignment reaches the library, so there is no route that sets a redirect_uri the builder did
        // not produce. Both call sites feed this one parameter.
        var assignments = CodeLines(flow).Where(l => l.Text.Contains("options.RedirectUri", StringComparison.Ordinal)).ToList();
        var assignment = Assert.Single(assignments);
        Assert.Equal("options.RedirectUri = redirectUri;", assignment.Text);
    }

    // The rule that stood here pinned the admin page's own JavaScript composition of the redirect_uri
    // against the server's path fragment. #1303 removed the composition rather than keeping the two copies
    // aligned, so this rule has no subject left: the page fetches the value from OID/RedirectUri and the
    // server is the only producer of these bytes. What replaced it is
    // OidcRedirectUriField_IsReadOnly_AndIsFilledFromTheServerRatherThanComposedInThePage in the LoginPath
    // partial, which refuses a composition coming BACK into config.js, and the call-site walk above, which
    // now covers the display path because it reaches the same builder over the same canonical base.

    [Fact]
    public void TheProvisionedUsernameAllowlist_StillMirrorsTheRecordedHostRule()
    {
        // ProvisionedUsername.AllowedPunctuation is a hand-copy of Jellyfin's own account-name check, which
        // the plugin cannot reference: it lives in the server, off the Controller/Model surface compiled
        // against. Its one in-repo record is the regex written into AvatarService's comment (#447), so the
        // copy is pinned to that record here. Nothing can pin either against the server - that residual is
        // stated on ProvisionedUsername - but the two halves inside this tree can no longer drift apart in
        // silence, which is the near-miss worth the rule: an editor widening or narrowing one spelling and
        // never learning that the other one decides what a brand-new account is actually named.
        var avatar = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Avatar", "AvatarService.cs"));
        var recorded = Regex.Match(avatar, @"\^\(\?!\\s\)\[\\w(?<members>[^\]]*)\]\+\(\?<!\\s\)\$", RegexOptions.None, TimeSpan.FromSeconds(5));

        Assert.True(recorded.Success, $"{nameof(AvatarService)} no longer records the host username regex, which is the only source {nameof(ProvisionedUsername)}'s allowlist is derived from (#1137).");
        Assert.Equal(ProvisionedUsername.AllowedPunctuation, recorded.Groups["members"].Value.Replace(@"\-", "-", StringComparison.Ordinal));
    }

    [Fact]
    public void TheOidcCallbackPathScan_LeavesTheSamlBuilderAlone()
    {
        // Must-not-catch, named by #1162: the SAML AssertionConsumerServiceURL is the sibling issue's subject
        // (#1163) and its builder must read as clean here, or the two rules would fight over one file.
        var saml = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Saml", "SamlAcsUrlBuilder.cs"));

        Assert.Empty(OidcCallbackPathCompositions(saml));
        Assert.Contains("/sso/SAML/", saml, StringComparison.Ordinal);
    }

    // The composition scan, fed synthetic source. The near-miss worth spending the fixtures on is a new
    // OpenID entry point whose author concatenates the path instead of calling the builder: it compiles, it
    // looks right, and it is wrong only in bytes. The last row is the scan's residual rather than an
    // oversight waved through - a fragment split across two literals is invisible to it, and pinning that
    // makes closing it later a deliberate edit with a failing test in front of it.
    [Theory]
    [InlineData("        var uri = baseUrl + \"/sso/OID/r/\" + provider;", true)]
    [InlineData("        return baseUrl + \"/sso/OID/\" + segment + \"/\" + provider;", true)]
    [InlineData("        var uri = $\"{baseUrl}/sso/OID/redirect/{provider}\";", true)]
    [InlineData("/// <param name=\"path\">The callback request path, e.g. <c>/sso/OID/redirect/{provider}</c>.</param>", false)]
    [InlineData("        // the hand-rolled \"/sso/OID/r/\" + provider was removed here", false)]
    [InlineData("     * see \"/sso/OID/redirect/\" for the spelling", false)]
    [InlineData("        return baseUrl + \"/sso/SAML/\" + segment + \"/\" + provider;", false)]
    [InlineData("        var uri = baseUrl + \"/sso/OID\" + \"/r/\" + provider;", false)]
    public void TheOidcCallbackPathScan_ReadsStringLiteralsOnCodeLines(string line, bool expected)
    {
        Assert.Equal(expected, OidcCallbackPathCompositions(line).Any());
    }

    // The local reader every redirect_uri call site takes its base from. Named once so the rule and its
    // message cannot disagree about which hop is being required.
    private const string OidcCanonicalBaseReader = "RequestBaseUrl";

    // A builder method, pinned by reflection so a rename fails here instead of turning the source scans into
    // a search for a token nothing contains - the shape #1162 asks for a sentinel against. The signature is
    // asserted too: a method renamed back into place with a different shape would satisfy a name-only check.
    private static MethodInfo OidcRedirectUriBuilderMethod(string name)
    {
        var method = typeof(OidcRedirectUriBuilder).GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);

        Assert.True(method is not null, $"{nameof(OidcRedirectUriBuilder)}.{name} was renamed or removed; the redirect_uri rules scan for it by name (#1162).");
        Assert.Equal(typeof(string), method!.ReturnType);

        var parameters = method.GetParameters();
        Assert.Equal(3, parameters.Length);
        Assert.Equal(typeof(string), parameters[0].ParameterType);
        Assert.Equal(typeof(string), parameters[2].ParameterType);

        return method;
    }
}
