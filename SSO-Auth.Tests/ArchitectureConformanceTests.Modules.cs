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
/// Conformance rules for the module DAG and the folder/namespace layout: which Api module may import which, the flat-Api ban, the test-tree mirror, and the internal-documentation gate.
/// </content>
public partial class ArchitectureConformanceTests
{
    // Module-boundary fitness function of the #777 folder migration: each extracted module may import ONLY the
    // Api modules explicitly allowed for it (a leaf allows none), pinning the module dependency DAG. Enforced at
    // the IMPORT level, which also catches method-body coupling (reflection over signatures would miss a
    // body-only call): using a type from another Api module requires importing its namespace. Importing NON-Api
    // namespaces (e.g. the Config persistence model or the still-unmigrated flat Api core) stays allowed, and a
    // file never imports its own module namespace. As each module lands (#777) it registers a case here with its
    // allowed dependencies; together the cases lock in the DAG and forbid a cycle.
    [Theory]
    [InlineData("Net")] // leaf - networking / URL / SSRF primitives: IpAddressClassifier, CanonicalBaseUrl, SsoHttp
    [InlineData("Secrets")] // leaf - secrets at rest: SecretStore, SecretEnvelope, ConfigSecretProtection
    [InlineData("Audit")] // leaf - append-only audit logging: SsoAudit
    [InlineData("Avatar", "Net", "RateLimit")] // avatar fetch - validates targets through the Net SSRF classifier, per-user store locks via KeyedLockStore (RateLimit)
    [InlineData("RateLimit", "Net")] // login throttling - keys buckets by the Net client-IP classifier
    [InlineData("Authz")] // leaf - role→permission mapping: PermissionGrant, PermissionRolePolicy, RolePrivilegeMapper
    [InlineData("Routing")] // leaf - the plugin's route-shape contract: RouteSuffix ({protocol}/{path-kind}/{provider} reader), ChallengePath (new/legacy classifier)
    [InlineData("Crypto")] // leaf - the shared asymmetric signing-key strength policy (min RSA bits / approved EC curves), referenced by both protocol paths so they cannot drift (#733)
    [InlineData("LoginButtons")] // leaf - login-page button rendering (#722): pure injector/builder over the config + a branding-sync hosted service; imports no other Api module
    [InlineData("Logout")] // leaf - Single Logout session-state store (#727): pure bounded operations over the config's LogoutSessions map; imports no other Api module
    [InlineData("Localization")] // leaf - served-surface string localizer (#913): loads embedded per-culture JSON catalogs and resolves keys through a fallback chain; imports no other Api module


    [InlineData("Provider", "Net", "RateLimit")] // provider config/test/naming - validates URLs (Net) and keys throttles (RateLimit)
    [InlineData("Linking", "Audit", "Provider", "RateLimit")] // account linking - audits writes, validates providers, throttles
    [InlineData("Saml", "Authz", "Crypto", "Identity", "RateLimit", "Session")] // SAML core/validators - mints the keystone (Identity), returns login outcomes (Session), maps roles (Authz), throttles (RateLimit), enforces the signing-key floor (Crypto)
    [InlineData("Oidc", "Audit", "Authz", "Avatar", "Crypto", "Identity", "Logout", "Net", "Provider", "RateLimit", "Routing")] // OIDC flow - mints the keystone (Identity), orchestrates roles, avatar, net, provider, throttle; reads its callback path through the Routing suffix reader; enforces the signing-key floor (Crypto); carries the captured logout context (Logout, #727); records a REFUSED role claim at the point the walk refused it, which is inside this module rather than at a gate downstream (Audit, leaf, no cycle - #1149)
    [InlineData("Identity", "Authz", "Provider")] // the identity keystone - grants (Authz) + link mode (Provider); decoupled from the protocols by #790
    [InlineData("Session", "Authz", "Avatar", "Linking")] // session mint + login outcomes - applies grants (Authz), sets avatars (Avatar), reconciles links (Linking)
    [InlineData("Shared", "Avatar", "Linking", "Localization", "RateLimit", "Routing", "Session")] // shared served-page / flow-response + rate-limit-gate helpers - depend downward on the session/linking/avatar/throttle/route/localization tiers, never on a protocol or the boundary
    [InlineData("Flows", "Audit", "Identity", "Linking", "Localization", "Logout", "Net", "Oidc", "Provider", "RateLimit", "Saml", "Session", "Shared")] // per-protocol login orchestration - drives both protocol modules (Oidc/Saml) and the downstream mint/link/session tiers; localizes the served auth-completion page (Localization, #913); persists the captured logout state at the mint (Logout, #727); nothing above the boundary imports it
    [InlineData("Http", "Audit", "Avatar", "Flows", "Linking", "Localization", "Logout", "Net", "Oidc", "Provider", "Saml", "Session", "Shared")] // the web boundary (SSOController + request helpers + the admin test-connection probe + the UI-string endpoint, #913): the composition top of the DAG - it fronts every flow, so its import list is deliberately wide (incl. the RP-initiated logout store, #727); nothing imports it back (#790/#807)
    public void ApiModule_ImportsOnlyItsAllowedApiModules(string module, params string[] allowed)
    {
        var moduleDir = Path.Combine(RepoTree.Root, "SSO-Auth", "Api", module);
        var permitted = new HashSet<string>(allowed) { module };
        var offenders = Directory.EnumerateFiles(moduleDir, "*.cs")
            .SelectMany(file => File.ReadLines(file)
                .Select(line => Regex.Match(line, @"^\s*using\s+Jellyfin\.Plugin\.SSO_Auth\.Api\.(?<mod>[A-Za-z0-9_]+)\s*;"))
                .Where(m => m.Success && !permitted.Contains(m.Groups["mod"].Value))
                .Select(m => Path.GetFileName(file) + ": " + m.Value.Trim()))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"The {module} module may import only [{string.Join(", ", allowed)}] among Api modules; these imports break that: " + string.Join(" | ", offenders));
    }

    [Fact]
    public void FlatApi_HoldsNoSourceFiles_EveryApiTypeLivesInAModule()
    {
        // The kernel dissolution is complete and locked (#790/#807): there is NO code directly in
        // SSO-Auth/Api/ - every type lives in a named module subfolder (Net, Secrets, …, Http). The former
        // flat "kernel" that once held the controller, the URL builders, the keystone and the served-page
        // types was a deliberate, transitional bucket; it is now empty and must stay empty, so a new type is
        // forced into a module (or a new one) at creation and can never re-accumulate a flat pile.
        var apiRoot = Path.Combine(RepoTree.Root, "SSO-Auth", "Api");
        var flatFiles = Directory.EnumerateFiles(apiRoot, "*.cs", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileName)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            flatFiles.Count == 0,
            "SSO-Auth/Api/ must hold no source files directly - every Api type belongs in a module subfolder (#790/#807). Found in the flat Api root: " + string.Join(", ", flatFiles));
    }

    [Fact]
    public void ModuleTests_MirrorTheSourceModuleFolders()
    {
        // #791: a test that covers a type in Api/<Module>/ lives under SSO-Auth.Tests/<Module>/, so a test is
        // as easy to place and find as the code it covers, and the test tree cannot drift back into a flat
        // pile. Governs the per-source-module tests (found by the <Type> -> <Type>Tests.cs naming); the
        // SSOController split tests (SSOController*Tests, which sit under Http/ next to the controller source),
        // the Config, and the shared-infrastructure tests are organised in their own folders (Config, _Support,
        // …) and have no exact <Type>Tests.cs source match, so they are out of scope here. A type with no
        // matching test file is simply skipped - this rule governs WHERE a mirrored file lives, never
        // whether one exists. Where an absence is a decision rather than an omission it is declared in
        // TypesWithNoMirroredTestFile below, which is the half of the question this rule cannot answer.
        var apiRoot = Path.Combine(RepoTree.Root, "SSO-Auth", "Api");
        var testsRoot = Path.Combine(RepoTree.Root, "SSO-Auth.Tests");
        var testFiles = Directory.EnumerateFiles(testsRoot, "*Tests.cs", SearchOption.AllDirectories)
            .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !p.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .ToList();

        var offenders = new List<string>();
        foreach (var src in Directory.EnumerateFiles(apiRoot, "*.cs", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(apiRoot, src);
            var separator = relative.IndexOf(Path.DirectorySeparatorChar);
            if (separator < 0)
            {
                continue; // a flat Api/ kernel file - not module-scoped
            }

            var module = relative[..separator];
            var expectedDir = Path.Combine(testsRoot, module) + Path.DirectorySeparatorChar;
            var testName = Path.GetFileNameWithoutExtension(src) + "Tests.cs";
            var test = testFiles.FirstOrDefault(p => string.Equals(Path.GetFileName(p), testName, StringComparison.Ordinal));
            if (test is not null && !test.StartsWith(expectedDir, StringComparison.Ordinal))
            {
                offenders.Add($"{testName} (covers Api/{module}) is at {Path.GetRelativePath(testsRoot, test)} - expected under {module}/");
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Each module's tests must mirror its source folder under SSO-Auth.Tests/<Module>/ (#791): " + string.Join(" | ", offenders));
    }

    // Production types that deliberately have no <Type>Tests.cs of their own, each with the files their
    // coverage actually lives in. A declaration, not a dispensation: the rule below refuses an entry whose
    // source is gone, an entry whose named cover files stopped naming the type, and an entry that has since
    // grown a mirrored file - so retiring one has to move the entry rather than leave it standing.
    private static readonly SortedDictionary<string, string[]> TypesWithNoMirroredTestFile = new(StringComparer.Ordinal)
    {
        // #1189, the recorded answer to a question the rule above cannot reach. The screen is a transport
        // handler with nothing to call directly: it exists to sit between the discovery read and the identity
        // library, so every property it has is a property of a request travelling through it. Its units are
        // therefore named for the property each one pins rather than for the type, and a RepeatedMemberScreenTests
        // would either duplicate them or hold the leftovers nobody could place - which is how a mirrored file
        // ends up being the least informative place to look.
        ["SSO-Auth/Api/Oidc/RepeatedMemberScreen.cs"] = new[]
        {
            "SSO-Auth.Tests/Oidc/OidcDiscoveryReaderTests.cs",
            "SSO-Auth.Tests/Oidc/RefusalEntryMemberNameTests.cs",
            "SSO-Auth.Tests/Oidc/DuplicateJsonKeyPostureTests.cs",
            "SSO-Auth.Tests/Http/ProviderConnectionTesterTests.cs",
            "SSO-Auth.Tests/Http/SSOControllerOidBackChannelLogoutTests.cs",
        },
    };

    /// <summary>
    /// A type with no mirrored test file is either a decision or an omission, and until #1189 a reviewer
    /// could not tell which - <see cref="ModuleTests_MirrorTheSourceModuleFolders"/> skips such a type by
    /// design, so silence meant both things at once. This is where the decision is written down, and it is
    /// refusable in three directions rather than a comment: the source has to exist, the files named as its
    /// coverage have to still name it, and a mirrored file appearing means the entry is now false and has to
    /// go.
    /// </summary>
    [Fact]
    public void EveryDeclaredlyAbsentTestFile_StillDescribesTheTree()
    {
        var root = RepoTree.Root;
        var testsRoot = Path.Combine(root, "SSO-Auth.Tests");

        foreach (var (source, covers) in TypesWithNoMirroredTestFile)
        {
            var sourcePath = Path.Combine(root, source.Replace('/', Path.DirectorySeparatorChar));
            Assert.True(File.Exists(sourcePath), $"A declared absence names a source file that does not exist: {source}");

            var typeName = Path.GetFileNameWithoutExtension(sourcePath);
            var mirrored = Directory.EnumerateFiles(testsRoot, typeName + "Tests.cs", SearchOption.AllDirectories)
                .Where(path => !IsBuildOutput(path))
                .Select(path => Path.GetRelativePath(testsRoot, path))
                .ToList();

            Assert.True(
                mirrored.Count == 0,
                $"{typeName} is declared as deliberately having no mirrored test file, and now has one: {string.Join(", ", mirrored)}. Remove the declaration rather than leaving both.");

            Assert.NotEmpty(covers);
            foreach (var cover in covers)
            {
                var coverPath = Path.Combine(root, cover.Replace('/', Path.DirectorySeparatorChar));
                Assert.True(File.Exists(coverPath), $"{typeName}'s declared coverage names a file that does not exist: {cover}");
                Assert.True(
                    File.ReadAllText(coverPath).Contains(typeName, StringComparison.Ordinal),
                    $"{cover} is declared as covering {typeName} and no longer names it.");
            }
        }
    }

    [Fact]
    public void SourceModuleNamespaces_MirrorTheirFolder()
    {
        // #873: every type in Api/<Module>/ declares namespace <Root>.Api.<Module>, so the namespace and the
        // folder can never drift apart. RequestHelpers once sat physically in Api/Http/ under the stale
        // namespace ...Helpers and no fitness function caught it until #867 moved it; this locks the invariant
        // in as an executable guard. Files directly in the flat Api/ root are out of scope - FlatApi_HoldsNoSourceFiles
        // keeps that empty.
        var apiRoot = Path.Combine(RepoTree.Root, "SSO-Auth", "Api");
        var offenders = new List<string>();
        foreach (var src in Directory.EnumerateFiles(apiRoot, "*.cs", SearchOption.AllDirectories))
        {
            if (src.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || src.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            {
                continue;
            }

            var relative = Path.GetRelativePath(apiRoot, src);
            var separator = relative.IndexOf(Path.DirectorySeparatorChar);
            if (separator < 0)
            {
                continue; // a flat Api/ file - not module-scoped
            }

            var module = relative[..separator];
            var expected = $"{Root}.Api.{module}";
            var declared = File.ReadLines(src)
                .Select(line => line.Trim())
                .FirstOrDefault(line => line.StartsWith("namespace ", StringComparison.Ordinal))
                ?.Substring("namespace ".Length)
                .TrimEnd(';', ' ', '{');
            if (!string.Equals(declared, expected, StringComparison.Ordinal))
            {
                offenders.Add($"Api/{relative} declares '{declared ?? "(no namespace)"}' - expected '{expected}'");
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Every type in Api/<Module>/ must declare namespace <Root>.Api.<Module> so the namespace and folder cannot drift (#873): " + string.Join(" | ", offenders));
    }

    [Fact]
    public void InternalDocumentationGate_StaysEnforced()
    {
        // #864/#873 - guard for the guard. The internal-surface XML-doc completeness gate rests on two
        // switches that a single quiet edit could disable: SA1600 must stay at warning-or-error in
        // .editorconfig (CI's warnaserror turns it into a build failure), and stylecop.json must keep
        // documentInternalElements=true (without it SA1600 checks only the public surface). Neither is
        // exercised by any other test, so pin both here - a revert to none, suggestion, silent, or
        // documentInternalElements=false fails this test rather than silently reopening the internal API to
        // undocumented members.
        var editorConfig = File.ReadAllText(Path.Combine(RepoTree.Root, ".editorconfig"));
        var severity = editorConfig
            .Split('\n')
            .Select(line => line.Trim())
            .FirstOrDefault(line => line.StartsWith("dotnet_diagnostic.SA1600.severity", StringComparison.Ordinal));
        Assert.True(
            severity is not null && (severity.EndsWith("= warning", StringComparison.Ordinal) || severity.EndsWith("= error", StringComparison.Ordinal)),
            $"SA1600 must stay enforced (warning or error) so the #864 internal-doc gate cannot be silently switched off - found: '{severity ?? "(missing)"}'.");

        var styleCop = File.ReadAllText(Path.Combine(RepoTree.Root, "stylecop.json"));
        Assert.Contains("\"documentInternalElements\": true", styleCop, StringComparison.Ordinal);
    }
}
