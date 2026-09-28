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

/// <summary>Architecture-conformance fitness functions for the target architecture of #318, run as part of the ordinary suite so a change that drifts from the agreed structure fails CI.</summary>
/// <remarks>
/// Most rules are reflection over the production assembly; the call-level ones are source scans, because a
/// call site is not visible in a compiled member. Every source scan discovers the controller files from
/// reflection rather than a hardcoded path and is sentinel-guarded against a vacuous pass, by pinning either
/// the scanned property or the marker set against its legitimate home (#388, #444). What each rule locks in
/// is on the issue it names: <see href="https://github.com/Flowfin/jellyfin-plugin-sso/issues/318"/>.
/// </remarks>
public partial class ArchitectureConformanceTests
{
    private const string Root = "Jellyfin.Plugin.SSO_Auth";

    // Suffixes that mark a pure, single-responsibility helper in the target layering (a "gate", store, or
    // mapper). By the "one unified OO architecture" + "default internal" principles these are internal
    // implementation detail, never part of the plugin's public surface.
    private static readonly string[] HelperSuffixes =
    {
        "Validator", "Cache", "Builder", "Mapper", "Policy", "Probe", "Store", "Revoker", "Extractor", "Gate", "State", "Resolver",
    };

    // The login-path caches that converged on the shared bounding pattern - a hard global cap plus TWO
    // distinct IntervalGates: "_pruneGate" (throttled expired-entry sweep, #452) and "_capWarnGate"
    // (throttled cap-refusal capacity warning, #246/#327/#470). ONE canonical list, consumed by both the
    // prune-gate rule and the cap-warn rule below, so a cache can never fall out of one rule's list but not
    // the other's (which is exactly how SamlOutcomeStore was missed on first draft). A new cap-bounded
    // login-path cache is added here once, and both fitness functions guard it.
    private static readonly Type[] LoginPathCapWarnCaches =
    {
        typeof(ReplayCache), typeof(SamlRequestCache), typeof(OidcStateStore), typeof(SamlOutcomeStore),
    };

    // Every production type - the base sequence for structural rules that must cover
    // interfaces/enums/structs/delegates too (e.g. the namespace boundary). Two kinds of type are not the
    // plugin's, and both are dropped HERE rather than at each rule, so every rule below judges the same set:
    // the ones the compiler emits, and the one the code-coverage collector injects when it instruments this
    // assembly statically (#1376).
    private static IEnumerable<Type> AllPluginTypes =>
        typeof(SSOPlugin).Assembly.GetTypes().Where(t => !IsCompilerGenerated(t) && !IsCoverageInstrumentation(t));

    // The class subset, for rules that only make sense on classes (helper shape, controller base type).
    private static IEnumerable<Type> PluginClasses => AllPluginTypes.Where(t => t.IsClass);

    private static bool IsHelper(Type t) =>
        HelperSuffixes.Any(s => SimpleName(t).EndsWith(s, StringComparison.Ordinal));

    [Fact]
    public void SingleResponsibilityHelpers_AreInternal_NotPartOfThePublicSurface()
    {
        // Any externally-visible accessibility leaks the helper: public, or a nested member reachable by a
        // consumer or a derived type (protected / protected-internal count as leaks too).
        var leaked = PluginClasses
            .Where(IsHelper)
            .Where(t => t.IsPublic || t.IsNestedPublic || t.IsNestedFamily || t.IsNestedFamORAssem)
            .Select(t => t.FullName)
            .ToList();

        Assert.True(leaked.Count == 0, "These helper types must be internal (target: default-internal, thin public surface): " + string.Join(", ", leaked));
    }

    [Fact]
    public void SingleResponsibilityHelpers_AreSealedOrStatic_NotAnInheritanceBase()
    {
        // A pure helper is a leaf: `static` (abstract+sealed in IL) or `sealed`. Anything not sealed - an
        // ordinary class OR an abstract base - is an open inheritance point the unified architecture rules
        // out. (A static class is sealed, so it passes.)
        var open = PluginClasses
            .Where(IsHelper)
            .Where(t => !t.IsSealed)
            .Select(t => t.FullName)
            .ToList();

        Assert.True(open.Count == 0, "These helper types must be sealed or static (a pure helper is a leaf, not an inheritance base): " + string.Join(", ", open));
    }

    [Fact]
    public void FlowServices_AreInternalAndSealed()
    {
        // The flow tier (#318): a *Service is a stateful collaborator (holds IUserManager, the config
        // store, …) that orchestrates pure helpers - distinct from the leaf *Helper suffixes above, so
        // it gets its own rule rather than joining HelperSuffixes. It is still internal-by-default and a
        // sealed leaf, never an inheritance base or part of the public surface.
        var stray = PluginClasses
            .Where(t => SimpleName(t).EndsWith("Service", StringComparison.Ordinal))
            .Where(t => t.IsPublic || t.IsNestedPublic || t.IsNestedFamily || t.IsNestedFamORAssem || !t.IsSealed)
            .Select(t => t.FullName)
            .ToList();

        Assert.True(stray.Count == 0, "Flow services (*Service) must be internal and sealed collaborators: " + string.Join(", ", stray));
    }

    [Fact]
    public void Controllers_DeriveFromControllerBase()
    {
        var stray = PluginClasses
            .Where(t => SimpleName(t).EndsWith("Controller", StringComparison.Ordinal))
            .Where(t => !typeof(ControllerBase).IsAssignableFrom(t))
            .Select(t => t.FullName)
            .ToList();

        Assert.True(stray.Count == 0, "Types named *Controller must derive from ControllerBase: " + string.Join(", ", stray));
    }

    [Fact]
    public void EverythingLivesUnderThePluginRootNamespace()
    {
        // The whole plugin stays under one root namespace; the migration reorganises the sub-namespaces
        // (Http/Flows/Oidc/Saml/Config/Shared/…) but never leaks a type outside the root. Covers ALL types
        // (interfaces/enums/structs/delegates too), rejects the global namespace, and matches the root
        // exactly or as a "Root."-prefixed descendant - so a sibling like "…SSO_AuthEvil" does not pass.
        var outside = AllPluginTypes
            .Where(t => !t.IsNested) // a nested type inherits its declaring type's namespace; check the outers
            .Where(t => t.Namespace is not { } ns || !(ns == Root || ns.StartsWith(Root + ".", StringComparison.Ordinal)))
            .Select(t => t.FullName ?? t.Name)
            .ToList();

        Assert.True(outside.Count == 0, "All plugin types must live under the " + Root + " root namespace: " + string.Join(", ", outside));
    }

    [Theory]
    // What the collector owns, and is therefore dropped before the rules above see it (#1376): the namespace
    // the injected tracker was measured in, the collector's root itself, and another descendant of that root,
    // which is where a later collector version moving the tracker would put it.
    [InlineData("Microsoft.CodeCoverage.Instrumentation.Static.Tracker", true)]
    [InlineData("Microsoft.CodeCoverage", true)]
    [InlineData("Microsoft.CodeCoverage.Somewhere.Else", true)]
    // What it does not own, so the rule above still bites for the reason it names. The plugin's own root and
    // its descendants are never dropped (a rule that dropped them would report nothing forever); the
    // "…SSO_AuthEvil" sibling the rule exists to catch stays in scope; a namespace that merely opens with the
    // collector's letters is somebody else's; and an ordinary foreign namespace is still an offender.
    [InlineData(Root, false)]
    [InlineData(Root + ".Api.Oidc", false)]
    [InlineData(Root + "Evil", false)]
    [InlineData("Microsoft.CodeCoverageOfMine", false)]
    [InlineData("Microsoft.AspNetCore.Mvc", false)]
    [InlineData(null, false)]
    public void CoverageCollectorTypes_AreTheOnlyOnesTheStructuralRulesDrop(string? ns, bool dropped)
    {
        // The exclusion the base type sequence applies is a correction to what the rules MEAN - a type the
        // measurement tool wrote is not one of the plugin's - so it has to be exactly as wide as the tool and
        // no wider. Widen it and the rules stop reporting real strays; the rows below are the ones that would
        // go red for it.
        Assert.Equal(dropped, IsCoverageCollectorNamespace(ns));
    }
}
