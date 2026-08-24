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
/// Conformance rules for where mutable state may live and how the login-path caches bound it: store-like placement, the interval-gated sweeps and warnings, and the immutable authorization variants.
/// </content>
public partial class ArchitectureConformanceTests
{
    [Fact]
    public void MutableKeyedState_LivesOnlyInsideStoreLikeTypes()
    {
        // Locked in by the OidcStateStore consolidation (#318): a raw dictionary holding runtime state
        // outside a *Store/*Cache/*Limiter type is how the pre-consolidation controller accumulated its
        // scattered cap/lifetime/sweep conventions. The former SSOController.DiscoveryFactsCache moved into a
        // *Cache type in #449 and was then removed entirely in #450 (discovery is now read once per challenge
        // and fed to the login, with nothing cached), so no discovery-facts dictionary remains to exempt.
        // Two documented exemptions remain, both persisted account-link config state:
        // - ProviderConfigBase._canonicalLinks: the persisted account-link map - serialized plugin
        //   configuration mutated only under the config lock, so a runtime store type would be the
        //   wrong home; it is config state, not in-flight state.
        // - OidConfig._canonicalLinkIssuers: the per-link issuer binding (#186), the exact parallel of
        //   _canonicalLinks - serialized config mutated only under the config lock, same rationale.
        // - PluginConfiguration._logoutSessions: the persisted Single Logout session map (#727) - serialized
        //   config mutated only under the config lock via SessionLogoutStore, so it is config state, not
        //   in-flight state; the store type (SessionLogoutStore) holds the bounding logic, not the field.
        // - ProviderConfigBase._canonicalLinkDeadlines: the persisted per-link account-expiry instants
        //   (#1145), the exact parallel of _canonicalLinks and bounded BY it - an entry is only ever written
        //   beside a live link and is removed with that link, so the link map is its ceiling and no separate
        //   cap or sweep convention is owed. Serialized config mutated only under the config lock.
        // - ProviderConfigBase._canonicalLinkLastLogins: the persisted per-link last-SSO-login instants
        //   (#1120), bounded by the link map in exactly the same way - one entry per live link, overwritten
        //   rather than appended by a repeat login, removed with the link on every erasure route. It is the
        //   ONE shape this rule has to keep out: a per-login event log would need a cap and a sweep, and the
        //   reason this needs neither is the bound, so the exemption is granted to the bounded design and not
        //   to the subject matter.
        // - DeclarativeManagedProviders._oid / ._saml: the provider-name-to-source map (#1415). Exempt for a
        //   different reason from the four above, and it is the reason rather than the subject that is
        //   exempted. The type is IMMUTABLE - both fields are assigned once in a private constructor and
        //   never written again, and Including() builds a whole new instance - so there is no mutable keyed
        //   state here for a cap, a lifetime or a sweep to bound. Its population is the set of providers a
        //   declarative document names, which the configuration already holds and already bounds, and the
        //   whole instance is discarded at process exit because it is re-derived on every start. These two
        //   fields were HashSets until a refusal had to say WHICH source owns a provider, so what changed is
        //   the value beside each name, not where the state lives or how long it lives.
        var storeLike = new[] { "Store", "Cache", "Limiter" };
        var exemptions = new[] { "ProviderConfigBase._canonicalLinks", "OidConfig._canonicalLinkIssuers", "PluginConfiguration._logoutSessions", "ProviderConfigBase._canonicalLinkDeadlines", "ProviderConfigBase._canonicalLinkLastLogins", "DeclarativeManagedProviders._oid", "DeclarativeManagedProviders._saml" };

        var offenders = PluginClasses
            .Where(t => !storeLike.Any(s => SimpleName(t).EndsWith(s, StringComparison.Ordinal)))
            .SelectMany(t => t.GetFields(BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            .Where(f => !f.Name.Contains('<', StringComparison.Ordinal)) // compiler-generated backing fields
            .Where(f => IsDictionaryLike(f.FieldType))
            .Select(f => $"{SimpleName(f.DeclaringType!)}.{f.Name}") // DeclaringType is never null for a type's own fields
            .Where(n => !exemptions.Contains(n))
            .ToList();

        Assert.True(offenders.Count == 0, "Raw dictionary state must live inside a *Store/*Cache/*Limiter type (or carry a documented exemption here): " + string.Join(", ", offenders));
    }

    [Fact]
    public void LoginPathCaches_ThrottleTheirExpiredEntrySweepThroughIntervalGate()
    {
        // Locked in by #452: the login-path caches converged on one bounding pattern - an
        // IntervalGate-throttled expired-entry sweep plus a hard global cap - so none can regress to the
        // unthrottled full-dictionary sweep (or the unbounded set) ReplayCache carried before #452.
        // Each named cache must declare the PRUNE gate specifically (an IntervalGate field named
        // "_pruneGate"), not merely some IntervalGate: the siblings also carry a "_capWarnGate", so keying
        // on the field type alone would miss a sibling that dropped its prune gate but kept cap-warn.
        // SamlRequestCache and OidcStateStore already had it (#246, #327); SamlReplayCache adopted it (#452).
        // The cache set is the shared LoginPathCapWarnCaches list, so this rule and the cap-warn rule below
        // can never disagree on which caches are login-path caches.
        const string pruneGateField = "_pruneGate";
        var missing = LoginPathCapWarnCaches
            .Where(t => !t.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.DeclaredOnly)
                .Any(f => f.FieldType == typeof(IntervalGate) && f.Name == pruneGateField))
            .Select(SimpleName)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Every login-path cache must throttle its expired-entry sweep through an IntervalGate field (#452): " + string.Join(", ", missing));
    }

    [Fact]
    public void LoginPathCaches_ThrottleTheirCapacityWarningThroughItsOwnIntervalGate()
    {
        // Locked in by #470: every login-path cache that refuses fail-closed at its hard cap surfaces that
        // refusal to the caller through a SEPARATE cap-warn IntervalGate ("_capWarnGate"), distinct from the
        // prune gate ("_pruneGate"), so a full cache is observable to operators yet a flood of refusals
        // cannot amplify into log volume (CWE-400). SamlRequestCache, OidcStateStore and SamlOutcomeStore
        // already carried it (#246, #327, #251); SamlReplayCache adopted it here (#470). Require BOTH gates as
        // distinct named fields so a later refactor cannot collapse the cap-warn signal onto the prune gate
        // (which would re-couple the two intervals) or drop it and regress a cache to a silent cap refusal.
        // The cache set is the shared LoginPathCapWarnCaches list, so it can never drift from the prune-gate
        // rule above.
        var missing = LoginPathCapWarnCaches
            .Where(t =>
            {
                var gates = t.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.DeclaredOnly)
                    .Where(f => f.FieldType == typeof(IntervalGate))
                    .Select(f => f.Name)
                    .ToList();
                return !gates.Contains("_pruneGate") || !gates.Contains("_capWarnGate");
            })
            .Select(SimpleName)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Every login-path cache must carry BOTH a _pruneGate and a distinct _capWarnGate IntervalGate (#470): " + string.Join(", ", missing));
    }

    [Fact]
    public void CanonicalLinkService_ThrottlesTheLegacyLinkWarningThroughAStaticIntervalGate()
    {
        // Locked in by #362 (CWE-400, log-volume): the terminal pending-legacy-link warnings live in a
        // service the controller constructs PER REQUEST, so the once-per-interval throttle must be a
        // PROCESS-WIDE (static) IntervalGate - an instance field would reset every login and throttle
        // nothing, letting a hot login loop for a not-yet-migrated user flood the log. Pin the static gate
        // so a later refactor cannot silently demote it to an instance field (which compiles and passes the
        // unit tests, because those inject a fresh gate) and reopen the flood.
        var staticGate = typeof(CanonicalLinkService)
            .GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Any(f => f.FieldType == typeof(IntervalGate));

        Assert.True(
            staticGate,
            "CanonicalLinkService must throttle its pending-legacy-link warning through a static IntervalGate (#362), because the service is constructed per request and an instance gate would throttle nothing.");
    }

    [Fact]
    public void AuthorizeStates_AreImmutableVariants()
    {
        // Locked in by #341: the in-flight OpenID authorize state is a CLOSED, IMMUTABLE sum - an
        // AuthorizeSession base with exactly the Pending and Ready variants, swapped atomically in the
        // store rather than promoted in place. Immutable variants are what make the swap torn-read-free: a
        // redeemer racing the promotion observes either the whole Pending (not redeemable) or the whole
        // Ready, never a half-applied field set. A settable property or writable instance field on the base
        // or a variant would reopen the in-place-promotion window #341 closed, so pin it structurally.
        var baseType = typeof(AuthorizeSession);
        var variants = new[] { typeof(AuthorizeSession.Pending), typeof(AuthorizeSession.Ready) };

        // Closed sum: the base is abstract, every AuthorizeSession subtype in the assembly is one of the
        // two known variants, and each variant is a sealed leaf - no third variant, no open inheritance
        // point.
        Assert.True(baseType.IsAbstract, "AuthorizeSession must be an abstract base (the root of the closed sum).");
        var subtypes = AllPluginTypes.Where(t => t != baseType && baseType.IsAssignableFrom(t)).ToList();
        Assert.Equal(variants.Length, subtypes.Count);
        Assert.All(variants, v => Assert.Contains(v, subtypes));
        Assert.All(variants, v => Assert.True(v.IsSealed, $"{SimpleName(v)} must be a sealed variant of the closed sum."));

        // Immutable: no settable property and no writable instance field on the base or either variant.
        // Get-only auto-properties compile to readonly (initonly) backing fields, so they pass; a
        // `{ get; set; }` / `{ get; private set; }` or a plain writable field would be flagged.
        const BindingFlags members = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
        var mutable = new[] { baseType }.Concat(variants)
            .SelectMany(t => t.GetProperties(members)
                .Where(p => p.SetMethod is not null)
                .Select(p => $"{SimpleName(t)}.{p.Name} (settable property)")
                .Concat(t.GetFields(members)
                    .Where(f => !f.IsInitOnly && !f.IsLiteral && !f.Name.Contains('<', StringComparison.Ordinal))
                    .Select(f => $"{SimpleName(t)}.{f.Name} (writable field)")))
            .ToList();

        Assert.True(
            mutable.Count == 0,
            "AuthorizeSession and its variants must be immutable (no settable property or writable instance field) so the store's Pending -> Ready swap stays torn-read-free (#341): " + string.Join(", ", mutable));
    }

    [Fact]
    public void SamlLoginOutcome_IsImmutable()
    {
        // Locked in by the SAML one-time outcome token (#251): the login outcome stored between the ACS
        // callback and the mint leg is redeemed by an atomic remove of the WHOLE record, so a redeemer never
        // observes a torn outcome. A settable property or writable instance field would reopen an in-place
        // mutation window on a value that IS the proof the assertion passed every gate, so pin it structurally
        // exactly as AuthorizeSession's variants are (#341). A get-only auto-property / positional record
        // parameter compiles to a readonly (initonly) backing field and passes; a `{ get; set; }` or a plain
        // writable field would be flagged.
        var outcome = typeof(SamlLoginOutcome);
        Assert.True(outcome.IsSealed, "SamlLoginOutcome must be a sealed leaf.");

        const BindingFlags members = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
        var mutable = outcome.GetProperties(members)
            .Where(p => p.SetMethod is not null && !IsInitOnlySetter(p.SetMethod))
            .Select(p => $"{SimpleName(outcome)}.{p.Name} (settable property)")
            .Concat(outcome.GetFields(members)
                .Where(f => !f.IsInitOnly && !f.IsLiteral && !f.Name.Contains('<', StringComparison.Ordinal))
                .Select(f => $"{SimpleName(outcome)}.{f.Name} (writable field)"))
            .ToList();

        Assert.True(
            mutable.Count == 0,
            "SamlLoginOutcome must be immutable (no settable property or writable instance field) so the store's one-time redeem stays torn-read-free (#251): " + string.Join(", ", mutable));
    }

    // A record's positional properties expose an `init` setter (SetMethod is non-null) but are immutable
    // after construction; treat an init-only setter as read-only so a record's own positional members are
    // not mis-flagged as mutable. An init-only setter carries the IsExternalInit modreq on its return type.
    private static bool IsInitOnlySetter(MethodInfo setter) =>
        setter.ReturnParameter.GetRequiredCustomModifiers().Any(m => m.FullName == "System.Runtime.CompilerServices.IsExternalInit");
}
