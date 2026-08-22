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
/// Conformance rules for the controller boundary: delegation of each flow to its service, rate limiting through the login outcome, the absence of mutable static state, and the typed provider mode.
/// </content>
public partial class ArchitectureConformanceTests
{
    [Fact]
    public void Controller_DelegatesLoginCompletionToTheFlowService()
    {
        // Locked in by the login-completion extraction (#160, #318 step 11): the one shared completion tail -
        // resolve/adopt the link, build the SessionParameters, mint the session under the revocation gate,
        // audit, map to a LoginOutcome - moved wholesale into LoginCompletionService. The controller's two
        // callbacks now hand a VerifiedIdentity to that service and return its result, so a CONTROLLER neither
        // builds SessionParameters nor mints a session itself. Call-level property, so it is a source scan
        // like the other controller rules above.
        //
        // The scanned tokens are derived from the moved types via nameof, so a rename of SessionParameters or
        // SessionMinter.MintAsync fails to COMPILE this rule (the strongest pin) rather than passing
        // vacuously. Constructing the minter to inject it (new SessionMinter(...)) is wiring, not the tail, so
        // it is deliberately not a scanned token - only building the parameters and minting are.
        var paramsToken = "new " + nameof(SessionParameters);
        var mintToken = nameof(SessionMinter.MintAsync) + "(";

        var controllerHits = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => l.Text.Contains(paramsToken, StringComparison.Ordinal) || l.Text.Contains(mintToken, StringComparison.Ordinal))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            controllerHits.Count == 0,
            "A controller must not build SessionParameters or mint a session directly; the shared login-completion tail lives in LoginCompletionService (#160). Found: " + string.Join(" | ", controllerHits));

        // Liveness against a vacuous pass: the tail must actually live in the flow service - a move, not a
        // silent removal - so LoginCompletionService's own source must contain both moved tokens.
        var completionSource = string.Join(
            "\n",
            SourceFilesDeclaring(new[] { typeof(LoginCompletionService) }).Select(File.ReadAllText));
        Assert.True(
            completionSource.Contains(paramsToken, StringComparison.Ordinal) && completionSource.Contains(mintToken, StringComparison.Ordinal),
            "LoginCompletionService must own the login-completion tail (build SessionParameters and mint the session); otherwise the controller scan passes vacuously (#160).");
    }

    [Fact]
    public void Controller_DelegatesOidcFlowToTheFlowService()
    {
        // Locked in by the OpenID flow extraction (#160, #318 step 12): the OpenID challenge and redirect
        // callback bodies, together with the OpenID-specific process-wide state (the in-flight authorize
        // store) and the discovery read, moved into OidcLoginService. The controller's OpenID endpoints now
        // apply the shared rate-limit gate and hand the request to that service, so a CONTROLLER neither
        // holds the OIDC authorize store / discovery read nor drives the OidcClient challenge/callback
        // protocol itself. Call-level property, so it is a source scan like the other controller rules above.
        //
        // The store and reader tokens are nameof-derived, so a rename of either type fails to COMPILE this
        // rule rather than passing vacuously; the two protocol tokens are the OidcClient methods the
        // challenge (PrepareLoginAsync) and callback (ProcessResponseAsync) drive. The shared per-client rate limiter
        // is deliberately NOT a marker - it fronts BOTH protocols, so rather than living on either flow
        // service it lives in the shared SsoRateLimitGate (#160), pinned off the controller by
        // Controller_HoldsNoMutableStaticState.
        var storeToken = nameof(OidcStateStore);
        var readerToken = nameof(OidcDiscoveryReader);
        var markers = new[] { storeToken, readerToken, "PrepareLoginAsync", "ProcessResponseAsync" };

        var controllerHits = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => markers.Any(m => l.Text.Contains(m, StringComparison.Ordinal)))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            controllerHits.Count == 0,
            "A controller must not hold the OpenID authorize/discovery caches or drive the OidcClient challenge/callback protocol; the OpenID flow lives in OidcLoginService (#160). Found: " + string.Join(" | ", controllerHits));

        // Liveness against a vacuous pass: the OpenID flow must actually live in OidcLoginService - a move,
        // not a silent removal - so the flow service's own source must contain every moved token.
        var oidcSource = string.Join(
            "\n",
            SourceFilesDeclaring(new[] { typeof(OidcLoginService) }).Select(File.ReadAllText));
        Assert.True(
            markers.All(m => oidcSource.Contains(m, StringComparison.Ordinal)),
            "OidcLoginService must own the OpenID challenge/callback flow, its authorize store, and the discovery read; otherwise the controller scan passes vacuously (#160).");
    }

    [Fact]
    public void Controller_DelegatesSamlFlowToTheFlowService()
    {
        // Locked in by the SAML flow extraction (#160, #318 step 13), the mirror of the OpenID rule above:
        // the SAML challenge, assertion-consumer callback, session-minting authenticate and manual-link
        // bodies, together with the SAML-specific process-wide state (the replay cache and the
        // outstanding-AuthnRequest cache), moved into SamlLoginService. The controller's SAML endpoints now
        // apply the shared rate-limit gate and hand the request to that service, so a CONTROLLER neither
        // holds those SAML caches nor drives the SAML challenge/validation protocol itself. Call-level
        // property, so it is a source scan like the other controller rules above.
        //
        // The request-cache token is nameof-derived, so a rename of that type fails to COMPILE this rule
        // rather than passing vacuously; the two protocol tokens are the outgoing-request builder
        // (SamlAuthnRequest, which the challenge constructs and signs) and the response validator
        // (ValidateSaml). The shared per-client rate limiter is deliberately NOT a marker - it fronts BOTH
        // protocols, so it lives in the shared SsoRateLimitGate (#160), pinned off the controller by
        // Controller_HoldsNoMutableStaticState, exactly as in the OpenID rule. The replay cache was a SAML
        // marker until #962 moved it to the shared RateLimit module (protocol-neutral ReplayCache, used by
        // both the SAML replay path and the OIDC back-channel-logout jti check), so it is no longer a
        // SAML-ownership marker.
        var requestToken = nameof(SamlRequestCache);
        var markers = new[] { requestToken, "SamlAuthnRequest", "ValidateSaml" };

        var controllerHits = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => markers.Any(m => l.Text.Contains(m, StringComparison.Ordinal)))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            controllerHits.Count == 0,
            "A controller must not hold the SAML replay/request caches or drive the SAML challenge/validation protocol; the SAML flow lives in SamlLoginService and SamlAssertionValidator (#160, #496). Found: " + string.Join(" | ", controllerHits));

        // Liveness against a vacuous pass: the SAML flow must actually live in the SAML flow tier - a move,
        // not a silent removal - so its own source must contain every moved token. The tier is now two types:
        // SamlLoginService owns the challenge/callback orchestration and the outstanding-request cache
        // (SamlRequestCache, SamlAuthnRequest), and the dedicated SamlAssertionValidator owns the inbound
        // validation and the replay cache (SamlReplayCache, ValidateSaml) it moved into (#496) - so scan both.
        var samlSource = string.Join(
            "\n",
            SourceFilesDeclaring(new[] { typeof(SamlLoginService), typeof(SamlAssertionValidator) }).Select(File.ReadAllText));
        Assert.True(
            markers.All(m => samlSource.Contains(m, StringComparison.Ordinal)),
            "The SAML flow tier (SamlLoginService + SamlAssertionValidator) must own the SAML challenge/callback/authenticate/link flow, its replay/request caches, and the inbound validation; otherwise the controller scan passes vacuously (#160, #496).");
    }

    [Fact]
    public void FlowServices_DoNotDuplicateChallengeNewPathResolution()
    {
        // Locked in by #670: the near-identical ResolveChallengeNewPath resolver - and its
        // _newPathPersistGate persist-throttle - that OidcLoginService and SamlLoginService each carried
        // (~40 lines apiece, differing only in which provider map the Mutate delegate re-resolved against)
        // are now ONE generic helper in ChallengeNewPathResolver (Api/Shared), with a single shared gate. Pin
        // by reflection that NEITHER flow service re-declares its own copy of either member, so the
        // duplication (and a second, divergent throttle) cannot silently reappear.
        const BindingFlags all = BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
        var flowServices = new[] { typeof(OidcLoginService), typeof(SamlLoginService) };

        var offenders = flowServices
            .SelectMany(t => t.GetMethods(all)
                .Where(m => m.Name == "ResolveChallengeNewPath")
                .Select(m => $"{SimpleName(t)}.{m.Name} (method)")
                .Concat(t.GetFields(all)
                    .Where(f => f.Name == "_newPathPersistGate")
                    .Select(f => $"{SimpleName(t)}.{f.Name} (field)")))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Neither flow service may declare its own ResolveChallengeNewPath method or _newPathPersistGate field; the single generic resolver and its one shared throttle live in ChallengeNewPathResolver (Api/Shared) (#670). Found: " + string.Join(", ", offenders));

        // Liveness against a vacuous pass: the shared resolver must actually own both - a move, not a silent
        // removal - so ChallengeNewPathResolver must declare the resolver method and the single gate field.
        var resolver = typeof(ChallengeNewPathResolver);
        Assert.True(
            resolver.GetMethods(all).Any(m => m.Name == "ResolveChallengeNewPath"),
            "ChallengeNewPathResolver must own the ResolveChallengeNewPath resolver; otherwise the flow-service scan passes vacuously (#670).");
        Assert.True(
            resolver.GetFields(all).Any(f => f.Name == "_newPathPersistGate" && f.FieldType == typeof(IntervalGate)),
            "ChallengeNewPathResolver must own the single _newPathPersistGate IntervalGate; otherwise the flow-service scan passes vacuously (#670).");
    }

    [Fact]
    public void SharedFlowResponses_OwnTheAuthPageErrorAndLinkWriteResults()
    {
        // Locked in by the shared-helper consolidation (#160, #500): the three HTTP result shapes both flow
        // services need - the security-headered intermediate auth page (the CSP build), the plain-text flow
        // error, and the manual-link write mapping - were duplicated (the controller's HtmlAuthPage +
        // ReturnError, and the OpenID service's PlainTextError twin). They now live once in FlowResponses,
        // which both flow services call, so a CONTROLLER neither builds the CSP auth page nor sets its
        // defensive headers itself. Call-level property, so it is a source scan like the other controller
        // rules above. Markers are the emission tokens: the CSP builder (AuthPageCsp.Build) and the two
        // clickjacking/sniffing headers the auth page sets.
        var markers = new[] { "AuthPageCsp.Build", "X-Frame-Options", "X-Content-Type-Options" };
        var offenders = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => markers.Any(m => l.Text.Contains(m, StringComparison.Ordinal)))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A controller must not build the CSP auth page or set its defensive headers directly; the shared flow-result shapes live in FlowResponses (#160). Found: " + string.Join(" | ", offenders));

        // Liveness against a vacuous pass: the auth page must actually live in FlowResponses - a move, not a
        // silent removal - so its own source must build the CSP and set the frame-options header.
        var sharedSource = string.Join(
            "\n",
            Directory.EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Shared"), "*.cs", SearchOption.AllDirectories)
                .Select(File.ReadAllText));
        Assert.True(
            sharedSource.Contains("AuthPageCsp.Build", StringComparison.Ordinal) && sharedSource.Contains("X-Frame-Options", StringComparison.Ordinal),
            "FlowResponses must own the CSP auth-page render (AuthPageCsp.Build + the defensive headers); otherwise the controller scan passes vacuously (#160).");
    }

    [Fact]
    public void RateLimiting_FlowsThroughLoginOutcome()
    {
        // Locked in by #474: the rate-limit rejection was the last login-path error that bypassed the single
        // mapper. It now flows as LoginOutcome.Throttled through LoginStatusMapper, which is the ONE place the
        // 429 status and its Retry-After header are emitted - so a CONTROLLER neither returns a bare rate-limit
        // ContentResult nor sets Retry-After itself. Call-level property, so it is a source scan like the other
        // controller rules above. Markers are the emission tokens, not prose: the 429 status constant, the
        // typed IHeaderDictionary accessor (".RetryAfter" - the leading dot excludes the "retryAfterSeconds"
        // local the controller still passes into the outcome), and the raw header-name literal.
        var markers = new[] { "Status429TooManyRequests", ".RetryAfter", "Retry-After" };
        var offenders = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => markers.Any(m => l.Text.Contains(m, StringComparison.Ordinal)))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A controller must not emit a rate-limit 429 or set Retry-After directly; route the rejection through LoginOutcome.Throttled and LoginStatusMapper (#474). Found: " + string.Join(" | ", offenders));

        // Liveness against a vacuous pass: the 429 + Retry-After must actually live in the mapper - a move,
        // not a silent removal - so LoginStatusMapper's own source must emit both.
        var mapperSource = string.Join(
            "\n",
            SourceFilesDeclaring(new[] { typeof(LoginStatusMapper) }).Select(File.ReadAllText));
        Assert.True(
            mapperSource.Contains("Status429TooManyRequests", StringComparison.Ordinal) && mapperSource.Contains("RetryAfter", StringComparison.Ordinal),
            "LoginStatusMapper must own the rate-limit 429 and its Retry-After header; otherwise the controller scan passes vacuously (#474).");
    }

    [Fact]
    public void RateLimitEndpointClass_UsesTypedConstants_NotLiterals()
    {
        // Locked in by #694: the per-client rate-limit bucket key is built as `class + ":" + clientKey` in
        // SsoRateLimitGate.Check, so the endpoint-class string IS the limiter grouping. Passed as a bare
        // literal at each call site, a single typo ("challange") compiles cleanly and silently mints a
        // separate, empty bucket - weakening the rate limit undetectably, with nothing to fail. Every call
        // site now references a SsoRateLimitClass member instead, so a typo is a compile error; this rule
        // forbids a raw literal from creeping back in. Call-level property, so it is a source scan like the
        // other controller rules above. The scan covers BOTH the controller's RateLimitCheck wrapper and any
        // direct SsoRateLimitGate.Check invocation (belt-and-braces: a future controller could call the gate
        // straight, bypassing the wrapper), and flags a string-literal FIRST argument to either - never the
        // typed SsoRateLimitClass member reference.
        var literalCall = new Regex("(?:RateLimitCheck|SsoRateLimitGate\\.Check)\\(\\s*\"");
        var offenders = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => literalCall.IsMatch(l.Text))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A rate-limited endpoint must pass its endpoint class as a SsoRateLimitClass member, never a raw string literal - a literal typo silently mints a separate empty limiter bucket (#694). Found: " + string.Join(" | ", offenders));

        // Sentinel against a vacuous pass: the scan only means something while the typed call sites exist. A
        // rename of the wrapper or a restructure that dropped every RateLimitCheck call would make the
        // offender scan match nothing and pass for the wrong reason, so pin the count of typed call sites. All
        // rate-limited endpoints route through the RateLimitCheck(SsoRateLimitClass.X) wrapper today; extend
        // this expected count in the same PR that adds or removes a rate-limited endpoint (as the provider-form
        // roster rules do), so a change to the limiter surface is a conscious update here rather than a silent
        // drift the offender scan cannot see.
        const int expectedTypedCallSites = 17;
        var typedCall = new Regex("RateLimitCheck\\(\\s*SsoRateLimitClass\\.");
        var typedCallSites = ControllerSourceFiles()
            .Sum(path => typedCall.Matches(File.ReadAllText(path)).Count);

        Assert.True(
            typedCallSites == expectedTypedCallSites,
            $"Expected {expectedTypedCallSites} typed RateLimitCheck(SsoRateLimitClass.X) call sites (#694); found {typedCallSites}. A rate-limited endpoint was added or removed - update this sentinel in the same PR so the literal scan cannot pass vacuously.");
    }

    [Fact]
    public void Controller_HoldsNoMutableStaticState()
    {
        // Locked in by the rate-limit-gate extraction (#160, #318): after the OpenID (#500), SAML (#501) and
        // rate-limit (#160) moves, the controller is a stateless request dispatcher - every process-wide
        // store, cache and limiter lives in a flow service or the Shared tier. So a controller holds NO
        // mutable process-wide state as a static field. The former SsoRateLimiter static (the last such on
        // SSOController) moved into SsoRateLimitGate; a new cache/limiter/counter/dictionary dropped back
        // onto ANY controller - the exact regression this rule guards - fails HERE.
        //
        // "Mutable state" is what is forbidden, not every static: a compile-time constant (a const, which is
        // IsLiteral) and an immutable static readonly VALUE (e.g. SSOViewsController's version-derived asset
        // ETag, an EntityTagHeaderValue computed once at load) are fine - they never accumulate runtime
        // state. So a static field is an offender only when it is genuinely mutable: a WRITABLE static (not
        // readonly, so it can be reassigned at runtime), OR a static readonly reference to a state CONTAINER
        // - a *Store/*Cache/*Limiter type, or a raw dictionary - which is readonly-by-reference but mutates
        // internally (exactly the shape SsoRateLimiter had on the controller). Compiler-generated backing
        // fields ('<'-named) are excluded, the same exclusion the other reflection rules use.
        var stateSuffixes = new[] { "Store", "Cache", "Limiter" };
        bool IsStateContainer(Type t) =>
            IsDictionaryLike(t)
            || (t.Assembly == typeof(SSOPlugin).Assembly && stateSuffixes.Any(s => SimpleName(t).EndsWith(s, StringComparison.Ordinal)));

        const BindingFlags statics = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
        var controllers = PluginClasses.Where(t => typeof(ControllerBase).IsAssignableFrom(t)).ToList();

        // Sentinel against a vacuous pass: a controller must be found, or a rename/rebase that lost the
        // ControllerBase base would pass this rule for the wrong reason (as ControllerSourceFiles guards the
        // source-scan rules).
        Assert.True(
            controllers.Count > 0,
            "No controller type was found to check for mutable static state; a controller was renamed or lost its ControllerBase base - update Controller_HoldsNoMutableStaticState.");

        var offenders = controllers
            .SelectMany(t => t.GetFields(statics)
                .Where(f => !f.Name.Contains('<', StringComparison.Ordinal))
                .Where(f => !f.IsLiteral)
                .Where(f => !f.IsInitOnly || IsStateContainer(f.FieldType))
                .Select(f => $"{SimpleName(t)}.{f.Name} ({SimpleName(f.FieldType)})"))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A controller must hold no mutable static state (a writable static, or a static readonly *Store/*Cache/*Limiter or dictionary); every process-wide store/cache/limiter belongs in a flow service or a Shared gate (#160, #318). Found: " + string.Join(", ", offenders));

        // Liveness against a vacuous pass: the rate limiter must actually live in its new home - a move, not
        // a silent removal - so SsoRateLimitGate must own the process-wide SsoRateLimiter instance the
        // controller no longer holds, and it is a state container the offender scan above would catch on a
        // controller (so the rule is proven non-vacuous on the very type that motivated it).
        var gateOwnsLimiter = typeof(SsoRateLimitGate)
            .GetFields(statics)
            .Any(f => f.FieldType == typeof(SsoRateLimiter));
        Assert.True(
            gateOwnsLimiter && IsStateContainer(typeof(SsoRateLimiter)),
            "SsoRateLimitGate must own the process-wide SsoRateLimiter (a state container) that moved off the controller; otherwise the controller scan passes vacuously (#160).");
    }

    [Fact]
    public void LegacyLinkMigration_ReturnsTheAuthoritativeMapping_NotAVoidReKey()
    {
        // Locked in by #363: the #155 legacy-link re-key runs as a SECOND lock acquisition after the
        // candidate-resolving read, so a concurrent login could migrate the same identity between the two.
        // The fix folds the re-key and the re-resolution into one config transaction that RETURNS the
        // authoritative user id, and the caller binds the login to that returned id rather than the
        // pre-migration snapshot. Structurally that means the migration helper must be a value-returning
        // mutation (Guid?), never a fire-and-forget void re-key whose result the caller ignores - a
        // revert to void would silently reopen the window. Reflection over the service's own private
        // methods pins it: any migration helper (name contains "Migrate") must return Guid?.
        var migrationHelpers = typeof(CanonicalLinkService)
            .GetMethods(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
            .Where(m => m.Name.Contains("Migrate", StringComparison.Ordinal))
            .ToList();

        // Sentinel against a vacuous pass: a rename that drops "Migrate" from the helper's name would make
        // the scan match nothing and pass for the wrong reason, so require at least one to exist and force
        // a conscious update of this rule if the naming changes.
        Assert.True(
            migrationHelpers.Count > 0,
            "No legacy-link migration helper (a private method whose name contains \"Migrate\") was found on CanonicalLinkService; it was renamed, so point this rule at the new name so the return-type invariant keeps guarding #363.");

        var voidReKeys = migrationHelpers
            .Where(m => m.ReturnType != typeof(Guid?))
            .Select(m => $"{m.Name} -> {m.ReturnType.Name}")
            .ToList();
        Assert.True(
            voidReKeys.Count == 0,
            "The legacy-link migration must return the authoritative mapping (Guid?) so the login binds to the post-migration state, not a pre-migration snapshot (#363); these do not: " + string.Join(", ", voidReKeys));
    }

    [Fact]
    public void ProviderMode_IsThreadedTyped_NotAsARawStringToken()
    {
        // Locked in by #369: the route's {mode} token is parsed ONCE at the controller boundary into the
        // ProviderMode enum, and the typed value is threaded inward - so no linking-tier method re-accepts
        // the raw string to re-parse or re-compare it (the two former divergent dispatches, a
        // culture-sensitive ToLower() switch and an invariant-lowercase one, that had to agree). Pin it
        // structurally on the two types the token flows through:
        //
        // 1. CanonicalLinkService - the linking workflow: NO method (public or private) may take a parameter
        //    named "mode" typed as string; it must be the ProviderMode enum. A revert to a string mode
        //    parameter (reopening the re-parse-inward hole) fails HERE.
        // 2. VerifiedIdentity.LinkMode - the identity the login path carries: must expose the protocol as the
        //    typed ProviderMode, not a "oid"/"saml" string the mint path would have to re-compare.
        const BindingFlags anyMethod = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
        var methods = typeof(CanonicalLinkService).GetMethods(anyMethod);

        var stringModeParams = methods
            .SelectMany(m => m.GetParameters().Select(p => (Method: m.Name, Param: p)))
            .Where(x => x.Param.Name == "mode" && x.Param.ParameterType == typeof(string))
            .Select(x => $"{x.Method}(string mode)")
            .ToList();
        Assert.True(
            stringModeParams.Count == 0,
            "CanonicalLinkService must take the parsed ProviderMode, never a raw string mode token, so the {mode} route string is parsed once at the boundary and threaded typed inward (#369): " + string.Join(", ", stringModeParams));

        // Sentinel against a vacuous pass: a ProviderMode-typed mode parameter must actually exist on the
        // surface, so a rename that dropped the parameter entirely does not pass for the wrong reason.
        var typedModeExists = methods
            .SelectMany(m => m.GetParameters())
            .Any(p => p.Name == "mode" && p.ParameterType == typeof(ProviderMode));
        Assert.True(
            typedModeExists,
            "No ProviderMode-typed \"mode\" parameter was found on CanonicalLinkService; the linking surface was renamed, so point this rule at the new shape so the typed-mode invariant keeps guarding #369.");

        var linkMode = typeof(VerifiedIdentity).GetProperty("LinkMode", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.True(linkMode is not null, "VerifiedIdentity.LinkMode was renamed or removed; point this rule at the new property so the typed-mode invariant keeps guarding #369.");
        Assert.True(
            linkMode!.PropertyType == typeof(ProviderMode),
            "VerifiedIdentity.LinkMode must be the typed ProviderMode, not a raw \"oid\"/\"saml\" string the mint path would re-compare (#369).");
    }

    [Fact]
    public void SSOPlugin_DeclaresNoConfigurationLogicBeyondTheStoreFacade()
    {
        // Locked in by the ProviderConfigStore extraction (#318): SSOPlugin is bootstrap + page
        // manifests + a thin facade, and every configuration read/write/validation/preservation rule
        // lives in Config/ (ProviderConfigStore, ProviderConfigValidator, ServerManagedFields). Any
        // declared method or field whose signature mentions a configuration type must be one of the
        // named facade members that delegate to the store. PersistBase is allow-listed by name: it is
        // the private bridge handing base.UpdateConfiguration to the store, not config logic of its own.
        // Compiler-generated members (the ctor's `() => Configuration` lambda, backing fields) are
        // artifacts of the allowed wiring, not declared members - same exclusion as the keyed-state rule.
        var facade = new[] { "ReadConfiguration", "MutateConfiguration", "UpdateConfiguration", "PersistBase" };
        const BindingFlags declared = BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;

        var offenders = typeof(SSOPlugin).GetMethods(declared)
            .Where(m => !facade.Contains(m.Name) && !m.Name.Contains('<', StringComparison.Ordinal))
            .Where(m => m.GetParameters().Select(p => p.ParameterType).Append(m.ReturnType).Any(MentionsConfiguration))
            .Select(m => m.Name)
            .Concat(typeof(SSOPlugin).GetFields(declared)
                .Where(f => !f.Name.Contains('<', StringComparison.Ordinal))
                .Where(f => MentionsConfiguration(f.FieldType))
                .Select(f => f.Name))
            .Concat(typeof(SSOPlugin).GetConstructors(declared)
                .Where(c => c.GetParameters().Select(p => p.ParameterType).Any(MentionsConfiguration))
                .Select(c => ".ctor"))
            .ToList();

        Assert.True(offenders.Count == 0, "SSOPlugin members touching configuration types must stay limited to the delegating facade (config logic lives in Config/): " + string.Join(", ", offenders));
    }

    [Fact]
    public void RawServedLinkingPage_ContainsNoDashboardLocalizationPlaceholders()
    {
        // The self-service linking page is served raw by SSOViewsController.GetView (route
        // /SSOViews/linking) - no Jellyfin dashboard, so no localization pass runs. A ${...} token the
        // dashboard would substitute therefore leaks to the end user verbatim (the ${Help} button label
        // was the live case, #666). Scan the raw-served page for such placeholders, ignoring inline
        // <script> blocks where ${...} is a legitimate JS template-literal interpolation, not a
        // dashboard token.
        var html = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "linking.html"));
        var withoutScripts = Regex.Replace(html, "<script.*?</script>", string.Empty, RegexOptions.Singleline | RegexOptions.IgnoreCase);

        var placeholders = Regex.Matches(withoutScripts, "\\$\\{[^}]*\\}", RegexOptions.Singleline)
            .Select(m => m.Value)
            .ToList();

        Assert.True(
            placeholders.Count == 0,
            "The raw-served linking page must not carry dashboard ${...} localization placeholders (they are not substituted off the dashboard, #666); found: " + string.Join(", ", placeholders));
    }
}
