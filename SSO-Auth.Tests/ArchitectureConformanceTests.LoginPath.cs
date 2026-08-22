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
/// Conformance rules for the login-path composition rules: the shared avatar client, the revocation recheck before the mint, the provisioning-only disabled write, and the OIDC state and step-up reads.
/// </content>
public partial class ArchitectureConformanceTests
{
    [Fact]
    public void AvatarService_HoldsAStaticSharedHttpClient()
    {
        // Locked in by the per-login churn trim (#248): the controller builds a fresh AvatarService per
        // request, so the outbound HTTP stack must be a STATIC shared client - one connection pool for the
        // whole process - not a per-instance client that would open a new pool (a full TCP+TLS handshake)
        // on every login. The reference field the constructor reads (_httpClient) points at this shared
        // client in production; the reference-equality across two production instances is proven behaviorally
        // in AvatarServiceTests, and this rule locks in that the shared field it points at exists at all.
        var staticClient = typeof(AvatarService)
            .GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
            .Where(f => !f.Name.Contains('<', StringComparison.Ordinal))
            .Any(f => typeof(System.Net.Http.HttpClient).IsAssignableFrom(f.FieldType));

        Assert.True(staticClient, "AvatarService must hold a static HttpClient so the outbound stack is reused across the controller's per-request instances rather than rebuilt per login (#248).");
    }

    [Fact]
    public void SessionMinter_RechecksRevocationImmediatelyBeforeTheMint()
    {
        // Locked in by the in-flight revocation gate (#232): MintAsync must evaluate the caller-supplied
        // revocation predicate (identityStillLinked) as the last gate before it authenticates the session,
        // so a refactor cannot silently drop it or reorder it after the mint and reopen the TOCTOU between
        // link-resolution (under the config lock) and AuthenticateDirect (outside it). Call-level property,
        // so it is a source scan like the controller rules above. The invocation "identityStillLinked()"
        // is distinct from the parameter declaration/param-doc (no parentheses), so it matches only a gate.
        // The FINAL gate is what closes the race, so this pins the LAST invocation before the mint (an
        // earlier pre-mutation gate must not satisfy the rule) AND that no user-mutating side effect sits
        // between that final gate and AuthenticateDirect - otherwise a revocation during that work would go
        // unre-checked.
        var minterSource = File.ReadAllLines(Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Session", "SessionMinter.cs"));
        var mintLine = Array.FindIndex(minterSource, l => l.Contains("AuthenticateDirect(", StringComparison.Ordinal));
        Assert.True(mintLine >= 0, "SessionMinter.MintAsync must call AuthenticateDirect to mint the session.");

        var finalGate = Array.FindLastIndex(minterSource, mintLine - 1, l => l.Contains("identityStillLinked()", StringComparison.Ordinal));
        Assert.True(finalGate >= 0, "SessionMinter.MintAsync must invoke the identityStillLinked revocation re-check before AuthenticateDirect (#232).");

        var mutationMarkers = new[] { "UpdateUserAsync", "SetPermission", "SetPreference", "TrySetAsync", "AuthenticationProviderId =" };
        var interveningMutation = minterSource
            .Skip(finalGate + 1)
            .Take(mintLine - finalGate - 1)
            .Any(l => mutationMarkers.Any(m => l.Contains(m, StringComparison.Ordinal)));
        Assert.False(
            interveningMutation,
            "No user-mutating side effect may sit between the final #232 revocation re-check and AuthenticateDirect - the re-check must be the last gate before the mint.");
    }

    [Fact]
    public void IsDisabledIsWrittenOnlyOnTheNewAccountProvisioningArm()
    {
        // Locked in by #737. IsDisabled is a lockout vector: the plugin deliberately never disabled an
        // account until the pending-approval provisioning feature, and it is barred from SSO role mapping
        // (PermissionRolePolicy) so no login can disable an EXISTING account. The one sanctioned write -
        // provisioning a BRAND-NEW account inert for admin approval - must stay confined to
        // CanonicalLinkService (the single create seam). A source scan pins that: any future
        // SetPermission(PermissionKind.IsDisabled, ...) elsewhere (a mint path, a role mapper, a controller)
        // would reopen the "an SSO login disabled my account" surface and fails here instead of shipping.
        var apiRoot = Path.Combine(RepoTree.Root, "SSO-Auth", "Api");
        var offenders = new List<string>();
        foreach (var src in Directory.EnumerateFiles(apiRoot, "*.cs", SearchOption.AllDirectories))
        {
            var lines = File.ReadAllLines(src);
            for (var i = 0; i < lines.Length; i++)
            {
                if (lines[i].Contains("SetPermission(PermissionKind.IsDisabled", StringComparison.Ordinal)
                    && !src.EndsWith(Path.Combine("Linking", "CanonicalLinkService.cs"), StringComparison.Ordinal))
                {
                    offenders.Add($"{Path.GetFileName(src)}:{i + 1}");
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            "IsDisabled may be written only on CanonicalLinkService's new-account provisioning arm (#737). Writing it elsewhere can disable an existing account via SSO - a lockout vector. Offending sites: " + string.Join(", ", offenders));
    }

    [Fact]
    public void OidcRedirectUriField_IsReadOnly_AndIsFilledFromTheServerRatherThanComposedInThePage()
    {
        // #724 put the exact redirect_uri on the config page so an admin registers it verbatim (a mismatch is
        // the most common OIDC setup failure). #1303 moved WHO computes it. The page used to compose the
        // canonical base and the path spelling itself, which made it a second producer of bytes an identity
        // provider compares literally - and a divergence between the two producers never fails here, it fails
        // at the identity provider. Structural properties a JS runtime test cannot pin (no JS harness exists),
        // locked as a source scan:
        //  - the field is READ-ONLY and carries NO sso-* marker class, so it never becomes a persisting field
        //    (it is not an OidConfig property; ProviderFormFieldIds_MatchOidConfigProperties stays green);
        //  - its value is set via .value, never innerHTML (#221);
        //  - the page FETCHES the value from the elevation-gated endpoint and composes no OIDC redirect path
        //    of its own, not even as a fallback - a fallback runs exactly when nobody is watching, so the
        //    second producer would come back at the worst moment;
        //  - the copy confirmation is announced through an aria-live region (not colour-only).
        var html = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "configPage.html"));
        var js = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));

        var field = Regex.Match(html, "<input\\b[^>]*id=\"OidRedirectUri\"[^>]*>", RegexOptions.Singleline);
        Assert.True(field.Success, "The read-only #OidRedirectUri field must exist in configPage.html (#724).");
        Assert.Contains("readonly", field.Value, StringComparison.Ordinal);
        Assert.DoesNotMatch(new Regex("class=\"[^\"]*sso-(text|line-list|toggle|folder-list|role-map)"), field.Value);

        // The copy confirmation is a live region, not a colour-only signal.
        Assert.Matches(new Regex("id=\"OidRedirectUri-copied\"[^>]*aria-live", RegexOptions.Singleline), html);

        // The page asks the server for the value and writes the answer via .value.
        Assert.Contains("sso/OID/RedirectUri/", js, StringComparison.Ordinal);
        Assert.Matches(new Regex("#OidRedirectUri\"\\)[\\s\\S]{0,900}\\.value\\s*=", RegexOptions.Singleline), js);
        Assert.DoesNotMatch(new Regex("OidRedirectUri[\\s\\S]{0,200}innerHTML", RegexOptions.Singleline), js);

        // And composes no OIDC redirect path itself. Both live spellings are refused: either one reappearing
        // in this file is the duplication #1303 removed, whichever variable it is concatenated onto.
        Assert.DoesNotContain("/sso/OID/redirect/", js, StringComparison.Ordinal);
        Assert.DoesNotContain("/sso/OID/r/", js, StringComparison.Ordinal);
    }

    [Fact]
    public void OidcStepUpGate_ReadsAcrFromTheSignatureVerifiedIdToken_NotTheUserInfoMergedPrincipal()
    {
        // Locked in by #757. With LoadProfile on (the default), OidcClient merges the UNSIGNED UserInfo
        // response into result.User, so the step-up / MFA gate MUST read the acr from the raw, signature-
        // verified id_token (result.IdentityToken via OidcIdTokenAcr), never from result.User - otherwise a
        // UserInfo-supplied acr could satisfy a step-up requirement the session never actually met. This is a
        // call-site property invisible to a unit test (the gate would still pass its behavioural tests reading
        // from either source when they happen to agree), so it is pinned as a source scan: a refactor that
        // sources the acr from the merged principal reopens the gap and fails here.
        var source = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Flows", "OidcLoginService.cs"));

        Assert.Contains("OidcIdTokenAcr.Read(result.IdentityToken)", source, StringComparison.Ordinal);
        Assert.DoesNotMatch(new Regex("result\\.User\\.Claims[^;]*\"acr\"", RegexOptions.Singleline), source);
    }

    [Fact]
    public void OidcAuthorizeState_IsKeyedOnUtc_NotMachineLocalTime()
    {
        // Locked in by #676: the in-flight OpenID authorize-state store keys its lifetime/expiry on the
        // instant the challenge stamps (the Pending's Created) and the callback/redeem legs compare against
        // (PruneExpired / PeekCurrent / TryRedeem). That instant MUST be UTC (DateTime.UtcNow), never
        // machine-LOCAL wall-clock (DateTime.Now): on a DST transition or a clock step local time jumps, so
        // a machine-local basis can expire a valid authorize state early - or shift its window - and
        // spuriously fail an otherwise-valid login. The SAML flow already keeps a UTC basis; this pins the
        // OpenID side to the same one. Call-level property, so it is a source scan like the controller /
        // SessionMinter rules above - the store TAKES `now` as a parameter, so the clock choice lives
        // entirely at these call sites and is invisible to a store-level unit test (which injects its own
        // clock and so passes with EITHER basis). The production code passes the clock inline at each site.
        //
        // Deliberately NOT in scope: the _newPathPersistGate.TryEnter(DateTime.Now) throttle in the same
        // file (and its SAML twin) - a best-effort config-persist throttle, not the authorize-state
        // lifetime; its clock jitter is harmless and it stays symmetric with the SAML side. The markers
        // below are scoped to the store's clock-bearing calls, so that line is out of scope by construction.
        var oidcSource = SourceFilesDeclaring(new[] { typeof(OidcLoginService) });
        Assert.True(
            oidcSource.Count == 1,
            "OidcLoginService's source file was not found (renamed/moved); point OidcAuthorizeState_IsKeyedOnUtc_NotMachineLocalTime at its new location so the UTC-basis scan keeps guarding #676.");

        var lines = File.ReadAllLines(oidcSource[0]);
        var storeClockMarkers = new[]
        {
            "StateStore.PruneExpired(", "StateStore.PeekCurrent(", "StateStore.TryRedeem(", "new AuthorizeSession.Pending(",
        };

        foreach (var marker in storeClockMarkers)
        {
            var markerLines = lines
                .Select((line, index) => (Text: line.Trim(), Number: index + 1))
                .Where(l => l.Text.Contains(marker, StringComparison.Ordinal))
                .ToList();

            // Liveness against a vacuous pass: the store's clock-bearing call site must still exist, or the
            // scan guards nothing - a rename/restructure of the flow fails HERE and forces a conscious
            // update of this rule (as the other source scans' sentinels do). "DateTime.Now" is not a
            // substring of "DateTime.UtcNow", so a correct UtcNow site never trips the machine-local check.
            Assert.True(
                markerLines.Count > 0,
                $"The OIDC authorize-state call site \"{marker}\" was not found in OidcLoginService; it was renamed or restructured, so update OidcAuthorizeState_IsKeyedOnUtc_NotMachineLocalTime so the UTC-basis scan keeps guarding #676.");

            var offenders = markerLines
                .Where(l => l.Text.Contains("DateTime.Now", StringComparison.Ordinal) || !l.Text.Contains("DateTime.UtcNow", StringComparison.Ordinal))
                .Select(l => $"line {l.Number}: {l.Text}")
                .ToList();
            Assert.True(
                offenders.Count == 0,
                $"Every OIDC authorize-state \"{marker}\" call must key on DateTime.UtcNow, never machine-local DateTime.Now, so a DST transition or clock step cannot expire a valid login early (#676). Found: " + string.Join(" | ", offenders));
        }
    }

    [Fact]
    public void SsoManagedProviderId_IsPinnedAndUsedByBothStampAndDetector()
    {
        // SECURITY / PERSISTENCE pin (#837). This exact string is written to User.AuthenticationProviderId
        // and persisted in Jellyfin's user database: every SSO-managed account provisioned by any version
        // carries it, the stamp (CanonicalLinkService) writes it, and the SSO-only detector
        // (SsoAuthenticationProviders.IsSsoProvider) compares against it. It MUST NEVER change - a different
        // value silently stops recognizing every existing SSO account - and it MUST stay decoupled from
        // typeof(SSOController).FullName so a future move of that type (e.g. into an Api.Http module, #807)
        // cannot orphan those accounts. The value equals the controller's historical full type name; that is
        // a coincidence of history, not a live coupling.
        Assert.Equal("Jellyfin.Plugin.SSO_Auth.Api.SSOController", SsoManagedProviderId.Value);

        // The detector resolves to the same pinned value, so the stamp and the detector can never disagree.
        Assert.Equal(SsoManagedProviderId.Value, SsoAuthenticationProviders.SsoProviderId);

        // The stamp uses the pin, and neither the stamp nor the detector recomputes the id from the
        // controller type. Source scans, so a regression to type-coupling fails here even if today's value
        // still happens to match.
        var stampSource = string.Join("\n", SourceFilesDeclaring(new[] { typeof(CanonicalLinkService) }).Select(File.ReadAllText));
        var detectorSource = string.Join("\n", SourceFilesDeclaring(new[] { typeof(SsoAuthenticationProviders) }).Select(File.ReadAllText));
        Assert.Contains("SsoManagedProviderId.Value", stampSource, StringComparison.Ordinal);
        Assert.DoesNotContain("typeof(SSOController)", stampSource, StringComparison.Ordinal);
        Assert.DoesNotContain("typeof(SSOController)", detectorSource, StringComparison.Ordinal);
    }
}
