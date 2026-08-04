// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcLogout"/> - the RP-initiated end_session URL builder (#727, SLO-2). The security
/// pins: the endpoint must be host-bound to the discovered issuer, and the post_logout_redirect_uri must be
/// allow-listed against this server's canonical base, so a logout can never navigate the browser to an
/// attacker host. A missing endpoint yields null (local-only logout).
/// </summary>
public class OidcLogoutTests
{
    private const string Issuer = "https://idp.example.com";
    private const string EndSession = "https://idp.example.com/protocol/openid-connect/logout";
    private const string Base = "https://jellyfin.example.com";

    [Fact]
    public void Build_HappyPath_IncludesHintClientIdAndAllowedReturn_Escaped()
    {
        var url = OidcLogout.BuildEndSessionUrl(EndSession, Issuer, "raw.id.token", "jellyfin-client", Base + "/web/", Base);

        Assert.StartsWith(EndSession + "?", url, System.StringComparison.Ordinal);
        Assert.Contains("id_token_hint=raw.id.token", url, System.StringComparison.Ordinal);
        Assert.Contains("client_id=jellyfin-client", url, System.StringComparison.Ordinal);
        // The return URL is present and percent-encoded (the "://" becomes %3A%2F%2F).
        Assert.Contains("post_logout_redirect_uri=https%3A%2F%2Fjellyfin.example.com", url, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Build_NoEndSessionEndpoint_ReturnsNull_ForLocalOnlyLogout()
    {
        Assert.Null(OidcLogout.BuildEndSessionUrl(null, Issuer, "t", "c", Base, Base));
        Assert.Null(OidcLogout.BuildEndSessionUrl("   ", Issuer, "t", "c", Base, Base));
        Assert.Null(OidcLogout.BuildEndSessionUrl("not-a-url", Issuer, "t", "c", Base, Base));
    }

    [Fact]
    public void Build_EndSessionOnADifferentHostThanTheIssuer_ReturnsNull()
    {
        // Host-binding: a discovery document pointing end_session at an attacker host must not redirect there.
        Assert.Null(OidcLogout.BuildEndSessionUrl("https://evil.example.net/logout", Issuer, "t", "c", Base, Base));
        // A different port is also a different authority.
        Assert.Null(OidcLogout.BuildEndSessionUrl("https://idp.example.com:8443/logout", Issuer, "t", "c", Base, Base));
    }

    [Fact]
    public void Build_PostLogoutRedirectOnAnAttackerHost_IsOmitted_NotIncluded()
    {
        var url = OidcLogout.BuildEndSessionUrl(EndSession, Issuer, "t", "c", "https://evil.example.net/steal", Base);

        Assert.NotNull(url);
        Assert.DoesNotContain("post_logout_redirect_uri", url, System.StringComparison.Ordinal);
        Assert.DoesNotContain("evil.example.net", url, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Build_PostLogoutRedirectUnderTheCanonicalBase_IsAllowed()
    {
        var url = OidcLogout.BuildEndSessionUrl(EndSession, Issuer, "t", "c", Base + "/sso/goodbye", Base);
        Assert.Contains("post_logout_redirect_uri=", url, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Build_PostLogoutRedirectOnASiblingPrefixHost_IsRejected()
    {
        // A host that merely starts with the base host string is a different authority - must not pass.
        var url = OidcLogout.BuildEndSessionUrl(EndSession, Issuer, "t", "c", "https://jellyfin.example.com.evil.net/", Base);
        Assert.DoesNotContain("post_logout_redirect_uri", url, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Build_EndpointWithExistingQuery_AppendsWithAmpersand()
    {
        var url = OidcLogout.BuildEndSessionUrl(EndSession + "?ui_locales=en", Issuer, "t", "c", null, Base);
        Assert.StartsWith(EndSession + "?ui_locales=en&", url, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Build_NoHintNoReturn_ReturnsTheEndpointWithOnlyClientId()
    {
        var url = OidcLogout.BuildEndSessionUrl(EndSession, Issuer, null, "c", null, Base);
        Assert.Equal(EndSession + "?client_id=c", url);
    }

    // The allow-list predicate is now internal and reused by the config-page save validator (#727, SLO-4), so
    // pin its contract directly - it is the single source of truth both the runtime builder above and
    // ProviderConfigValidator.ValidatePostLogoutRedirectUri call.

    [Theory]
    [InlineData("https://jellyfin.example.com")] // the base itself
    [InlineData("https://jellyfin.example.com/web/")] // under the base path
    public void IsAllowedPostLogoutRedirect_AtOrUnderBase_IsAllowed_AndReturnsTheCandidate(string candidate)
    {
        Assert.True(OidcLogout.IsAllowedPostLogoutRedirect(candidate, Base, out var allowed));
        Assert.Equal(candidate, allowed);
    }

    [Theory]
    [InlineData("https://evil.example.net/steal")] // different authority
    [InlineData("https://jellyfin.example.com.evil.net/")] // suffix family: a host the base host is a prefix of
    [InlineData("not-a-url")] // not absolute
    [InlineData("ftp://jellyfin.example.com/x")] // not http(s)
    [InlineData("https://user:pass@jellyfin.example.com/")] // userinfo
    [InlineData("")] // blank candidate
    public void IsAllowedPostLogoutRedirect_OffBaseOrMalformedOrBlank_IsRejected_WithEmptyOut(string candidate)
    {
        Assert.False(OidcLogout.IsAllowedPostLogoutRedirect(candidate, Base, out var allowed));
        Assert.Equal(string.Empty, allowed);
    }

    // --- The containment boundary (#1181): prefix, suffix, subdomain and case ---
    //
    // Both the XML doc on the predicate and the admin-facing validator message promise a return URL "at or
    // under this server's base URL". These rows are the four ways a candidate can look like it is under the
    // base without being under it. The realistic deployment is a reverse proxy serving more than one app
    // under one hostname, where the base carries a path base.

    private const string PathBase = "https://jf.example.com/jellyfin";

    [Theory]
    // Prefix family: same authority, and the base path is a string prefix of the candidate path but not a
    // segment prefix of it. "/jellyfinevil" is a different application, not something under "/jellyfin".
    [InlineData(PathBase, "https://jf.example.com/jellyfinevil/x")]
    [InlineData(PathBase, "https://jf.example.com/jellyfinevil")]
    // Suffix family, both readings of it: a host carrying the base host plus a suffix, and a host or path
    // that ENDS with the base string without being under it. Different authority in the host cases, so those
    // are refused by the host compare rather than by the path rule.
    [InlineData(Base, "https://jellyfin.example.com.evil.net/web/")]
    [InlineData(Base, "https://eviljellyfin.example.com/")]
    [InlineData(PathBase, "https://jf.example.com/notjellyfin")]
    // Escaped separators and a segment parameter: Uri leaves them intact, so without the guard on them a
    // hop that decodes or strips them resolves the path outside the base after the check has passed.
    [InlineData(PathBase, "https://jf.example.com/jellyfin/..%2f..%2fevil")]
    [InlineData(PathBase, "https://jf.example.com/jellyfin/%2E%2E%2Fevil")]
    [InlineData(PathBase, "https://jf.example.com/jellyfin/..%5C..%5Cevil")]
    [InlineData(PathBase, "https://jf.example.com/jellyfin/..;/evil")]
    // Subdomain family, in both directions: neither contains the other.
    [InlineData(Base, "https://sub.jellyfin.example.com/")]
    [InlineData("https://sub.jellyfin.example.com", "https://jellyfin.example.com/")]
    // Case family, path half: URL paths are case-sensitive, the path compare is ordinal, and a
    // differently-cased path segment is a different path - including the candidate that differs from the
    // base in nothing but case. Pinned deliberately; the host half below is the opposite direction and is
    // intended.
    [InlineData(PathBase, "https://jf.example.com/JELLYFIN/x")]
    [InlineData(PathBase, "https://jf.example.com/JELLYFIN")]
    public void IsAllowedPostLogoutRedirect_OutsideTheBase_IsRejected_WithEmptyOut(string canonicalBase, string candidate)
    {
        Assert.False(OidcLogout.IsAllowedPostLogoutRedirect(candidate, canonicalBase, out var allowed));
        Assert.Equal(string.Empty, allowed);
    }

    [Theory]
    // Case family, host half: the acceptance is INTENDED. DNS host names are case-insensitive and a
    // differently-cased host is the same server. What delivers the acceptance for these rows is Uri's own
    // lower-casing of an ASCII host rather than the OrdinalIgnoreCase compare in IsSameAuthority, so these
    // rows pin the observable behaviour and not that compare - from this entry point the compare cannot be
    // falsified, because no ASCII host reaches it with its case intact.
    [InlineData(Base, "https://JELLYFIN.EXAMPLE.COM/web/")]
    [InlineData("https://JELLYFIN.example.com", "https://jellyfin.example.com/web/")]
    // A base with a path base contains itself and everything at a segment boundary below it.
    [InlineData(PathBase, PathBase)]
    [InlineData(PathBase, "https://jf.example.com/jellyfin/")]
    [InlineData(PathBase, "https://jf.example.com/jellyfin/web/index.html")]
    public void IsAllowedPostLogoutRedirect_AtOrUnderBase_IncludingADifferentlyCasedHost_IsAllowed(string canonicalBase, string candidate)
    {
        Assert.True(OidcLogout.IsAllowedPostLogoutRedirect(candidate, canonicalBase, out var allowed));
        Assert.Equal(candidate, allowed);
    }

    [Fact]
    public void IsAllowedPostLogoutRedirect_PaddedCandidate_IsAcceptedTrimmed_SoWhatIsEmittedIsWhatWasChecked()
    {
        // Uri.TryCreate parses the trimmed form, so the padding is not part of what the checks above ran on.
        // Emitting it would break the OP's exact match against the registered URI.
        Assert.True(OidcLogout.IsAllowedPostLogoutRedirect("  " + Base + "/web/  ", Base, out var allowed));
        Assert.Equal(Base + "/web/", allowed);
    }

    [Fact]
    public void Build_PostLogoutRedirectSharingOnlyAPrefixOfTheBasePath_LeavesTheParameterAbsentEntirely()
    {
        var url = OidcLogout.BuildEndSessionUrl(EndSession, Issuer, "t", "c", "https://jf.example.com/jellyfinevil/x", PathBase);

        // Absent, not present-and-empty: a bare "post_logout_redirect_uri=" is still a parameter the OP
        // reads, and the whole value must be gone rather than blanked.
        Assert.NotNull(url);
        Assert.DoesNotContain("post_logout_redirect_uri", url, System.StringComparison.Ordinal);
        Assert.DoesNotContain("jellyfinevil", url, System.StringComparison.Ordinal);
        Assert.Equal(EndSession + "?id_token_hint=t&client_id=c", url);
    }

    [Fact]
    public void IsAllowedPostLogoutRedirect_BlankBase_IsRejected()
    {
        // A blank canonical base cannot allow-list anything (the save validator relies on this to skip the
        // check when no Base URL Override pins a determinate base).
        Assert.False(OidcLogout.IsAllowedPostLogoutRedirect(Base, null, out var allowed));
        Assert.Equal(string.Empty, allowed);
    }
}
