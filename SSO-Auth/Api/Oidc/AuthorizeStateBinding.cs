// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>Binds an in-flight OpenID authorize state to the browser that started it (#326).</summary>
/// <remarks>
/// The authorize state token alone proves knowledge of an unguessable key and does not tie the callback to the
/// user-agent that initiated authorization, the role RFC 6749 section 10.12 assigns it, so an attacker could
/// complete their own flow in a victim's browser. The challenge sets a cookie carrying a fresh random id and
/// records the same id on the state, and the callbacks require the two to match:
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#login-browser-binding-forced-login-defense"/>.
/// </remarks>
internal static class AuthorizeStateBinding
{
    /// <summary>
    /// The browser-binding cookie name. The <c>__Host-</c> prefix makes the browser enforce that the
    /// cookie is Secure, host-only (no <c>Domain</c>), and <c>Path=/</c> - so a sibling subdomain under
    /// a shared parent domain cannot plant a same-named <c>Domain</c>-scoped cookie to poison the binding
    /// check (cookie tossing). The prefix requires HTTPS, which every real OpenID deployment already uses.
    /// </summary>
    internal const string CookieName = "__Host-sso_oid_state_binding";

    /// <summary>
    /// The SAML browser-binding cookie name (#415). Separate from the OpenID cookie so the two flows
    /// cannot cross-satisfy each other's binding check; the <c>__Host-</c> prefix carries the same
    /// cookie-tossing defense described for <see cref="CookieName"/>. Checked at the same-origin
    /// session-mint endpoint (SAML/auth), where a <c>SameSite=Lax</c> cookie is sent - the ACS POST
    /// from the identity provider is cross-site and would not carry it.
    /// </summary>
    internal const string SamlCookieName = "__Host-sso_saml_state_binding";

    /// <summary>A fresh 256-bit CSPRNG binding id, hex-encoded (URL- and cookie-safe).</summary>
    /// <returns>The new binding id.</returns>
    internal static string NewId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// Whether a presented binding id matches the one recorded on the state. Fail closed: a state with
    /// no recorded id, or a missing/mismatched presented id, does not match. The stored id is an
    /// unguessable server-minted value, so an ordinal compare carries the same risk profile as the
    /// existing state-token lookup.
    /// </summary>
    /// <param name="storedBindingId">The id recorded on the stored state.</param>
    /// <param name="presentedBindingId">The id presented by the callback (the cookie value).</param>
    /// <returns>True only when both are present and equal.</returns>
    internal static bool Matches(string storedBindingId, string? presentedBindingId)
        => !string.IsNullOrEmpty(storedBindingId)
           && string.Equals(storedBindingId, presentedBindingId, StringComparison.Ordinal);

    /// <summary>The cookie policy for the binding cookie: Secure, HttpOnly, SameSite=Lax, scoped to the whole app and bounded to the state lifetime.</summary>
    /// <remarks>
    /// Secure is always set because every real OpenID deployment is HTTPS at the browser edge, even where a
    /// proxy forwards plain HTTP to the app. Lax rather than Strict, because the provider returns the browser
    /// through a top-level cross-site navigation, on which Strict cookies are not sent and every login would fail.
    /// </remarks>
    /// <param name="lifetime">How long the cookie should live, matching the authorize-state lifetime.</param>
    /// <returns>The cookie options.</returns>
    internal static CookieOptions CookieOptions(TimeSpan lifetime) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        MaxAge = lifetime,
    };
}
