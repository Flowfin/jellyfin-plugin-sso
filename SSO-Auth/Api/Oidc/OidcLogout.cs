// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>Composes the OpenID Connect RP-initiated logout URL the browser is redirected to after the local Jellyfin session is ended (#727).</summary>
/// <remarks>
/// Pure string logic, because this URL navigates an authenticated user's browser to an external host. The
/// endpoint is accepted only when its authority equals the discovered issuer's, so a tampered discovery cannot
/// send the browser anywhere but the identity provider, and the return URL is included only when
/// <see cref="IsAllowedPostLogoutRedirect"/> accepts it. A blank or mismatched endpoint yields <c>null</c> and the
/// caller falls back to a local-only logout: <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#single-logout-opt-in"/>.
/// </remarks>
internal static class OidcLogout
{
    /// <summary>Builds the RP-initiated <c>end_session</c> URL, or <c>null</c> when there is no endpoint or it is not host-bound to the issuer, in which case the caller performs a local-only logout.</summary>
    /// <param name="endSessionEndpoint">The OP's advertised <c>end_session_endpoint</c> (may be null/empty).</param>
    /// <param name="issuer">The discovered issuer (its authority host-binds the endpoint).</param>
    /// <param name="idTokenHint">The revealed captured <c>id_token</c> for the <c>id_token_hint</c> (may be null).</param>
    /// <param name="clientId">The provider's client id.</param>
    /// <param name="postLogoutRedirectUri">The desired post-logout return URL (allow-listed below; may be null).</param>
    /// <param name="canonicalBaseUrl">This server's canonical base, the allow-list root for the return URL.</param>
    /// <returns>The absolute end-session URL, or <c>null</c> for a local-only logout.</returns>
    internal static string? BuildEndSessionUrl(
        string? endSessionEndpoint,
        string? issuer,
        string? idTokenHint,
        string? clientId,
        string? postLogoutRedirectUri,
        string? canonicalBaseUrl)
    {
        if (string.IsNullOrWhiteSpace(endSessionEndpoint)
            || !Uri.TryCreate(endSessionEndpoint, UriKind.Absolute, out var endSession)
            || (!string.Equals(endSession.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                && !string.Equals(endSession.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)))
        {
            return null;
        }

        // Issuer host-binding: only redirect to the discovered issuer's own authority.
        if (string.IsNullOrWhiteSpace(issuer)
            || !Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri)
            || !IsSameAuthority(endSession, issuerUri))
        {
            return null;
        }

        var query = new System.Text.StringBuilder();

        if (!string.IsNullOrEmpty(idTokenHint))
        {
            Append(query, "id_token_hint", idTokenHint);
        }

        if (!string.IsNullOrEmpty(clientId))
        {
            Append(query, "client_id", clientId);
        }

        // Allow-list the return URL against this server's canonical base; omit it otherwise.
        if (IsAllowedPostLogoutRedirect(postLogoutRedirectUri, canonicalBaseUrl, out var allowed))
        {
            Append(query, "post_logout_redirect_uri", allowed);
        }

        // The endpoint may already carry a query (RFC 6749 §3.1); use '?' or '&' accordingly. When there is
        // nothing to add, return it unchanged.
        if (query.Length == 0)
        {
            return endSessionEndpoint;
        }

        var separator = string.IsNullOrEmpty(endSession.Query) ? "?" : "&";
        return endSessionEndpoint + separator + query;
    }

    // Two URIs share an authority when scheme, host (ordinal-ignore-case per DNS), and effective port match.
    private static bool IsSameAuthority(Uri a, Uri b)
        => string.Equals(a.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase)
            && a.Port == b.Port;

    /// <summary>Whether a <c>post_logout_redirect_uri</c> candidate parses as an absolute http(s) URL with no userinfo and sits at or under this server's <paramref name="canonicalBaseUrl"/>, so a logout can only return the browser to this Jellyfin.</summary>
    /// <remarks>
    /// At or under means the same scheme, host and port, no percent-escape or <c>;</c> parameter in the path, and a
    /// path that equals the base path or continues it at a segment boundary, compared ordinally; a query and a
    /// fragment ride along. The save-time validator calls it too, so the config page rejects exactly what the runtime would drop.
    /// </remarks>
    /// <param name="candidate">The desired post-logout return URL (may be null/blank).</param>
    /// <param name="canonicalBaseUrl">This server's canonical base, the allow-list root.</param>
    /// <param name="allowed">The accepted return URL, trimmed, when the result is <see langword="true"/>, else empty.</param>
    /// <returns><see langword="true"/> if the candidate is a return URL at or under the canonical base.</returns>
    internal static bool IsAllowedPostLogoutRedirect(string? candidate, string? canonicalBaseUrl, out string allowed)
    {
        allowed = string.Empty;
        if (string.IsNullOrWhiteSpace(candidate)
            || string.IsNullOrWhiteSpace(canonicalBaseUrl)
            || !Uri.TryCreate(candidate, UriKind.Absolute, out var candidateUri)
            || (!string.Equals(candidateUri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                && !string.Equals(candidateUri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
            || !string.IsNullOrEmpty(candidateUri.UserInfo)
            || !Uri.TryCreate(canonicalBaseUrl, UriKind.Absolute, out var baseUri))
        {
            return false;
        }

        // Same authority as the canonical base, so a sibling host (a suffix of the base host) or a subdomain
        // of it is a different server and cannot slip through.
        if (!IsSameAuthority(candidateUri, baseUri))
        {
            return false;
        }

        var basePath = baseUri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        var candidatePath = candidateUri.GetLeftPart(UriPartial.Path).TrimEnd('/');

        // The path is compared in the form Uri canonicalizes it to, and that form is only as good as what the
        // NEXT hop does with it. Uri resolves literal and %2e dot segments here, but leaves every other
        // escape escaped and keeps a ";" segment parameter, so "/jellyfin/..%2f..%2fevil" and
        // "/jellyfin/..;/evil" would satisfy the boundary rule below and still resolve outside the base at any
        // proxy that decodes or strips them. Enumerating the dangerous escapes does not close that: %252f and
        // %3b reach the same place one decoding hop further out. A return URL to this server needs no escape
        // in its path at all, so refuse the whole family rather than guess how the next hop normalizes (#1181).
        if (candidatePath.Contains('%') || candidatePath.Contains(';'))
        {
            return false;
        }

        // Then the boundary itself: the candidate must EQUAL the base path or continue it at a SEGMENT
        // boundary. A plain string prefix is not enough - under a base of "https://host/jellyfin" it would
        // accept "https://host/jellyfinevil/x", a different application on the same reverse-proxied hostname.
        if (!candidatePath.StartsWith(basePath, StringComparison.Ordinal)
            || (candidatePath.Length != basePath.Length && candidatePath[basePath.Length] != '/'))
        {
            return false;
        }

        // Trimmed, because Uri.TryCreate above parsed the trimmed form: a padded value would otherwise be
        // emitted with its padding and fail the OP's exact match against the registered URI.
        allowed = candidate.Trim();
        return true;
    }

    private static void Append(System.Text.StringBuilder query, string name, string value)
    {
        if (query.Length > 0)
        {
            query.Append('&');
        }

        query.Append(name).Append('=').Append(Uri.EscapeDataString(value));
    }
}
