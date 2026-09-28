// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>The per-session state a Single Logout needs, captured at login and persisted so it survives a restart (#727).</summary>
/// <remarks>
/// A plain XML-serializable class, because it is a <see cref="SerializableDictionary{TKey,TValue}"/> value;
/// <see cref="IdToken"/> is a bearer secret, encrypted at rest. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Single-Logout-Design"/>.
/// </remarks>
public class LogoutSession
{
    /// <summary>Gets or sets the protocol that minted the session, <c>OpenID</c> or <c>SAML</c>, which selects the logout mechanism.</summary>
    public string Protocol { get; set; } = string.Empty;

    /// <summary>Gets or sets the provider name the session was authenticated through.</summary>
    public string Provider { get; set; } = string.Empty;

    /// <summary>Gets or sets the stable subject an inbound SAML <c>LogoutRequest</c> is matched on.</summary>
    public string Subject { get; set; } = string.Empty;

    /// <summary>Gets or sets the identity-provider session identifier, when the provider issued one.</summary>
    public string? SessionIndex { get; set; }

    /// <summary>Gets or sets the id_token issuer the logout URL is host-bound to (OpenID only).</summary>
    public string? Issuer { get; set; }

    /// <summary>Gets or sets the <c>end_session_endpoint</c> captured from discovery at login; blank falls back to a local-only logout.</summary>
    public string? EndSessionEndpoint { get; set; }

    /// <summary>Gets or sets the raw OpenID <c>id_token</c> used as the <c>id_token_hint</c>; a bearer secret, encrypted at rest.</summary>
    // Ignored at the field as well as at the enclosing map, so a directly serialized session still cannot leak it.
    [System.Text.Json.Serialization.JsonIgnore]
    public string? IdToken { get; set; }

    /// <summary>Gets or sets the Jellyfin user id whose tokens a logout revokes.</summary>
    public Guid UserId { get; set; }

    /// <summary>Gets or sets the UTC ticks at which the session was captured, which bound and expire the store.</summary>
    public long CapturedUtcTicks { get; set; }
}
