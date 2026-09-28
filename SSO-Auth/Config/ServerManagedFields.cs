// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>Re-injects the server-managed fields a save must not be allowed to clear (#157, #189).</summary>
/// <remarks>
/// The per-provider overloads are the one rule every admin write path converges on, so a field added here is preserved
/// on every door (#318). See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#the-import-merges-and-preserves-an-unchanged-providers-secrets-and-links"/>.
/// </remarks>
internal static class ServerManagedFields
{
    /// <summary>Copies the server-managed fields from <paramref name="live"/> into <paramref name="incoming"/>, so a stale client snapshot cannot clear them.</summary>
    /// <remarks>Only providers present in both are touched, and a write-only secret is kept only when the incoming value is blank.</remarks>
    /// <param name="incoming">The configuration about to be persisted.</param>
    /// <param name="live">The current live configuration to read server-managed values from.</param>
    internal static void Preserve(PluginConfiguration incoming, PluginConfiguration live)
    {
        Preserve(incoming?.OidConfigs, live?.OidConfigs, Preserve);
        Preserve(incoming?.SamlConfigs, live?.SamlConfigs, Preserve);

        // The SSO-only pair can only change through the elevated endpoints that run the guard and the sweep (#165).
        if (incoming is not null && live is not null)
        {
            incoming.DisablePasswordLogin = live.DisablePasswordLogin;
            incoming.BreakGlassAdminUsername = live.BreakGlassAdminUsername;
            incoming.SsoOnlyRepointedUserIds = live.SsoOnlyRepointedUserIds;

            // Withheld from JSON, so a save arrives with them empty; the login, logout and mint paths stay the only writers (#727, #1733).
            incoming.LogoutSessions = live.LogoutSessions;
            incoming.ProvisionedPasswords = live.ProvisionedPasswords;
        }
    }

    private static void Preserve<T>(SerializableDictionary<string, T>? incoming, SerializableDictionary<string, T>? live, Action<T, T> preserveProvider)
        where T : ProviderConfigBase
    {
        if (incoming is null || live is null)
        {
            return;
        }

        foreach (var kvp in live)
        {
            if (incoming.TryGetValue(kvp.Key, out var incomingProvider))
            {
                preserveProvider(incomingProvider, kvp.Value);
            }
        }
    }

    /// <summary>Re-injects an OpenID provider's server-managed fields: the link maps, carried only while the discovery endpoint is unchanged, and the write-only client secret (#157, #186, #189).</summary>
    /// <param name="incoming">The provider config about to be persisted; a null entry is skipped.</param>
    /// <param name="live">The current live provider config to read server-managed values from; null skips.</param>
    internal static void Preserve(OidConfig incoming, OidConfig? live)
    {
        if (incoming is null || live is null)
        {
            return;
        }

        // A changed endpoint re-identifies the provider, so every per-link map is dropped with the links rather than inherited (#186).
        var endpointUnchanged = string.Equals(incoming.OidEndpoint, live.OidEndpoint, StringComparison.Ordinal);
        incoming.CanonicalLinks = endpointUnchanged ? live.CanonicalLinks : new SerializableDictionary<string, Guid>();
        incoming.CanonicalLinkIssuers = endpointUnchanged ? live.CanonicalLinkIssuers : new SerializableDictionary<string, string>();
        incoming.CanonicalLinkDeadlines = endpointUnchanged ? live.CanonicalLinkDeadlines : new SerializableDictionary<string, DateTime>();
        incoming.CanonicalLinkLastLogins = endpointUnchanged ? live.CanonicalLinkLastLogins : new SerializableDictionary<string, DateTime>();
        incoming.CanonicalLinkPendingApprovals = endpointUnchanged ? live.CanonicalLinkPendingApprovals : new SerializableDictionary<string, PendingApproval>();

        incoming.OidSecret = ResolveUpdatedSecret(incoming, live);
    }

    /// <summary>Re-injects a SAML provider's server-managed fields: the link maps and the write-only signing keys, each kept when the incoming value is blank (#157, #167, #491).</summary>
    /// <param name="incoming">The provider config about to be persisted; a null entry is skipped.</param>
    /// <param name="live">The current live provider config to read server-managed values from; null skips.</param>
    internal static void Preserve(SamlConfig incoming, SamlConfig? live)
    {
        if (incoming is null || live is null)
        {
            return;
        }

        // Withheld from JSON, so a save arrives with the maps empty; SAML has no repoint belt to gate them on.
        incoming.CanonicalLinks = live.CanonicalLinks;
        incoming.CanonicalLinkDeadlines = live.CanonicalLinkDeadlines;
        incoming.CanonicalLinkLastLogins = live.CanonicalLinkLastLogins;
        incoming.CanonicalLinkPendingApprovals = live.CanonicalLinkPendingApprovals;
        incoming.SamlSigningKeyPfx = PreserveSigningKeyIfBlank(incoming.SamlSigningKeyPfx, live.SamlSigningKeyPfx);
        incoming.SamlRolloverSigningKeyPfx = PreserveSigningKeyIfBlank(incoming.SamlRolloverSigningKeyPfx, live.SamlRolloverSigningKeyPfx);
    }

    /// <summary>Decides which signing key an updated SAML provider keeps: a non-blank incoming key is a rotation, a blank one keeps the stored key.</summary>
    /// <remarks>No identity guard, unlike the client secret: a signing key is never transmitted, so a repoint cannot exfiltrate it.</remarks>
    /// <param name="incoming">The key about to be persisted; blank when the save did not rotate it.</param>
    /// <param name="live">The corresponding stored key.</param>
    /// <returns>The incoming key when non-blank, otherwise the stored key.</returns>
    private static string? PreserveSigningKeyIfBlank(string? incoming, string? live)
        => string.IsNullOrWhiteSpace(incoming) ? live : incoming;

    /// <summary>Decides which OpenID client secret an updated provider keeps: a non-blank incoming secret wins, a blank one keeps the stored secret only while the provider identity is unchanged (#189).</summary>
    /// <remarks>Dropping it on a repoint is what stops a write-only secret being exfiltrated to a different token endpoint.</remarks>
    /// <param name="incoming">The provider config about to be persisted.</param>
    /// <param name="live">The current live provider config.</param>
    /// <returns>The secret to persist for the updated provider.</returns>
    internal static string? ResolveUpdatedSecret(OidConfig incoming, OidConfig live)
    {
        if (!string.IsNullOrWhiteSpace(incoming.OidSecret))
        {
            return incoming.OidSecret;
        }

        return IdentityUnchanged(incoming, live) ? live.OidSecret : incoming.OidSecret;
    }

    /// <summary>Says whether <see cref="ResolveUpdatedSecret"/> is about to drop a stored secret for this save, so the save can ask for it again (#1872).</summary>
    /// <remarks>Read against the stored provider, never against a posted config the preserve has already resolved.</remarks>
    /// <param name="incoming">The provider config about to be persisted.</param>
    /// <param name="live">The current live provider config, or null when the provider is new.</param>
    /// <returns>True when this save drops a stored secret because the provider identity changed.</returns>
    internal static bool SecretDroppedByRepoint(OidConfig incoming, OidConfig? live)
        => live is not null
            && !string.IsNullOrWhiteSpace(live.OidSecret)
            && string.IsNullOrWhiteSpace(incoming.OidSecret)
            && !IdentityUnchanged(incoming, live);

    private static bool IdentityUnchanged(OidConfig incoming, OidConfig live)
        => string.Equals(incoming.OidEndpoint, live.OidEndpoint, StringComparison.Ordinal)
            && string.Equals(incoming.OidClientId, live.OidClientId, StringComparison.Ordinal);
}
