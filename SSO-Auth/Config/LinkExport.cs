// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>One canonical link as the configuration holds it; the single walk of the two link maps every document projects from (#1119).</summary>
/// <param name="Protocol">The protocol the provider speaks.</param>
/// <param name="Provider">The provider the link belongs to.</param>
/// <param name="CanonicalName">The identity key the link is stored under.</param>
/// <param name="UserId">The Jellyfin user id the link points at, which may no longer resolve to an account.</param>
/// <param name="Issuer">The issuer this OpenID link is bound to (#186), or null for SAML and for links written before the binding existed.</param>
/// <param name="LastSsoLoginUtc">The instant of the last successful SSO login through this link (#1120), or null when none has been stamped.</param>
/// <param name="PendingApprovalSinceUtc">The instant this plugin provisioned the linked account disabled and awaiting approval (#1529), or null when it did not.</param>
internal readonly record struct CanonicalLinkRow(string Protocol, string Provider, string CanonicalName, Guid UserId, string? Issuer, DateTime? LastSsoLoginUtc, DateTime? PendingApprovalSinceUtc);

/// <summary>Builds the portable account-link snapshot, resolving each user id to the username that survives a rebuilt user database (#1126).</summary>
/// <remarks>No provider field is copied, so a secret cannot reach the output by construction. See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Server-Migration"/>.</remarks>
internal static class LinkExport
{
    /// <summary>The current document format version, a sequence of its own.</summary>
    internal const int FormatVersion = 1;

    /// <summary>The protocol name an OpenID link is reported under.</summary>
    internal const string OpenIdProtocol = "OpenID";

    /// <summary>The protocol name a SAML link is reported under.</summary>
    internal const string SamlProtocol = "SAML";

    /// <summary>Walks both protocols' link maps once, OpenID first; call it under the config lock so the maps are read atomically.</summary>
    /// <param name="live">The live plugin configuration to walk.</param>
    /// <returns>Every canonical link the configuration holds.</returns>
    internal static IEnumerable<CanonicalLinkRow> Rows(PluginConfiguration live)
    {
        ArgumentNullException.ThrowIfNull(live);

        foreach (var (provider, config) in Providers(live.OidConfigs))
        {
            foreach (var link in config.CanonicalLinks)
            {
                // A link written before the binding existed has no entry, and null is the honest answer (#186).
                yield return new CanonicalLinkRow(
                    OpenIdProtocol,
                    provider,
                    link.Key,
                    link.Value,
                    config.CanonicalLinkIssuers.TryGetValue(link.Key, out var issuer) ? issuer : null,
                    LastSsoLogin(config, link.Key),
                    PendingApprovalSince(config, link.Key));
            }
        }

        foreach (var (provider, config) in Providers(live.SamlConfigs))
        {
            foreach (var link in config.CanonicalLinks)
            {
                yield return new CanonicalLinkRow(SamlProtocol, provider, link.Key, link.Value, null, LastSsoLogin(config, link.Key), PendingApprovalSince(config, link.Key));
            }
        }
    }

    /// <summary>Builds the link document from the live configuration; call it under the config lock, and the result holds only strings.</summary>
    /// <param name="live">The live plugin configuration to snapshot.</param>
    /// <param name="resolveUsername">Resolves a Jellyfin user id to its username, or null when no such account exists.</param>
    /// <returns>The link export document.</returns>
    internal static LinkExportDocument Build(PluginConfiguration live, Func<Guid, string?> resolveUsername)
    {
        ArgumentNullException.ThrowIfNull(live);
        ArgumentNullException.ThrowIfNull(resolveUsername);

        var document = new LinkExportDocument { FormatVersion = FormatVersion };

        foreach (var row in Rows(live))
        {
            // A dangling link is dropped here, once, rather than exported as a row nothing could restore.
            if (resolveUsername(row.UserId) is not { } username)
            {
                continue;
            }

            // The last-login stamp is an observation, not restorable state, so it stays out of the document (#1120).
            document.Links.Add(new LinkExportEntry
            {
                Protocol = row.Protocol,
                Provider = row.Provider,
                CanonicalName = row.CanonicalName,
                Username = username,
                Issuer = row.Issuer,
            });
        }

        return document;
    }

    // Null rather than a default DateTime, so "never" is not rendered as a login in year one (#1120).
    private static DateTime? LastSsoLogin(ProviderConfigBase config, string canonicalName) =>
        config.CanonicalLinkLastLogins.TryGetValue(canonicalName, out var stamped)
            ? stamped.ToUniversalTime()
            : null;

    // Read through the same rule the approve action asks, so the roster cannot present a row that action would refuse (#1529).
    private static DateTime? PendingApprovalSince(ProviderConfigBase config, string canonicalName) =>
        PendingApproval.Live(config, canonicalName)?.SinceUtc.ToUniversalTime();

    // A null-bodied add can store a null provider (#350), which every read skips.
    private static IEnumerable<(string Provider, TConfig Config)> Providers<TConfig>(
        SerializableDictionary<string, TConfig> configs)
        where TConfig : ProviderConfigBase
    {
        if (configs is null)
        {
            yield break;
        }

        foreach (var entry in configs)
        {
            if (entry.Value is not null)
            {
                yield return (entry.Key, entry.Value);
            }
        }
    }
}
