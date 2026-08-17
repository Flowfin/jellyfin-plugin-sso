// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// One canonical link exactly as the configuration holds it, before any decision about what a reader of it
/// is allowed to see (#1119). It is the single walk of the two link maps; every document assembled from
/// those maps projects from this sequence rather than repeating the walk, so a provider shape the walk
/// learns to skip is skipped for all of them at once.
/// </summary>
/// <param name="Protocol">The protocol the provider speaks.</param>
/// <param name="Provider">The provider the link belongs to.</param>
/// <param name="CanonicalName">The identity key the link is stored under.</param>
/// <param name="UserId">The Jellyfin user id the link points at, which may no longer resolve to an account.</param>
/// <param name="Issuer">The issuer this OpenID link is bound to (#186), or null for SAML and for links written before the binding existed.</param>
/// <param name="LastSsoLoginUtc">The instant of the last successful SSO login through this link (#1120), or null when none has been stamped since the field existed.</param>
internal readonly record struct CanonicalLinkRow(string Protocol, string Provider, string CanonicalName, Guid UserId, string? Issuer, DateTime? LastSsoLoginUtc);

/// <summary>
/// Builds the portable account-link snapshot (#1126). It reads the two link maps and resolves each
/// Jellyfin user id to a username, which is the whole of the transformation: the id is what a rebuilt user
/// database destroys, and the username is what survives it.
/// </summary>
/// <remarks>
/// Nothing here redacts anything, because nothing it reads is a secret. The document is assembled from the
/// canonical-link maps and the OpenID issuer bindings only; no provider configuration field is copied, so a
/// client secret or a signing key cannot reach the output by construction rather than by a converter that
/// has to be remembered. The one value that could leak by accident is the Jellyfin user id, and it is
/// consumed rather than emitted.
/// </remarks>
internal static class LinkExport
{
    /// <summary>
    /// The current document format version. Its own sequence, unrelated to the configuration export's.
    /// </summary>
    internal const int FormatVersion = 1;

    /// <summary>The protocol name an OpenID link is reported under.</summary>
    internal const string OpenIdProtocol = "OpenID";

    /// <summary>The protocol name a SAML link is reported under.</summary>
    internal const string SamlProtocol = "SAML";

    /// <summary>
    /// Walks both protocols' canonical-link maps once, in a fixed order (every OpenID link, then every
    /// SAML link). Call it under the config lock (through <c>ReadConfiguration</c>) so the two maps are
    /// read atomically against each other.
    /// </summary>
    /// <param name="live">The live plugin configuration to walk.</param>
    /// <returns>Every canonical link the configuration holds.</returns>
    internal static IEnumerable<CanonicalLinkRow> Rows(PluginConfiguration live)
    {
        ArgumentNullException.ThrowIfNull(live);

        foreach (var (provider, config) in Providers(live.OidConfigs))
        {
            foreach (var link in config.CanonicalLinks)
            {
                // The issuer binding is keyed by the same canonical name as the link (#186). A link
                // written before the binding existed has no entry, and null is the honest answer for it
                // rather than the provider's currently configured issuer, which was never what bound it.
                yield return new CanonicalLinkRow(
                    OpenIdProtocol,
                    provider,
                    link.Key,
                    link.Value,
                    config.CanonicalLinkIssuers.TryGetValue(link.Key, out var issuer) ? issuer : null,
                    LastSsoLogin(config, link.Key));
            }
        }

        foreach (var (provider, config) in Providers(live.SamlConfigs))
        {
            foreach (var link in config.CanonicalLinks)
            {
                yield return new CanonicalLinkRow(SamlProtocol, provider, link.Key, link.Value, null, LastSsoLogin(config, link.Key));
            }
        }
    }

    /// <summary>
    /// Builds the link document from the live configuration. Call it under the config lock (through
    /// <c>ReadConfiguration</c>) so the two link maps are read atomically against each other; the returned
    /// document holds only strings, so the JSON formatter serializing it after the lock is released cannot
    /// tear against a concurrent login writing a link.
    /// </summary>
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
            // A link pointing at an account that no longer exists is dangling: exporting it would put a
            // row in the document that nothing could ever be restored to, and a restore that silently
            // dropped it would differ from the document it claimed to apply. Drop it here, once.
            if (resolveUsername(row.UserId) is not { } username)
            {
                continue;
            }

            // The last-SSO-login stamp on the row is deliberately NOT carried into this document (#1120). The
            // export exists to be re-applied to a rebuilt server, and a login instant is an observation rather
            // than restorable state: writing it back would assert a login that never happened on the new
            // server, and shipping it out widens where that personal data travels for no gain. The roster,
            // which is a read of the live server, is the one document that reports it.
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

    // The last-SSO-login stamp for one link (#1120), keyed by the same canonical name as the link itself and
    // carried on both protocols. Null when no login has been stamped since the field existed, which is the
    // honest answer a reader has to be able to distinguish from an instant: a default DateTime here would be
    // rendered as a login in year one rather than as "never". Normalized to UTC on the way out, the same way
    // every other reader of these maps does it, so what the roster serializes carries a Z and cannot be read
    // as the server's local wall clock.
    private static DateTime? LastSsoLogin(ProviderConfigBase config, string canonicalName) =>
        config.CanonicalLinkLastLogins.TryGetValue(canonicalName, out var stamped)
            ? stamped.ToUniversalTime()
            : null;

    // A provider stored with a null config object is reachable through a null-bodied add (#350), and the
    // read side treats that the same fail-closed way the link listings do: skipped, never dereferenced.
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
