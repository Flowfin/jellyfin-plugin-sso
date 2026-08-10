// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Config;

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

    private const string OpenIdProtocol = "OpenID";
    private const string SamlProtocol = "SAML";

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

        foreach (var (provider, config) in Providers(live.OidConfigs))
        {
            foreach (var link in config.CanonicalLinks)
            {
                // A link pointing at an account that no longer exists is dangling: exporting it would put a
                // row in the document that nothing could ever be restored to, and a restore that silently
                // dropped it would differ from the document it claimed to apply. Drop it here, once.
                if (resolveUsername(link.Value) is not { } username)
                {
                    continue;
                }

                document.Links.Add(new LinkExportEntry
                {
                    Protocol = OpenIdProtocol,
                    Provider = provider,
                    CanonicalName = link.Key,
                    Username = username,
                    // The issuer binding is keyed by the same canonical name as the link (#186). A link
                    // written before the binding existed has no entry, and null is the honest answer for it
                    // rather than the provider's currently configured issuer, which was never what bound it.
                    Issuer = config.CanonicalLinkIssuers.TryGetValue(link.Key, out var issuer) ? issuer : null,
                });
            }
        }

        foreach (var (provider, config) in Providers(live.SamlConfigs))
        {
            foreach (var link in config.CanonicalLinks)
            {
                if (resolveUsername(link.Value) is not { } username)
                {
                    continue;
                }

                document.Links.Add(new LinkExportEntry
                {
                    Protocol = SamlProtocol,
                    Provider = provider,
                    CanonicalName = link.Key,
                    Username = username,
                });
            }
        }

        return document;
    }

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
