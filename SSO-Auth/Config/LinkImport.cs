// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>How many links one provider got back from an import, for the audit line (#1129).</summary>
/// <param name="Protocol">The protocol the provider speaks.</param>
/// <param name="Provider">The provider the links were written on.</param>
/// <param name="Links">How many links were written.</param>
internal readonly record struct LinkImportCount(string Protocol, string Provider, int Links);

/// <summary>Restores the portable account-link snapshot onto this instance, rebinding every link to the user id this server holds today (#1129).</summary>
/// <remarks>
/// Every entry is validated before one link is written, a link this instance already holds for a different account
/// is refused, and no new binding is written onto an administrator (#1559). Nothing is created, only rebound. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Server-Migration"/>.
/// </remarks>
internal static class LinkImport
{
    // A refusal names this many entries and then the count of the rest, so a toast stays readable.
    private const int MaxReportedEntries = 10;

    /// <summary>Validates and applies the link document onto <paramref name="live"/>, throwing before any mutation when an entry cannot be restored.</summary>
    /// <param name="live">The live configuration to restore into (mutated in place).</param>
    /// <param name="document">The link document to restore.</param>
    /// <param name="resolveUserId">Resolves a Jellyfin username to the id this instance holds for it, or null when no such account exists.</param>
    /// <param name="isAdministrator">Whether an account holds administrator rights; required rather than defaulted, so a forgotten caller fails loudly (#1559).</param>
    /// <returns>How many links each provider got back, for the audit line. Empty when the document carried none.</returns>
    /// <exception cref="ArgumentException">The document version is unsupported, or an entry names a protocol, provider, canonical name or username this instance cannot restore, or the document contradicts itself or the stored link table.</exception>
    internal static IReadOnlyList<LinkImportCount> Apply(
        PluginConfiguration live,
        LinkExportDocument document,
        Func<string, Guid?> resolveUserId,
        Func<Guid, bool> isAdministrator)
    {
        ArgumentNullException.ThrowIfNull(live);
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(resolveUserId);
        ArgumentNullException.ThrowIfNull(isAdministrator);

        if (document.FormatVersion != LinkExport.FormatVersion)
        {
            throw new ArgumentException(
                $"Unsupported link export format version {document.FormatVersion.ToString(CultureInfo.InvariantCulture)}; this plugin imports version {LinkExport.FormatVersion.ToString(CultureInfo.InvariantCulture)}.");
        }

        // An empty document restores nothing and is applied, and the audited count says so.
        var resolved = Resolve(live, document, resolveUserId, isAdministrator);
        return Write(resolved);
    }

    private static List<ResolvedLink> Resolve(
        PluginConfiguration live,
        LinkExportDocument document,
        Func<string, Guid?> resolveUserId,
        Func<Guid, bool> isAdministrator)
    {
        var refusals = new List<string>();
        var resolved = new List<ResolvedLink>();

        // What the document itself has claimed, so two entries mapping one identity to two accounts are caught.
        var claimed = new Dictionary<(string Protocol, string Provider, string CanonicalName), Guid>();

        // One verdict per (provider, issuer) pair, because this walk runs under the lock every login reads through.
        var issuerVerdicts = new Dictionary<(ProviderConfigBase Config, string Issuer), string?>();

        for (var index = 0; index < document.Links.Count; index++)
        {
            var entry = document.Links[index];
            if (entry is null)
            {
                refusals.Add(Describe(index, null, null, "the entry is empty"));
                continue;
            }

            if (!TryResolveProvider(live, entry.Protocol, entry.Provider, out var protocol, out var config))
            {
                refusals.Add(Describe(index, entry.Protocol, entry.Provider, "no provider of that name is configured for that protocol on this instance"));
                continue;
            }

            if (string.IsNullOrWhiteSpace(entry.CanonicalName))
            {
                refusals.Add(Describe(index, entry.Protocol, entry.Provider, "the entry carries no canonical name, so it names no identity to restore"));
                continue;
            }

            if (string.IsNullOrWhiteSpace(entry.Username))
            {
                refusals.Add(Describe(index, entry.Protocol, entry.Provider, "the entry carries no username, so nothing can be resolved for it"));
                continue;
            }

            // The import never creates an account; a file that could would be a much larger primitive.
            if (resolveUserId(entry.Username) is not { } userId)
            {
                refusals.Add(Describe(index, entry.Protocol, entry.Provider, $"no Jellyfin account is named '{entry.Username.ReplaceLineEndings(string.Empty).Replace('[', '(')}' on this instance"));
                continue;
            }

            var key = (protocol, entry.Provider!, entry.CanonicalName!);
            if (BindingRefusal(entry, config, userId, claimed.TryGetValue(key, out var alreadyClaimed) && alreadyClaimed != userId, isAdministrator, issuerVerdicts) is { } refusal)
            {
                refusals.Add(Describe(index, entry.Protocol, entry.Provider, refusal));
                continue;
            }

            claimed[key] = userId;
            resolved.Add(new ResolvedLink(protocol, entry.Provider!, config, entry.CanonicalName!, userId, entry.Issuer));
        }

        if (refusals.Count > 0)
        {
            throw new ArgumentException(
                "The link import was rejected and nothing was restored. "
                + string.Join("; ", refusals.Take(MaxReportedEntries))
                + (refusals.Count > MaxReportedEntries
                    ? $"; and {(refusals.Count - MaxReportedEntries).ToString(CultureInfo.InvariantCulture)} more entr(y/ies)."
                    : "."));
        }

        return resolved;
    }

    // The rules that keep a crafted file from being a takeover primitive: an identity linked to somebody else, an
    // administrator not already linked (#1559), an issuer already bound (#186) and an issuer the provider cannot issue (#1518).
    private static string? BindingRefusal(
        LinkExportEntry entry,
        ProviderConfigBase config,
        Guid userId,
        bool claimedByAnotherAccount,
        Func<Guid, bool> isAdministrator,
        Dictionary<(ProviderConfigBase Config, string Issuer), string?> issuerVerdicts)
    {
        if (claimedByAnotherAccount)
        {
            return "the document maps this identity to two different accounts";
        }

        if (config.CanonicalLinks.TryGetValue(entry.CanonicalName!, out var held) && held != userId)
        {
            return "this instance already links that identity to a different account; unlink it first";
        }

        // A rebuilt target holds no links, so the rule above never fires there.
        if (isAdministrator(userId) && !config.CanonicalLinks.ContainsKey(entry.CanonicalName!))
        {
            return "that account is an administrator and this instance does not already link that identity to it; pre-provision the link deliberately, then import";
        }

        // An entry carrying no issuer overwrites nothing.
        if (string.IsNullOrWhiteSpace(entry.Issuer) || config is not OidConfig oidConfig)
        {
            return null;
        }

        if (oidConfig.CanonicalLinkIssuers.TryGetValue(entry.CanonicalName!, out var boundTo)
            && !string.Equals(boundTo, entry.Issuer, StringComparison.Ordinal))
        {
            return "this instance already binds that link to a different issuer; unlink it first";
        }

        // Stored, an unissuable issuer would refuse every later login for that link.
        return IssuerRefusal(issuerVerdicts, oidConfig, entry.Issuer!);
    }

    private static string? IssuerRefusal(
        Dictionary<(ProviderConfigBase Config, string Issuer), string?> verdicts,
        OidConfig config,
        string issuer)
    {
        var key = ((ProviderConfigBase)config, issuer);
        if (!verdicts.TryGetValue(key, out var verdict))
        {
            verdict = OidcConfiguredIssuer.Refuse(config, issuer);
            verdicts[key] = verdict;
        }

        return verdict;
    }

    private static List<LinkImportCount> Write(List<ResolvedLink> resolved)
    {
        foreach (var link in resolved)
        {
            link.Config.CanonicalLinks[link.CanonicalName] = link.UserId;

            // The issuer binding travels with the link, or the first login after a migration would stamp whatever answered (#186).
            if (link.Config is OidConfig oid && !string.IsNullOrWhiteSpace(link.Issuer))
            {
                oid.CanonicalLinkIssuers[link.CanonicalName] = link.Issuer!;
            }
        }

        return resolved
            .GroupBy(link => (link.Protocol, link.Provider))
            .Select(group => new LinkImportCount(group.Key.Protocol, group.Key.Provider, group.Count()))
            .OrderBy(count => count.Protocol, StringComparer.Ordinal)
            .ThenBy(count => count.Provider, StringComparer.Ordinal)
            .ToList();
    }

    // The protocol is matched loosely and the provider name exactly, because logins look the name up ordinally.
    private static bool TryResolveProvider(
        PluginConfiguration live,
        string? protocol,
        string? provider,
        out string resolvedProtocol,
        out ProviderConfigBase config)
    {
        resolvedProtocol = string.Empty;
        config = null!;

        if (string.IsNullOrWhiteSpace(provider))
        {
            return false;
        }

        if (string.Equals(protocol, LinkExport.OpenIdProtocol, StringComparison.OrdinalIgnoreCase))
        {
            resolvedProtocol = LinkExport.OpenIdProtocol;
            return TryGetConfig(live.OidConfigs, provider, out config);
        }

        if (string.Equals(protocol, LinkExport.SamlProtocol, StringComparison.OrdinalIgnoreCase))
        {
            resolvedProtocol = LinkExport.SamlProtocol;
            return TryGetConfig(live.SamlConfigs, provider, out config);
        }

        return false;
    }

    // A null-bodied add can store a null provider (#350), which every read treats as absent.
    private static bool TryGetConfig<TConfig>(
        SerializableDictionary<string, TConfig> configs,
        string provider,
        out ProviderConfigBase config)
        where TConfig : ProviderConfigBase
    {
        config = null!;
        if (configs is null || !configs.TryGetValue(provider, out var stored) || stored is null)
        {
            return false;
        }

        config = stored;
        return true;
    }

    // Names the entry by index and never by canonical name, and sanitizes the document's values where they enter the sentence (#1566).
    private static string Describe(int index, string? protocol, string? provider, string reason) =>
        $"entry #{index.ToString(CultureInfo.InvariantCulture)} ({protocol?.ReplaceLineEndings(string.Empty).Replace('[', '(') ?? "no protocol"}/{provider?.ReplaceLineEndings(string.Empty).Replace('[', '(') ?? "no provider"}): {reason}";

    // One validated entry; nothing is written while the list is being built, which is the fail-closed property.
    private readonly record struct ResolvedLink(
        string Protocol,
        string Provider,
        ProviderConfigBase Config,
        string CanonicalName,
        Guid UserId,
        string? Issuer);
}
