// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// How many links one provider got back from an import (#1129), for the audit line. The protocol is part
/// of the identity because the two protocols keep separate provider namespaces.
/// </summary>
/// <param name="Protocol">The protocol the provider speaks.</param>
/// <param name="Provider">The provider the links were written on.</param>
/// <param name="Links">How many links were written.</param>
internal readonly record struct LinkImportCount(string Protocol, string Provider, int Links);

/// <summary>
/// Restores the portable account-link snapshot (<see cref="LinkExportDocument"/>) onto this instance
/// (#1129), rebinding every link to the user id this server holds TODAY. The export keys on the username
/// because a rebuilt user database issues new ids; this is the half that resolves those usernames back to
/// ids, and it is the half with the security weight, because writing a link is granting future login
/// capability to an identity-provider subject.
/// </summary>
/// <remarks>
/// Two properties make it safe to hand an administrator a file and let them apply it.
/// <list type="bullet">
/// <item>Validate first, mutate second. Every entry is checked before a single link is written, and the
/// first failure rejects the WHOLE document. Called inside <c>MutateConfiguration</c>, which persists only
/// when the mutation returns without throwing AND rolls the change back out of the live configuration when
/// the write itself fails (#1521), so a rebuilt server either gets its complete link table back or is left
/// exactly as it was. A half-applied link table is the worst outcome available here: it looks restored and
/// silently is not.</item>
/// <item>No silent repoint. A canonical name this instance already links to a DIFFERENT account is
/// refused rather than overwritten, because otherwise a crafted backup file is a primitive for remapping
/// an identity-provider subject onto an administrator's account. An administrator unlinks first and then
/// re-imports, which is one deliberate act rather than a side effect of a restore.</item>
/// </list>
/// The import never creates a Jellyfin account, never creates a provider, and never invents a user id. It
/// only rebinds what both sides already hold, which is what keeps a backup file from being a way to bring
/// new principals into existence.
/// </remarks>
internal static class LinkImport
{
    // How many offending entries a refusal names before it stops. A document can carry thousands of
    // links, and a message enumerating every bad one is unreadable in a dashboard toast and pointless in
    // a log line; the count that follows says how many more there were.
    private const int MaxReportedEntries = 10;

    // How much of a provider-authored issuer a refusal reproduces. See Bound below for why one is needed.
    private const int MaxReportedIssuerChars = 256;

    /// <summary>
    /// Validates and applies the link document onto <paramref name="live"/>. Throws before any mutation
    /// when the document is unsupported or any entry is unrestorable, so the caller's
    /// <c>MutateConfiguration</c> persists nothing.
    /// </summary>
    /// <param name="live">The live configuration to restore into (mutated in place).</param>
    /// <param name="document">The link document to restore.</param>
    /// <param name="resolveUserId">
    /// Resolves a Jellyfin username to the id this instance holds for it, or null when no such account
    /// exists. The controller supplies one backed by <c>IUserManager</c>.
    /// </param>
    /// <param name="configuredIssuers">
    /// What each OpenID provider named in the document is configured to issue, keyed by provider name
    /// (#1518). An entry carrying an issuer is restorable only when the fact for its provider names an
    /// issuer equal to it; a fact naming a failed read, and a provider absent from the map, both refuse the
    /// entry. The caller reads these from the discovery documents before taking the configuration lock.
    /// Entries carrying no issuer never consult it, so a document written before the issuer binding existed
    /// restores with the identity provider unreachable.
    /// </param>
    /// <returns>How many links each provider got back, for the audit line. Empty when the document carried none.</returns>
    /// <exception cref="ArgumentException">The document version is unsupported, or an entry names a protocol, provider, canonical name or username this instance cannot restore, or the document contradicts itself, the stored link table, or what the provider is configured to issue.</exception>
    internal static IReadOnlyList<LinkImportCount> Apply(
        PluginConfiguration live,
        LinkExportDocument document,
        Func<string, Guid?> resolveUserId,
        IReadOnlyDictionary<string, LinkImportIssuerFact> configuredIssuers)
    {
        ArgumentNullException.ThrowIfNull(live);
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(resolveUserId);
        ArgumentNullException.ThrowIfNull(configuredIssuers);

        if (document.FormatVersion != LinkExport.FormatVersion)
        {
            throw new ArgumentException(
                $"Unsupported link export format version {document.FormatVersion.ToString(CultureInfo.InvariantCulture)}; this plugin imports version {LinkExport.FormatVersion.ToString(CultureInfo.InvariantCulture)}.");
        }

        // An empty document is applied rather than refused, and it restores nothing. The rejection rules
        // below are about entries that cannot be restored; a document with no entries contradicts nothing
        // and leaves nothing half-done, and the count the caller audits says plainly that zero links came
        // back - which an operator who applied the wrong file reads immediately.
        var resolved = Resolve(live, document, resolveUserId, configuredIssuers);
        return Write(resolved);
    }

    private static List<ResolvedLink> Resolve(
        PluginConfiguration live,
        LinkExportDocument document,
        Func<string, Guid?> resolveUserId,
        IReadOnlyDictionary<string, LinkImportIssuerFact> configuredIssuers)
    {
        var refusals = new List<string>();
        var resolved = new List<ResolvedLink>();

        // What this document itself has already claimed, so two entries mapping ONE identity to two
        // different accounts are caught. Without it the document's own order would decide which of the
        // two won, silently, and a restore would be non-deterministic in exactly the case that matters.
        var claimed = new Dictionary<(string Protocol, string Provider, string CanonicalName), Guid>();

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

            // The import never creates an account. A username this server does not hold is refused rather
            // than provisioned, because a backup file that could bring principals into existence is a
            // different and much larger primitive than one that restores links between things that exist.
            if (resolveUserId(entry.Username) is not { } userId)
            {
                refusals.Add(Describe(index, entry.Protocol, entry.Provider, $"no Jellyfin account is named '{entry.Username}' on this instance"));
                continue;
            }

            var key = (protocol, entry.Provider!, entry.CanonicalName!);
            if (claimed.TryGetValue(key, out var alreadyClaimed) && alreadyClaimed != userId)
            {
                refusals.Add(Describe(index, entry.Protocol, entry.Provider, "the document maps this identity to two different accounts"));
                continue;
            }

            // The rule that makes a hostile backup file useless as a takeover primitive: an identity this
            // instance already links to somebody ELSE is refused, and the stored link stays as it is. A
            // restore onto a server that still holds the same mapping is not a repoint and stays a
            // success, so re-running an import after a partial migration is safe.
            if (config.CanonicalLinks.TryGetValue(entry.CanonicalName!, out var held) && held != userId)
            {
                refusals.Add(Describe(index, entry.Protocol, entry.Provider, "this instance already links that identity to a different account; unlink it first"));
                continue;
            }

            // The same rule one level down, for the issuer binding (#186). A document naming a DIFFERENT
            // issuer for a link this instance already holds is a contradiction between the backup and the
            // server, and quietly overwriting the stored binding would rewrite a security decision as a
            // side effect of a restore. Its immediate consequence is only fail-closed - that link's next
            // login is refused for a mismatch - but a restore that silently changes what a link is bound
            // to is the same shape as the repoint above, and it is refused for the same reason. An entry
            // carrying no issuer overwrites nothing, so a document from before the binding existed
            // restores against a bound link without relaxing it.
            if (!string.IsNullOrWhiteSpace(entry.Issuer)
                && config is OidConfig existing
                && existing.CanonicalLinkIssuers.TryGetValue(entry.CanonicalName!, out var boundTo)
                && !string.Equals(boundTo, entry.Issuer, StringComparison.Ordinal))
            {
                refusals.Add(Describe(index, entry.Protocol, entry.Provider, "this instance already binds that link to a different issuer; unlink it first"));
                continue;
            }

            // #1518. THE GUARD THIS HELPER GAINED, and it is the one the rules above cannot stand in for:
            // every one of them compares the file against something this instance ALREADY HOLDS, and a
            // rebuilt migration target holds nothing. On that server - the one the export exists for - the
            // file's issuer was written verbatim with nothing comparing it to anything, and a stored issuer
            // that does not match what the provider actually issues is terminal rather than degrading:
            // CanonicalLinkService classifies it Mismatch and refuses EVERY login for that link, with no
            // path back through a login. So the comparison is made here, against what the provider is
            // configured to issue, at the one moment an operator is still standing at the machine.
            //
            // FAIL CLOSED IN BOTH DIRECTIONS. A mismatch is refused, and so is an issuer that could not be
            // compared at all - an unreadable discovery document, or a provider the caller looked nothing up
            // for. Writing an unverified issuer IS the defect, so "could not check" and "checked and it is
            // wrong" get the same answer, and the message says which of the two happened. An entry carrying
            // no issuer reaches none of this, so a document from before the binding existed still restores
            // with the identity provider down.
            //
            // WHAT THE COMPARISON IS BETWEEN, AND WHY DoNotValidateIssuerName TAKES AN ENTRY OUT OF IT. The
            // stored binding is the id_token's `iss`; the fact is the discovery document's `issuer`. With
            // ValidateIssuerName on - the default - the login has already required those two to be equal
            // before a binding could ever be stamped, so comparing against the discovery issuer asks exactly
            // "has this provider's issuer changed since the backup". The escape hatch turns that requirement
            // off, and it exists for providers whose two values legitimately differ FOREVER: a templated,
            // multi-tenant discovery issuer against a concrete per-tenant id_token issuer. OidcResponseIssuer
            // accepts both anchors for the same reason and says so. On such a provider there is no comparand
            // here at all, and refusing would turn a supported deployment's whole restore into a refusal
            // whose printed remedy is impossible. Those entries therefore restore as they did before this
            // guard existed, which is a DISCLOSED GAP rather than a check that quietly passed: the operator
            // who set that flag has already declared this provider's issuer unverifiable against its
            // discovery document, and docs/SERVER-MIGRATION.md says the same in the operator's own words.
            if (config is OidConfig target && !target.DoNotValidateIssuerName && !string.IsNullOrWhiteSpace(entry.Issuer))
            {
                var fact = configuredIssuers.TryGetValue(entry.Provider!, out var known) ? known : default;
                if (!string.IsNullOrWhiteSpace(fact.Unreadable))
                {
                    refusals.Add(Describe(index, entry.Protocol, entry.Provider, $"the file binds that link to issuer '{entry.Issuer}', and what this provider issues could not be read to compare it against: {fact.Unreadable}"));
                    continue;
                }

                if (string.IsNullOrWhiteSpace(fact.Issuer))
                {
                    refusals.Add(Describe(index, entry.Protocol, entry.Provider, $"the file binds that link to issuer '{entry.Issuer}', and nothing was read for this provider to compare it against"));
                    continue;
                }

                // The fact was read before the configuration lock, because it is a network round trip. A
                // provider re-pointed in that window is a DIFFERENT identity provider - ServerManagedFields
                // clears the link and issuer maps on exactly that change - so a fact read from the old
                // endpoint must not be allowed to write the old issuers back in under the lock. That would
                // re-create this issue's own mass lockout through the change meant to close it.
                if (!string.Equals(fact.ReadFromEndpoint, target.OidEndpoint?.Trim(), StringComparison.Ordinal))
                {
                    refusals.Add(Describe(index, entry.Protocol, entry.Provider, "this provider's OpenID endpoint changed while the import was being prepared, so what it issues was read from an endpoint it no longer uses; import again"));
                    continue;
                }

                if (!string.Equals(fact.Issuer, entry.Issuer, StringComparison.Ordinal))
                {
                    refusals.Add(Describe(index, entry.Protocol, entry.Provider, $"the file binds that link to issuer '{entry.Issuer}', but this provider is configured to issue '{Bound(fact.Issuer)}'; re-point the provider, or re-key the links deliberately, before importing"));
                    continue;
                }
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

    private static List<LinkImportCount> Write(List<ResolvedLink> resolved)
    {
        foreach (var link in resolved)
        {
            link.Config.CanonicalLinks[link.CanonicalName] = link.UserId;

            // The issuer binding travels with the link (#186). Restoring the link without it would leave
            // the restored account on trust-on-first-use, so the first login after a migration would
            // stamp whatever issuer answered - which is precisely the repoint the binding exists to
            // refuse. SAML carries no binding, so an issuer on a SAML entry is dropped rather than
            // written into a map that protocol does not have.
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

    // The issuer read off a discovery document is NOT the plugin's string. Under DoNotValidateIssuerName it
    // need not equal the authority, and the response body it came from is bounded in megabytes rather than
    // characters, so a provider could otherwise put as much text into a refusal as it liked. The same reason
    // OidcDiscoveryReader bounds the library error it logs, and the same shape of bound.
    private static string Bound(string? issuer) =>
        issuer is { Length: > MaxReportedIssuerChars }
            ? string.Concat(issuer.AsSpan(0, MaxReportedIssuerChars), "...")
            : issuer ?? string.Empty;

    // The protocol name is matched case-insensitively while the provider name is matched exactly, and the
    // difference is deliberate. The protocol is a two-value vocabulary this plugin writes itself, so
    // accepting "openid" costs nothing and refuses nothing real; the provider name is a key in a map the
    // rest of the plugin looks up ordinally, so matching it loosely here would restore links onto a
    // provider no login would ever resolve.
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

    // A provider stored with a null config object is reachable through a null-bodied add (#350). It is
    // treated as absent here, exactly as every read of these maps treats it, rather than dereferenced.
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

    // A refusal names WHICH entry and WHY, and never the canonical name. The subject is the one field in
    // the document that identifies a real person at the identity provider, and the audit trail already
    // carries no raw subject value (T-I1); echoing it into an HTTP error body and from there into
    // whatever logs that body would widen where it travels for no gain an operator could use. The index
    // into the document they are holding is what lets them find the entry.
    private static string Describe(int index, string? protocol, string? provider, string reason) =>
        $"entry #{index.ToString(CultureInfo.InvariantCulture)} ({protocol ?? "no protocol"}/{provider ?? "no provider"}): {reason}";

    // One validated entry: the map it belongs in, and everything needed to write it. Nothing is written
    // while this list is being built, which is the whole of the fail-closed property - the first refusal
    // throws out of Apply with the live configuration untouched.
    private readonly record struct ResolvedLink(
        string Protocol,
        string Provider,
        ProviderConfigBase Config,
        string CanonicalName,
        Guid UserId,
        string? Issuer);
}
