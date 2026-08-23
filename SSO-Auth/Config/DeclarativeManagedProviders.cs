// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// The providers a declarative source decided on this boot (#1102), so a config-page save cannot alter one
/// and an admin can be told which ones those are. Recorded by
/// <see cref="DeclarativeProviderConfig.ApplyDocument"/> once a document has been accepted, held on
/// <see cref="ProviderConfigStore"/> for the life of the process, and never persisted: the sources are read
/// while the plugin is being constructed, so the set is re-derived on every start and a mount that is taken
/// away stops managing anything at the next one.
/// </summary>
/// <remarks>
/// <para>
/// THE UNIT IS THE PROVIDER, NOT THE FIELD, and that is a measurement rather than a simplification.
/// <see cref="ConfigImport"/> merges by provider: it replaces the whole stored provider object with the one
/// the document carries and re-injects only the <see cref="ServerManagedFields"/>. So a field the document
/// does not name comes back at its deserialized default at the next start, not at whatever an admin last
/// typed. Every field of a named provider is therefore decided by the source, and a surface that greyed out
/// three fields and left the rest editable would tell the admin the opposite of what happens.
/// </para>
/// <para>
/// What the freeze re-injects is the LIVE stored provider, not a retained copy of the document. The document
/// was applied to the store during construction, so the stored provider IS the declarative one, and reaching
/// the declarative value through the store means no resolved secret has to be held in memory for the life of
/// the process to answer a save. It also keeps the runtime half of a managed provider - the canonical links,
/// the deadlines, the login stamps a login writes after the apply - which a retained document would have
/// thrown away.
/// </para>
/// <para>
/// A managed provider missing from an incoming save is re-added rather than deleted. Deleting one would
/// break every login against it until the next start, at which point the source would put it back, so the
/// deletion is never a durable intent; it is a page saved against a set the file owns.
/// </para>
/// </remarks>
internal sealed class DeclarativeManagedProviders
{
    /// <summary>
    /// The set of an installation that configures no declarative source: nothing is managed, nothing is
    /// frozen, and the config page behaves exactly as it did before this existed.
    /// </summary>
    internal static readonly DeclarativeManagedProviders None = new(
        new HashSet<string>(StringComparer.Ordinal),
        new HashSet<string>(StringComparer.Ordinal));

    private readonly HashSet<string> _oid;
    private readonly HashSet<string> _saml;

    private DeclarativeManagedProviders(HashSet<string> oid, HashSet<string> saml)
    {
        _oid = oid;
        _saml = saml;
    }

    /// <summary>Gets the OpenID provider names the declarative sources named, ordered so the report is stable.</summary>
    internal IReadOnlyList<string> OidConfigs => _oid.OrderBy(name => name, StringComparer.Ordinal).ToList();

    /// <summary>Gets the SAML provider names the declarative sources named, ordered so the report is stable.</summary>
    internal IReadOnlyList<string> SamlConfigs => _saml.OrderBy(name => name, StringComparer.Ordinal).ToList();

    /// <summary>Gets a value indicating whether no provider is declaratively managed.</summary>
    internal bool IsEmpty => _oid.Count == 0 && _saml.Count == 0;

    /// <summary>
    /// Answers a new set carrying everything this one carries plus every provider <paramref name="applied"/>
    /// names. A union rather than a replacement, because the two sources apply in sequence (the file, then
    /// the environment) and each manages what it named - a second source that names nothing must not release
    /// the first source's providers.
    /// </summary>
    /// <param name="applied">The configuration a source just applied; null adds nothing.</param>
    /// <returns>The widened set.</returns>
    internal DeclarativeManagedProviders Including(PluginConfiguration? applied)
    {
        if (applied is null)
        {
            return this;
        }

        var oid = new HashSet<string>(_oid, StringComparer.Ordinal);
        var saml = new HashSet<string>(_saml, StringComparer.Ordinal);
        Add(oid, applied.OidConfigs);
        Add(saml, applied.SamlConfigs);
        return new DeclarativeManagedProviders(oid, saml);
    }

    /// <summary>
    /// Freezes every managed provider in <paramref name="incoming"/> against its stored value, and reports
    /// the ones whose posted form differed so the caller can audit the ignored write.
    /// </summary>
    /// <remarks>
    /// Runs AFTER <see cref="ServerManagedFields.Preserve(PluginConfiguration, PluginConfiguration)"/> on
    /// purpose, and the comparison is the reason. A config-page save arrives with the write-only secrets
    /// blank and the link maps absent, so comparing before that re-injection would call every save a changed
    /// provider and audit one on every unrelated settings change. Compared after it, a provider the admin did
    /// not touch is byte-identical to the stored one and nothing is reported.
    /// </remarks>
    /// <param name="incoming">The configuration about to be persisted.</param>
    /// <param name="live">The current live configuration, which holds the declarative values.</param>
    /// <param name="ignored">Collects (protocol, provider) for each managed provider whose posted form differed.</param>
    internal void Reinject(PluginConfiguration? incoming, PluginConfiguration? live, ICollection<(string Protocol, string Provider)> ignored)
    {
        ArgumentNullException.ThrowIfNull(ignored);

        if (incoming is null || live is null || IsEmpty)
        {
            return;
        }

        Reinject(_oid, "OpenID", incoming.OidConfigs, live.OidConfigs, ignored, (holder, name, provider) => holder.OidConfigs[name] = provider);
        Reinject(_saml, "SAML", incoming.SamlConfigs, live.SamlConfigs, ignored, (holder, name, provider) => holder.SamlConfigs[name] = provider);
    }

    private static void Add<T>(HashSet<string> names, SerializableDictionary<string, T>? providers)
        where T : ProviderConfigBase
    {
        if (providers is null)
        {
            return;
        }

        foreach (var kvp in providers)
        {
            names.Add(kvp.Key);
        }
    }

    // One loop for both protocols: the maps differ only in the concrete provider type, and every rule below
    // - freeze, re-add, report a difference - is the same on either.
    private static void Reinject<T>(
        HashSet<string> managed,
        string protocol,
        SerializableDictionary<string, T>? incoming,
        SerializableDictionary<string, T>? live,
        ICollection<(string Protocol, string Provider)> ignored,
        Action<PluginConfiguration, string, T> place)
        where T : ProviderConfigBase
    {
        if (incoming is null || live is null)
        {
            return;
        }

        foreach (var name in managed)
        {
            if (!live.TryGetValue(name, out var stored) || stored is null)
            {
                // Named by a source but no longer in the store: a later write removed it, and there is no
                // declarative value left to re-inject. Nothing is invented here; the next start re-applies
                // the source and the provider comes back.
                continue;
            }

            var posted = incoming.TryGetValue(name, out var candidate) ? candidate : null;
            if (posted is null || !string.Equals(PersistedForm(name, posted, place), PersistedForm(name, stored, place), StringComparison.Ordinal))
            {
                ignored.Add((protocol, name));
            }

            incoming[name] = stored;
        }
    }

    // The persisted form of ONE provider, which is what "did this save change it" has to be asked against:
    // the persisted form is what the store WRITES, so it sees every field that survives a restart - including
    // the secrets the JSON boundary withholds. A JSON comparison would call a rotated client secret an
    // unchanged provider and let the rotation through the freeze in silence.
    //
    // The provider is carried in a throwaway configuration and put through the store's OWN round-trip rather
    // than serialized here. Two reasons, and the second is the one that would be missed. Only the SAML module
    // may hold an XML parse seam (#1003), and the configuration model is the one allowlisted exception, so
    // reaching the form through it adds no second stack. And the round-trip is what makes the two sides
    // comparable at all: XML serialization does not distinguish an absent collection from an empty one, so an
    // object that has been through one (the posted configuration, which arrived over the wire) and one that
    // has not (the live object a loader built) emit different bytes for identical content. Measured rather
    // than supposed - a version of this that serialized once called every untouched provider a changed one.
    private static string PersistedForm<T>(string name, T provider, Action<PluginConfiguration, string, T> place)
        where T : ProviderConfigBase
    {
        var holder = new PluginConfiguration();
        place(holder, name, provider);
        return holder.DetachedCopy().ToPersistedForm();
    }
}
