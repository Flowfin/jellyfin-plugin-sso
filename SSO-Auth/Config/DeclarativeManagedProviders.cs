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
    /// <summary>The protocol label a refusal and an audit line name an OpenID provider by.</summary>
    internal const string OpenIdProtocol = "OpenID";

    /// <summary>The protocol label a refusal and an audit line name a SAML provider by.</summary>
    internal const string SamlProtocol = "SAML";

    /// <summary>
    /// The set of an installation that configures no declarative source: nothing is managed, nothing is
    /// frozen, and the config page behaves exactly as it did before this existed.
    /// </summary>
    internal static readonly DeclarativeManagedProviders None = new(
        new Dictionary<string, string>(StringComparer.Ordinal),
        new Dictionary<string, string>(StringComparer.Ordinal),
        new Dictionary<string, string>(StringComparer.Ordinal));

    // Name -> what names the source that owns it. A dictionary rather than a set because a refusal that
    // cannot say WHICH source decided a provider leaves an administrator with nothing to edit: the two
    // sources are a mounted document and the environment, and they are changed in different places.
    private readonly Dictionary<string, string> _oid;
    private readonly Dictionary<string, string> _saml;

    // The provisioning profiles a source DEFINED, held beside the providers rather than in a second type:
    // every rule is the same one - a source decided it, so a write gets the stored value back - and a second
    // holder would be a second place to forget one of the two doors.
    private readonly Dictionary<string, string> _profiles;

    private DeclarativeManagedProviders(
        Dictionary<string, string> oid,
        Dictionary<string, string> saml,
        Dictionary<string, string> profiles)
    {
        _oid = oid;
        _saml = saml;
        _profiles = profiles;
    }

    /// <summary>Gets the OpenID provider names the declarative sources named, ordered so the report is stable.</summary>
    internal IReadOnlyList<string> OidConfigs => _oid.Keys.OrderBy(name => name, StringComparer.Ordinal).ToList();

    /// <summary>Gets the SAML provider names the declarative sources named, ordered so the report is stable.</summary>
    internal IReadOnlyList<string> SamlConfigs => _saml.Keys.OrderBy(name => name, StringComparer.Ordinal).ToList();

    /// <summary>Gets the provisioning profile names the declarative sources defined, ordered so the report is stable.</summary>
    internal IReadOnlyList<string> Profiles => _profiles.Keys.OrderBy(name => name, StringComparer.Ordinal).ToList();

    /// <summary>Gets a value indicating whether nothing at all is declaratively managed.</summary>
    internal bool IsEmpty => _oid.Count == 0 && _saml.Count == 0 && _profiles.Count == 0;

    /// <summary>
    /// Answers a new set carrying everything this one carries plus every provider <paramref name="applied"/>
    /// names. A union rather than a replacement, because the two sources apply in sequence (the file, then
    /// the environment) and each manages what it named - a second source that names nothing must not release
    /// the first source's providers.
    /// </summary>
    /// <param name="applied">The configuration a source just applied; null adds nothing.</param>
    /// <param name="source">
    /// What names the source in a refusal: the document's path, or the environment variable prefix. Where
    /// both sources name one provider the LAST one wins the attribution, because the sources apply in
    /// sequence and the later one is the value the store now holds.
    /// </param>
    /// <returns>The widened set.</returns>
    internal DeclarativeManagedProviders Including(PluginConfiguration? applied, string source)
    {
        if (applied is null)
        {
            return this;
        }

        var oid = new Dictionary<string, string>(_oid, StringComparer.Ordinal);
        var saml = new Dictionary<string, string>(_saml, StringComparer.Ordinal);
        Add(oid, applied.OidConfigs, source);
        Add(saml, applied.SamlConfigs, source);
        var profiles = new Dictionary<string, string>(_profiles, StringComparer.Ordinal);
        AddProfiles(profiles, applied.ProvisioningProfiles, source);
        return new DeclarativeManagedProviders(oid, saml, profiles);
    }

    /// <summary>
    /// Answers what names the source that owns the OpenID provider <paramref name="name"/>, or null where no
    /// declarative source named it and every write door is open on it exactly as it always was.
    /// </summary>
    /// <param name="name">The OpenID provider name a write door was asked to alter or delete.</param>
    /// <returns>The source, or null when the provider is not declaratively managed.</returns>
    internal string? OidSource(string name) => Source(_oid, name);

    /// <summary>
    /// Answers what names the source that owns the SAML provider <paramref name="name"/>, or null where no
    /// declarative source named it.
    /// </summary>
    /// <param name="name">The SAML provider name a write door was asked to alter or delete.</param>
    /// <returns>The source, or null when the provider is not declaratively managed.</returns>
    internal string? SamlSource(string name) => Source(_saml, name);

    /// <summary>
    /// Answers what names the source that defined the provisioning profile <paramref name="name"/>, or null
    /// where no declarative source defined it.
    /// </summary>
    /// <param name="name">The provisioning profile name a write door was asked to alter.</param>
    /// <returns>The source, or null when the profile is not declaratively managed.</returns>
    internal string? ProfileSource(string name) => Source(_profiles, name);

    /// <summary>
    /// Answers every managed provider <paramref name="incoming"/> names, so a whole-document write door
    /// (<c>Config/Import</c>) can refuse before it merges anything and say which providers stopped it.
    /// </summary>
    /// <remarks>
    /// Ordered by protocol then by name, so one document produces the same refusal on two runs and a test can
    /// pin the wording. The comparison is by NAME only: the unit of management is the provider, so a document
    /// naming a managed one is refused whether or not the fields it carries differ from the stored ones.
    /// Comparing values instead would admit a document that happens to agree today through a door the next
    /// edit of that same document walks straight past.
    /// </remarks>
    /// <param name="incoming">The document's configuration payload; null names nothing.</param>
    /// <returns>The (protocol, provider, source) of each managed provider the payload names; empty when it names none.</returns>
    internal IReadOnlyList<(string Protocol, string Provider, string Source)> NamedIn(PluginConfiguration? incoming)
    {
        if (incoming is null || IsEmpty)
        {
            return [];
        }

        var named = new List<(string Protocol, string Provider, string Source)>();
        Collect(_oid, OpenIdProtocol, incoming.OidConfigs, named);
        Collect(_saml, SamlProtocol, incoming.SamlConfigs, named);
        return named;
    }

    /// <summary>
    /// Answers every managed provisioning profile <paramref name="incoming"/> redefines, so the
    /// whole-document write door can refuse before it merges anything.
    /// </summary>
    /// <remarks>
    /// A document carrying no provider at all reaches this. A profile is what a managed provider provisions
    /// a new account THROUGH, so redefining one changes what that provider grants without naming it, and a
    /// refusal that looked only at provider names lets the whole policy in through the door it guards.
    /// Ordered by name, so one document produces the same refusal on two runs and a test can pin the wording.
    /// </remarks>
    /// <param name="incoming">The document's configuration payload; null redefines nothing.</param>
    /// <returns>The (profile, source) of each managed profile the payload redefines; empty when it redefines none.</returns>
    internal IReadOnlyList<(string Profile, string Source)> ProfilesNamedIn(PluginConfiguration? incoming)
    {
        if (incoming?.ProvisioningProfiles is null || _profiles.Count == 0)
        {
            return [];
        }

        var named = new List<(string Profile, string Source)>();
        foreach (var kvp in incoming.ProvisioningProfiles.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            // A null-valued entry carries nothing to import and is skipped by the merge (#538), so refusing
            // on one would refuse a document that could not have altered the managed profile anyway.
            if (kvp.Value is not null && _profiles.TryGetValue(kvp.Key, out var source))
            {
                named.Add((kvp.Key, source));
            }
        }

        return named;
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
    /// <param name="ignoredProfiles">Collects the name of each managed provisioning profile whose posted form differed.</param>
    internal void Reinject(
        PluginConfiguration? incoming,
        PluginConfiguration? live,
        ICollection<(string Protocol, string Provider)> ignored,
        ICollection<string> ignoredProfiles)
    {
        ArgumentNullException.ThrowIfNull(ignored);
        ArgumentNullException.ThrowIfNull(ignoredProfiles);

        if (incoming is null || live is null || IsEmpty)
        {
            return;
        }

        // A posted collection that is NULL rather than empty is the same admin intent as one that dropped
        // every provider, and the freeze has to reach it. Without this the per-protocol loop below returns
        // at its own null check before re-adding anything, so a save shaped this way deletes every managed
        // provider AND reports no ignored write - the one combination this freeze exists to make impossible.
        // Materialized only where a source actually named a provider of that protocol, so an installation
        // managing nothing keeps a null collection exactly as it arrived.
        if (_oid.Count > 0 && incoming.OidConfigs is null)
        {
            incoming.OidConfigs = new SerializableDictionary<string, OidConfig>();
        }

        if (_saml.Count > 0 && incoming.SamlConfigs is null)
        {
            incoming.SamlConfigs = new SerializableDictionary<string, SamlConfig>();
        }

        Reinject(_oid, OpenIdProtocol, incoming.OidConfigs, live.OidConfigs, ignored, (holder, name, provider) => holder.OidConfigs[name] = provider);
        Reinject(_saml, SamlProtocol, incoming.SamlConfigs, live.SamlConfigs, ignored, (holder, name, provider) => holder.SamlConfigs[name] = provider);

        // The same materialization for the profile set, and for the same reason: a posted set that is NULL
        // rather than empty is what an explicit null in the body produces, and the loop below would return
        // at its own null check having re-injected nothing.
        if (_profiles.Count > 0 && incoming.ProvisioningProfiles is null)
        {
            incoming.ProvisioningProfiles = new SerializableDictionary<string, ProvisioningPolicyTemplate>();
        }

        ReinjectProfiles(incoming.ProvisioningProfiles, live.ProvisioningProfiles, ignoredProfiles);
    }

    private static void Add<T>(Dictionary<string, string> names, SerializableDictionary<string, T>? providers, string source)
        where T : ProviderConfigBase
    {
        if (providers is null)
        {
            return;
        }

        foreach (var kvp in providers)
        {
            names[kvp.Key] = source;
        }
    }

    private static void AddProfiles(
        Dictionary<string, string> names,
        SerializableDictionary<string, ProvisioningPolicyTemplate>? profiles,
        string source)
    {
        if (profiles is null)
        {
            return;
        }

        foreach (var kvp in profiles)
        {
            names[kvp.Key] = source;
        }
    }

    // The provider loop written for the one type that is not a provider. A profile carries no write-only
    // field, so unlike a provider there is nothing the JSON boundary withholds - but the comparison still
    // goes through the store's own round-trip on BOTH sides, because XML serialization does not
    // distinguish an absent collection from an empty one and only one of the two sides has been over the
    // wire. Comparing a round-tripped posted set against a live object a loader built would call every
    // untouched profile a changed one, which is the measurement the provider comparison already records.
    private void ReinjectProfiles(
        SerializableDictionary<string, ProvisioningPolicyTemplate>? incoming,
        SerializableDictionary<string, ProvisioningPolicyTemplate>? live,
        ICollection<string> ignored)
    {
        if (incoming is null || live is null)
        {
            return;
        }

        foreach (var name in _profiles.Keys)
        {
            if (!live.TryGetValue(name, out var stored) || stored is null)
            {
                // Defined by a source but no longer in the store: a later write removed it and there is no
                // declarative value left to re-inject. Nothing is invented here; the next start re-applies
                // the source and the profile comes back.
                continue;
            }

            var posted = incoming.TryGetValue(name, out var candidate) ? candidate : null;
            if (posted is null || !string.Equals(PersistedProfileForm(name, posted), PersistedProfileForm(name, stored), StringComparison.Ordinal))
            {
                ignored.Add(name);
            }

            incoming[name] = stored;
        }
    }

    // The persisted form of ONE profile, reached through the configuration model for the same two reasons
    // the provider form is: the persisted form is what the store writes, and putting both sides through the
    // same round-trip is what makes them comparable at all.
    private static string PersistedProfileForm(string name, ProvisioningPolicyTemplate profile)
    {
        var holder = new PluginConfiguration();
        holder.ProvisioningProfiles[name] = profile;
        return holder.DetachedCopy().ToPersistedForm();
    }

    private static string? Source(Dictionary<string, string> managed, string name) =>
        name is not null && managed.TryGetValue(name, out var source) ? source : null;

    private static void Collect<T>(
        Dictionary<string, string> managed,
        string protocol,
        SerializableDictionary<string, T>? incoming,
        List<(string Protocol, string Provider, string Source)> named)
        where T : ProviderConfigBase
    {
        if (incoming is null)
        {
            return;
        }

        foreach (var kvp in incoming.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            // A null-valued entry carries nothing to import and is skipped by the merge (#538), so refusing
            // on one would refuse a document that could not have altered the managed provider anyway.
            if (kvp.Value is not null && managed.TryGetValue(kvp.Key, out var source))
            {
                named.Add((protocol, kvp.Key, source));
            }
        }
    }

    // One loop for both protocols: the maps differ only in the concrete provider type, and every rule below
    // - freeze, re-add, report a difference - is the same on either.
    private static void Reinject<T>(
        Dictionary<string, string> managed,
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

        foreach (var name in managed.Keys)
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
