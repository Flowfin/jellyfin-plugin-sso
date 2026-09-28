// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>The providers and profiles a declarative source decided on this boot, so a config-page save cannot alter them (#1102).</summary>
/// <remarks>
/// The unit is the provider, because <see cref="ConfigImport"/> merges by provider; the freeze re-injects the live
/// stored value and re-adds a managed provider a save dropped. Held for the life of the process and never persisted. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Config-as-code#what-the-settings-page-shows"/>.
/// </remarks>
internal sealed class DeclarativeManagedProviders
{
    /// <summary>The protocol label a refusal and an audit line name an OpenID provider by.</summary>
    internal const string OpenIdProtocol = "OpenID";

    /// <summary>The protocol label a refusal and an audit line name a SAML provider by.</summary>
    internal const string SamlProtocol = "SAML";

    /// <summary>The set of an installation that configures no declarative source: nothing is managed and nothing is frozen.</summary>
    internal static readonly DeclarativeManagedProviders None = new(
        new Dictionary<string, string>(StringComparer.Ordinal),
        new Dictionary<string, string>(StringComparer.Ordinal),
        new Dictionary<string, string>(StringComparer.Ordinal));

    // Name to the source that owns it, so a refusal can say which of the two sources to edit.
    private readonly Dictionary<string, string> _oid;
    private readonly Dictionary<string, string> _saml;
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

    /// <summary>Answers a new set carrying everything this one carries plus every provider and profile <paramref name="applied"/> names.</summary>
    /// <remarks>A union, because the two sources apply in sequence and a later source that names nothing must not release the earlier one's providers.</remarks>
    /// <param name="applied">The configuration a source just applied; null adds nothing.</param>
    /// <param name="source">What names the source in a refusal; where both sources name one provider the last one wins the attribution.</param>
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

    /// <summary>Answers what names the source that owns the OpenID provider <paramref name="name"/>, or null where none does.</summary>
    /// <param name="name">The OpenID provider name a write door was asked to alter or delete.</param>
    /// <returns>The source, or null when the provider is not declaratively managed.</returns>
    internal string? OidSource(string name) => Source(_oid, name);

    /// <summary>Answers what names the source that owns the SAML provider <paramref name="name"/>, or null where none does.</summary>
    /// <param name="name">The SAML provider name a write door was asked to alter or delete.</param>
    /// <returns>The source, or null when the provider is not declaratively managed.</returns>
    internal string? SamlSource(string name) => Source(_saml, name);

    /// <summary>Answers what names the source that defined the provisioning profile <paramref name="name"/>, or null where none does.</summary>
    /// <param name="name">The provisioning profile name a write door was asked to alter.</param>
    /// <returns>The source, or null when the profile is not declaratively managed.</returns>
    internal string? ProfileSource(string name) => Source(_profiles, name);

    /// <summary>Answers every managed provider <paramref name="incoming"/> names, so a whole-document write door can refuse before it merges.</summary>
    /// <remarks>By name only and in a stable order: a document naming a managed provider is refused whether or not its fields differ.</remarks>
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

    /// <summary>Answers every managed provisioning profile <paramref name="incoming"/> redefines, so the whole-document write door can refuse before it merges.</summary>
    /// <remarks>Redefining a profile changes what a managed provider grants without naming the provider, so a refusal on provider names alone would miss it.</remarks>
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
            // A null-valued entry is skipped by the merge (#538), so it could not have altered the managed profile.
            if (kvp.Value is not null && _profiles.TryGetValue(kvp.Key, out var source))
            {
                named.Add((kvp.Key, source));
            }
        }

        return named;
    }

    /// <summary>Freezes every managed provider and profile in <paramref name="incoming"/> against its stored value, and reports the ones whose posted form differed.</summary>
    /// <remarks>Runs after <see cref="ServerManagedFields.Preserve(PluginConfiguration, PluginConfiguration)"/>, so a save that only left the secrets blank compares equal.</remarks>
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

        // A null collection is a save that dropped every provider, and the loops below would return before re-adding any.
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

    // The provider loop for the one managed type that is not a provider; the same round-trip on both sides, for the same reason.
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
                // No declarative value is left to re-inject; the next start re-applies the source.
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
            // A null-valued entry is skipped by the merge (#538), so it could not have altered the managed provider.
            if (kvp.Value is not null && managed.TryGetValue(kvp.Key, out var source))
            {
                named.Add((protocol, kvp.Key, source));
            }
        }
    }

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
                // No declarative value is left to re-inject; the next start re-applies the source.
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

    // The persisted form sees the secrets JSON withholds, and the round-trip on both sides is what makes them comparable (#1003).
    private static string PersistedForm<T>(string name, T provider, Action<PluginConfiguration, string, T> place)
        where T : ProviderConfigBase
    {
        var holder = new PluginConfiguration();
        place(holder, name, provider);
        return holder.DetachedCopy().ToPersistedForm();
    }
}
