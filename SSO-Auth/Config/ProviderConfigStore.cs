// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using MediaBrowser.Model.Plugins;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Owns every read and write of the plugin configuration behind one lock (#318): locked reads and
/// atomic read-modify-writes of the live configuration, plus the validated save pipeline
/// (validate, preserve server-managed fields, persist, audit) for a replacement configuration such
/// as an admin config-page save. Extracted from <see cref="SSOPlugin"/>, which keeps only a thin
/// delegating facade; persistence itself stays with the plugin base class and is reached through
/// the injected persist delegate.
/// </summary>
internal sealed class ProviderConfigStore
{
    // Serializes every read-modify-write of the plugin configuration so concurrent mutations
    // (notably first-logins each writing a canonical link) cannot lose one another's updates.
    // Static on purpose: it keeps the process-wide serialization of the old SSOPlugin lock, so two
    // plugin instances (tests construct several; production has one) can never interleave writes.
    // It becomes an instance field once the store is a DI singleton (#318 step 9).
    private static readonly System.Threading.Lock Sync = new();

    private readonly Func<PluginConfiguration> _live;
    private readonly Action<BasePluginConfiguration> _persist;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ProviderConfigStore"/> class.
    /// </summary>
    /// <param name="live">Returns the live plugin configuration (the plugin's lazily loaded <c>Configuration</c>).</param>
    /// <param name="persist">Persists a configuration through the plugin base class (<c>base.UpdateConfiguration</c>).</param>
    /// <param name="logger">The logger (used to audit insecure-option saves, #140).</param>
    internal ProviderConfigStore(Func<PluginConfiguration> live, Action<BasePluginConfiguration> persist, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(live);
        ArgumentNullException.ThrowIfNull(persist);
        _live = live;
        _persist = persist;
        _logger = logger;
    }

    /// <summary>
    /// Gets the providers a declarative source decided on this boot (#1102). Empty on an installation that
    /// configures none, which is every installation built before those sources existed.
    /// </summary>
    internal DeclarativeManagedProviders ManagedProviders { get; private set; } = DeclarativeManagedProviders.None;

    /// <summary>
    /// Records that a declarative source has applied <paramref name="applied"/>, so every provider it names is
    /// frozen against the config-page save from here on (#1102). Called by the loaders once a document has
    /// been accepted; a rejected document records nothing, because it changed nothing.
    /// </summary>
    /// <param name="applied">The configuration the source applied.</param>
    /// <param name="source">
    /// What names the source in a refusal an administrator reads: the document's path, or the environment
    /// variable prefix. Carried per provider so a write door that refuses can say where to make the change
    /// instead, which is the difference between a refusal and a dead end (#1415).
    /// </param>
    internal void RecordDeclarativelyManaged(PluginConfiguration? applied, string source)
    {
        lock (Sync)
        {
            ManagedProviders = ManagedProviders.Including(applied, source);
        }
    }

    /// <summary>
    /// Reads a value from the live configuration under the same lock as <see cref="Mutate(Action{PluginConfiguration})"/>,
    /// so a read cannot tear against a concurrent write of a (non-thread-safe) configuration collection.
    /// </summary>
    /// <typeparam name="T">The value read.</typeparam>
    /// <param name="read">The read to perform against the live configuration.</param>
    /// <returns>The value returned by <paramref name="read"/>.</returns>
    public T Read<T>(Func<PluginConfiguration, T> read)
    {
        ArgumentNullException.ThrowIfNull(read);
        lock (Sync)
        {
            return read(_live());
        }
    }

    /// <summary>
    /// Applies a mutation under a single lock and persists it, so a read-modify-write cannot race
    /// another and lose its update, and so a persist that fails leaves nothing behind (#1521).
    /// </summary>
    /// <param name="mutate">The mutation to apply.</param>
    public void Mutate(Action<PluginConfiguration> mutate)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        Mutate<object?>(configuration =>
        {
            mutate(configuration);
            return null;
        });
    }

    /// <summary>
    /// Applies a mutation that returns a result (e.g. whether a removal changed anything) under the
    /// same single lock and persists it, so the read-modify-write and the result observation are one
    /// atomic operation.
    /// </summary>
    /// <typeparam name="T">The value the mutation returns.</typeparam>
    /// <param name="mutate">The mutation to apply.</param>
    /// <returns>The value returned by <paramref name="mutate"/>.</returns>
    public T Mutate<T>(Func<PluginConfiguration, T> mutate)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        lock (Sync)
        {
            var live = _live();

            // Taken BEFORE the mutation and thrown away on the way out of a successful write: it exists
            // only so that a persist which throws can be undone (#1521). A failed persist used to leave
            // the live configuration carrying every change while nothing reached the XML, so logins
            // behaved as though the import had succeeded until the process restarted and the next
            // unrelated save committed the changes silently, at a moment nobody connects to the import.
            // A full disk and a read-only volume are exactly what a freshly built migration target hits.
            //
            // The persisted FORM rather than a detached copy, because this path runs on the login side:
            // the string is one serialization and the parse back is paid only by the failure that needs
            // it. It is not free and the number is not small, so it is stated rather than implied.
            // Measured 2026-09-05, Release net9.0, 200 iterations, one OpenID provider carrying a link,
            // an issuer stamp and a last-login stamp per subject: 0.127 ms at no links, 1.576 ms at 100,
            // 6.092 ms at 1000, 33.555 ms at 5000 - against 0.480 / 5.152 / 17.481 / 88.919 ms for a
            // detached copy. It is paid inside this process-wide lock, on top of the serialization the
            // write itself does, and #1532 holds whether a large installation needs a cheaper undo.
            var snapshot = Snapshot(live);

            try
            {
                var result = mutate(live);

                // Persists directly instead of routing through Save: the object being written IS the live
                // one, so Save's fresh-config pipeline (validate/preserve/audit) would be skipped by its
                // identity guard anyway - same observable behavior, without the reentrant detour.
                _persist(live);
                return result;
            }
            catch
            {
                // The mutation is inside the try as well as the write, so a lambda that throws half way
                // through leaves nothing behind either - which is what the import endpoints promise
                // their callers and could not previously deliver for a merge that failed after its
                // first write.
                Restore(live, snapshot);
                throw;
            }
        }
    }

    /// <summary>
    /// Persists a replacement configuration, re-injecting server-managed fields from the live
    /// configuration first (#157). The admin settings page saves through this path (Jellyfin core's
    /// UpdatePluginConfiguration) with a snapshot taken at page load, so a canonical link created by a
    /// login since then would be absent from the posted config; re-injecting the live links stops the
    /// save from wiping them. Takes the same lock as <see cref="Mutate(Action{PluginConfiguration})"/>
    /// and skips the copy when the incoming object is the live one.
    /// </summary>
    /// <param name="configuration">The configuration to persist.</param>
    public void Save(BasePluginConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        List<(string Protocol, string Provider, IReadOnlyList<string> Options)>? insecureToAudit = null;
        var declarativeWritesIgnored = new List<(string Protocol, string Provider)>();
        var declarativeProfileWritesIgnored = new List<string>();
        lock (Sync)
        {
            // The same undo as Mutate, and it is not redundant even though the posted object is a
            // different one (#1521): the pipeline below hands the LIVE object's server-managed maps and
            // declaratively managed providers to the posted one, and the persist delegate then encrypts
            // the secrets inside those shared objects in place. A write that throws afterwards would
            // otherwise leave the live configuration carrying envelopes the file does not have.
            var snapshot = Snapshot(_live());

            try
            {
                Persist(configuration, insecure => insecureToAudit = insecure, declarativeWritesIgnored, declarativeProfileWritesIgnored);
            }
            catch
            {
                Restore(_live(), snapshot);
                throw;
            }
        }

        // Outside the lock, and after the save is durably persisted: a slow or misbehaving logging
        // provider can neither block config reads/writes nor turn a completed save into a failure.
        if (insecureToAudit != null && _logger != null)
        {
            foreach (var (protocol, provider, options) in insecureToAudit)
            {
                SsoAudit.InsecureOptionsEnabled(_logger, protocol, provider, options);
            }
        }

        if (_logger != null)
        {
            foreach (var (protocol, provider) in declarativeWritesIgnored)
            {
                SsoAudit.DeclarativeWriteIgnored(_logger, protocol, provider);
            }

            foreach (var profile in declarativeProfileWritesIgnored)
            {
                SsoAudit.DeclarativeProfileWriteIgnored(_logger, profile);
            }
        }
    }

    // The body of Save, under the caller's lock and inside its rollback: validate a replacement config,
    // re-inject what the server owns, and write. Split out so the snapshot/restore around it reads as one
    // thing rather than as a try wrapped around forty lines.
    private void Persist(
        BasePluginConfiguration configuration,
        Action<List<(string Protocol, string Provider, IReadOnlyList<string> Options)>> collectInsecure,
        List<(string Protocol, string Provider)> declarativeWritesIgnored,
        List<string> declarativeProfileWritesIgnored)
    {
        if (configuration is PluginConfiguration incoming && !ReferenceEquals(incoming, _live()))
        {
            // Reject the save fail-closed before anything is persisted if a base-URL override is
            // malformed (#139), a SAML signing certificate is not loadable (#206), or a NEWLY
            // registered provider name contains control, URI-reserved, or backslash characters
            // (#336/#360 - the live config is passed so names it already holds stay saveable). This validates the config-page save
            // (a fresh incoming config); the OID/SAML Add endpoints write through Mutate (the live
            // object, so this branch is skipped) and validate their own incoming provider at the
            // controller via the Reject* guards. Login-path writes (canonical links) also reuse the
            // live object and are intentionally not revalidated here, so a slow/bad override can
            // never throw on the login path.
            ProviderConfigValidator.Validate(incoming, _live());

            ServerManagedFields.Preserve(incoming, _live());

            // #1102: a provider a declarative source named is decided by that source, so the config-page
            // save gets the stored (declarative) provider back rather than the posted one. AFTER the
            // re-injection above, never before: that is what makes an untouched provider compare equal to
            // the stored one, so the audit below reports a save that actually tried to change a managed
            // provider instead of firing on every unrelated settings change. Nothing happens here on an
            // installation that configures no declarative source.
            ManagedProviders.Reinject(incoming, _live(), declarativeWritesIgnored, declarativeProfileWritesIgnored);

            // Snapshot which providers were saved with an insecure option (#140) while under the
            // lock, but emit the warnings AFTER releasing it (below) - logging must not run inside
            // the global config lock, where a slow provider would block concurrent config access.
            collectInsecure(CollectInsecureOptions(incoming));
        }

        // The persist delegate makes the written configuration live once the write has returned
        // (SSOPlugin.PersistBase), so a throw here leaves the live one on the stored state.
        _persist(configuration);
    }

    // The undo for a write that fails (#1521), taken under the caller's lock before anything is touched.
    // NOT fatal when it cannot be taken: the serializer that produces it refuses characters the one on
    // the way to disk may accept, and a configuration already holding such a byte would otherwise have
    // EVERY write refused from here on - including the delete that would remove it. So a snapshot that
    // cannot be made costs the rollback for that one write, which is where this plugin stood before
    // #1521, rather than costing the write itself. Null means "no undo available", and the caller says
    // so in the log rather than silently.
    private string? Snapshot(PluginConfiguration live)
    {
        try
        {
            return live.ToPersistedForm();
        }
        catch (InvalidOperationException ex)
        {
            SsoAudit.ConfigurationRollbackUnavailable(_logger, ex);
            return null;
        }
        catch (ArgumentException ex)
        {
            SsoAudit.ConfigurationRollbackUnavailable(_logger, ex);
            return null;
        }
    }

    // Puts the live configuration back on what the file still holds. Guarded, because the exception the
    // caller is about to rethrow is the one that says what actually went wrong: a restore that threw and
    // replaced it would leave an operator debugging the undo instead of the full disk underneath it. A
    // restore that fails leaves the live configuration mutated, which is the pre-#1521 state, and says so.
    private void Restore(PluginConfiguration live, string? snapshot)
    {
        if (snapshot is null)
        {
            return;
        }

        try
        {
            live.AdoptFrom(PluginConfiguration.FromPersistedForm(snapshot));
        }
#pragma warning disable CA1031 // the original failure must reach the caller, whatever the undo did
        catch (Exception ex)
#pragma warning restore CA1031
        {
            SsoAudit.ConfigurationRollbackFailed(_logger, ex);
        }
    }

    // Snapshots, under the caller's lock, the OpenID and SAML providers saved with a default-on security
    // check disabled (#140, #672), as (protocol, provider, enabled-option-names) triples. Pure read: it
    // does not log, so the audit warnings can be emitted after the config lock is released. Only the admin
    // save path reaches here (a fresh incoming config), so it fires once per save, not per login.
    private static List<(string Protocol, string Provider, IReadOnlyList<string> Options)> CollectInsecureOptions(PluginConfiguration incoming)
    {
        var records = new List<(string, string, IReadOnlyList<string>)>();

        if (incoming.OidConfigs != null)
        {
            foreach (var kvp in incoming.OidConfigs)
            {
                var insecure = OidcInsecureToggles.Enabled(kvp.Value);
                if (insecure.Count > 0)
                {
                    records.Add(("OpenID", kvp.Key, insecure));
                }
            }
        }

        if (incoming.SamlConfigs != null)
        {
            foreach (var kvp in incoming.SamlConfigs)
            {
                var insecure = SamlInsecureToggles.Enabled(kvp.Value);
                if (insecure.Count > 0)
                {
                    records.Add(("SAML", kvp.Key, insecure));
                }
            }
        }

        return records;
    }
}
