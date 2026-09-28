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

/// <summary>Owns every read and write of the plugin configuration behind one lock, and the validated save pipeline for a replacement configuration (#318).</summary>
/// <remarks>Persistence stays with the plugin base class and is reached through the injected persist delegate.</remarks>
internal sealed class ProviderConfigStore
{
    // Static so two plugin instances in one process can never interleave writes.
    private static readonly System.Threading.Lock Sync = new();

    private readonly Func<PluginConfiguration> _live;
    private readonly Action<BasePluginConfiguration> _persist;
    private readonly ILogger _logger;

    /// <summary>Initializes a new instance of the <see cref="ProviderConfigStore"/> class.</summary>
    /// <param name="live">Returns the live plugin configuration.</param>
    /// <param name="persist">Persists a configuration through the plugin base class.</param>
    /// <param name="logger">The logger the audit lines go to.</param>
    internal ProviderConfigStore(Func<PluginConfiguration> live, Action<BasePluginConfiguration> persist, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(live);
        ArgumentNullException.ThrowIfNull(persist);
        _live = live;
        _persist = persist;
        _logger = logger;
    }

    /// <summary>Gets the providers a declarative source decided on this boot; empty where none is configured (#1102).</summary>
    internal DeclarativeManagedProviders ManagedProviders { get; private set; } = DeclarativeManagedProviders.None;

    /// <summary>Records that a declarative source has applied <paramref name="applied"/>, freezing every provider it names against the config-page save (#1102).</summary>
    /// <param name="applied">The configuration the source applied.</param>
    /// <param name="source">What names the source in a refusal, so the refusal can say where to make the change instead (#1415).</param>
    internal void RecordDeclarativelyManaged(PluginConfiguration? applied, string source)
    {
        lock (Sync)
        {
            ManagedProviders = ManagedProviders.Including(applied, source);
        }
    }

    /// <summary>Reads a value from the live configuration under the same lock as <see cref="Mutate(Action{PluginConfiguration})"/>.</summary>
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

    /// <summary>Applies a mutation under the lock and persists it; a persist that fails leaves nothing behind (#1521).</summary>
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

    /// <summary>Applies a mutation that returns a result under the lock and persists it, so the write and the observation are one atomic operation.</summary>
    /// <typeparam name="T">The value the mutation returns.</typeparam>
    /// <param name="mutate">The mutation to apply.</param>
    /// <returns>The value returned by <paramref name="mutate"/>.</returns>
    public T Mutate<T>(Func<PluginConfiguration, T> mutate)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        lock (Sync)
        {
            var live = _live();

            // The undo for a persist that throws, as the persisted form because the parse back is paid only on failure (#1521, #1532).
            var snapshot = Snapshot(live);

            try
            {
                var result = mutate(live);

                // The object written is the live one, so Save's fresh-config pipeline would skip it anyway.
                _persist(live);
                return result;
            }
            catch
            {
                // The mutation is inside the try too, so a lambda that throws half way leaves nothing behind.
                Restore(live, snapshot);
                throw;
            }
        }
    }

    /// <summary>Persists a replacement configuration, re-injecting the server-managed fields from the live one first (#157).</summary>
    /// <remarks>The settings page posts a snapshot taken at page load, so a link a login wrote since then would otherwise be wiped.</remarks>
    /// <param name="configuration">The configuration to persist.</param>
    public void Save(BasePluginConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        List<(string Protocol, string Provider, IReadOnlyList<string> Options)>? insecureToAudit = null;
        var declarativeWritesIgnored = new List<(string Protocol, string Provider)>();
        var declarativeProfileWritesIgnored = new List<string>();
        lock (Sync)
        {
            // The posted object shares the live object's maps, which the persist encrypts in place, so the undo is needed here too (#1521).
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

        // Outside the lock, so a slow logging provider can neither block configuration access nor fail a completed save.
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

    // The body of Save, under the caller's lock and inside its rollback.
    private void Persist(
        BasePluginConfiguration configuration,
        Action<List<(string Protocol, string Provider, IReadOnlyList<string> Options)>> collectInsecure,
        List<(string Protocol, string Provider)> declarativeWritesIgnored,
        List<string> declarativeProfileWritesIgnored)
    {
        if (configuration is PluginConfiguration incoming && !ReferenceEquals(incoming, _live()))
        {
            // Only a fresh incoming configuration is validated; the Add endpoints and the login path write the live object through Mutate.
            ProviderConfigValidator.Validate(incoming, _live());

            ServerManagedFields.Preserve(incoming, _live());

            // After the re-injection, so an untouched managed provider compares equal to the stored one (#1102).
            ManagedProviders.Reinject(incoming, _live(), declarativeWritesIgnored, declarativeProfileWritesIgnored);

            // Collected under the lock and emitted after it (#140).
            collectInsecure(CollectInsecureOptions(incoming));
        }

        // The persist delegate makes the written configuration live once the write returned, so a throw leaves the stored state.
        _persist(configuration);
    }

    // A snapshot that cannot be taken costs the rollback for one write and never the write itself, or a bad byte would refuse every write including its own delete.
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

    // Guarded, because the exception the caller is about to rethrow is the one that says what went wrong.
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

    // A pure read of the providers saved with a default-on check disabled, so the audit can be emitted after the lock (#140, #672).
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
