// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using Duende.IdentityModel.OidcClient.Infrastructure;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Secrets;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth;

/// <summary>
/// The SSO plugin class: bootstrap and page manifests. All configuration access is owned by
/// <see cref="ProviderConfigStore"/> (#318); the public methods below remain the plugin's
/// configuration facade and delegate to it.
/// </summary>
public class SSOPlugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    // The STABLE config-page registration prefix, deliberately DECOUPLED from the display Name below
    // (the rebrand to "Community SSO for Jellyfin"): these strings are page identifiers baked into the
    // served config-page URLs and the .js/.css the pages load by name, so they are part of the plugin's
    // page identity - like the root namespace, they must NOT track a display-name change (a rename here
    // would break every existing config page's load path). The display Name is free to change; this is not.
    private const string PageId = "SSO-Auth";

    private readonly ILogger _logger;

    private readonly Lazy<SecretStore> _secrets;

    // Volatile because it is written during construction and on the repair path, and read from request
    // threads: it makes each read see the last write rather than a value the reader cached. What it does
    // NOT do is order this field against the static Instance a request thread reaches it through - that
    // would be a property of the write to Instance, not of this one. Nothing rests on it: Instance is
    // assigned at the end of the constructor, and the HTTP pipeline serves nothing before the plugin has
    // loaded.
    private volatile bool _servingDefaultConfiguration;

    /// <summary>
    /// Initializes static members of the <see cref="SSOPlugin"/> class.
    /// </summary>
    static SSOPlugin()
    {
        // Stop the OidcClient trace serializer from JSON-serializing the full options object - the
        // client secret included - into a transient string on every Prepare/Process call, which it does
        // even with Trace logging off (#247). We never consume that trace output, so disabling it in the
        // type initializer (runs once, before any login) keeps the secret out of transient heap strings
        // (defense in depth). The flag is a process-global, so setting it here covers every login.
        LogSerializer.Enabled = false;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SSOPlugin"/> class.
    /// </summary>
    /// <param name="applicationPaths">Internal Jellyfin interface for the ApplicationPath.</param>
    /// <param name="xmlSerializer">Internal Jellyfin interface for the XML information.</param>
    /// <param name="logger">The logger (used to audit insecure-option saves, #140).</param>
    public SSOPlugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer, ILogger<SSOPlugin> logger)
        : base(applicationPaths, xmlSerializer)
    {
        // The logger first, because everything below reports through it.
        _logger = logger;

        // First on purpose (#1543): the host loads the configuration lazily and writes defaults over a file it
        // cannot read, so the damaged bytes exist only before anything reads Configuration, and the screen reads
        // the file itself. Wrapped, because anything that escapes a plugin constructor takes every SSO login on
        // the server offline, and the realistic trigger, a full disk, also breaks the log sink the screen writes to.
        try
        {
            ServingDefaultConfiguration = UnreadableConfiguration.Preserve(ConfigurationFilePath, xmlSerializer, logger, DateTime.UtcNow).IsUnreadable;
        }
#pragma warning disable CA1031, RCS1075 // a failed screen must never be the reason the plugin does not load
        catch (Exception)
#pragma warning restore CA1031, RCS1075
        {
            // Deliberately silent, and it has to be: the one failure that reaches here is a logger that
            // throws, so reporting it is the thing that just failed. What it costs is this check; the
            // server behaves as it did before the check existed.
            ServingDefaultConfiguration = false;
        }

        // #1601, and it belongs beside the screen above rather than after it for the same reason: the
        // moment before anything reads Configuration is the only moment the file on disk is still the
        // operator's. Two copies of this plugin loaded at once make the host unable to read a
        // configuration back across them, and its answer is to serve defaults and write them over the
        // file. This cannot prevent that write. What it does is take the copy first, and then refuse
        // every write of our own so the plugin adds nothing to the damage.
        // Order against the screen above does not matter - neither touches Configuration - and it is
        // second only because the screen has to stay the first thing this constructor does.
        // Wrapped for the reason everything on this path is: a check that throws would fail the plugin
        // load, and the state it exists to report is one an operator repairs by hand anyway.
        try
        {
            var duplicated = DuplicateInstall.Detect(ConfigurationFilePath, DateTime.UtcNow);
            LoadedMoreThanOnce = duplicated.IsDuplicated;
            DuplicateInstall.Announce(duplicated, logger);
        }
#pragma warning disable CA1031, RCS1075 // a check that could not run must not be the reason the plugin does not load
        catch (Exception)
#pragma warning restore CA1031, RCS1075
        {
            LoadedMoreThanOnce = false;
        }

        // Handing out `() => Configuration` here is safe: BasePlugin's constructor only records the
        // config path and loads the configuration lazily on first access, so nothing calls back into
        // UpdateConfiguration (and thus ConfigStore) before this assignment completes.
        ConfigStore = new ProviderConfigStore(() => Configuration, PersistBase, logger);

        // Lazy with the default thread-safe mode: the SecretStore (and thus the data-encryption key) is
        // built exactly once, even under concurrent first-use, so two callers can never generate two
        // divergent keys. The key lives in the plugin data folder, separate from the config XML, and is
        // created lazily on the first encrypt (a save) - never at load - so startup does no key I/O.
        _secrets = new Lazy<SecretStore>(() => new SecretStore(Path.Combine(DataFolderPath, "sso-secret.key")));
        Instance = this;

        // A mounted provider document is applied over the stored configuration before any login is served against
        // the old one (#1095); last in the constructor because it persists, and it returns an outcome rather than
        // throwing so a wrong file cannot take the plugin offline. The reveal delegate lets the loader tell an
        // unchanged secret from a rotation (#1096) without owning the key, and Secrets stays lazy.
        DeclarativeProviderConfig.ApplyFromEnvironment(ConfigStore, logger, stored => Secrets.Reveal(stored));

        // #1097: the environment half of the same source, applied AFTER the file so that where both name a
        // field the environment wins - the deployment's own variables are the closer of the two to the
        // process, and a mounted file is the shared artefact they override. Both merge over what is stored
        // rather than replacing it, through the same ConfigImport. Applied separately rather than merged
        // into one document, so an environment the operator got wrong leaves an accepted file standing
        // instead of taking it down as well. With no variable set it reads nothing and writes nothing.
        DeclarativeEnvironmentConfig.ApplyFromEnvironment(ConfigStore, logger, stored => Secrets.Reveal(stored));
    }

    /// <summary>
    /// Gets the instance of the SSO plugin.
    /// </summary>
    public static SSOPlugin Instance { get; private set; } = null!;

    /// <summary>
    /// Gets the name of the SSO plugin.
    /// </summary>
    public override string Name => "Community SSO for Jellyfin";

    /// <summary>
    /// Gets the GUID of the SSO plugin.
    /// </summary>
    public override Guid Id => Guid.Parse("505ce9d1-d916-42fa-86ca-673ef241d7df");

    /// <summary>
    /// Gets the store that owns every configuration read and write (#318).
    /// </summary>
    internal ProviderConfigStore ConfigStore { get; }

    /// <summary>
    /// Gets a value indicating whether a second copy of this plugin is loaded into this server (#1601).
    /// While it is set, every configuration write from this plugin is refused: the two copies cannot
    /// round-trip a configuration between them, and a write attempted anyway is how the providers on disk
    /// get replaced by defaults. Set once, in the constructor, and never cleared - the repair is to remove
    /// a plugin directory and restart, which this process does not survive to see.
    /// </summary>
    internal bool LoadedMoreThanOnce { get; }

    /// <summary>Gets a value indicating whether the stored configuration could not be read at start, so what is being served is a default one and not the one this server had (#1543).</summary>
    /// <remarks>
    /// While true, every SSO sign-in route refuses with 503 rather than as no matching provider. One rule ends it,
    /// whichever door the write came through: a persisted configuration holding at least one provider, so an
    /// unrelated whole-configuration save no longer clears it. It survives a restart through a marker file, because
    /// by then the host has replaced the damaged file with a readable default; the marker is what keeps this from
    /// being a lockout on a server whose administrators all arrived through SSO, since an operator can delete it.
    /// </remarks>
    internal bool ServingDefaultConfiguration
    {
        get => _servingDefaultConfiguration;
        private set => _servingDefaultConfiguration = value;
    }

    /// <summary>
    /// Gets the store that encrypts the plugin's at-rest secrets - the OpenID client secret and the SAML
    /// signing key (#158). Its data-encryption key lives in a dedicated file in the plugin data folder,
    /// separate from the config XML, so a leaked config alone cannot decrypt anything. The login flows
    /// reveal a stored secret through this at the point of use.
    /// </summary>
    internal SecretStore Secrets => _secrets.Value;

    /// <summary>Applies a mutation to the live configuration under a single lock and persists it, so a read-modify-write cannot race another and lose its update; every configuration write goes through this.</summary>
    /// <remarks>All-or-nothing against both failures (#1521): a mutation that throws persists nothing, and a write that throws is rolled back out of the live configuration before the exception reaches the caller. The residual is a caller holding a provider object taken before the mutation, which keeps the rejected values.</remarks>
    /// <param name="mutate">The mutation to apply to the live configuration.</param>
    public void MutateConfiguration(Action<PluginConfiguration> mutate) => ConfigStore.Mutate(mutate);

    /// <summary>
    /// Applies a mutation that returns a result (e.g. whether a removal changed anything) under the
    /// same single lock and persists it, so the read-modify-write and the result observation are one
    /// atomic operation.
    /// </summary>
    /// <typeparam name="T">The value the mutation returns.</typeparam>
    /// <param name="mutate">The mutation to apply to the live configuration.</param>
    /// <returns>The value returned by <paramref name="mutate"/>.</returns>
    public T MutateConfiguration<T>(Func<PluginConfiguration, T> mutate) => ConfigStore.Mutate(mutate);

    /// <summary>
    /// Reads a value from the live configuration under the same lock as <see cref="MutateConfiguration(Action{PluginConfiguration})"/>,
    /// so a read cannot tear against a concurrent write of a (non-thread-safe) configuration collection.
    /// </summary>
    /// <typeparam name="T">The value read.</typeparam>
    /// <param name="read">The read to perform against the live configuration.</param>
    /// <returns>The value returned by <paramref name="read"/>.</returns>
    public T ReadConfiguration<T>(Func<PluginConfiguration, T> read) => ConfigStore.Read(read);

    /// <summary>
    /// Persists a replacement configuration through the store's validated save pipeline
    /// (<see cref="ProviderConfigStore.Save"/>): fail-closed validation (#139/#206), server-managed
    /// field preservation (#157/#189), and the insecure-option audit (#140). Jellyfin core's
    /// UpdatePluginConfiguration (the admin config-page save) enters here.
    /// </summary>
    /// <param name="configuration">The configuration to persist.</param>
    public override void UpdateConfiguration(BasePluginConfiguration configuration) => ConfigStore.Save(configuration);

    /// <summary>Ends the serve-defaults state an unreadable configuration put this server into (#1543), and removes the marker so the next start agrees.</summary>
    /// <remarks>Reached from one place, the persist bridge, once the write has landed and only when what landed holds a provider, so every door an administrator has ends there without a rule of its own. A sign-in write cannot reach it because every sign-in route answers 503 while this stands; a logout can, and on the one boot where that matters the clear is correct.</remarks>
    internal void ConfigurationSuppliedByAdministrator()
    {
        if (!ServingDefaultConfiguration)
        {
            return;
        }

        ServingDefaultConfiguration = false;
        UnreadableConfiguration.ClearMarker(ConfigurationFilePath, _logger);
        SsoAudit.UnreadableConfigurationCleared(_logger);
    }

    // The store's only road to disk: this named bridge hands base.UpdateConfiguration to the store so a store save
    // cannot re-enter the overridden pipeline above. Every write funnels through here, so it is the one choke point
    // for at-rest secret encryption (#158), where ProtectAll is idempotent, and for clearing the serve-defaults
    // state (#1543), derived from the persisted configuration holding a provider rather than declared per door,
    // because a whole-configuration save from the settings page carries no provider and repaired nothing.
    private void PersistBase(BasePluginConfiguration configuration)
    {
        // FIRST, before the type check below and before anything reaches the base class (#1601). With two
        // copies of this plugin loaded, that check is itself part of the fault: a configuration produced
        // by the other copy is not this copy's PluginConfiguration, so it falls through to the base class
        // unchanged and the host writes it - which is the shape that empties the file. Refusing loudly
        // costs the caller a 500 on a server whose SSO routes are already ambiguous and answering nothing;
        // writing costs the operator every provider they have.
        if (LoadedMoreThanOnce)
        {
            throw new InvalidOperationException(
                "This plugin is loaded twice in this server, so its configuration cannot be written without destroying it. Keep exactly one plugin directory for this plugin under the plugins folder, delete the others, and restart the server. The plugin log names the directories and where the configuration was copied.");
        }

        if (configuration is not PluginConfiguration incoming)
        {
            // Not this plugin's configuration type, so there is nothing to encrypt and nothing this
            // method knows how to swap in; hand it to the base class unchanged.
            base.UpdateConfiguration(configuration);
            return;
        }

        ConfigSecretProtection.ProtectAll(incoming, Secrets);

        // The file first (#1521): base.UpdateConfiguration assigns Configuration before it serializes, so a write
        // that threw left the plugin running on a configuration not on disk, while SaveConfiguration is the write
        // half alone. The write is not atomic and uses no temporary file, and that is a decision (#1532): the host
        // rewrites a truncated file with defaults on the next load regardless, the mocked serializer cannot tell a
        // temporary file written from one that was not, and the running server is already rolled back; the operator
        // consequence is stated in the server-migration guide.
        SaveConfiguration(incoming);

        // After the write and not before it (#1543), so a persist that throws leaves the server still refusing
        // rather than answering logins with no matching provider for a configuration that never reached the disk.
        // It may not throw, because the store would roll the live configuration back away from a file that has the
        // change, which is why the condition is inside the try and both maps are read null-tolerant.
        try
        {
            if (ServingDefaultConfiguration && (incoming.OidConfigs?.Count > 0 || incoming.SamlConfigs?.Count > 0))
            {
                ConfigurationSuppliedByAdministrator();
            }
        }
#pragma warning disable CA1031, RCS1075 // nothing on the repair path may unwind a write that has landed
        catch (Exception)
#pragma warning restore CA1031, RCS1075
        {
            // Silent for the same reason the constructor's screen is: the one failure that reaches here is
            // the logger itself, so reporting it is the thing that just failed. Where the clear did run,
            // the state is already false and the running server accepts sign-in; the marker is what may be
            // left behind, and the next start reads a configuration holding a provider and removes it.
        }

        // Then the live object, in place rather than by reference: every reader in this plugin holds the
        // object Configuration returns, and Jellyfin core hands it out on GET /Plugins/{id}/Configuration
        // without taking the store's lock, so replacing the reference would leave holders on an
        // abandoned configuration. A no-op when the caller handed in the live object itself, which is
        // every Mutate.
        Configuration.AdoptFrom(incoming);

        // Last, and it cannot undo either of the two above. The base-class update this method replaces
        // raised this event, so the replacement owes it; but the store rolls a write back on any
        // exception out of this delegate, and the write is already durable here - a subscriber that
        // threw would otherwise revert the live configuration away from a file that has the change.
        // Swallowed for the same reason the insecure-option audit is emitted outside the config lock: a
        // misbehaving subscriber must not turn a completed save into a failure.
        try
        {
            ConfigurationChanged?.Invoke(this, Configuration);
        }
#pragma warning disable CA1031 // any subscriber failure, and none of them may unwind a durable write
        catch (Exception ex)
#pragma warning restore CA1031
        {
            SsoAudit.ConfigurationChangedSubscriberFailed(_logger, ex);
        }
    }

    // Both tables are the plugin's public URL contract (#370): the first element of each pair is the name a caller
    // requests an asset by, the second the embedded resource suffix, which must match the source file's name and
    // casing under Web/. GetViews is matched ordinally in SSOViewsController; GetPages is matched by the host
    // case-insensitively. Renaming a registered name breaks every caller of that URL, and renaming a source file
    // without the suffix is a runtime 404; tools/ui-mock-fields.js refuses a link that names nothing registered.
    // Web.style.css is deliberately published under two names, for two unrelated consumers.

    /// <summary>
    /// Returns the available internal web pages of this plugin.
    /// </summary>
    /// <returns>A list of internal webpages in this application.</returns>
    public IEnumerable<PluginPageInfo> GetPages() =>
        new[]
        {
            // The FIVE tabs (#1527). PageId itself stays the Overview page, because that is the name the
            // dashboard's plugin list links to and it is the entry an administrator arrives on; the other
            // four hang off it by suffix, and the tab strip in every page's markup links to exactly these
            // names. They are the URL contract the comment above describes: a rename here and not in the
            // strip leaves four dead tabs, and the reverse leaves four pages nothing links to.
            Page(PageId, "Web.configPage.html"),
            Page(PageId + ".js", "Web.overview.js"),
            Page(PageId + "-providers", "Web.providersPage.html"),
            Page(PageId + "-providers.js", "Web.providers.js"),
            Page(PageId + "-accounts", "Web.accountsPage.html"),
            Page(PageId + "-accounts.js", "Web.accounts.js"),
            Page(PageId + "-policies", "Web.policiesPage.html"),
            Page(PageId + "-policies.js", "Web.policies.js"),
            Page(PageId + "-server", "Web.serverPage.html"),
            Page(PageId + "-server.js", "Web.server.js"),

            // The shared core the five page scripts load. Registered here rather than under GetViews
            // because this is the route the pages themselves are served from, so it widens nothing: it is
            // reachable by exactly the audience that can already fetch the page markup and the five page
            // scripts beside it. It is not a page anybody navigates to, and no markup names it.
            Page(PageId + "-core.js", "Web.sso-core.js"),

            Page(PageId + ".css", "Web.style.css"),
            Page(PageId + "-linking", "Web.linking.html"),
            Page(PageId + "-linking.js", "Web.linking.js"),
        };

    /// <summary>
    /// Returns the available user views for this plugin.
    /// </summary>
    /// <returns>A list of user views for this plugin.</returns>
    public IEnumerable<PluginPageInfo> GetViews() =>
        new[]
        {
            Page("style.css", "Web.style.css"),
            Page("linking", "Web.linking.html"),
            Page("linking.js", "Web.linking.js"),
            Page("i18n.js", "Web.i18n.js"),
            Page("ApiClient.js", "Web.ApiClient.js"),
            Page("emby-restyle.css", "Web.emby-restyle.css"),
            Page("jellyfin-apiClient.esm.min.js", "Web.jellyfin-apiClient.esm.min.js"),
        };

    // Every GetPages/GetViews entry is a (registered name, embedded resource) pair under this
    // plugin's namespace; this factory collapses the repeated PluginPageInfo construction to one
    // call per entry.
    private PluginPageInfo Page(string name, string resource) =>
        new() { Name = name, EmbeddedResourcePath = $"{GetType().Namespace}.{resource}" };
}
