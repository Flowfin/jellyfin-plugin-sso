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
        // Handing out `() => Configuration` here is safe: BasePlugin's constructor only records the
        // The logger first, because everything below reports through it.
        _logger = logger;

        // #1543, and it is FIRST on purpose. The host loads the configuration lazily and, when that load
        // throws, hands out defaults and WRITES THEM OVER THE FILE - so the only moment the damaged bytes
        // still exist is before anything reads Configuration. Nothing above this line touches that
        // property, and the screen reads the file itself rather than through the base class, so it cannot
        // trigger the load it exists to get ahead of. ConfigurationFilePath is composed from the
        // application paths and reads no configuration.
        // Wrapped, to the standard the declarative loader below sets and for its reason: anything that
        // escapes a plugin constructor fails the plugin load and takes every SSO login on the server
        // offline. The realistic trigger is the same cause as the damage - a full disk truncates the
        // configuration AND breaks the file log sink, so the Error line this screen writes throws out of
        // the logger - and the answer to that must not be a plugin that never loads and a 500 on every
        // route. A screen that could not run leaves the server where it stood before it existed.
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

        ConfigStore = new ProviderConfigStore(() => Configuration, PersistBase, logger);

        // Lazy with the default thread-safe mode: the SecretStore (and thus the data-encryption key) is
        // built exactly once, even under concurrent first-use, so two callers can never generate two
        // divergent keys. The key lives in the plugin data folder, separate from the config XML, and is
        // created lazily on the first encrypt (a save) - never at load - so startup does no key I/O.
        _secrets = new Lazy<SecretStore>(() => new SecretStore(Path.Combine(DataFolderPath, "sso-secret.key")));
        Instance = this;

        // #1095: a deployment that mounts a provider document gets it applied over the stored configuration
        // here, before anything can serve a login against the old one. Last in the constructor because it
        // persists through ConfigStore, and it returns an outcome rather than throwing - a file the operator
        // got wrong must not take the plugin, and with it every SSO login on the server, offline. With no
        // source path configured it reads nothing, writes nothing and logs nothing.
        // The reveal delegate lets the loader tell a resolved secret that is ALREADY the stored one from a
        // genuine rotation (#1096), so an unchanged mount leaves the at-rest envelope alone instead of
        // rewriting it on every boot. A delegate rather than the store itself, because the loader has no
        // business with the data-encryption key beyond that one comparison - and Secrets stays lazy: nothing
        // touches the key file unless a document actually carries a reference over a provider that has a
        // stored secret.
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
    /// Gets a value indicating whether the stored configuration could not be read at start, so what is
    /// being served is a default one and not the one this server had (#1543).
    /// </summary>
    /// <remarks>
    /// While it is true every SSO sign-in route refuses with 503 rather than failing as no matching
    /// provider, because a default configuration holds no provider and the two are not the same fact for
    /// the operator reading the log. ONE RULE ENDS IT, whichever door the write came through: a persisted
    /// configuration that holds at least one provider. A save of the whole configuration from the settings
    /// page is not a special case of that and used to be - which meant an administrator toggling single
    /// logout, on a server holding nothing, cleared the refusal and deleted the marker, and the log said a
    /// configuration had been supplied. It survives a restart, because by the next start the host has
    /// replaced the damaged file with a readable default and the screen alone would report a healthy
    /// server that is serving nobody's settings.
    /// <para>
    /// T-D1 ON THIS SURFACE IS THE MARKER FILE, NOT LOCAL SIGN-IN, and the difference matters. This plugin
    /// does not touch Jellyfin password sign-in - but an account it PROVISIONED has no usable password by
    /// construction, so on a server whose administrators all arrived through SSO there is no local door to
    /// fall back to, and a refusal that survives restarts would leave nobody able to administer anything.
    /// What keeps that from being a lockout is that the state lives in a file an operator can delete:
    /// remove the marker beside the configuration, restart, and SSO answers exactly as it did before this
    /// check existed. Every log line that announces the refusal says so.
    /// </para>
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

    /// <summary>
    /// Applies a mutation to the live configuration under a single lock and persists it, so a
    /// read-modify-write cannot race another and lose its update. All configuration writes must go
    /// through this rather than reading <see cref="BasePlugin{T}.Configuration"/>, mutating, and
    /// calling <c>UpdateConfiguration</c> separately.
    /// </summary>
    /// <remarks>
    /// All-or-nothing against BOTH failures, which is what callers document to their operators (#1521):
    /// a mutation that throws persists nothing, and a WRITE that throws - a full disk, a read-only
    /// volume - is rolled back out of the live configuration before the exception reaches the caller.
    /// The residual is named rather than implied: a caller holding a reference to a PROVIDER object
    /// taken before the mutation keeps an object carrying the rejected values, and is receiving the
    /// exception rather than carrying on.
    /// </remarks>
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

    /// <summary>
    /// Ends the serve-defaults state an unreadable configuration put this server into (#1543), and
    /// removes the marker so the next start agrees.
    /// </summary>
    /// <remarks>
    /// Reached from ONE place, which is the point: the persist bridge below, once the write has actually
    /// landed and only when what landed holds a provider. Every door an administrator has - a provider
    /// saved on the page, a whole-configuration save that carries one, an imported document, a declarative
    /// source - ends there, so none of them needs a rule of its own. A SIGN-IN write cannot reach it,
    /// because every SSO sign-in route answers 503 while this stands - but a logout can, since logout is
    /// deliberately not gated and persists through the same bridge. That only matters on the boot where
    /// this state coexists with a live configuration holding providers, and there the clear is correct:
    /// the configuration really is good.
    /// </remarks>
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

    // The store's only road to disk: persistence stays with the plugin base class, and this named
    // bridge hands base.UpdateConfiguration to the store so a store save cannot re-enter the
    // overridden pipeline above. Every road to disk - the config-page Save and every Mutate (provider
    // Add, login-path canonical-link writes) - funnels through here, so this is the single chokepoint
    // where at-rest secret encryption belongs (#158): the config model is owned by the store, but the
    // on-disk representation is owned by the persistence boundary, and that is where a secret becomes an
    // ssoenc: envelope. ProtectAll is idempotent (an already-encrypted or empty value is left unchanged),
    // so re-persisting is a no-op and a legacy plaintext value is rewritten encrypted on its next save.
    // The one choke point every configuration write goes through - the store's Mutate and its Save both
    // end here - which is why the serve-defaults state is cleared here rather than at each door (#1543).
    // The doors are not all the same shape: the settings page saves a provider through MutateConfiguration
    // and never enters the UpdateConfiguration override, and a declarative source applies its document the
    // same way, so a rule written at the override alone left a server that had done exactly what the
    // banner told it to do refusing every SSO sign-in for good.
    //
    // What counts is DERIVED rather than declared: a persisted configuration holding at least one provider
    // is a configuration somebody supplied, whichever door it came through, and there is no second rule
    // beside it. A SIGN-IN write cannot satisfy it, and the reason is the 503 on every sign-in route
    // rather than the configuration being empty - it can hold providers while this state stands, on the
    // boot where a restore rewrote the file under the screen's own read. A logout is not gated and does
    // persist through here; on that one boot it clears the state, which is the right answer, because the
    // configuration it just wrote is the operator's own. A whole-configuration save from the settings page was one until #1543's fifth review:
    // every unrelated toggle on that page - single logout, the login buttons, a provisioning profile - is
    // a whole-configuration save, and on a server serving defaults it carries no provider, so the refusal
    // and the marker were being cleared by a change that repaired nothing. A server that genuinely holds
    // no provider has no SSO sign-in to refuse; what it loses by staying marked is a banner it can end by
    // saving a provider, importing one, or removing the marker, which is what the banner says.
    private void PersistBase(BasePluginConfiguration configuration)
    {
        if (configuration is not PluginConfiguration incoming)
        {
            // Not this plugin's configuration type, so there is nothing to encrypt and nothing this
            // method knows how to swap in; hand it to the base class unchanged.
            base.UpdateConfiguration(configuration);
            return;
        }

        ConfigSecretProtection.ProtectAll(incoming, Secrets);

        // The file FIRST (#1521). Measured rather than assumed: base.UpdateConfiguration assigns
        // Configuration BEFORE it serializes, so a write that threw - a full disk, a read-only volume -
        // left the plugin running on a configuration that is not on disk, with no error path back.
        // SaveConfiguration is the write half alone: it creates the configuration directory and
        // serializes to the same file, and it neither assigns Configuration nor raises
        // ConfigurationChanged. So a throw here reaches the caller with nothing made live.
        //
        // THIS WRITE IS NOT ATOMIC AND DOES NOT GO THROUGH A TEMPORARY FILE, WHICH IS A DECISION RATHER
        // THAN AN OVERSIGHT (#1532). It serializes straight over SSO-Auth.xml with no temporary copy and
        // no rename, so the failure the line above is about - a disk that fills mid-write - leaves a
        // truncated file. Three reasons it is left that way, in the order they bind:
        //
        // A rename would not save the file it is meant to save. BasePlugin<T>.LoadConfiguration catches
        // every exception, builds a default configuration AND WRITES IT BACK over the file, so a
        // truncated SSO-Auth.xml becomes an empty one on the next start with every provider, link and
        // at-rest secret envelope gone and the evidence overwritten. The destructive half is on the LOAD
        // side and is the host's; a write-side rename leaves it exactly as it is, and shipping one would
        // buy the appearance of durability without the fact. That is #1543.
        //
        // Owning the write means owning what 'the serializer produced a file' means. Replacing this call
        // with SerializeToFile-then-rename needs a definition of the temporary file having been written,
        // and the plugin cannot tell a serializer that wrote nothing from one that wrote in place - the
        // test harness mocks IXmlSerializer precisely so no file appears, so the rename would throw
        // through every persisting test in the suite and the repair would be to make the mock write,
        // which changes what those tests mean.
        //
        // And the running server is already covered, which is what #1521 bought: a write that throws is
        // rolled back out of the live configuration, so the process goes back to the stored state rather
        // than carrying a change the file does not have. What is not covered is the FILE, and the
        // operator-facing consequence is stated where an operator reads it, in docs/SERVER-MIGRATION.md:
        // copy SSO-Auth.xml before a migration step and check it after a failed one, before restarting.
        SaveConfiguration(incoming);

        // AFTER the write and not before it (#1543). A persist that throws - the full disk this whole
        // area is about - must leave the server on the state it is actually in: still serving defaults,
        // still refusing. Clearing first would have answered logins with "no matching provider" for the
        // rest of the process on a server whose configuration never reached the disk.
        //
        // AND IT MAY NOT THROW, for the reason the ConfigurationChanged notification below is wrapped for:
        // the write above is already durable, and the store rolls the live configuration back on any
        // exception out of this delegate. An unwrapped line here would revert the live configuration away
        // from a file that HAS the change - and what it does is delete a file and write a log line, on a
        // server whose defining symptom is a disk that fails writes and a log sink that fails with it.
        // NULL-TOLERANT ON BOTH MAPS, and the condition is INSIDE the try rather than beside it. Every
        // other reader of these two on this path already tolerates a null - a legacy store, a posted
        // document naming one of them as null - and this was the one that did not, in the one place where
        // throwing costs the most: after the write has landed, where the store's rollback would revert the
        // live configuration away from a file that HAS the change.
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

    // Both tables below are the plugin's public URL contract (#370): the first element of each Page()
    // pair is the name a caller (the admin config page, the linking page, SSOViewsController) requests
    // an asset by, matched case-sensitively (SSOViewsController.GetView); the second is the embedded
    // resource path suffix, which must match the source file's actual on-disk name and casing under
    // this project's default (path-derived) embedded-resource naming. Every served asset lives under the
    // one flat Web/ folder, so the suffix is Web.<file>. The two elements never have to agree with each
    // other, but changing either one changes what breaks: renaming the registered name breaks every
    // caller of that URL (config.js, linking.html, config page markup); renaming/moving the source file
    // without updating the resource suffix here breaks the embedded-resource lookup at runtime (a 404,
    // since GetManifestResourceStream is also case-sensitive). Web.style.css is deliberately published
    // under two different registered names below - "SSO-Auth.css" (GetPages, the admin config page's own
    // stylesheet load) and "style.css" (GetViews, the public linking page) - the same resource, two
    // unrelated consumers with independently-chosen URL conventions, not a casing inconsistency.

    /// <summary>
    /// Returns the available internal web pages of this plugin.
    /// </summary>
    /// <returns>A list of internal webpages in this application.</returns>
    public IEnumerable<PluginPageInfo> GetPages() =>
        new[]
        {
            Page(PageId, "Web.configPage.html"),
            Page(PageId + ".js", "Web.config.js"),
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
