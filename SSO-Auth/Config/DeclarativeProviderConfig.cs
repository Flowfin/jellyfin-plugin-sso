// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// What one declarative load did, so the caller and the tests observe an outcome instead of inferring it
/// from a log line (#1095).
/// </summary>
internal enum DeclarativeLoadOutcome
{
    /// <summary>No source path is configured, so the plugin behaves exactly as it does without this feature.</summary>
    NotConfigured,

    /// <summary>The document was valid and changed the stored configuration, which was persisted.</summary>
    Applied,

    /// <summary>The document was valid and the stored configuration already matched it, so nothing was persisted.</summary>
    AlreadyCurrent,

    /// <summary>The source or the document could not be used, and the stored configuration was left untouched.</summary>
    Rejected,
}

/// <summary>
/// Applies a provider configuration document mounted into the container over the stored configuration at
/// startup (#1095), so a deployment can describe its identity providers in a file it owns rather than by
/// clicking through the settings page. The foundation of #828; the secret-reference form (#1096), the
/// environment-variable source (#1097), the read-only admin surface (#1104) and the documentation (#1116)
/// are siblings and are deliberately not here.
/// </summary>
/// <remarks>
/// <para>
/// ONE setting names the source: the <see cref="SourcePathVariable"/> environment variable, holding the path
/// of the document. An environment variable rather than a field in the plugin configuration, because the
/// source that MANAGES the stored configuration cannot itself be stored there - a fresh install has no
/// configuration yet, and the deployment shape this exists for points a mount at a path from its own
/// environment. When the variable is absent or blank nothing is read, nothing is written and nothing is
/// logged, so an installation that never sets it is byte-identical to one built before this existed.
/// </para>
/// <para>
/// The document is the same shape <c>GET /sso/Config/Export</c> produces and <c>POST /sso/Config/Import</c>
/// accepts, and it is applied through the same <see cref="ConfigImport"/>. That is the whole of the
/// precedence rule, and it is a MERGE rather than a replace: a provider the document names wins over the
/// stored one of that name, a provider the document does not name is left exactly as it is, and the
/// server-managed link maps and issuer bindings survive the apply because
/// <see cref="ServerManagedFields"/> re-injects them. A blank secret in the document keeps the stored
/// secret, so a document that carries none does not blank one out. A secret written into the document IS
/// applied, which is what #1096 replaces with a reference form.
/// </para>
/// <para>
/// The link maps survive with ONE exception, inherited whole from the import path rather than invented
/// here: <see cref="ServerManagedFields"/>'s repoint belt (#186) treats a changed discovery endpoint or
/// client id on an EXISTING OpenID provider as a repoint to a possibly different identity provider, and
/// clears that provider's links, issuer bindings and stored secret. So editing an endpoint in the mounted
/// file unlinks every account on that provider, exactly as editing it on the settings page does. It is the
/// behaviour that stops a foreign identity provider inheriting the old one's account mappings, and it is
/// stated here because a file edit is a quieter act than a form save.
/// </para>
/// <para>
/// Fail-closed in one direction only: a document that cannot be read, cannot be parsed, carries a version
/// this plugin does not import, or carries a provider <see cref="ProviderConfigValidator"/> refuses is
/// rejected AS A UNIT, logged at Error, and leaves the stored configuration byte-identical. It is never
/// half-applied, because the document is applied to a detached copy first and only reaches the live
/// configuration once that copy has taken it whole. Nothing here throws: this runs while the plugin is
/// being constructed, and a throw would take the plugin - and with it every SSO login on the server -
/// offline over a configuration file. A rejected document is a loud log line and a server that keeps
/// running on what it already had.
/// </para>
/// <para>
/// Applying the identical document twice persists nothing the second time. The comparison is made against
/// the detached copy before the live configuration is touched, so a restart loop against an unchanged mount
/// cannot rewrite <c>config.xml</c> on every boot.
/// </para>
/// </remarks>
internal static class DeclarativeProviderConfig
{
    /// <summary>
    /// The one setting that names the declarative document. Reserved by this loader: the naming scheme for
    /// expressing the document's own FIELDS in the environment is #1097's, and must not reuse this name.
    /// </summary>
    internal const string SourcePathVariable = "JELLYFIN_SSO_CONFIG_FILE";

    // The document is hand-written as often as it is exported, so a property spelled in another case is
    // matched rather than silently dropped. Unknown properties are still ignored, which is the default and
    // is disclosed rather than claimed away: a misspelled field name is a no-op here, and refusing one is
    // the sibling rule #1097 states for its own source.
    private static readonly JsonSerializerOptions ReadOptions = new() { PropertyNameCaseInsensitive = true };

    /// <summary>
    /// Reads the document named by <see cref="SourcePathVariable"/> and applies it to <paramref name="store"/>.
    /// </summary>
    /// <param name="store">The configuration store to apply the document through.</param>
    /// <param name="logger">The logger a rejection is reported on.</param>
    /// <returns>What the load did.</returns>
    internal static DeclarativeLoadOutcome ApplyFromEnvironment(ProviderConfigStore store, ILogger? logger)
    {
        try
        {
            return Apply(
                store,
                Environment.GetEnvironmentVariable(SourcePathVariable),
                File.Exists,
                path => File.ReadAllText(path),
                logger);
        }
#pragma warning disable CA1031 // Do not catch general exception types
        catch (Exception ex)
#pragma warning restore CA1031
        {
            // The one place a broad catch is the correct instrument. This is called from the plugin's
            // constructor, so anything that escapes fails the plugin load and takes every SSO login on the
            // server offline - over a configuration file. The typed catches inside Apply name the failures
            // that were reasoned about; this names the ones that were not, and refuses to let a
            // configuration source decide whether the plugin exists.
            if (logger?.IsEnabled(LogLevel.Error) == true)
            {
                logger.LogError(
                    ex,
                    "The declarative SSO configuration could not be applied and nothing was changed. The plugin is running on its stored configuration.");
            }

            return DeclarativeLoadOutcome.Rejected;
        }
    }

    /// <summary>
    /// Applies the document at <paramref name="sourcePath"/>, reading the filesystem through the supplied
    /// delegates so the outcome can be driven without one.
    /// </summary>
    /// <param name="store">The configuration store to apply the document through.</param>
    /// <param name="sourcePath">The document's path, or null/blank when no source is configured.</param>
    /// <param name="exists">Answers whether the path names a readable document.</param>
    /// <param name="read">Reads the document's text.</param>
    /// <param name="logger">The logger a rejection is reported on.</param>
    /// <returns>What the load did.</returns>
    internal static DeclarativeLoadOutcome Apply(
        ProviderConfigStore store,
        string? sourcePath,
        Func<string, bool> exists,
        Func<string, string> read,
        ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(exists);
        ArgumentNullException.ThrowIfNull(read);

        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            return DeclarativeLoadOutcome.NotConfigured;
        }

        if (!exists(sourcePath))
        {
            return Reject(logger, sourcePath, "the path names no readable file");
        }

        string text;
        try
        {
            text = read(sourcePath);
        }
        catch (IOException ex)
        {
            return Reject(logger, sourcePath, ex.Message);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Reject(logger, sourcePath, ex.Message);
        }
        catch (ArgumentException ex)
        {
            // A path the platform will not accept at all, which is what a typo in a mount produces. It
            // arrives as an argument fault rather than an I/O one, and it is a rejection like any other.
            return Reject(logger, sourcePath, ex.Message);
        }
        catch (NotSupportedException ex)
        {
            return Reject(logger, sourcePath, ex.Message);
        }

        // Screened before it is deserialized, over EVERY object scope. A member named twice makes the
        // document say two things and lets the deserializer pick one silently, which on this surface decides
        // a client id, an endpoint or a secret - and the whole document is handed to a deserializer whose
        // indexed member set this caller does not narrow, so there is no smaller set of scopes to name. It
        // is refused rather than resolved, which is the same posture the discovery read takes.
        var screened = StrictJson.Inspect(text, out var repeatedMember);
        if (screened != StrictJson.Verdict.Clean)
        {
            var reason = screened == StrictJson.Verdict.Repeated
                ? $"the document names the member '{repeatedMember}' twice in one object, so it says two things at once"
                : "the document could not be read to the end";
            return Reject(logger, sourcePath, reason);
        }

        ConfigExportDocument? document;
        try
        {
            document = JsonSerializer.Deserialize<ConfigExportDocument>(text, ReadOptions);
        }
        catch (JsonException ex)
        {
            return Reject(logger, sourcePath, ex.Message);
        }

        if (document is null)
        {
            return Reject(logger, sourcePath, "the file holds no document");
        }

        // Applied to a DETACHED COPY of the live configuration first. That is what makes the whole document
        // validate before anything is mutated, and it is also the comparison that keeps a restart loop from
        // rewriting config.xml: the copy either refuses the document or shows exactly what the live
        // configuration would become, and both answers are reached without touching it.
        string? rejection = null;
        var changed = store.Read(live =>
        {
            var candidate = live.DetachedCopy();
            try
            {
                // No break-glass resolver: this runs during plugin construction, where no user manager
                // exists, so a document asserting SSO-only login cannot prove a surviving admin password
                // path and the whole document is refused. That mode is turned on through the elevated,
                // audited SSO-Only endpoints, never by a file.
                ConfigImport.Apply(candidate, document);
            }
            catch (ArgumentException ex)
            {
                rejection = ex.Message;
                return false;
            }

            return !string.Equals(candidate.ToPersistedForm(), live.ToPersistedForm(), StringComparison.Ordinal);
        });

        if (rejection is not null)
        {
            return Reject(logger, sourcePath, rejection);
        }

        if (!changed)
        {
            if (logger?.IsEnabled(LogLevel.Debug) == true)
            {
                logger.LogDebug(
                    "The declarative SSO configuration at {SourcePath} already matches the stored configuration; nothing was written.",
                    sourcePath.ReplaceLineEndings(string.Empty));
            }

            return DeclarativeLoadOutcome.AlreadyCurrent;
        }

        try
        {
            store.Mutate(live => ConfigImport.Apply(live, document));
        }
        catch (ArgumentException ex)
        {
            // The live configuration moved between the copy and this apply (a login writing a canonical
            // link is the ordinary way). ConfigImport validates before it mutates, so the refusal happened
            // before anything was written and the store persisted nothing.
            return Reject(logger, sourcePath, ex.Message);
        }

        if (logger?.IsEnabled(LogLevel.Information) == true)
        {
            logger.LogInformation(
                "Applied the declarative SSO configuration at {SourcePath} over the stored configuration.",
                sourcePath.ReplaceLineEndings(string.Empty));
        }

        AuditInsecureOptions(logger, document.Configuration);
        return DeclarativeLoadOutcome.Applied;
    }

    // A mounted file that turns off a default-on protection has to leave the same [SSO Audit] trace a form
    // save and a config import already leave (#140/#672). Without this the quietest way to disable audience
    // validation on this server would be the one route that wrote nothing about it, and the declarative
    // source is the route an operator is least likely to be watching at the moment it applies.
    private static void AuditInsecureOptions(ILogger? logger, PluginConfiguration? applied)
    {
        if (logger is null || applied is null)
        {
            return;
        }

        if (applied.OidConfigs is { } oidConfigs)
        {
            foreach (var kvp in oidConfigs)
            {
                var insecure = kvp.Value is null ? null : OidcInsecureToggles.Enabled(kvp.Value);
                if (insecure?.Count > 0)
                {
                    SsoAudit.InsecureOptionsEnabled(logger, "OpenID", kvp.Key, insecure);
                }
            }
        }

        if (applied.SamlConfigs is { } samlConfigs)
        {
            foreach (var kvp in samlConfigs)
            {
                var insecure = kvp.Value is null ? null : SamlInsecureToggles.Enabled(kvp.Value);
                if (insecure?.Count > 0)
                {
                    SsoAudit.InsecureOptionsEnabled(logger, "SAML", kvp.Key, insecure);
                }
            }
        }
    }

    // A rejection is Error rather than Warning: the operator asked for this file to decide the providers,
    // and the server is now running on something else. The reason is echoed with its line endings stripped
    // at the emission point, because it can quote a provider name that came out of the file
    // (cs/log-forging is sanitized inline, never behind a helper).
    private static DeclarativeLoadOutcome Reject(ILogger? logger, string sourcePath, string reason)
    {
        if (logger?.IsEnabled(LogLevel.Error) == true)
        {
            logger.LogError(
                "The declarative SSO configuration at {SourcePath} was rejected and nothing was changed: {Reason}",
                sourcePath.ReplaceLineEndings(string.Empty),
                reason.ReplaceLineEndings(string.Empty));
        }

        return DeclarativeLoadOutcome.Rejected;
    }
}
