// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Audit;

/// <summary>The configuration lines: provider writes, rollbacks, declarative refusals, imports and unreadable stores.</summary>
internal static partial class SsoAudit
{
    /// <summary>Records a provider being added or updated.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    internal static void ProviderConfigured(ILogger logger, string protocol, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] Provider configured: {Protocol} '{Provider}'.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records a provider being removed.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    internal static void ProviderRemoved(ILogger logger, string protocol, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] Provider removed: {Protocol} '{Provider}'.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records that a ConfigurationChanged subscriber threw after a completed save (#1521); the save stands, so the failure is contained here at Warning.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="error">What the subscriber threw; no configuration content is recorded.</param>
    internal static void ConfigurationChangedSubscriberFailed(ILogger logger, Exception error)
    {
        if (logger is null || !logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] A ConfigurationChanged subscriber failed after a completed configuration save ({Reason}). The save itself is stored and live; whatever that subscriber keeps in step with the configuration may not be.",
            error?.Message?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records a configuration write going ahead without an undo because the previous state could not be serialized (#1521); refusing the write would make the configuration permanently unwritable.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="error">What refused the serialization; no configuration content is recorded.</param>
    internal static void ConfigurationRollbackUnavailable(ILogger logger, Exception error)
    {
        if (logger is null || !logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Configuration write proceeding without a rollback: the current configuration could not be serialized for one ({Reason}). If this write fails, the running server keeps the change while the file does not, until the next restart.",
            error?.Message?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records a configuration write that failed and whose undo failed too (#1521): the running server carries a change the file lacks until a restart.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="error">What the restore threw; no configuration content is recorded.</param>
    internal static void ConfigurationRollbackFailed(ILogger logger, Exception error)
    {
        if (logger is null || !logger.IsEnabled(LogLevel.Error))
        {
            return;
        }

        logger.LogError(
            "[SSO Audit] Configuration write failed and could not be rolled back ({Reason}): the running server is carrying a change that is not in the file. Restart the server to put it back on the stored configuration.",
            error?.Message?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records a settings-page save whose change to a declaratively managed provider was ignored and the stored value kept (#1102).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider name; no field value is recorded.</param>
    internal static void DeclarativeWriteIgnored(ILogger logger, string protocol, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Configuration save ignored for {Protocol} provider '{Provider}': it is managed by a declarative source, so the stored value was kept. Edit the source and restart the server to change it.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records a save whose write to a declaratively defined provisioning profile was ignored and the stored value kept (#1102).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="profile">The profile name; no field value is recorded.</param>
    internal static void DeclarativeProfileWriteIgnored(ILogger logger, string profile)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Configuration save ignored for provisioning profile '{Profile}': it is defined by a declarative source, so the stored value was kept. Edit the source and restart the server to change it.",
            profile?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records an elevated single-provider door refusing to alter or delete a declaratively managed provider (#1415); unlike the settings page it cannot half-honour the request, so nothing is written.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="door">The route that was refused, such as <c>OID/Del</c>.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider name; no field value is recorded.</param>
    /// <param name="source">The declarative source that owns the provider.</param>
    internal static void DeclarativeWriteRefused(ILogger logger, string door, string protocol, string provider, string source)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] {Door} refused for {Protocol} provider '{Provider}': it is managed by the declarative source {Source}, so nothing was written. Edit that source and restart the server to change it.",
            door?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            source?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>Records a whole-document write refused because the document redefines a declaratively defined profile (#1102); an import is all-or-nothing.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="door">The route that was refused, such as <c>Config/Import</c>.</param>
    /// <param name="profile">The profile name; no field value is recorded.</param>
    /// <param name="source">The declarative source that defined the profile.</param>
    internal static void DeclarativeProfileWriteRefused(ILogger logger, string door, string profile, string source)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] {Door} refused for provisioning profile '{Profile}': it is defined by the declarative source {Source}, so nothing was written. Edit that source and restart the server to change it.",
            door?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            profile?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            source?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>Records that a provider's authorization server does not advertise PKCE S256 support (#141).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The provider name.</param>
    internal static void PkceNotAdvertised(ILogger logger, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] OpenID provider '{Provider}' does not advertise PKCE (S256) in its discovery document (code_challenge_methods_supported). PKCE is still sent, but a server that ignores it leaves cross-session authorization-code injection undetectable (RFC 9700 §2.1.1). Set RequirePkce to fail closed once the provider supports it.",
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records an administrator importing a configuration document (#161).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="oidProviders">How many OpenID providers the import merged.</param>
    /// <param name="samlProviders">How many SAML providers the import merged.</param>
    internal static void ConfigImported(ILogger logger, int oidProviders, int samlProviders)
        => logger.LogWarning(
            "[SSO Audit] Configuration imported by an administrator: {OidProviders} OpenID and {SamlProviders} SAML provider(s) merged. Server-managed secrets and links were preserved; redacted secrets must be re-entered on this instance.",
            oidProviders,
            samlProviders);

    /// <summary>Records a provider being saved with one or more default-on security checks disabled (#140, #672).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="options">The enabled insecure option names (configuration keys, not user input).</param>
    internal static void InsecureOptionsEnabled(ILogger logger, string protocol, string provider, IReadOnlyList<string> options)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        // Shared by OpenID (#140) and SAML (#672); the option names are configuration keys.
        logger.LogWarning(
            "[SSO Audit] {Protocol} provider '{Provider}' saved with security checks disabled: {Options}. Each switches off a default-on protection on the login path (such as transport, issuer/audience, or endpoint binding); keep them only if the provider genuinely requires it.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            string.Join(", ", options));
    }

    /// <summary>Records that the stored configuration could not be read at start (#1543): defaults are served and SSO refuses until a configuration arrives; Error, naming the preserved copy or its absence.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="configurationFilePath">The configuration file that failed to read back.</param>
    /// <param name="preservedCopyPath">Where the damaged file was copied, or <see langword="null"/> when the copy failed.</param>
    internal static void UnreadableConfigurationFound(ILogger logger, string configurationFilePath, string? preservedCopyPath)
    {
        if (!logger.IsEnabled(LogLevel.Error))
        {
            return;
        }

        if (preservedCopyPath is null)
        {
            logger.LogError(
                "[SSO Audit] {ConfigurationFile} could not be read, and NO copy of it was kept. Default settings are being served, the server is about to overwrite the file with them, and every SSO sign-in is refused with 503 until a configuration holding at least one provider is saved or imported, or the stored file is restored and the server started again - a save that carries no provider does not end it, and a server serving defaults usually has none to save. This plugin does not touch Jellyfin password sign-in - but an account it provisioned has none, and on a server that was in SSO-only mode the accounts it repointed have none either, so the only certain way in is the break-glass administrator. If nobody can sign in at all, move the unreadable configuration file out of the way and delete the marker file beside it - the one whose name is the configuration file plus .unreadable, with no timestamp on the end - then restart: SSO then answers as it did before this check existed. Keep any timestamped copies lying beside the configuration file rather than deleting them: they are from an earlier fault, or from an earlier boot of this one whose record was lost, and one of them may hold more than this server now has.",
                configurationFilePath?.ReplaceLineEndings(string.Empty));
            return;
        }

        logger.LogError(
            "[SSO Audit] {ConfigurationFile} could not be read. It was copied to {PreservedCopy} before the server overwrites it. Default settings are being served - no provider, no account link, no stored secret - and every SSO sign-in is refused with 503 until a configuration holding at least one provider is saved or imported, or the stored file is restored and the server started again. A save that carries no provider does not end it, and a server serving defaults usually has none to save. This plugin does not touch Jellyfin password sign-in - but an account it provisioned has none, and on a server that was in SSO-only mode the accounts it repointed have none either, so the only certain way in is the break-glass administrator. If nobody can sign in at all, move the unreadable configuration file out of the way and delete the marker file beside it - the one whose name is the configuration file plus .unreadable, with no timestamp on the end - then restart: SSO then answers as it did before this check existed. Do not delete it, nor any other timestamped copy beside the configuration file: the one named above is what was kept this time, and any others are from earlier boots or earlier faults and may hold more than it does.",
            configurationFilePath?.ReplaceLineEndings(string.Empty),
            preservedCopyPath?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>Records that the damaged configuration could not be copied aside (#1543); its own line, because lost evidence is a different failure from an unreadable file.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="preservedCopyPath">The copy that was attempted.</param>
    /// <param name="error">Why the copy failed.</param>
    internal static void UnreadableConfigurationNotPreserved(ILogger logger, string preservedCopyPath, Exception error)
        => logger.LogError(
            error,
            "[SSO Audit] The unreadable configuration could not be copied to {PreservedCopy}. The line after this one says what copy, if any, remains.",
            preservedCopyPath?.ReplaceLineEndings(string.Empty));

    /// <summary>Records that the readability check could not open the configuration and decided nothing (#1543); Warning, because the host's own read may still succeed.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="configurationFilePath">The configuration file that could not be read.</param>
    /// <param name="error">Why it could not be read.</param>
    internal static void UnreadableConfigurationCheckSkipped(ILogger logger, string configurationFilePath, Exception error)
        => logger.LogWarning(
            error,
            "[SSO Audit] {ConfigurationFile} could not be opened for the startup readability check, so it was not judged. If the server can read it, nothing is wrong; if it cannot, it will serve default settings without this warning saying so.",
            configurationFilePath?.ReplaceLineEndings(string.Empty));

    /// <summary>Records that an earlier start found the configuration unreadable and none has been supplied since (#1543); the marker is believed over the file the host rewrote.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="configurationFilePath">The configuration file now holding defaults.</param>
    /// <param name="preservedCopyPath">Where the damaged file was kept, or <see langword="null"/> when no copy is recorded or the recorded one is gone.</param>
    internal static void UnreadableConfigurationStillUnrepaired(ILogger logger, string configurationFilePath, string? preservedCopyPath)
        => logger.LogError(
            "[SSO Audit] {ConfigurationFile} was unreadable at an earlier start and no configuration has been supplied since, so this server is still serving default settings and still refusing every SSO sign-in. The copy kept for this incident: {PreservedCopy}. Save or import a configuration holding at least one provider to clear this; if no administrator can sign in at all, move the unreadable configuration file out of the way, delete the marker file beside it - the configuration file plus .unreadable, with no timestamp - and restart. Do not delete the copy named above, nor any other timestamped copy beside the configuration file: the one named is this incident's, and an earlier one may hold more than it does.",
            configurationFilePath?.ReplaceLineEndings(string.Empty),
            preservedCopyPath?.ReplaceLineEndings(string.Empty) ?? "none recorded, or the recorded one is no longer beside the configuration");

    /// <summary>Records the configuration coming back on disk while the marker stood (#1543), which ends the refusal.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="configurationFilePath">The configuration file that now holds providers again.</param>
    internal static void UnreadableConfigurationRepairedOnDisk(ILogger logger, string configurationFilePath)
        => logger.LogWarning(
            "[SSO Audit] {ConfigurationFile} holds a configuration again, so this server stops serving defaults and accepts SSO sign-in. The preserved copy of the unreadable file is left where it is.",
            configurationFilePath?.ReplaceLineEndings(string.Empty));

    /// <summary>Records that the marker keeping the refusal across a restart could not be written (#1543); reported rather than thrown, because it costs only the restart.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="markerPath">The marker that could not be written.</param>
    /// <param name="error">Why it could not be written.</param>
    internal static void UnreadableConfigurationMarkerNotWritten(ILogger logger, string markerPath, Exception error)
        => logger.LogError(
            error,
            "[SSO Audit] The marker {MarkerPath} could not be written. This server is serving default settings and refusing SSO now, but a restart will forget that and answer as though no provider were configured.",
            markerPath?.ReplaceLineEndings(string.Empty));

    /// <summary>Records that the marker could not be removed after a configuration arrived (#1543); a restart would refuse again.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="markerPath">The marker that could not be removed.</param>
    /// <param name="error">Why it could not be removed.</param>
    internal static void UnreadableConfigurationMarkerNotCleared(ILogger logger, string markerPath, Exception error)
        => logger.LogError(
            error,
            "[SSO Audit] The marker {MarkerPath} could not be removed. SSO is accepted again now, but a restart would refuse it once more; delete that file by hand.",
            markerPath?.ReplaceLineEndings(string.Empty));

    /// <summary>Records a configuration with a provider arriving while defaults were served (#1543), which ends the refusal; it names what landed and not who, because this line cannot know the caller.</summary>
    /// <param name="logger">The logger.</param>
    internal static void UnreadableConfigurationCleared(ILogger logger)
        => logger.LogWarning(
            "[SSO Audit] A configuration holding at least one provider was persisted; the server stops serving defaults and SSO sign-in is accepted again. The preserved copy of the unreadable file is left where it is.");

    /// <summary>Records a second copy of this plugin loaded into the same server (#1601), naming the files and the preserved copy, because the remedy is deleting a directory.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="installLocations">The file each loaded copy came from.</param>
    /// <param name="preservedCopyPath">Where the configuration was copied, or <see langword="null"/> when it was not.</param>
    internal static void DuplicateInstallFound(ILogger logger, string installLocations, string? preservedCopyPath)
    {
        if (!logger.IsEnabled(LogLevel.Error))
        {
            return;
        }

        if (preservedCopyPath is null)
        {
            logger.LogError(
                "[SSO Audit] This plugin is loaded TWICE in this server, from {InstallLocations}, and NO copy of the configuration was kept. Two copies register every route twice, so the settings page answers nothing, and the host cannot read a configuration back across them - it serves defaults and writes them over the file, destroying every provider it holds. Every configuration write from this plugin is refused while this lasts. Stop the server, keep exactly ONE plugin directory for this plugin under the plugins folder, delete the others, and start it again. A downgrade through the plugin catalog is what usually leaves two: it adds the older version beside the newer one instead of replacing it.",
                installLocations.ReplaceLineEndings(string.Empty));
            return;
        }

        logger.LogError(
            "[SSO Audit] This plugin is loaded TWICE in this server, from {InstallLocations}. The configuration was copied to {PreservedCopy} first, and that copy is what to restore from. Two copies register every route twice, so the settings page answers nothing, and the host cannot read a configuration back across them - it serves defaults and writes them over the file. Every configuration write from this plugin is refused while this lasts. Stop the server, keep exactly ONE plugin directory for this plugin under the plugins folder, delete the others, start it again, and put the copy back over SSO-Auth.xml if the providers are gone from it. A downgrade through the plugin catalog is what usually leaves two: it adds the older version beside the newer one instead of replacing it.",
            installLocations.ReplaceLineEndings(string.Empty),
            preservedCopyPath.ReplaceLineEndings(string.Empty));
    }
}
