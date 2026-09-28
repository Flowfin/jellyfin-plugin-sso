// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>What one declarative load did, so a caller observes an outcome instead of inferring it from a log line (#1095).</summary>
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

/// <summary>Applies the provider configuration document a mounted file names over the stored configuration at startup (#1095).</summary>
/// <remarks>
/// The document is the export shape, merged through <see cref="ConfigImport"/> onto a detached copy first, so a
/// fault rejects it as a unit and an unchanged document persists nothing. Secrets arrive as references (#1096).
/// See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Config-as-code"/>.
/// </remarks>
internal static class DeclarativeProviderConfig
{
    /// <summary>The environment variable that names the declarative document.</summary>
    internal const string SourcePathVariable = "JELLYFIN_SSO_CONFIG_FILE";

    // Hand-written as often as exported, so a member in another case is matched; an unknown member is still ignored.
    private static readonly JsonSerializerOptions ReadOptions = new() { PropertyNameCaseInsensitive = true };

    /// <summary>Reads the document named by <see cref="SourcePathVariable"/> and applies it to <paramref name="store"/>.</summary>
    /// <param name="store">The configuration store to apply the document through.</param>
    /// <param name="logger">The logger a rejection is reported on.</param>
    /// <param name="revealStoredSecret">Recovers the plaintext of a stored secret (#1096); null skips the comparison that keeps an unchanged envelope.</param>
    /// <returns>What the load did.</returns>
    internal static DeclarativeLoadOutcome ApplyFromEnvironment(
        ProviderConfigStore store,
        ILogger? logger,
        Func<string?, string?>? revealStoredSecret = null)
    {
        try
        {
            return Apply(
                store,
                Environment.GetEnvironmentVariable(SourcePathVariable),
                File.Exists,
                path => File.ReadAllText(path),
                logger,
                Environment.GetEnvironmentVariable,
                ReadReferenceFile,
                revealStoredSecret);
        }
#pragma warning disable CA1031 // Do not catch general exception types
        catch (Exception ex)
#pragma warning restore CA1031
        {
            // Called from the plugin constructor, where an escaping exception takes every SSO login offline.
            if (logger?.IsEnabled(LogLevel.Error) == true)
            {
                logger.LogError(
                    ex,
                    "The declarative SSO configuration could not be applied and nothing was changed. The plugin is running on its stored configuration.");
            }

            return DeclarativeLoadOutcome.Rejected;
        }
    }

    /// <summary>Applies the document at <paramref name="sourcePath"/>, reading the filesystem through the supplied delegates.</summary>
    /// <param name="store">The configuration store to apply the document through.</param>
    /// <param name="sourcePath">The document's path, or null/blank when no source is configured.</param>
    /// <param name="exists">Answers whether the path names a readable document.</param>
    /// <param name="read">Reads the document's text.</param>
    /// <param name="logger">The logger a rejection is reported on.</param>
    /// <param name="readEnvironmentVariable">Reads a variable a secret reference names; the process environment by default.</param>
    /// <param name="readReferenceFile">Reads a file a secret reference names, null when it cannot be read; the filesystem by default.</param>
    /// <param name="revealStoredSecret">Recovers the plaintext of a stored secret (#1096); null skips the comparison that keeps an unchanged envelope.</param>
    /// <returns>What the load did.</returns>
    internal static DeclarativeLoadOutcome Apply(
        ProviderConfigStore store,
        string? sourcePath,
        Func<string, bool> exists,
        Func<string, string> read,
        ILogger? logger,
        Func<string, string?>? readEnvironmentVariable = null,
        Func<string, string?>? readReferenceFile = null,
        Func<string?, string?>? revealStoredSecret = null)
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

        // A member named twice would let the deserializer pick one silently, so it is refused like the discovery read does.
        var screened = StrictJson.Inspect(text, out var repeatedMember);
        if (screened != StrictJson.Verdict.Clean)
        {
            var reason = screened == StrictJson.Verdict.Repeated
                ? $"the document names the member '{repeatedMember}' twice in one object, so it says two things at once"
                : "the document could not be read to the end";
            return Reject(logger, sourcePath, reason);
        }

        // Resolved after the screen and before the deserializer, so the deserializer sees no reference (#1096).
        if (!DeclarativeSecretReference.TryResolve(
            text,
            readEnvironmentVariable ?? Environment.GetEnvironmentVariable,
            readReferenceFile ?? ReadReferenceFile,
            out var resolvedText,
            out var secretRejection))
        {
            return Reject(logger, sourcePath, secretRejection ?? "a secret reference could not be resolved");
        }

        ConfigExportDocument? document;
        try
        {
            document = JsonSerializer.Deserialize<ConfigExportDocument>(resolvedText, ReadOptions);
        }
        catch (JsonException ex)
        {
            return Reject(logger, sourcePath, ex.Message);
        }

        if (document is null)
        {
            return Reject(logger, sourcePath, "the file holds no document");
        }

        return ApplyDocument(store, document, sourcePath, logger, revealStoredSecret);
    }

    /// <summary>Applies an already-parsed document to <paramref name="store"/>, shared by the file and the environment source (#1097).</summary>
    /// <remarks>The atomicity, the merge precedence, the restart-loop promise and the insecure-option audit live here so the two sources cannot disagree.</remarks>
    /// <param name="store">The configuration store to apply the document through.</param>
    /// <param name="document">The parsed document.</param>
    /// <param name="sourcePath">What names the source in a log line: the document's path, or the variable prefix.</param>
    /// <param name="logger">The logger a rejection is reported on.</param>
    /// <param name="revealStoredSecret">Recovers the plaintext of a secret as the store holds it (#1096); null skips that comparison.</param>
    /// <returns>What the apply did.</returns>
    internal static DeclarativeLoadOutcome ApplyDocument(
        ProviderConfigStore store,
        ConfigExportDocument document,
        string sourcePath,
        ILogger? logger,
        Func<string?, string?>? revealStoredSecret)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(document);

        // A detached copy validates the whole document and detects a no-op before the live configuration is touched.
        string? rejection = null;
        var changed = store.Read(live =>
        {
            KeepWhatIsAlreadyStored(document.Configuration, live, revealStoredSecret);

            var candidate = live.DetachedCopy();
            try
            {
                // No break-glass resolver exists during construction, so a document asserting SSO-only login is refused whole.
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
            // A document that changed nothing still decided the providers it names, so the freeze is recorded here too (#1102).
            store.RecordDeclarativelyManaged(document.Configuration, sourcePath);

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
            // The live configuration moved between the copy and this apply; ConfigImport validates before it mutates.
            return Reject(logger, sourcePath, ex.Message);
        }

        // Recorded only after the write landed, so a persist failure the store rolls back freezes nothing (#1534).
        store.RecordDeclarativelyManaged(document.Configuration, sourcePath);

        if (logger?.IsEnabled(LogLevel.Information) == true)
        {
            logger.LogInformation(
                "Applied the declarative SSO configuration at {SourcePath} over the stored configuration.",
                sourcePath.ReplaceLineEndings(string.Empty));
        }

        AuditInsecureOptions(logger, document.Configuration);
        return DeclarativeLoadOutcome.Applied;
    }

    // Every failure to read a referenced file is the same answer, and the resolver turns it into a refusal naming the path.
    private static string? ReadReferenceFile(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    // A resolved secret the store already holds is blanked, so blank-means-keep leaves the at-rest envelope untouched.
    private static void KeepWhatIsAlreadyStored(PluginConfiguration? incoming, PluginConfiguration live, Func<string?, string?>? reveal)
    {
        if (incoming is null || reveal is null)
        {
            return;
        }

        if (incoming.OidConfigs is { } oidConfigs && live.OidConfigs is { } storedOid)
        {
            foreach (var kvp in oidConfigs)
            {
                if (kvp.Value is null
                    || string.IsNullOrWhiteSpace(kvp.Value.OidSecret)
                    || !storedOid.TryGetValue(kvp.Key, out var stored)
                    || stored is null)
                {
                    continue;
                }

                // On a repoint ServerManagedFields drops the stored secret on purpose (#186), so blanking would leave none.
                if (!string.Equals(kvp.Value.OidEndpoint, stored.OidEndpoint, StringComparison.Ordinal)
                    || !string.Equals(kvp.Value.OidClientId, stored.OidClientId, StringComparison.Ordinal))
                {
                    continue;
                }

                if (IsAlreadyStored(reveal, stored.OidSecret, kvp.Value.OidSecret))
                {
                    kvp.Value.OidSecret = null;
                }
            }
        }

        if (incoming.SamlConfigs is { } samlConfigs && live.SamlConfigs is { } storedSaml)
        {
            foreach (var kvp in samlConfigs)
            {
                if (kvp.Value is null || !storedSaml.TryGetValue(kvp.Key, out var stored) || stored is null)
                {
                    continue;
                }

                // No identity guard here, because ServerManagedFields has none for a SAML signing key either.
                if (IsAlreadyStored(reveal, stored.SamlSigningKeyPfx, kvp.Value.SamlSigningKeyPfx))
                {
                    kvp.Value.SamlSigningKeyPfx = null;
                }

                if (IsAlreadyStored(reveal, stored.SamlRolloverSigningKeyPfx, kvp.Value.SamlRolloverSigningKeyPfx))
                {
                    kvp.Value.SamlRolloverSigningKeyPfx = null;
                }
            }
        }
    }

    private static bool IsAlreadyStored(Func<string?, string?> reveal, string? stored, string? resolved)
    {
        if (string.IsNullOrWhiteSpace(resolved) || string.IsNullOrEmpty(stored))
        {
            return false;
        }

        try
        {
            return string.Equals(reveal(stored), resolved, StringComparison.Ordinal);
        }
        catch (CryptographicException)
        {
            // An envelope this instance cannot read is handed to the merge and the persist boundary, which fail closed on it.
            return false;
        }
    }

    // A file that turns off a default-on protection leaves the same audit trace a form save does (#140, #672).
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

    /// <summary>Reports a rejection and answers <see cref="DeclarativeLoadOutcome.Rejected"/>, shared by both declarative sources.</summary>
    /// <remarks>Error rather than Warning, because the operator asked for this source to decide the providers and the server now runs on something else.</remarks>
    /// <param name="logger">The logger the rejection is reported on.</param>
    /// <param name="sourcePath">What names the source: the document's path, or the variable prefix.</param>
    /// <param name="reason">Why the source was refused.</param>
    /// <returns>Always <see cref="DeclarativeLoadOutcome.Rejected"/>.</returns>
    internal static DeclarativeLoadOutcome Reject(ILogger? logger, string sourcePath, string reason)
    {
        if (logger?.IsEnabled(LogLevel.Error) == true)
        {
            logger.LogError(
                "The declarative SSO configuration at {SourcePath} was rejected and nothing was changed: {Reason}",
                sourcePath.ReplaceLineEndings(string.Empty),
                reason.ReplaceLineEndings(string.Empty).Replace('[', '('));
        }

        return DeclarativeLoadOutcome.Rejected;
    }
}
