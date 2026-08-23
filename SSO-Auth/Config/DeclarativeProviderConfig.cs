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
/// clicking through the settings page. The foundation of #828; the secrets it carries are references rather
/// than values and are resolved by <see cref="DeclarativeSecretReference"/> (#1096), while the
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
/// secret, so a document that carries none does not blank one out.
/// </para>
/// <para>
/// A secret is never written into the document. <see cref="DeclarativeSecretReference"/> resolves the
/// <c>Env</c> and <c>File</c> reference forms into it just before it is deserialized (#1096), and refuses a
/// document that spells a secret out, so the file this loader reads can live wherever the deployment keeps
/// the rest of its configuration without carrying a client secret or a signing key there. A reference that
/// cannot be resolved rejects the whole document exactly like any other fault; nothing falls back to a blank
/// secret, because a blank one is KEPT rather than applied and would leave the server running on its
/// previous secret with nothing said about it.
/// </para>
/// <para>
/// A resolved secret the store already holds is put back to blank before the merge, so the encrypted value
/// at rest survives untouched. Without that the restart-loop promise below would not survive the first
/// reference: what is stored is an envelope and what a reference resolves to is the plaintext inside it, so
/// the two never compare equal and every boot would rewrite <c>config.xml</c>.
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
    /// <param name="revealStoredSecret">
    /// Recovers the plaintext of a secret as the store holds it, so a reference resolving to what is already
    /// stored leaves the at-rest envelope alone (#1096). Null skips that comparison, which costs a rewrite
    /// rather than correctness.
    /// </param>
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
    /// <param name="readEnvironmentVariable">Reads a variable a secret reference names; the process environment by default.</param>
    /// <param name="readReferenceFile">Reads a file a secret reference names, null when it cannot be read; the filesystem by default.</param>
    /// <param name="revealStoredSecret">
    /// Recovers the plaintext of a secret as the store holds it (#1096). Null skips the comparison that keeps
    /// an unchanged secret's at-rest envelope, which costs a rewrite rather than correctness.
    /// </param>
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

        // The secrets arrive as references and are resolved into the document HERE, after the repeated-member
        // screen and before the deserializer, so the pass that decides a secret reads the same bytes the
        // screen just cleared and hands the deserializer a document with no reference left in it (#1096).
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

    /// <summary>
    /// Applies an already-parsed document to <paramref name="store"/>, which is everything the two
    /// declarative sources do identically once each has produced a document (#1097).
    /// </summary>
    /// <remarks>
    /// The whole of the atomicity, the merge precedence, the restart-loop promise and the insecure-option
    /// audit live here rather than at either caller, so the mounted file and the environment cannot come to
    /// disagree about them. What each caller owns is only the way it turns its own source into a document
    /// and refuses one it cannot.
    /// </remarks>
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

        // Applied to a DETACHED COPY of the live configuration first. That is what makes the whole document
        // validate before anything is mutated, and it is also the comparison that keeps a restart loop from
        // rewriting config.xml: the copy either refuses the document or shows exactly what the live
        // configuration would become, and both answers are reached without touching it.
        string? rejection = null;
        var changed = store.Read(live =>
        {
            KeepWhatIsAlreadyStored(document.Configuration, live, revealStoredSecret);

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

        // Recorded before both accepting returns below, and on BOTH of them (#1102). A document that changed
        // nothing still decided the providers it names - it agrees with the store rather than being absent
        // from it - so releasing those providers to the config page whenever a restart happens to find the
        // mount already applied would make the freeze depend on whether anything moved.
        store.RecordDeclarativelyManaged(document.Configuration);

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

    // The filesystem behind a secret reference. A path that cannot be read is null rather than an exception,
    // because every way of failing to read one is the same answer to the only question the resolver asks -
    // "does this reference produce a secret" - and the resolver turns that answer into a refusal naming the
    // path. The document's own read keeps its typed catches: there the reason reaches the operator.
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

    // A resolved secret that is ALREADY the stored one is put back to blank, so the merge keeps the encrypted
    // value at rest instead of writing the plaintext over it. Without this the loader's restart-loop promise
    // dies at the first reference: what is stored is an ssoenc: envelope, what a reference resolves to is the
    // plaintext inside it, the two never compare equal, and every boot rewrites config.xml with a freshly
    // nonced envelope. Blank means keep, which is the rule ServerManagedFields already carries for every
    // other write path, so this reaches the outcome through that rule rather than beside it.
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

                // Only while the provider's identity is unchanged. On a repoint ServerManagedFields drops the
                // stored secret ON PURPOSE (#186), so blanking here would hand that provider no secret at all
                // - the one case where "already stored" is true and keeping it is still wrong.
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

                // No identity guard on this arm, because ServerManagedFields has none either: a SAML signing
                // key is never transmitted, so blank-means-keep holds for it whatever else the document moved.
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
            // A stored envelope this instance can no longer read - the key file is gone. Answering "not the
            // same" hands that case to the merge and the persist boundary, which already fail closed on
            // exactly that pairing, rather than deciding it here on a comparison that could not be made.
            return false;
        }
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

    /// <summary>
    /// Reports a rejection and answers <see cref="DeclarativeLoadOutcome.Rejected"/>, shared by both
    /// declarative sources so a refused file and a refused environment read identically in the log.
    /// </summary>
    /// <remarks>
    /// Error rather than Warning: the operator asked for this source to decide the providers, and the server
    /// is now running on something else. The reason is echoed with its line endings stripped at the emission
    /// point, because it can quote a provider name that came out of the source (cs/log-forging is sanitized
    /// inline, never behind a helper).
    /// </remarks>
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
                reason.ReplaceLineEndings(string.Empty));
        }

        return DeclarativeLoadOutcome.Rejected;
    }
}
