// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Mime;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Events;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Api;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>The configuration and link export and import endpoints.</summary>
public partial class SSOController
{
    /// <summary>
    /// Exports the whole plugin configuration as a redacted, importable document (#161). Requires
    /// administrator privileges, like the other config endpoints - the document lists every provider's
    /// settings. The redaction is the config's OWN JSON-boundary withholding, reused: the provider secrets
    /// (OidSecret, the SAML signing keys) are serialized as null by their WriteOnlySecretConverter (#189) and
    /// the server-managed canonical-link maps are dropped by [JsonIgnore] (#157/#186), so the document carries
    /// no plaintext secret, no <c>ssoenc:</c> envelope, and no link map. The at-rest data-encryption key
    /// (sso-secret.key) lives in a separate file and is never part of the configuration object at all.
    /// </summary>
    /// <returns>The redacted export document.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Config/Export")]
    public ActionResult ExportConfig()
    {
        // Snapshot under the config lock; the JSON formatter redacts the secrets and links as it serializes
        // the returned document (the same withholding OID/Get relies on), after the lock is released.
        return Ok(SSOPlugin.Instance.ReadConfiguration(ConfigExport.Build));
    }

    /// <summary>
    /// Reports which providers, and which provisioning profiles (#1498), a declarative source decided on this
    /// boot, so the config page can render them as managed instead of letting an admin edit a form the next
    /// start wins back (#1104).
    /// Requires administrator privileges, like the other config endpoints. Read-only - it changes nothing,
    /// and it carries provider NAMES only: no field value, no secret and no reference, so nothing here is
    /// sensitive even where the whole set is.
    /// </summary>
    /// <returns>The managed provider set; both lists empty when no declarative source is configured.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Config/Managed")]
    public ActionResult<ManagedProviderSetDocument> ManagedProviders()
    {
        // The set is process state decided during plugin construction, not configuration, so this reads no
        // provider and takes no config lock beyond the one the store holds for its own field.
        var managed = SSOPlugin.Instance.ConfigStore.ManagedProviders;
        return Ok(new ManagedProviderSetDocument
        {
            OidConfigs = managed.OidConfigs,
            SamlConfigs = managed.SamlConfigs,
            ProvisioningProfiles = managed.Profiles,
        });
    }

    /// <summary>Publishes the permission names an administrator may map (#1484), so the config page can offer them instead of letting one be typed and meet a save-time refusal; elevation-gated and read-only.</summary>
    /// <remarks>Derived by <see cref="MappablePermissions"/> from the same classification the save-time validator refuses by, so the vocabulary and the refusal cannot disagree when Jellyfin adds or removes a permission.</remarks>
    /// <returns>The mappable permission names.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Config/Permissions")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult<MappablePermissionDocument> PermissionVocabulary()
    {
        // No config read and no lock: the set is Jellyfin's compiled enum minus this plugin's compiled
        // exclusion set, so it is the same answer on every installation and on every request.
        return Ok(MappablePermissions.Build());
    }

    /// <summary>Exports the account-link table as a portable, username-keyed document (#1126); elevation-gated and read-only.</summary>
    /// <remarks>A separate download from <c>Config/Export</c>, because this one carries identity data an administrator asks for explicitly; keyed on the username so the snapshot survives the user-database rebuild that invalidates every id, and a link whose id no longer resolves is dropped rather than exported dangling.</remarks>
    /// <returns>The link export document.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Config/Links/Export")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult ExportLinks()
    {
        // Snapshot under the config lock so the two protocols' link maps are read atomically against each
        // other; the resolution to usernames happens there too, so the document that leaves the lock holds
        // no user id for the formatter to serialize.
        return Ok(SSOPlugin.Instance.ReadConfiguration(
            live => LinkExport.Build(live, userId => _userManager.GetUserById(userId)?.Username)));
    }

    /// <summary>Lists every Jellyfin account that holds an SSO link, with the provider and canonical name behind each (#1119); elevation-gated and read-only.</summary>
    /// <remarks>The per-user listings answer only for an id the caller already has; this answers which accounts are linked in one read, and unlike the portable export it reports an orphaned link left by a deleted account, which is invisible from every other surface.</remarks>
    /// <returns>The linked-account roster.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Links/Roster")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult LinkedAccountRoster()
    {
        // Snapshot under the config lock so the two protocols' link maps are inverted against each other
        // atomically; the document that leaves the lock holds only strings and ids, so the JSON formatter
        // cannot tear against a concurrent login writing a link.
        // The disabled flag rides along with the username (#1529) so the roster can withhold a pending row
        // whose account somebody has since enabled; the page never reads the flag itself and never infers
        // anything from it - it is the roster agreeing with the approve action, which reads the same flag.
        return Ok(SSOPlugin.Instance.ReadConfiguration(
            live => LinkRoster.Build(
                live,
                userId => _userManager.GetUserById(userId) is { } account
                    ? new LinkedAccountState(account.Username, account.HasPermission(PermissionKind.IsDisabled))
                    : null)));
    }

    /// <summary>Exports the SSO linkages held for one Jellyfin account, across both protocols, in the shape <c>Config/Links/Export</c> produces (#1091); elevation-gated and read-only.</summary>
    /// <remarks>A separate route so an operator answering a data-subject access request can produce that subject's linkages without handling every other account's; throttled, unlike the per-protocol listings, because it is the surface most likely to be driven in a loop over the whole user list.</remarks>
    /// <param name="jellyfinUserId">The Jellyfin user id to export the linkages of.</param>
    /// <returns>The link export document for that account, or 404 when no such account exists.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Links/Export/{jellyfinUserId}")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult ExportUserLinks(Guid jellyfinUserId)
    {
        // Throttle before the account lookup, exactly as Unregister does: the 404 an unknown id produces is
        // an existence answer, and an unthrottled one would enumerate the user table for an administrator
        // whose elevation was borrowed rather than earned.
        if (RateLimitCheck(SsoRateLimitClass.Export) is { } throttled)
        {
            return throttled;
        }

        if (_userManager.GetUserById(jellyfinUserId)?.Username is not { } username)
        {
            return NotFound("No Jellyfin account exists with that user id.");
        }

        // The export is the whole-table builder with a resolver that answers for this one id and null for
        // every other, so the filtering falls out of the rule that already drops a link no account resolves
        // to - there is no second walk of the link maps to keep in step with the first. Resolved once here
        // rather than inside the lambda so the user manager is not called under the config lock.
        return Ok(SSOPlugin.Instance.ReadConfiguration(
            live => LinkExport.Build(live, userId => userId == jellyfinUserId ? username : null)));
    }

    /// <summary>Imports a configuration export document into this instance (#161) as a fail-closed merge: validated whole through the same validator the config-page save uses, then merged atomically with the stored secrets and server-managed links preserved.</summary>
    /// <remarks>A provider new to this instance arrives with a blank secret and fails its login closed until an administrator re-enters it; the request body is size-capped so an oversized document is rejected before it is parsed.</remarks>
    /// <param name="document">The export document to import.</param>
    /// <returns>No content on success, or 400 when the document is missing, unsupported, or invalid.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("Config/Import")]
    [RequestSizeLimit(ConfigImportMaxBytes)]
    [Consumes(MediaTypeNames.Application.Json)]
    public ActionResult ImportConfig([FromBody] ConfigExportDocument document)
    {
        if (document is null)
        {
            return BadRequest("The configuration import document is missing or is not valid JSON.");
        }

        if (RefuseManagedImport(document) is { } managedRefusal)
        {
            return managedRefusal;
        }

        try
        {
            // Validate-then-merge lives in the Config helper; the mutation persists only if it returns without
            // throwing (an invalid document throws inside the lambda, so MutateConfiguration persists nothing).
            // The break-glass resolver lets Apply run the SSO-only activation guard fail-closed on the import
            // path (#165, T-T2): a document asserting SSO-only with no surviving admin login path is rejected.
            SSOPlugin.Instance.MutateConfiguration(configuration => ConfigImport.Apply(configuration, document, _ssoOnly.DescribeBreakGlass));
        }
        catch (ArgumentException ex)
        {
            // The validator and the import throw ArgumentException for a hostile/malformed document (a bad
            // Base URL override, an unloadable certificate/key, a reserved-character provider name, an
            // unsupported version). Strip line endings from the echoed message so it cannot split a log line.
            return BadRequest(ex.Message?.ReplaceLineEndings(string.Empty));
        }

        AuditImportedDocument(document);

        return NoContent();
    }

    // A document naming a declaratively managed provider (#1415) or redefining a managed profile (#1102) refuses
    // the whole import before anything is merged: a partial import that reported success is the worse failure.
    private BadRequestObjectResult? RefuseManagedImport(ConfigExportDocument document)
    {
        // #1415: a document naming a declaratively managed provider refuses the WHOLE import, before anything
        // is merged. The whole document rather than the offending providers, because an import is already
        // all-or-nothing on every other rejection (one invalid provider rejects the document), and because
        // dropping part of a document silently is the worse failure: an administrator restoring a backup
        // would be told it succeeded and would have no way to see which providers did not arrive. Refusing
        // names them, so the repair is to delete those entries from the document and import the rest.
        var managed = SSOPlugin.Instance.ConfigStore.ManagedProviders.NamedIn(document.Configuration);
        if (managed.Count > 0)
        {
            foreach (var (protocol, provider, source) in managed)
            {
                SsoAudit.DeclarativeWriteRefused(_logger, "Config/Import", protocol, provider, source);
            }

            var (firstProtocol, firstProvider, firstSource) = managed[0];
            return BadRequest(string.Create(
                CultureInfo.InvariantCulture,
                $"{ManagedProviderRefusal(firstProtocol, firstProvider, firstSource)} The import names {managed.Count} declaratively managed provider(s) and none of it was applied; remove them from the document and import the rest.").ReplaceLineEndings(string.Empty));
        }

        // #1102: the same refusal for a profile the document REDEFINES. A managed provider is what an
        // administrator sees frozen, but the profile it points at is what that provider actually writes onto
        // a brand-new account, so a document carrying no provider at all can still change what every managed
        // provider grants. The whole document again, for the reason above: a partial import that reported
        // success is the worse failure.
        var managedProfiles = SSOPlugin.Instance.ConfigStore.ManagedProviders.ProfilesNamedIn(document.Configuration);
        if (managedProfiles.Count > 0)
        {
            foreach (var (profile, profileSource) in managedProfiles)
            {
                SsoAudit.DeclarativeProfileWriteRefused(_logger, "Config/Import", profile, profileSource);
            }

            var (firstProfile, firstProfileSource) = managedProfiles[0];
            return BadRequest(string.Create(
                CultureInfo.InvariantCulture,
                $"{ManagedProfileRefusal(firstProfile, firstProfileSource)} The import redefines {managedProfiles.Count} declaratively defined provisioning profile(s) and none of it was applied; remove them from the document and import the rest.").ReplaceLineEndings(string.Empty));
        }

        return null;
    }

    // The import leaves the same trace a form save would: the counts, and every provider that arrived with a
    // security check disabled (#140, #672).
    private void AuditImportedDocument(ConfigExportDocument document)
    {
        // Audit the import and any provider that arrived with a security check disabled (#140), so importing
        // an escape hatch (DisableHttps, DoNotValidateIssuerName, …) leaves the same trace a form save would.
        var oidCount = document.Configuration?.OidConfigs?.Count ?? 0;
        var samlCount = document.Configuration?.SamlConfigs?.Count ?? 0;
        SsoAudit.ConfigImported(_logger, oidCount, samlCount);
        if (document.Configuration?.OidConfigs is { } oidConfigs)
        {
            foreach (var kvp in oidConfigs)
            {
                if (kvp.Value is null)
                {
                    continue;
                }

                var insecure = OidcInsecureToggles.Enabled(kvp.Value);
                if (insecure.Count > 0)
                {
                    SsoAudit.InsecureOptionsEnabled(_logger, OpenIdProtocol, kvp.Key, insecure);
                }
            }
        }

        // A mistaken or hostile import that disables a default-on SAML protection (DoNotValidateAudience)
        // must leave the same [SSO Audit] trace the OpenID escape hatches above do (#672) - the import path
        // is exactly one of the failure scenarios that issue calls out.
        if (document.Configuration?.SamlConfigs is { } samlConfigs)
        {
            foreach (var kvp in samlConfigs)
            {
                if (kvp.Value is null)
                {
                    continue;
                }

                var insecure = SamlInsecureToggles.Enabled(kvp.Value);
                if (insecure.Count > 0)
                {
                    SsoAudit.InsecureOptionsEnabled(_logger, SamlProtocol, kvp.Key, insecure);
                }
            }
        }
    }

    /// <summary>Restores an account-link backup onto this instance (#1129), rebinding every link to the user id this server holds for that username today, the half that completes a server migration after a rebuilt user database issued new ids.</summary>
    /// <remarks>
    /// Fail-closed and atomic: the whole document is validated before a link is written, and the mutation rolls
    /// back on a write failure (#1521), so a rebuilt server gets its complete table back or keeps what it had; the
    /// file itself is not written atomically (#1532). A canonical name already linked to a different account is
    /// rejected rather than overwritten, so a crafted backup cannot remap a subject onto an administrator, and the
    /// import never creates an account, a provider or a user id.
    /// </remarks>
    /// <param name="document">The link export document to restore.</param>
    /// <returns>What the import restored, or 400 when the document is unsupported or carries an entry this instance cannot restore.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("Config/Links/Import")]
    [RequestSizeLimit(ConfigImportMaxBytes)]
    // NO [Produces] HERE, DELIBERATELY, and this endpoint is the one place in the controller where
    // that attribute would cost something. It would retype the refusal body too: the reachable 400 is
    // BadRequest(ex.Message) below, whose literals docs/ACCOUNT-MANAGEMENT-API.md and
    // docs/SERVER-MIGRATION.md quote and LinkImportTests pins, and under [Produces] that plain string
    // is written as a JSON string - quoted, and typed application/json - so the sentence an operator
    // reads on the settings page arrives inside quotation marks. It buys nothing in exchange:
    // measured against a running 10.11.11, Config/Export carries no [Produces] and answers
    // `Content-Type: application/json; charset=utf-8` anyway, including to a caller sending
    // `Accept: application/xml`, so the success body is JSON either way on this host.
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> ImportLinks([FromBody] LinkExportDocument document)
    {
        // Throttle after the elevation guard, before any work (#382, #516): the [Authorize] filter refuses
        // a non-elevated caller before the body runs, so an unauthorized request never reaches the limiter
        // and there is no rate-limit oracle. Past it, this shares the "link" bucket with the single link
        // writes, because it is the same config-XML persist under the global lock - in bulk - and because
        // its refusal names usernames this instance does not hold, which an unthrottled caller could drive
        // in a loop as a user-table oracle.
        if (RateLimitCheck(SsoRateLimitClass.Link) is { } throttled)
        {
            return throttled;
        }

        // A backstop rather than the answer an operator reads. Measured against a running 10.11.11 with
        // this plugin installed, an absent, null or unparseable body is refused by the host model
        // validation before this action runs, so this literal reaches no caller and what a caller gets is
        // a ProblemDetails this plugin neither chooses nor formats. docs/ACCOUNT-MANAGEMENT-API.md quoted
        // this sentence as what such a caller reads until #1520. The arm stays, because the plugin does
        // not own the pipeline that makes it unreachable and a hosted route that stops binding for it
        // would otherwise dereference null.
        if (document is null)
        {
            return BadRequest("The link import document is missing or is not valid JSON.");
        }

        // Every username the document names is resolved BEFORE the lock is taken, and the importer then
        // reads this snapshot rather than the user manager. A document can carry thousands of entries, and
        // resolving each one inside MutateConfiguration would hold the global configuration lock across
        // that many user-manager calls - blocking every login for the duration. Same discipline as
        // ExportUserLinks, which resolves its one username outside the lock for the same reason. A name
        // resolved a moment before the lock is the same answer a name resolved inside it would have given,
        // except in a race with an account being renamed or deleted, where the import's own refusal rules
        // are what decide the outcome either way.
        var directory = document.Links
            .Where(entry => !string.IsNullOrWhiteSpace(entry?.Username))
            .Select(entry => entry.Username!)
            .Distinct(StringComparer.Ordinal)
            .ToDictionary(username => username, username => _userManager.GetUserByName(username), StringComparer.Ordinal);

        // Which of those accounts hold administrator rights, read in the SAME pre-pass and for the same
        // reason (#1559): the rule that uses it runs inside MutateConfiguration, and asking the user
        // manager from in there would hold the global configuration lock across one call per named
        // account, blocking every login for the duration. A set, so the rule is a membership test.
        var administrators = directory.Values
            .Where(user => user is not null && user.HasPermission(PermissionKind.IsAdministrator))
            .Select(user => user!.Id)
            .ToHashSet();

        IReadOnlyList<LinkImportCount> restored;
        try
        {
            // Validate-then-write lives in the Config helper; the mutation persists only if it returns
            // without throwing, so a rejected document leaves the stored link table untouched.
            restored = SSOPlugin.Instance.MutateConfiguration(
                configuration => LinkImport.Apply(
                    configuration,
                    document,
                    username => directory.GetValueOrDefault(username)?.Id,
                    administrators.Contains));
        }
        catch (ArgumentException ex)
        {
            // The importer throws ArgumentException for an unsupported version and for every unrestorable
            // entry. Strip line endings from the echoed message so a username inside it cannot split a log
            // line (cs/log-forging is sanitized inline at the emission point, never behind a helper).
            //
            // THE REFUSAL LEAVES A TRACE (#1518). Only the SUCCESS of an import was recorded, so a control
            // whose job is to surface a migration mistake - and which a hostile backup file also trips -
            // produced nothing an operator reading the log or an incident responder could see. The message
            // is the same text the caller receives and names no canonical name, which is the rule the
            // importer builds its refusals under.
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                // The refusal is a sentence this plugin composed, and its foreign parts - the document's
                // protocol, provider, username and issuer - are substituted where they enter it, in
                // LinkImport.Describe and OidcConfiguredIssuer.Echo (#1566). Substituting the whole sentence
                // here rewrote the plugin's own "[truncated]" marker in the log while the answer on the wire
                // kept it, so the log and the wire disagreed about one refusal. The strip stays inline for
                // cs/log-forging; composedRefusal is named in the conformance rule's exact-print list.
                var composedRefusal = ex.Message;
                _logger.LogWarning("The account-link import was refused and nothing was restored: {Reason}", composedRefusal?.ReplaceLineEndings(string.Empty));
            }

            return BadRequest(ex.Message?.ReplaceLineEndings(string.Empty));
        }

        var result = LinkImportResultDocument.Of(restored);

        SsoAudit.LinksImported(
            _logger,
            await ResolveActorAsync().ConfigureAwait(false),
            result.Restored,
            string.Join(", ", restored.Select(count => $"{count.Protocol} '{count.Provider}': {count.Links.ToString(CultureInfo.InvariantCulture)}")));

        // The count leaves with the ANSWER and not only with the audit line (#1520). Answering 204 made a
        // restore that rebound every link and one that rebound none identical on the wire and identical on
        // the settings page, and that is what let #1517 - an import that silently restored nothing - stand
        // from 4.3.0-beta.43 until it was found by reading the code rather than by anybody using it.
        return Ok(result);
    }
}
