// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using Jellyfin.Plugin.SSO_Auth.Api.Routing;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for the provider forms in the admin page: every persisting field id matches a config property, and every persisting field is rendered.
/// </content>
public partial class ArchitectureConformanceTests
{
    [Fact]
    public void ProviderFormFieldIds_MatchOidConfigProperties()
    {
        // The provider settings form's save contract (#365), locked in as a fitness function. config.js
        // saveProvider persists each marked input as current_config[element.id] = value, so every input
        // bearing a persisting behavior-marker class MUST have an id equal to a real OidConfig property -
        // otherwise it renders but silently never saves, because the server drops JSON members that are not
        // OidConfig properties. The five marker classes mirror config.js listArgumentsByType
        // (sso-text/sso-line-list/sso-toggle) plus the two populate-helper widgets (sso-folder-list =
        // EnabledFolders, sso-role-map = FolderRoleMapping). The provider-name input is deliberately
        // unmarked - its value is the OidConfigs dictionary key, not a property - so it is not scanned.
        // Matching is token-exact (so sso-role-map does not swallow sso-role-mapping-container), and the
        // scan is scoped to #sso-new-oidc-provider so a future SAML form (whose fields map to SamlConfig)
        // would not be checked against OidConfig. The forward check (every marked id is a real property) is
        // paired below with a reverse pin (every security-critical property is still a marked field), so
        // neither a mistyped id nor a dropped marker class can silently break a security setting's save.
        var markerClasses = new[] { "sso-text", "sso-line-list", "sso-toggle", "sso-folder-list", "sso-role-map" };

        var form = OidcProviderFormMarkup(
            File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "configPage.html")));

        var oidConfigProperties = typeof(OidConfig)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .ToHashSet(StringComparer.Ordinal);

        var matchedIds = new HashSet<string>(StringComparer.Ordinal);
        var offenders = new List<string>();
        foreach (Match tag in Regex.Matches(form, "<[a-zA-Z][^>]*>", RegexOptions.Singleline))
        {
            var classAttr = Regex.Match(tag.Value, "class=\"([^\"]*)\"", RegexOptions.Singleline);
            if (!classAttr.Success)
            {
                continue;
            }

            var classes = classAttr.Groups[1].Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (!classes.Any(c => markerClasses.Contains(c, StringComparer.Ordinal)))
            {
                continue;
            }

            // (?<![-\w]) so an attribute whose name merely ends in "id" (a future data-id, gridid, …) is
            // not misread as the element id; an id attribute is preceded by whitespace or the tag open.
            var idMatch = Regex.Match(tag.Value, "(?<![-\\w])id=\"([^\"]*)\"", RegexOptions.Singleline);
            var id = idMatch.Success ? idMatch.Groups[1].Value : "(no id)";
            matchedIds.Add(id);
            if (!oidConfigProperties.Contains(id))
            {
                offenders.Add($"{id} (classes: {classAttr.Groups[1].Value.Trim()})");
            }
        }

        // Guard against a vacuous pass (a broken regex or a renamed form marker silently matching nothing):
        // one sentinel id per marker class must have been scanned, proving the parser reached the form and
        // every marker class is live.
        var sentinels = new[] { "OidEndpoint", "Roles", "Enabled", "EnabledFolders", "FolderRoleMapping" };
        var missingSentinels = sentinels.Where(s => !matchedIds.Contains(s)).ToList();
        Assert.True(
            missingSentinels.Count == 0,
            "The provider-form scan did not reach expected fields (broken parse or renamed marker class?); missing sentinels: " + string.Join(", ", missingSentinels));

        // Reverse direction: the forward check catches a mistyped id, but dropping a marker class entirely
        // - the exact operation this contract change performs on the provider-name field - would silently
        // stop a field persisting while leaving the forward check green. For a security setting that is
        // fail-open (the server keeps the stored value; the admin can no longer harden it), so pin the
        // security-critical settings: each MUST remain a marked, correctly-typed persisting field. Extend
        // this roster in the same PR that surfaces a new security toggle in the admin form; a deliberately
        // XML-only toggle is not a form field and so stays out of this roster until it is surfaced (as
        // RequireVerifiedEmailForAdoption was, #484/#488, and RequireVerifiedEmailForLogin was, #524).
        var securityCritical = new[]
        {
            "EnableAuthorization", "OidSecret", "DisableHttps", "DisablePushedAuthorization",
            "DoNotValidateEndpoints", "DoNotValidateIssuerName", "DoNotValidateResponseIssuer",
            "AllowPrivateNetworkAddresses",
            "DoNotLoadProfile", "RequirePkce", "AllowExistingAccountLink",
            "RequireVerifiedEmailForAdoption", "RequireVerifiedEmailForLogin",
            "RequireAcr", "AcrValues",
        };
        var unsaved = securityCritical.Where(p => !matchedIds.Contains(p)).ToList();
        Assert.True(
            unsaved.Count == 0,
            "These security-critical settings must remain persisting provider-form fields (a marked input whose id equals the OidConfig property); missing or unmarked: " + string.Join(", ", unsaved));

        Assert.True(
            offenders.Count == 0,
            "Every persisting provider-form field (sso-text/sso-line-list/sso-toggle/sso-folder-list/sso-role-map) must have an id equal to an OidConfig property; these do not: " + string.Join(" | ", offenders));
    }

    [Fact]
    public void ProviderForm_RendersEveryPersistingFieldId()
    {
        // The full save-contract roster, pinned after the #365 provider-workspace redesign reordered and
        // regrouped the form into native accordion sections. ProviderFormFieldIds_MatchOidConfigProperties
        // guards the FORWARD direction (no stray marked id) and a reverse pin for the security-critical
        // SUBSET; this test is the exhaustive reverse pin: every persisting field must still render as a
        // marked input with its exact id, so a field silently dropped or unmarked during a future re-layout -
        // which would stop it persisting - fails here rather than shipping as silent data loss. The
        // provider-name KEY input (OidProviderName) is deliberately unmarked (it supplies the OidConfigs
        // dictionary key, not an OidConfig property) and is asserted present separately.
        //
        // The roster is compared as a SET IN BOTH DIRECTIONS (#934). A subset assertion silently tolerated a
        // newly added field that nobody listed here - which is exactly how DisableAvatarFromPictureClaim
        // (#723) and RoleClaimIsObjectMap escaped it - so a new form field now fails this test until it is
        // rostered, instead of shipping outside the guard.
        var markerClasses = new[] { "sso-text", "sso-line-list", "sso-toggle", "sso-folder-list", "sso-role-map" };
        var form = OidcProviderFormMarkup(
            File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "configPage.html")));

        var markedIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match tag in Regex.Matches(form, "<[a-zA-Z][^>]*>", RegexOptions.Singleline))
        {
            var classAttr = Regex.Match(tag.Value, "class=\"([^\"]*)\"", RegexOptions.Singleline);
            if (!classAttr.Success)
            {
                continue;
            }

            var classes = classAttr.Groups[1].Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (!classes.Any(c => markerClasses.Contains(c, StringComparer.Ordinal)))
            {
                continue;
            }

            var idMatch = Regex.Match(tag.Value, "(?<![-\\w])id=\"([^\"]*)\"", RegexOptions.Singleline);
            if (idMatch.Success)
            {
                markedIds.Add(idMatch.Groups[1].Value);
            }
        }

        var expected = new[]
        {
            "OidEndpoint", "OidClientId", "OidSecret", "OidScopes", "Enabled",
            "EnableAuthorization", "DefaultUsernameClaim", "DefaultProvider", "AvatarUrlFormat", "DisableAvatarFromPictureClaim",
            "RoleClaim", "RoleClaimIsObjectMap",
            "Roles", "AdminRoles", "EnableAllFolders", "EnabledFolders", "EnableFolderRoles", "FolderRoleMapping",
            "EnableLiveTvRoles", "LiveTvRoles", "LiveTvManagementRoles", "EnableLiveTv", "EnableLiveTvManagement",
            "DoNotLoadProfile", "SchemeOverride", "PortOverride", "BaseUrlOverride",
            "RequirePkce", "AllowExistingAccountLink", "ProvisionNewUsersDisabled", "SyncUsernameFromProvider", "RequireVerifiedEmailForAdoption", "RequireVerifiedEmailForLogin",
            "AcrValues", "Prompt", "MaxAge", "RequireAcr",
            "DisableHttps", "DisablePushedAuthorization", "DoNotValidateEndpoints", "DoNotValidateIssuerName", "DoNotValidateResponseIssuer",
            "AllowPrivateNetworkAddresses",
            "HideLoginButton", "LoginButtonText", "PostLogoutRedirectUri",
        };

        Assert.Equal(46, expected.Length);
        var missing = expected.Where(id => !markedIds.Contains(id)).ToList();
        Assert.True(
            missing.Count == 0,
            "These persisting provider-form fields are missing their marked input in configPage.html (a re-layout dropped or unmarked them, so they would stop persisting): " + string.Join(", ", missing));

        // The other direction: a marked input nobody rostered is a field that shipped outside this guard.
        var unrostered = markedIds.Where(id => !expected.Contains(id, StringComparer.Ordinal)).OrderBy(id => id, StringComparer.Ordinal).ToList();
        Assert.True(
            unrostered.Count == 0,
            "These provider-form fields render a marked input but are not in this test's roster, so they are outside the persistence guard - add them to `expected` and bump its count: " + string.Join(", ", unrostered));

        // The provider-name KEY input must still be present (unmarked by design).
        Assert.Contains("id=\"OidProviderName\"", form, StringComparison.Ordinal);
    }

    [Fact]
    public void ProviderFormFieldIds_MatchSamlConfigProperties()
    {
        // The SAML provider form's save contract (#725), locked in as the SamlConfig-side twin of
        // ProviderFormFieldIds_MatchOidConfigProperties. config.js saveSamlProvider persists each marked
        // input as current_config[samlPropOf(element.id)] = value, where samlPropOf strips the mandatory
        // "saml-" id prefix (the prefix keeps every SAML field id unique in a document the OpenID form already
        // populated). So every input bearing a persisting marker class MUST (a) have a "saml-"-prefixed id and
        // (b) once stripped, equal a real SamlConfig property - otherwise it renders but silently never saves,
        // because the server drops JSON members that are not SamlConfig properties. The scan is scoped to
        // #sso-new-saml-provider so it is checked against SamlConfig, never OidConfig. Paired below with a
        // reverse security-critical pin so neither a mistyped id nor a dropped marker class can silently break
        // a SAML security setting's save.
        var markerClasses = new[] { "sso-text", "sso-line-list", "sso-toggle", "sso-folder-list", "sso-role-map" };

        var form = SamlProviderFormMarkup(
            File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "configPage.html")));

        var samlConfigProperties = typeof(SamlConfig)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .ToHashSet(StringComparer.Ordinal);

        // matchedProps holds the STRIPPED property names (samlPropOf) so the sentinel/security pins below read
        // as plain SamlConfig property names, mirroring the OpenID test.
        var matchedProps = new HashSet<string>(StringComparer.Ordinal);
        var offenders = new List<string>();
        foreach (Match tag in Regex.Matches(form, "<[a-zA-Z][^>]*>", RegexOptions.Singleline))
        {
            var classAttr = Regex.Match(tag.Value, "class=\"([^\"]*)\"", RegexOptions.Singleline);
            if (!classAttr.Success)
            {
                continue;
            }

            var classes = classAttr.Groups[1].Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (!classes.Any(c => markerClasses.Contains(c, StringComparer.Ordinal)))
            {
                continue;
            }

            var idMatch = Regex.Match(tag.Value, "(?<![-\\w])id=\"([^\"]*)\"", RegexOptions.Singleline);
            var id = idMatch.Success ? idMatch.Groups[1].Value : "(no id)";

            // The prefix itself is part of the contract: a marked SAML field without it would collide with the
            // OpenID field of the same name AND be mis-saved, so flag it rather than silently stripping nothing.
            if (!id.StartsWith("saml-", StringComparison.Ordinal))
            {
                offenders.Add($"{id} (missing the required saml- id prefix; classes: {classAttr.Groups[1].Value.Trim()})");
                continue;
            }

            var prop = id.Substring("saml-".Length);
            matchedProps.Add(prop);
            if (!samlConfigProperties.Contains(prop))
            {
                offenders.Add($"{id} -> {prop} (classes: {classAttr.Groups[1].Value.Trim()})");
            }
        }

        // Guard against a vacuous pass: one sentinel per marker class must have been scanned.
        var sentinels = new[] { "SamlEndpoint", "Roles", "Enabled", "EnabledFolders", "FolderRoleMapping" };
        var missingSentinels = sentinels.Where(s => !matchedProps.Contains(s)).ToList();
        Assert.True(
            missingSentinels.Count == 0,
            "The SAML provider-form scan did not reach expected fields (broken parse or renamed marker class?); missing sentinels: " + string.Join(", ", missingSentinels));

        // Reverse direction: pin the SAML security-critical settings - each MUST remain a marked, correctly
        // "saml-"-prefixed persisting field, so dropping its marker class (fail-open: the server keeps the
        // stored value and the admin can no longer change it in the form) fails here. DoNotValidateAudience is
        // the SAML insecure toggle; ValidateRecipient/ValidateInResponseTo/SignAuthnRequests are the opt-in
        // hardening toggles; the signing keys are the write-only secrets; AllowExistingAccountLink and
        // ProvisionNewUsersDisabled govern account adoption/provisioning. Extend in the same PR that surfaces a
        // new SAML security setting.
        var securityCritical = new[]
        {
            "EnableAuthorization", "DoNotValidateAudience", "ValidateRecipient", "ValidateInResponseTo",
            "SignAuthnRequests", "SamlSigningKeyPfx", "SamlRolloverSigningKeyPfx",
            "AllowExistingAccountLink", "ProvisionNewUsersDisabled",
        };
        var unsaved = securityCritical.Where(p => !matchedProps.Contains(p)).ToList();
        Assert.True(
            unsaved.Count == 0,
            "These SAML security-critical settings must remain persisting provider-form fields (a marked input whose id is \"saml-\" + the SamlConfig property); missing or unmarked: " + string.Join(", ", unsaved));

        Assert.True(
            offenders.Count == 0,
            "Every persisting SAML provider-form field (sso-text/sso-line-list/sso-toggle/sso-folder-list/sso-role-map) must have an id equal to \"saml-\" + a SamlConfig property; these do not: " + string.Join(" | ", offenders));
    }

    [Fact]
    public void SamlProviderForm_RendersEveryPersistingFieldId()
    {
        // The exhaustive reverse pin for the SAML save contract (#725), the twin of
        // ProviderForm_RendersEveryPersistingFieldId: every one of the 32 persisting SAML fields must render
        // as a marked input with its exact "saml-"-prefixed id, so a field silently dropped or unmarked during
        // a future re-layout - which would stop it persisting - fails here rather than shipping as silent data
        // loss. The provider-name KEY input (saml-provider-name) is deliberately unmarked (it supplies the
        // SamlConfigs dictionary key, not a SamlConfig property) and is asserted present separately.
        var markerClasses = new[] { "sso-text", "sso-line-list", "sso-toggle", "sso-folder-list", "sso-role-map" };
        var form = SamlProviderFormMarkup(
            File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "configPage.html")));

        var markedProps = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match tag in Regex.Matches(form, "<[a-zA-Z][^>]*>", RegexOptions.Singleline))
        {
            var classAttr = Regex.Match(tag.Value, "class=\"([^\"]*)\"", RegexOptions.Singleline);
            if (!classAttr.Success)
            {
                continue;
            }

            var classes = classAttr.Groups[1].Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (!classes.Any(c => markerClasses.Contains(c, StringComparer.Ordinal)))
            {
                continue;
            }

            var idMatch = Regex.Match(tag.Value, "(?<![-\\w])id=\"([^\"]*)\"", RegexOptions.Singleline);
            if (idMatch.Success && idMatch.Groups[1].Value.StartsWith("saml-", StringComparison.Ordinal))
            {
                markedProps.Add(idMatch.Groups[1].Value.Substring("saml-".Length));
            }
        }

        var expected = new[]
        {
            "SamlEndpoint", "SamlSloEndpoint", "SamlClientId", "SamlCertificate", "SamlSecondaryCertificate", "SamlAudience",
            "DoNotValidateAudience", "ValidateRecipient", "ValidateInResponseTo", "SignAuthnRequests",
            "SamlSigningKeyPfx", "SamlRolloverSigningKeyPfx",
            "Enabled", "EnableAuthorization", "DefaultProvider", "AllowExistingAccountLink", "ProvisionNewUsersDisabled",
            "Roles", "AdminRoles", "EnableAllFolders", "EnabledFolders", "EnableFolderRoles", "FolderRoleMapping",
            "EnableLiveTvRoles", "LiveTvRoles", "LiveTvManagementRoles", "EnableLiveTv", "EnableLiveTvManagement",
            "SchemeOverride", "PortOverride", "BaseUrlOverride",
            "HideLoginButton", "LoginButtonText",
        };

        Assert.Equal(33, expected.Length);
        var missing = expected.Where(p => !markedProps.Contains(p)).ToList();
        Assert.True(
            missing.Count == 0,
            "These persisting SAML provider-form fields are missing their marked \"saml-\"-prefixed input in configPage.html (a re-layout dropped or unmarked them, so they would stop persisting): " + string.Join(", ", missing));

        // The provider-name KEY input must still be present (unmarked by design).
        Assert.Contains("id=\"saml-provider-name\"", form, StringComparison.Ordinal);
    }
}
