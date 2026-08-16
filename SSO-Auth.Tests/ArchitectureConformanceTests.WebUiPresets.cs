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
/// Conformance rules for the provider presets and the editor reset in the admin page, with the markup and catalog parsing the preset rules read.
/// </content>
public partial class ArchitectureConformanceTests
{
    [Fact]
    public void OpenSamlProvider_ResetsEditorBeforeLoadingTheProvider()
    {
        // #689/#725 (provider-switch state bleed) for the SAML editor: the SAML editor is a single reused
        // form, so opening a provider must start from a clean slate or a field the target provider does not
        // set keeps the PREVIOUS provider's value and a later save silently persists it. No JS runtime harness
        // exists, so this pins the ordering statically: within openSamlProvider, resetSamlEditor(page) must run
        // BEFORE loadSamlProvider(page, provider_name), the same clean-slate-first order OpenProvider enforces.
        var js = File.ReadAllText(
            Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));

        var open = js.IndexOf("openSamlProvider:", StringComparison.Ordinal);
        Assert.True(open >= 0, "openSamlProvider was not found in config.js.");

        var nextMethod = js.IndexOf("addSamlProvider:", open, StringComparison.Ordinal);
        Assert.True(nextMethod > open, "addSamlProvider (the method after openSamlProvider) was not found in config.js.");
        var body = js[open..nextMethod];

        var reset = body.IndexOf("resetSamlEditor(page)", StringComparison.Ordinal);
        var load = body.IndexOf("loadSamlProvider(page, provider_name)", StringComparison.Ordinal);
        Assert.True(reset >= 0, "openSamlProvider must call resetSamlEditor(page) to clear the previous provider's state before loading.");
        Assert.True(load >= 0, "openSamlProvider must call loadSamlProvider(page, provider_name).");
        Assert.True(
            reset < load,
            "openSamlProvider must call resetSamlEditor(page) BEFORE loadSamlProvider(page, provider_name); otherwise the previous provider's unset fields bleed into the loaded provider and can be silently saved (#689/#725).");
    }

    [Fact]
    public void ProviderPresets_OidcFieldsAndTogglesAreRenderedMarkedFields()
    {
        // #726 provider templates: applying a preset writes into the editor field whose id equals the
        // preset's `fields` key (and pre-checks the toggle whose id equals the toggle name). If a key does
        // not match a marked field in the OpenID form, the apply silently no-ops (a broken preset) - and the
        // separate save-contract test already guarantees every marked field id is a real OidConfig property,
        // so this pins the composition: every OIDC preset field/toggle targets a real persisting field, so
        // applying a preset always respects the save contract.
        var js = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));
        var (fieldKeys, toggles) = ParsePresetCatalog(js, "OIDC_PRESETS");
        Assert.True(fieldKeys.Count > 0, "OIDC_PRESETS parsed to zero field keys - broken parse or empty catalog.");

        var markedIds = MarkedFieldIds(OidcProviderFormMarkup(
            File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "configPage.html"))));

        var missing = fieldKeys.Concat(toggles).Where(k => !markedIds.Contains(k)).ToList();
        Assert.True(
            missing.Count == 0,
            "These OIDC preset field/toggle keys do not match a marked field id in #sso-new-oidc-provider (a preset would silently fill nothing): " + string.Join(", ", missing));
    }

    [Fact]
    public void ProviderPresets_SamlFieldsAndTogglesAreRenderedMarkedFields()
    {
        // The SAML counterpart: a SAML preset's field/toggle key K targets the id "saml-"+K, so each must
        // exist as a marked field in #sso-new-saml-provider.
        var js = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));
        var (fieldKeys, toggles) = ParsePresetCatalog(js, "SAML_PRESETS");
        Assert.True(fieldKeys.Count > 0, "SAML_PRESETS parsed to zero field keys - broken parse or empty catalog.");

        var markedIds = MarkedFieldIds(SamlProviderFormMarkup(
            File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "configPage.html"))));

        var missing = fieldKeys.Concat(toggles).Where(k => !markedIds.Contains("saml-" + k)).ToList();
        Assert.True(
            missing.Count == 0,
            "These SAML preset field/toggle keys do not match a marked \"saml-\"+key field id in #sso-new-saml-provider: " + string.Join(", ", missing));
    }

    [Fact]
    public void ProviderPresets_NeverFillSecrets()
    {
        // A preset pre-fills only NON-secret fields (#726 acceptance). Pin it: no preset's `fields` may carry
        // a write-only secret property, so a template can never place a secret value in the form (or, worse,
        // a plausible-looking wrong one the admin trusts).
        var js = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));
        var secrets = new[] { "OidSecret", "SamlSigningKeyPfx", "SamlRolloverSigningKeyPfx" };

        foreach (var catalog in new[] { "OIDC_PRESETS", "SAML_PRESETS" })
        {
            var (fieldKeys, _) = ParsePresetCatalog(js, catalog);
            var offending = fieldKeys.Where(k => secrets.Contains(k, StringComparer.Ordinal)).ToList();
            Assert.True(
                offending.Count == 0,
                $"{catalog} must never pre-fill a secret field; found: " + string.Join(", ", offending));
        }
    }

    [Fact]
    public void ProviderPresets_OnlyPreCheckKnownCompatToggles()
    {
        // A preset may pre-check ONLY a known compatibility/insecure toggle, never a fail-closed hardening
        // toggle (#726): silently enabling a hardening toggle could lock out a not-yet-ready IdP, and
        // enabling an unrelated toggle is a downgrade the admin did not choose. Pin both directions: every
        // preset toggle is in the protocol's managed-toggle allow-list, and every allow-list entry is a real
        // config property that is NOT one of the hardening toggles.
        var js = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));

        var oidcProps = typeof(OidConfig).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        var samlProps = typeof(SamlConfig).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name).ToHashSet(StringComparer.Ordinal);

        var hardening = new[]
        {
            "RequirePkce", "RequireVerifiedEmailForAdoption", "RequireVerifiedEmailForLogin", "RequireAcr",
            "ValidateRecipient", "ValidateInResponseTo", "SignAuthnRequests",
        };

        var oidcManaged = ParseJsStringArrayConst(js, "OIDC_PRESET_MANAGED_TOGGLES");
        var samlManaged = ParseJsStringArrayConst(js, "SAML_PRESET_MANAGED_TOGGLES");

        // Allow-list entries are real properties and are not hardening toggles.
        foreach (var (managed, props, name) in new[]
        {
            (oidcManaged, oidcProps, "OIDC_PRESET_MANAGED_TOGGLES"),
            (samlManaged, samlProps, "SAML_PRESET_MANAGED_TOGGLES"),
        })
        {
            var notProp = managed.Where(t => !props.Contains(t)).ToList();
            Assert.True(notProp.Count == 0, $"{name} contains non-properties: " + string.Join(", ", notProp));
            var isHardening = managed.Where(t => hardening.Contains(t, StringComparer.Ordinal)).ToList();
            Assert.True(isHardening.Count == 0, $"{name} must not include a hardening toggle: " + string.Join(", ", isHardening));
        }

        // Every preset toggle is within its protocol's allow-list.
        var oidcToggles = ParsePresetCatalog(js, "OIDC_PRESETS").toggles;
        var samlToggles = ParsePresetCatalog(js, "SAML_PRESETS").toggles;
        var oidcStray = oidcToggles.Where(t => !oidcManaged.Contains(t)).ToList();
        var samlStray = samlToggles.Where(t => !samlManaged.Contains(t)).ToList();
        Assert.True(oidcStray.Count == 0, "OIDC presets pre-check a toggle outside the allow-list: " + string.Join(", ", oidcStray));
        Assert.True(samlStray.Count == 0, "SAML presets pre-check a toggle outside the allow-list: " + string.Join(", ", samlStray));
    }

    [Fact]
    public void ProviderPresets_OidcPresetsShareTheSameFieldKeySet()
    {
        // #726 idempotency invariant: applyOidcPreset overwrites only the fields the newly chosen preset
        // sets (after clearing the managed toggles), so if two presets set DIFFERENT field-key sets,
        // switching from a richer to a poorer one would leave a stale value behind - e.g. a preset that
        // dropped RoleClaim would keep the previous provider's claim path. Every OIDC preset must therefore
        // set EXACTLY the same four fields; this locks that in so a future preset cannot silently reintroduce
        // the state-bleed (a review follow-up on #726).
        var js = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));
        var start = js.IndexOf("const OIDC_PRESETS = {", StringComparison.Ordinal);
        Assert.True(start >= 0, "OIDC_PRESETS was not found in config.js.");
        var end = js.IndexOf("};", start, StringComparison.Ordinal);
        Assert.True(end > start, "OIDC_PRESETS has no closing }};.");
        var region = js[start..end];

        var required = new[] { "OidEndpoint", "OidScopes", "RoleClaim", "DefaultUsernameClaim" };
        var blocks = Regex.Matches(region, @"fields:\s*\{([^}]*)\}", RegexOptions.Singleline)
            .Select(m => m.Groups[1].Value)
            .ToList();
        Assert.True(
            blocks.Count >= 9,
            $"Expected at least 9 OIDC preset field blocks, found {blocks.Count} - broken parse or shrunken catalog.");

        foreach (var block in blocks)
        {
            var keys = Regex.Matches(block, "(\\w+)\\s*:\\s*\"")
                .Select(m => m.Groups[1].Value)
                .ToHashSet(StringComparer.Ordinal);
            var missing = required.Where(r => !keys.Contains(r)).ToList();
            var extra = keys.Where(k => !required.Contains(k)).ToList();
            Assert.True(
                missing.Count == 0,
                "An OIDC preset omits a shared field key (switching templates would leave a stale value): " + string.Join(", ", missing));
            Assert.True(
                extra.Count == 0,
                "An OIDC preset sets a field key outside the shared set (breaks idempotent switching): " + string.Join(", ", extra));
        }
    }

    [Fact]
    public void OpenProvider_ResetsEditorBeforeLoadingTheProvider()
    {
        // #689 (provider-switch state bleed): the editor is a single reused form, so opening a provider must
        // start from a clean slate or a text/array field the target provider does not set keeps the
        // PREVIOUS provider's value and a later save silently persists it (e.g. repointing the #186-sensitive
        // OidEndpoint with no admin edit). No JS runtime harness exists (the config.js checks are static text
        // parsers), so this pins the ordering invariant statically: within openProvider, resetEditor(page)
        // must run BEFORE loadProvider(page, provider_name) - the same clean-slate-first order addProvider
        // already uses. loadProvider then fills the target's real values on top of the reset baseline.
        var js = File.ReadAllText(
            Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));

        var open = js.IndexOf("openProvider:", StringComparison.Ordinal);
        Assert.True(open >= 0, "openProvider was not found in config.js.");

        // Scope to the openProvider method body (up to the next method, addProvider) so resetEditor/
        // loadProvider references elsewhere in the file cannot satisfy the check.
        var nextMethod = js.IndexOf("addProvider:", open, StringComparison.Ordinal);
        Assert.True(nextMethod > open, "addProvider (the method after openProvider) was not found in config.js.");
        var body = js[open..nextMethod];

        var reset = body.IndexOf("resetEditor(page)", StringComparison.Ordinal);
        var load = body.IndexOf("loadProvider(page, provider_name)", StringComparison.Ordinal);
        Assert.True(reset >= 0, "openProvider must call resetEditor(page) to clear the previous provider's state before loading.");
        Assert.True(load >= 0, "openProvider must call loadProvider(page, provider_name).");
        Assert.True(
            reset < load,
            "openProvider must call resetEditor(page) BEFORE loadProvider(page, provider_name); otherwise the previous provider's unset fields bleed into the loaded provider and can be silently saved (#689).");
    }

    [Fact]
    public void SyncDependentFields_ExpandsEnclosingSecuritySectionOnTheOrOfInsecureOrSensitive()
    {
        // #689 (active downgrade hidden behind a collapsed accordion): the insecure toggles live behind a
        // "Show insecure options" list that is itself inside the "Security & hardening" emby-collapse, which
        // is authored collapsed. Expanding only the inner list left an active DisableHttps /
        // AllowExistingAccountLink invisible. syncDependentFields must expand the ENCLOSING accordion section
        // (by its stable id) when any insecure OR sensitive toggle is active. No JS runtime harness exists,
        // so this pins statically both the target (the section id in the markup and the call) AND the
        // condition shape: the expand is driven by the OR of the two sets, so a `||`->`&&` mutant - which
        // would stop a sensitive-only (AllowExistingAccountLink) provider from expanding - fails here.
        var html = File.ReadAllText(
            Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "configPage.html"));
        var js = File.ReadAllText(
            Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));

        // The enclosing accordion is the emby-collapse carrying the stable id, and it is the security section.
        Assert.Matches(
            new Regex("<div\\b[^>]*is=\"emby-collapse\"[^>]*id=\"sso-security-section\"[^>]*title=\"Security & hardening\"", RegexOptions.Singleline),
            html);

        // Scope to the syncDependentFields method body (up to the next method) so the reference is inside it.
        var sync = js.IndexOf("syncDependentFields:", StringComparison.Ordinal);
        Assert.True(sync >= 0, "syncDependentFields was not found in config.js.");
        var nextMethod = js.IndexOf("setInsecureOptionsExpanded:", sync, StringComparison.Ordinal);
        Assert.True(nextMethod > sync, "The method after syncDependentFields was not found in config.js.");
        var body = js[sync..nextMethod];

        // anyInsecure is derived from the insecure set.
        Assert.Matches(
            new Regex(@"anyInsecure\s*=\s*ssoConfigurationPage\.insecureFieldIds\.some\(", RegexOptions.Singleline),
            body);

        // The combined condition is the OR (never AND) of anyInsecure and the sensitive set - the disjunction
        // a `||`->`&&` mutant would break. Both sets must feed it, not just appear somewhere in the body.
        Assert.Matches(
            new Regex(@"anySensitive\s*=\s*anyInsecure\s*\|\|\s*ssoConfigurationPage\.sensitiveFieldIds\.some\(", RegexOptions.Singleline),
            body);

        // The inner insecure-options list is gated on anyInsecure; the ENCLOSING section on the combined
        // anySensitive - so the section expands for a sensitive-only provider too.
        Assert.Matches(
            new Regex(@"if\s*\(\s*anyInsecure\s*\)\s*\{\s*ssoConfigurationPage\.setInsecureOptionsExpanded\(\s*page,\s*true", RegexOptions.Singleline),
            body);
        Assert.Matches(
            new Regex("if\\s*\\(\\s*anySensitive\\s*\\)\\s*\\{\\s*ssoConfigurationPage\\.setSectionExpanded\\(\\s*page,\\s*\"sso-security-section\"", RegexOptions.Singleline),
            body);

        // The flag / auto-expand trigger set must contain only settings whose ENABLED state is a downgrade or
        // an attack-surface widening: the six insecure toggles and AllowExistingAccountLink. It must NOT
        // contain the fail-closed hardening toggles (RequireVerifiedEmailForAdoption/ForLogin, RequirePkce),
        // which are OFF by default and whose ON state is MORE secure - flagging those is backwards (#689
        // re-review). Scoped to the two array literals so a stray mention elsewhere cannot mask a regression.
        var insecureSet = ArrayLiteralAfter(js, "insecureFieldIds:");
        var sensitiveSet = ArrayLiteralAfter(js, "sensitiveFieldIds:");
        var trigger = insecureSet + " " + sensitiveSet;
        foreach (var id in new[]
        {
            "DisableHttps", "DisablePushedAuthorization", "DoNotValidateEndpoints",
            "DoNotValidateIssuerName", "DoNotValidateResponseIssuer", "AllowPrivateNetworkAddresses",
            "AllowExistingAccountLink",
        })
        {
            Assert.Contains("\"" + id + "\"", trigger, StringComparison.Ordinal);
        }

        foreach (var hardening in new[]
        {
            "RequireVerifiedEmailForAdoption", "RequireVerifiedEmailForLogin", "RequirePkce", "RequireAcr",
        })
        {
            Assert.DoesNotContain(hardening, trigger, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ResetEditor_ClearsEveryConditionallyLoadedFieldCategory()
    {
        // #689 (provider-switch state bleed): loadProvider fills the text, line-list, folder-list and
        // role-map categories ONLY under `if (provider[id])`, so the clean slate that prevents a previous
        // provider's value bleeding through has to come from resetEditor unconditionally clearing every one
        // of those categories (plus the checkboxes). No JS runtime harness exists to assert the live DOM is
        // zeroed, so this statically pins that the resetEditor body contains the clear for each category - a
        // mutant deleting any one category's reset (which would let that category bleed) fails here. Scoped
        // to the resetEditor body so a clear living in some other method cannot satisfy the check.
        var js = File.ReadAllText(
            Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));

        var start = js.IndexOf("resetEditor:", StringComparison.Ordinal);
        Assert.True(start >= 0, "resetEditor was not found in config.js.");
        var nextMethod = js.IndexOf("resetEditorSections:", start, StringComparison.Ordinal);
        Assert.True(nextMethod > start, "resetEditorSections (the method after resetEditor) was not found in config.js.");
        var body = js[start..nextMethod];

        // text and line-list categories clear their input value to the empty string ("").
        Assert.Matches(
            new Regex("text_fields\\.forEach\\(.*?\\.value = \"\"", RegexOptions.Singleline),
            body);
        Assert.Matches(
            new Regex("text_list_fields\\.forEach\\(.*?\\.value = \"\"", RegexOptions.Singleline),
            body);

        // checkboxes reset to unchecked.
        Assert.Matches(
            new Regex(@"check_fields\.forEach\(.*?\.checked = false;", RegexOptions.Singleline),
            body);

        // folder-list and role-map categories reset to an empty collection via their populate helpers.
        Assert.Matches(
            new Regex(@"folder_list_fields\.forEach\(.*?populateEnabledFolders\(\s*\[\]", RegexOptions.Singleline),
            body);
        Assert.Matches(
            new Regex(@"role_map_fields\.forEach\(.*?populateRoleMappings\(\s*\[\]", RegexOptions.Singleline),
            body);
    }

    // The markup of the #sso-new-oidc-provider settings form (from the opening tag's id attribute to its
    // closing </form>). Forms are not nested here, so the first </form> after the id marker closes it; the
    // preceding #sso-load-config form is left out because its </form> sits before the marker.
    // Return the first flat "[ ... ]" array literal that follows a marker (e.g. "sensitiveFieldIds:") in
    // config.js. Used to scope a membership assertion to a specific field-id set rather than the whole file,
    // so a stray mention of an id elsewhere cannot mask a regression in the set's contents.
    private static string ArrayLiteralAfter(string source, string marker)
    {
        var m = source.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(m >= 0, $"'{marker}' was not found in config.js.");
        var open = source.IndexOf('[', m);
        Assert.True(open > m, $"No array literal follows '{marker}' in config.js.");
        var close = source.IndexOf(']', open);
        Assert.True(close > open, $"The array literal after '{marker}' is not closed in config.js.");
        return source[open..(close + 1)];
    }

    private static string OidcProviderFormMarkup(string html)
    {
        const string marker = "id=\"sso-new-oidc-provider\"";
        var start = html.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "The #sso-new-oidc-provider form was not found in configPage.html.");
        var end = html.IndexOf("</form>", start, StringComparison.Ordinal);
        Assert.True(end > start, "The #sso-new-oidc-provider form has no closing </form> tag.");
        return html[start..end];
    }

    private static string SamlProviderFormMarkup(string html)
    {
        const string marker = "id=\"sso-new-saml-provider\"";
        var start = html.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "The #sso-new-saml-provider form was not found in configPage.html.");
        var end = html.IndexOf("</form>", start, StringComparison.Ordinal);
        Assert.True(end > start, "The #sso-new-saml-provider form has no closing </form> tag.");
        return html[start..end];
    }

    // The set of persisting (marker-classed) field ids in a provider form's markup - the ids the save
    // contract reads. Shared by the #726 preset tests to prove every preset field/toggle targets one.
    private static HashSet<string> MarkedFieldIds(string formMarkup)
    {
        var markerClasses = new[] { "sso-text", "sso-line-list", "sso-toggle", "sso-folder-list", "sso-role-map" };
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match tag in Regex.Matches(formMarkup, "<[a-zA-Z][^>]*>", RegexOptions.Singleline))
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
                ids.Add(idMatch.Groups[1].Value);
            }
        }

        return ids;
    }

    // Parse a preset catalog object literal (const <name> = { … };) from config.js into the set of `fields`
    // keys and the set of `toggles` entries across all its presets. The catalog contains no nested "};", so
    // the first "};" after the declaration is its terminator; a `fields:{…}` block contains no nested "}"
    // and a `toggles:[…]` no nested "]", so the per-block regexes are exact. A field key is matched only in
    // key position (`word:` immediately followed by a quote), so a ':' inside a URL value is never mistaken
    // for a key.
    private static (HashSet<string> fieldKeys, HashSet<string> toggles) ParsePresetCatalog(string js, string constName)
    {
        var start = js.IndexOf("const " + constName + " = {", StringComparison.Ordinal);
        Assert.True(start >= 0, $"{constName} was not found in config.js.");
        var end = js.IndexOf("};", start, StringComparison.Ordinal);
        Assert.True(end > start, $"{constName} has no closing }};.");
        var region = js[start..end];

        var fieldKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match block in Regex.Matches(region, @"fields:\s*\{([^}]*)\}", RegexOptions.Singleline))
        {
            foreach (Match key in Regex.Matches(block.Groups[1].Value, "(\\w+)\\s*:\\s*\""))
            {
                fieldKeys.Add(key.Groups[1].Value);
            }
        }

        var toggles = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match block in Regex.Matches(region, @"toggles:\s*\[([^\]]*)\]", RegexOptions.Singleline))
        {
            foreach (Match t in Regex.Matches(block.Groups[1].Value, "\"(\\w+)\""))
            {
                toggles.Add(t.Groups[1].Value);
            }
        }

        return (fieldKeys, toggles);
    }
}
