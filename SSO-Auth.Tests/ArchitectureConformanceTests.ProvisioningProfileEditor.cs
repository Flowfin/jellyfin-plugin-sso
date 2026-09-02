// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for the provisioning-profile editor and the two per-provider profile selectors
/// (#1105). Same means as the provisioning-template rules next door and for the same reason: this tree
/// carries no JavaScript runtime, no DOM and no browser automation, so nothing below executes the page.
/// Each rule pins a STRUCTURAL property a wrong edit cannot satisfy by accident. What a reading of the
/// markup cannot reach - what an administrator sees after pressing a button - is argued in the pull
/// request rather than claimed here.
/// </content>
public partial class ArchitectureConformanceTests
{
    // The editor renders the same nine controls a third time, outside both provider forms, under this id
    // prefix. It is deliberately not "saml-" and not empty: templateControls in config.js resolves a prefix
    // to a form, and two prefixes resolving to one form would make each one's serializer read the other's
    // fields.
    private const string ProfileEditorPrefix = "profile-";

    private static string ProfileEditorMarkup(string html)
    {
        const string marker = "id=\"sso-provisioning-profiles\"";
        var start = html.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "The #sso-provisioning-profiles form was not found in configPage.html.");
        var end = html.IndexOf("</form>", start, StringComparison.Ordinal);
        Assert.True(end > start, "The #sso-provisioning-profiles form has no closing </form> tag.");
        return html[start..end];
    }

    [Fact]
    public void ProvisioningProfileEditor_OffersExactlyTheTemplateProperties()
    {
        // The editor's twin of ProvisioningTemplateForm_OffersExactlyTheTemplateProperties. A profile IS a
        // ProvisioningPolicyTemplate, so a field the editor does not render is a field of the named policy
        // an administrator cannot set from the dashboard at all - and a marked id that is not a property
        // renders and never saves, because the server drops JSON members the type does not declare.
        // Compared as a SET IN BOTH DIRECTIONS for that reason: a subset assertion would pass an editor
        // that quietly stopped offering a field.
        var form = ProfileEditorMarkup(ProvisioningTemplateMarkup());
        var controls = TemplateControls(form);
        Assert.True(controls.Count > 0, "the profile editor carries no template control at all - a renamed marker class would empty this scan silently");

        var offenders = controls
            .Where(c => !c.Id.StartsWith(ProfileEditorPrefix + "Tmpl-", StringComparison.Ordinal))
            .Select(c => $"{c.Id} (classes: {c.Classes})")
            .ToList();
        Assert.True(
            offenders.Count == 0,
            $"Every profile-editor control must have an id of \"{ProfileEditorPrefix}Tmpl-\" + a ProvisioningPolicyTemplate property; these do not: " + string.Join(" | ", offenders));

        var offered = controls
            .Select(c => c.Id[(ProfileEditorPrefix + "Tmpl-").Length..])
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(TemplatePropertyNames(), offered);
    }

    [Fact]
    public void ProvisioningProfileEditorNullableBooleans_RenderAsThreeStateSelects()
    {
        // The fail-closed direction, on the third rendering of the control set. A profile's three `bool?`
        // members mean the same thing they mean inline - null leaves Jellyfin's own default alone - and a
        // checkbox has two states, so an editor built with checkboxes would write a deliberate false onto
        // every account created under the profile for a field nobody touched. The field set is DERIVED from
        // the type, so a member that becomes nullable later joins this rule on its own.
        var nullableBooleans = typeof(ProvisioningPolicyTemplate)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType == typeof(bool?))
            .Select(p => p.Name)
            .ToList();
        Assert.Equal(3, nullableBooleans.Count);

        var form = ProfileEditorMarkup(ProvisioningTemplateMarkup());

        foreach (var name in nullableBooleans)
        {
            var id = ProfileEditorPrefix + "Tmpl-" + name;
            var control = TemplateControls(form).SingleOrDefault(c => c.Id == id);
            Assert.True(control.Tag != null, $"{id} is not a marked template control in the profile editor");
            Assert.StartsWith("<select", control.Tag, StringComparison.Ordinal);
            Assert.Contains("sso-tmpl-bool", control.Classes, StringComparison.Ordinal);
            Assert.DoesNotContain("sso-toggle", control.Classes, StringComparison.Ordinal);

            var start = form.IndexOf(control.Tag, StringComparison.Ordinal);
            var end = form.IndexOf("</select>", start, StringComparison.Ordinal);
            Assert.True(end > start, $"{id} has no closing select tag");
            Assert.Contains("value=\"\"", form[start..end], StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ProvisioningProfileEditor_SitsOutsideBothProviderForms()
    {
        // The editor writes a ROOT PluginConfiguration member, so a control of it placed inside a provider
        // form would be read by that form's serializer instead: the flat contract writes
        // current_config[element.id] onto the provider, and the template serializer scans the form for the
        // sso-tmpl-* markers. Either would silently persist the editor's fields onto whichever provider
        // happened to be open. Checked as a position rather than as an intention.
        var html = ProvisioningTemplateMarkup();

        foreach (var (name, slice) in new[]
        {
            ("#sso-new-oidc-provider", OidcProviderFormMarkup(html)),
            ("#sso-new-saml-provider", SamlProviderFormMarkup(html)),
        })
        {
            Assert.DoesNotContain("id=\"sso-provisioning-profiles\"", slice, StringComparison.Ordinal);
            Assert.False(
                slice.Contains(ProfileEditorPrefix + "Tmpl-", StringComparison.Ordinal),
                $"A profile-editor control is inside {name}, where that form's own serializer would persist it onto the open provider.");
        }
    }

    [Fact]
    public void TemplateFormSelectors_NameOneDistinctFormPerPrefix()
    {
        // templateControls resolves a prefix to the form it scans. Two prefixes resolving to one form would
        // make each prefix's serializer read the other's controls - reading the OpenID provider's fields
        // while saving a profile, for instance - and a prefix naming a form the page does not carry would
        // throw on a querySelectorAll of null. Both are read out of the declaration rather than assumed.
        var js = ProvisioningTemplateScript();
        var body = ProvisioningTemplateFunctionBody(js, "templateFormSelectors: {");
        var pairs = Regex.Matches(body, "\"(?<prefix>[^\"]*)\":\\s*\"(?<form>#[^\"]+)\"")
            .Select(m => (Prefix: m.Groups["prefix"].Value, Form: m.Groups["form"].Value))
            .ToList();

        Assert.Equal(3, pairs.Count);
        Assert.Equal(pairs.Count, pairs.Select(p => p.Prefix).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(pairs.Count, pairs.Select(p => p.Form).Distinct(StringComparer.Ordinal).Count());
        Assert.Contains(ProfileEditorPrefix, pairs.Select(p => p.Prefix));

        var html = ProvisioningTemplateMarkup();
        var missing = pairs
            .Where(p => !html.Contains($"id=\"{p.Form[1..]}\"", StringComparison.Ordinal))
            .Select(p => $"{p.Prefix} -> {p.Form}")
            .ToList();
        Assert.True(
            missing.Count == 0,
            "These template-form selectors name no element in configPage.html, so templateControls would query a null form: " + string.Join(", ", missing));
    }

    [Fact]
    public void ProviderFormProfileSelectors_ExistAndStayOffTheFlatSavePath()
    {
        // Each provider form names its profile with a select whose id is the exact ProviderConfigBase
        // property (prefixed for SAML, as every SAML field is). It must NOT carry a flat marker class: the
        // flat LOAD path sets a text field only when the loaded provider carries a value, so a provider
        // naming no profile would keep the previous provider's name selected and the next save would write
        // it onto the second provider. That is a change to what a provider's new accounts get, made by
        // switching providers in a dropdown, so the field is filled and read beside the inline template
        // instead - which is also where the mutual exclusion between the two lives.
        var flatMarkers = new[] { "sso-text", "sso-line-list", "sso-toggle", "sso-folder-list", "sso-role-map" };
        var html = ProvisioningTemplateMarkup();
        Assert.Contains("ProvisioningProfile", typeof(OidConfig).GetProperties().Select(p => p.Name));
        Assert.Contains("ProvisioningProfile", typeof(SamlConfig).GetProperties().Select(p => p.Name));

        foreach (var (name, id, slice) in new[]
        {
            ("oidc", "ProvisioningProfile", OidcProviderFormMarkup(html)),
            ("saml", "saml-ProvisioningProfile", SamlProviderFormMarkup(html)),
        })
        {
            var tag = Regex.Matches(slice, "<[a-zA-Z][^>]*>", RegexOptions.Singleline)
                .Select(m => m.Value)
                .SingleOrDefault(t => Regex.IsMatch(t, "(?<![-\\w])id=\"" + Regex.Escape(id) + "\""));
            Assert.True(tag != null, $"The {name} provider form carries no element with id=\"{id}\".");
            Assert.StartsWith("<select", tag, StringComparison.Ordinal);

            var classes = Regex.Match(tag!, "class=\"([^\"]*)\"").Groups[1].Value
                .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            var flat = classes.Where(c => flatMarkers.Contains(c, StringComparer.Ordinal)).ToList();
            Assert.True(
                flat.Count == 0,
                $"{id} carries the flat save-contract marker(s) {string.Join(", ", flat)}, which would put it back on the load path that leaves a stale profile name selected when switching providers.");
        }
    }

    [Fact]
    public void ProviderSavePaths_ReadTheProfileFromTheirOwnSelector()
    {
        // The selector is off the flat contract by the rule above, so nothing writes it unless the save
        // path reads it by hand - and a save that never read it would post the STORED name back every time,
        // making the control look connected while changing nothing. Each path must read its OWN selector:
        // the two ids differ only by the prefix, so a copy-paste that kept the OpenID id in the SAML arm
        // would write the OpenID form's choice onto a SAML provider. What happens to the inline template
        // once a profile is named is the neighbouring rule's subject
        // (ProvisioningTemplateSave_NeverSendsATemplateBesideANamedProfile) and is not re-checked here.
        var js = ProvisioningTemplateScript();

        foreach (var (opener, selector, foreign) in new[]
        {
            ("saveProvider: (page, provider_name) => {", "#ProvisioningProfile", "#saml-ProvisioningProfile"),
            ("saveSamlProvider: (page, provider_name) => {", "#saml-ProvisioningProfile", "#ProvisioningProfile"),
        })
        {
            var body = ProvisioningTemplateFunctionBody(js, opener);
            Assert.Contains("current_config.ProvisioningProfile =", body, StringComparison.Ordinal);
            Assert.Contains($"page.querySelector(\"{selector}\").value || null;", body, StringComparison.Ordinal);
            Assert.DoesNotContain($"querySelector(\"{foreign}\")", body, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ProfileDelete_IsRefusedWhileAnythingStillNamesTheProfile()
    {
        // The Surfaces clause of #1105, and the one act on this page that can change what a provider's new
        // accounts get without touching that provider. Deleting a profile some provider or role rule still
        // names produces exactly the state ProviderConfigValidator refuses, so the delete consults the
        // reference walk BEFORE the PUT and stops. Cascading instead - clearing the references - would
        // silently switch each of those providers to a different starting policy, or, where the provider
        // carries no inline template, to none at all.
        var js = ProvisioningTemplateScript();
        var body = ProvisioningTemplateFunctionBody(js, "deleteProvisioningProfile: (page) => {");

        var walk = body.IndexOf("provisioningProfileReferences(", StringComparison.Ordinal);
        var put = body.IndexOf("putProvisioningProfiles(", StringComparison.Ordinal);
        Assert.True(walk >= 0, "deleteProvisioningProfile no longer consults provisioningProfileReferences.");
        Assert.True(put > walk, "deleteProvisioningProfile posts the configuration before checking what still names the profile.");
        Assert.Contains("references.length > 0", body, StringComparison.Ordinal);
    }

    [Fact]
    public void ProfileRename_RepointsEveryReferenceInTheSameDocument()
    {
        // A rename that left the references behind would be a delete with extra steps: every provider and
        // role rule naming the old name would point at a name the configuration no longer defines, which
        // provisions NOTHING at the next first login rather than falling back. The repoint therefore
        // happens in the same object that is posted, so the configuration is never in the refused state at
        // any point, not even briefly.
        var js = ProvisioningTemplateScript();
        var body = ProvisioningTemplateFunctionBody(js, "renameProvisioningProfile: (page) => {");

        var repoint = body.IndexOf("repointProvisioningProfile(config, from, to)", StringComparison.Ordinal);
        var put = body.IndexOf("putProvisioningProfiles(", StringComparison.Ordinal);
        Assert.True(repoint >= 0, "renameProvisioningProfile no longer repoints the references.");
        Assert.True(put > repoint, "renameProvisioningProfile posts the configuration before repointing the references.");

        // Both reference shapes, so a rename cannot repoint the provider default and forget the role rules
        // #1106 added beside it.
        var walk = ProvisioningTemplateFunctionBody(js, "repointProvisioningProfile: (config, from, to) => {");
        Assert.Contains("provider_config.ProvisioningProfile === from", walk, StringComparison.Ordinal);
        Assert.Contains("ProvisioningProfileRoleMappings", walk, StringComparison.Ordinal);
    }

    [Fact]
    public void ProfileEditorNames_AreRenderedAsTextNeverAsMarkup()
    {
        // A profile name is administrator-supplied configuration that this page reads back out of the saved
        // document and renders in three places - the editor's list and both provider selectors. The rule
        // linking.js states for the self-service page holds here too (#221): built with
        // createElement/textContent, never innerHTML. Scoped to the option builder, which is the one place
        // a name becomes an element.
        var js = ProvisioningTemplateScript();
        var body = ProvisioningTemplateFunctionBody(js, "populateProvisioningProfileOptions: (select, names, selected) => {");

        Assert.Contains("option.textContent = name;", body, StringComparison.Ordinal);
        Assert.DoesNotContain("innerHTML", body, StringComparison.Ordinal);
        Assert.DoesNotContain("new Option(", body, StringComparison.Ordinal);
    }

    [Fact]
    public void ProfileEditorButtons_AreNotWiredToTheProviderSavePaths()
    {
        // The editor's four acts each write the ROOT profile set and nothing else. Wiring one of them to a
        // provider save would post a provider's whole form as a side effect of editing a profile, which is
        // the failure the separate global handlers exist to prevent - the same reason saveLoginButtons is
        // its own path rather than a flag on the provider form.
        var js = ProvisioningTemplateScript();
        var acts = new[]
        {
            "addProvisioningProfile",
            "renameProvisioningProfile",
            "deleteProvisioningProfile",
            "saveProvisioningProfile",
        };

        var bodies = new List<string>();
        foreach (var act in acts)
        {
            bodies.Add(ProvisioningTemplateFunctionBody(js, act + ": (page) => {"));
        }

        foreach (var body in bodies)
        {
            Assert.DoesNotContain("saveProvider(", body, StringComparison.Ordinal);
            Assert.DoesNotContain("saveSamlProvider(", body, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ProfileNames_AreRefusedWhereAnAssignmentWouldNotCreateThem()
    {
        // The profile set is a plain JavaScript object, so profiles[name] = template does not create an own
        // property for every string: "__proto__" sets the prototype and creates nothing. Add would then
        // report a profile it did not create, and RENAME - which deletes the source name first - would lose
        // the profile while reporting that it had moved. Both acts must refuse such a name BEFORE they
        // touch the set, and the refusal must be DERIVED by probing an assignment rather than listed by
        // name, so a second spelling with the same asymmetry is refused without anybody thinking of it.
        var js = ProvisioningTemplateScript();

        var helper = ProvisioningTemplateFunctionBody(js, "provisioningProfileNameIsAssignable: (name) => {");
        Assert.Contains("probe[name] = true;", helper, StringComparison.Ordinal);
        Assert.Contains("Object.prototype.hasOwnProperty.call(probe, name)", helper, StringComparison.Ordinal);
        Assert.DoesNotContain("__proto__", helper, StringComparison.Ordinal);

        foreach (var (opener, mutation) in new[]
        {
            ("addProvisioningProfile: (page) => {", "profiles[name] = template || {};"),
            ("renameProvisioningProfile: (page) => {", "delete profiles[from];"),
        })
        {
            var body = ProvisioningTemplateFunctionBody(js, opener);
            var guard = body.IndexOf("provisioningProfileNameIsAssignable(", StringComparison.Ordinal);
            var writes = body.IndexOf(mutation, StringComparison.Ordinal);
            Assert.True(guard >= 0, $"{opener} no longer refuses a name an assignment would not create.");
            Assert.True(writes > guard, $"{opener} changes the profile set before checking the name is assignable.");
        }
    }

    [Fact]
    public void ProfileSave_WaitsForTheFillItIsSerializing()
    {
        // The permission rows are cleared synchronously and re-rendered only once sso/Config/Permissions
        // answers, so the editor is EMPTY of them for the length of that fetch. A Save pressed inside that
        // window serializes no rows and writes a profile with every grant and deny removed - with a success
        // message, because nothing failed. The save therefore waits on the fill it is about to read.
        var js = ProvisioningTemplateScript();

        var show = ProvisioningTemplateFunctionBody(js, "showSelectedProvisioningProfile: (page, config) => {");
        Assert.Contains("ssoConfigurationPage.provisioningProfileFill =", show, StringComparison.Ordinal);

        var save = ProvisioningTemplateFunctionBody(js, "saveProvisioningProfile: (page) => {");
        var wait = save.IndexOf("ssoConfigurationPage.provisioningProfileFill", StringComparison.Ordinal);
        var read = save.IndexOf("readProvisioningTemplate(page, \"profile-\")", StringComparison.Ordinal);
        Assert.True(wait >= 0, "saveProvisioningProfile no longer waits for the fill in flight.");
        Assert.True(read > wait, "saveProvisioningProfile reads the editor before the fill it is serializing has settled.");
    }
}
