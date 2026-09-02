// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for the provisioning-template controls on both provider forms (#1367). The controls
/// are browser code and this tree carries no JavaScript runtime, no DOM and no browser automation - a
/// means decision taken on 2026-08-31 and not revisited here - so nothing below executes them. Each rule
/// therefore pins a STRUCTURAL property a wrong edit cannot satisfy by accident: which ids exist, which
/// KIND of control each field renders, which vocabulary the options carry, and which branch the save path
/// takes. What that reading cannot reach - the value a control actually yields when nobody touched it - is
/// argued in the pull request rather than claimed here.
/// </content>
public partial class ArchitectureConformanceTests
{
    // The four marker classes the template serializer reads, mirroring config.js templateControls. They are
    // deliberately NOT the five flat-contract classes (sso-text/sso-line-list/sso-toggle/sso-folder-list/
    // sso-role-map): those ids must equal an OidConfig or SamlConfig property, and every field here belongs
    // to the NESTED ProvisioningPolicyTemplate instead, so a marker of that family would be refused by
    // ProviderFormFieldIds_MatchOidConfigProperties - correctly, because the flat save path cannot reach it.
    private static readonly string[] TemplateMarkerClasses =
        ["sso-tmpl-number", "sso-tmpl-text", "sso-tmpl-bool", "sso-tmpl-perms"];

    private static string ProvisioningTemplateMarkup()
        => File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "configPage.html"));

    private static string ProvisioningTemplateScript()
        => File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));

    private static IReadOnlyList<string> TemplatePropertyNames()
        => typeof(ProvisioningPolicyTemplate)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

    // Every element in one form that carries a template marker class, as (id, class attribute, whole tag).
    private static List<(string Id, string Classes, string Tag)> TemplateControls(string form)
    {
        var found = new List<(string, string, string)>();
        foreach (Match tag in Regex.Matches(form, "<[a-zA-Z][^>]*>", RegexOptions.Singleline))
        {
            var classAttr = Regex.Match(tag.Value, "class=\"([^\"]*)\"", RegexOptions.Singleline);
            if (!classAttr.Success)
            {
                continue;
            }

            var classes = classAttr.Groups[1].Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (!classes.Any(c => TemplateMarkerClasses.Contains(c, StringComparer.Ordinal)))
            {
                continue;
            }

            var idMatch = Regex.Match(tag.Value, "(?<![-\\w])id=\"([^\"]*)\"", RegexOptions.Singleline);
            found.Add((idMatch.Success ? idMatch.Groups[1].Value : "(no id)", classAttr.Groups[1].Value.Trim(), tag.Value));
        }

        return found;
    }

    [Theory]
    [InlineData("oidc", "")]
    [InlineData("saml", "saml-")]
    public void ProvisioningTemplateForm_OffersExactlyTheTemplateProperties(string protocol, string prefix)
    {
        // The nested twin of ProviderFormFieldIds_MatchOidConfigProperties. A marked id whose stripped name
        // is not a ProvisioningPolicyTemplate property renders and never saves - the server drops JSON
        // members the type does not declare - and a property with no control is a field of the starting
        // policy that stays invisible on the page, which is the whole of what this issue is about. Compared
        // as a SET IN BOTH DIRECTIONS for that reason: a subset assertion would pass a form that quietly
        // stopped offering a field.
        var form = protocol == "oidc"
            ? OidcProviderFormMarkup(ProvisioningTemplateMarkup())
            : SamlProviderFormMarkup(ProvisioningTemplateMarkup());

        var controls = TemplateControls(form);
        Assert.True(controls.Count > 0, $"the {protocol} form carries no template control at all - a renamed marker class would empty this scan silently");

        var offenders = controls
            .Where(c => !c.Id.StartsWith(prefix + "Tmpl-", StringComparison.Ordinal))
            .Select(c => $"{c.Id} (classes: {c.Classes})")
            .ToList();
        Assert.True(
            offenders.Count == 0,
            $"Every template control on the {protocol} form must have an id of \"{prefix}Tmpl-\" + a ProvisioningPolicyTemplate property; these do not: " + string.Join(" | ", offenders));

        var offered = controls
            .Select(c => c.Id[(prefix + "Tmpl-").Length..])
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(TemplatePropertyNames(), offered);
    }

    [Theory]
    [InlineData("oidc", "")]
    [InlineData("saml", "saml-")]
    public void ProvisioningTemplateNullableBooleans_RenderAsThreeStateSelects(string protocol, string prefix)
    {
        // THE FAIL-CLOSED DIRECTION OF THIS FEATURE, and the one a straightforward form gets wrong. Three
        // members of the template are `bool?`, where null means "leave Jellyfin's own default alone" and
        // false means "do not do this". A checkbox has TWO states, so it would post a deliberate false for
        // a field the administrator never touched - a declined field turned into a set one, written onto
        // every account the provider creates. The control kind is therefore pinned to a select carrying an
        // empty-valued option, and the set of fields it applies to is DERIVED from the type rather than
        // typed here, so a member that becomes nullable later joins this rule on its own.
        var nullableBooleans = typeof(ProvisioningPolicyTemplate)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType == typeof(bool?))
            .Select(p => p.Name)
            .ToList();
        Assert.Equal(3, nullableBooleans.Count);

        var form = protocol == "oidc"
            ? OidcProviderFormMarkup(ProvisioningTemplateMarkup())
            : SamlProviderFormMarkup(ProvisioningTemplateMarkup());

        foreach (var name in nullableBooleans)
        {
            var id = prefix + "Tmpl-" + name;
            var control = TemplateControls(form).SingleOrDefault(c => c.Id == id);
            Assert.True(control.Tag != null, $"{id} is not a marked template control on the {protocol} form");
            Assert.StartsWith("<select", control.Tag, StringComparison.Ordinal);
            Assert.Contains("sso-tmpl-bool", control.Classes, StringComparison.Ordinal);
            Assert.DoesNotContain("sso-toggle", control.Classes, StringComparison.Ordinal);

            // The element's own options, from its tag to the closing tag: one of them must carry the empty
            // value, which is the state that declines the field.
            var start = form.IndexOf(control.Tag, StringComparison.Ordinal);
            var end = form.IndexOf("</select>", start, StringComparison.Ordinal);
            Assert.True(end > start, $"{id} has no closing select tag");
            Assert.Contains("value=\"\"", form[start..end], StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("oidc", "")]
    [InlineData("saml", "saml-")]
    public void ProvisioningTemplateSubtitleMode_OffersExactlyTheEnumNames(string protocol, string prefix)
    {
        // SubtitleMode is the one template field with a closed vocabulary, validated case-sensitively
        // against SubtitlePlaybackMode by name (#1482). A free-text box would let a lowercase spelling
        // through to a save-time refusal, and a hand-written option list would drift against the enum in
        // both directions. The expectation is read out of the enum, so a mode Jellyfin adds or removes
        // fails this test rather than reaching an administrator as a wrong list.
        var form = protocol == "oidc"
            ? OidcProviderFormMarkup(ProvisioningTemplateMarkup())
            : SamlProviderFormMarkup(ProvisioningTemplateMarkup());

        var control = TemplateControls(form).SingleOrDefault(c => c.Id == prefix + "Tmpl-SubtitleMode");
        Assert.True(control.Tag != null, $"{prefix}Tmpl-SubtitleMode is not a marked template control on the {protocol} form");
        Assert.StartsWith("<select", control.Tag, StringComparison.Ordinal);

        var start = form.IndexOf(control.Tag, StringComparison.Ordinal);
        var end = form.IndexOf("</select>", start, StringComparison.Ordinal);
        var options = Regex.Matches(form[start..end], "<option value=\"(?<value>[^\"]*)\"")
            .Select(m => m.Groups["value"].Value)
            .ToList();

        // The empty option first (declining the field), then every declared mode and nothing else.
        Assert.Equal(string.Empty, options.FirstOrDefault());
        Assert.Equal(
            Enum.GetNames<SubtitlePlaybackMode>().OrderBy(n => n, StringComparer.Ordinal).ToList(),
            options.Skip(1).OrderBy(n => n, StringComparer.Ordinal).ToList());
    }

    [Fact]
    public void ProvisioningTemplatePermissions_KeepNoVocabularyOfTheirOwn()
    {
        // The mappable permission names are derived on the server from Jellyfin's enum minus a private
        // exclusion set, and #1484 published them at one route for exactly this control. A second copy on
        // the page drifts silently in three directions - a member Jellyfin adds stays invisible, one it
        // removes stays offerable and is refused at save, and a name added to the exclusion set keeps being
        // offered. So the page must FETCH the vocabulary and must not spell a PermissionKind member.
        var js = ProvisioningTemplateScript();
        Assert.Contains("ApiClient.getUrl(\"sso/Config/Permissions\")", js, StringComparison.Ordinal);

        // Scoped to the functions that build the control rather than to the whole file: several
        // PermissionKind names are also OidConfig properties the flat provider form persists under the same
        // spelling (EnableAllFolders, EnableLiveTvAccess), and those are a different setting on a different
        // save path. A copy of the vocabulary would have to live where the rows are made.
        var permissionCode = string.Concat(
            ProvisioningTemplateFunctionBody(js, "loadTemplatePermissionNames: () => {"),
            ProvisioningTemplateFunctionBody(js, "populateTemplatePermissions: (page, prefix, entries) => {"),
            ProvisioningTemplateFunctionBody(js, "renderTemplatePermissionRow: (container, entry, names) => {"),
            ProvisioningTemplateFunctionBody(js, "serializeTemplatePermissions: (container) => {"));

        var spelled = Enum.GetNames<PermissionKind>()
            .Where(name => permissionCode.Contains("\"" + name + "\"", StringComparison.Ordinal))
            .ToList();
        Assert.True(
            spelled.Count == 0,
            "the permission-row code must not carry a copy of the vocabulary - it is published by sso/Config/Permissions; these names are spelled there: " + string.Join(", ", spelled));
    }

    [Fact]
    public void ProvisioningTemplatePermissionRow_NamesTheEntryMembersTheServerDeclares()
    {
        // A permission row is the one place on this page that builds a nested object of its OWN, member by
        // member, so a wrong member name is not a typo the compiler or the flat contract catches: the server
        // drops JSON members ProvisionedPermissionEntry does not declare, and the row would render, save
        // without complaint and write nothing. It was written as Value first, for exactly that reason - the
        // property is Granted - and the mistake survived every other rule in this file. So the names are
        // DERIVED from the type here, in both directions.
        var expected = typeof(ProvisionedPermissionEntry)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        var js = ProvisioningTemplateScript();
        var serializer = ProvisioningTemplateFunctionBody(js, "serializeTemplatePermissions: (container) => {");

        var written = Regex.Matches(serializer, @"^\s{10}(?<member>[A-Za-z][A-Za-z0-9]*):", RegexOptions.Multiline)
            .Select(m => m.Groups["member"].Value)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();
        Assert.Equal(expected, written);

        // The reader half: every member the row writes must also be the one it reads back, or a saved row
        // renders at its default the next time the provider is opened.
        var renderer = ProvisioningTemplateFunctionBody(js, "renderTemplatePermissionRow: (container, entry, names) => {");
        foreach (var member in expected)
        {
            Assert.Contains("entry." + member, renderer, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ProvisioningTemplateSerializer_TreatsAnUntouchedControlAsDeclined()
    {
        // The three-state meaning of every template field lives in ONE function on the page, so this pins
        // its shape rather than its behaviour: an empty value contributes no member (the field stays
        // declined and Jellyfin's own default governs), and only the two boolean literals become a value.
        // A rewrite that assigned unconditionally - the natural way to write it, and the way the flat
        // contract beside it is written - would turn every untouched control into a set field.
        var reader = ProvisioningTemplateFunctionBody(
            ProvisioningTemplateScript(),
            "readProvisioningTemplate: (page, prefix) => {");

        Assert.Contains("if (element.value !== \"\")", reader, StringComparison.Ordinal);
        Assert.Contains("if (element.value === \"true\")", reader, StringComparison.Ordinal);
        Assert.Contains("else if (element.value === \"false\")", reader, StringComparison.Ordinal);
        Assert.DoesNotContain(".checked", reader, StringComparison.Ordinal);

        // An all-unset form is NO OBJECT rather than an object of nulls: ProviderConfigValidator refuses an
        // inline template beside a named provisioning profile on the object being PRESENT, whatever it
        // carries, so an always-assembled object would make every profile-using provider unsaveable here.
        Assert.Contains("Object.keys(template).length === 0 ? null : template", reader, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("saveProvider: (page, provider_name) => {")]
    [InlineData("saveSamlProvider: (page, provider_name) => {")]
    public void ProvisioningTemplateSave_LeavesAProfileUsingProviderAlone(string opener)
    {
        // The other half of the same refusal, one level up. A provider that names a provisioning profile
        // may carry no inline template at all, so the save must write NOTHING here rather than write null:
        // the member is left exactly as stored, and a provider whose policy comes from a profile stays
        // saveable from this page - client id, secret, redirect path and all - over a section the
        // administrator never opened.
        var save = ProvisioningTemplateFunctionBody(ProvisioningTemplateScript(), opener);

        var guard = save.IndexOf("if (!current_config.ProvisioningProfile) {", StringComparison.Ordinal);
        Assert.True(guard >= 0, $"{opener} must guard the template write on the provider not naming a profile");

        var write = save.IndexOf("current_config.ProvisioningPolicyTemplate", StringComparison.Ordinal);
        Assert.True(write > guard, $"{opener} writes the template outside the profile guard");
    }

    // The text of one property on the ssoConfigurationPage object literal, by the same rule the
    // linked-accounts rules read one: from its opener to the next "  }," at the object's own indent.
    private static string ProvisioningTemplateFunctionBody(string js, string opener)
    {
        var start = js.IndexOf(opener, StringComparison.Ordinal);
        Assert.True(start >= 0, $"config.js no longer declares '{opener}' - the provisioning-template rules cannot read it.");

        var end = js.IndexOf("\n  },", start, StringComparison.Ordinal);
        Assert.True(end > start, $"config.js: could not find the end of '{opener}'.");

        return js[start..end];
    }
}
