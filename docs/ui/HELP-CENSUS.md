# Every help text the settings pages show, and where it is

Written for stage 2, slice 0 of the 4.4 surface (#1661), before any of that
stage's help moves. One row per **site** - one field, on one page, naming one
`*_help` key of the English catalogue. The stage that follows condenses every
one of these into a sentence under the field and the whole text behind a
`<details>`, and the promise it makes is "nothing is deleted, only moved". This
table is what that promise is measured against.

## How the number is kept honest

The table is not the authority on its own; it is reconciled against the pages,
in both directions, by a gate the `.NET` workflow runs:

```
$ node tools/ui-help-census.js
calibration:        29 arms, 14 that must pass and 15 that must be refused, all as expected
accountsPage.html:    4 help site(s), 4 distinct key(s), 0 behind a <details>
configPage.html:      1 help site(s), 1 distinct key(s), 0 behind a <details>
policiesPage.html:   13 help site(s), 13 distinct key(s), 0 behind a <details>
providersPage.html: 112 help site(s), 98 distinct key(s), 0 behind a <details>
serverPage.html:      3 help site(s), 3 distinct key(s), 0 behind a <details>
the five pages:     133 help site(s) in total, 0 behind a <details>
HELP-CENSUS.md:     133 row(s), one per site
en.json:            109 *_help key(s), every one named by a page
every help text is on the page its row names, inside the field that names it, exactly once
```

A row this table names that no page holds any more is a deleted help text. A
site the pages hold that no row names is one that arrived unmeasured. Both are
refused, by name, and the counts above are printed rather than written here for
the reason `docs/ui/mock/FIELDS.md` gives for its own: a number typed into a
document goes stale against the tool that decides it.

The arms are the gate's own calibration. They run against fixtures whose answers
are known, before the real pages are opened, and the run stops instead of
counting if any of them disagrees - because a census that counts everything
passes its own arithmetic. The one refusal they do not cover is this file being
absent altogether, which is the existence of a file rather than a judgement
about one.

## What is refused, and why each one is a real loss

- **A help text the page stopped showing.** The marker still claims the key and
  the prose is gone, which is the shape a condensing edit produces when the
  `<details>` is opened and the text is not carried into it.
- **A help text the page shows twice.** Moved and also left standing. Nothing
  looks wrong on the screen; the next edit changes one of the two copies and the
  reader is shown whichever one their path reaches.
- **A help text shown the right number of times, in the wrong fields.** Ten keys
  sit on two pages and fourteen sit twice on the Providers page, once per
  protocol form, so "condensed in the OIDC form twice and dropped from the SAML
  one" balances as a count. Each occurrence is therefore attributed to the
  innermost field whose scope holds it, and a field left with none is named -
  including the case where the field that lost its text is the block the other
  one sits inside.
- **A help text outside the field that names it.** "Moved" has a destination,
  and a `<details>` opened in the next field over is not it.
- **A site the table lost, and a site the table never saw.** The set comparison,
  which is what catches a swap - a row kept for a deleted field and a new field
  with no row cancel out in a count and do not cancel out in a set. The row
  count is compared as well, because a set cannot see a row pasted twice.
- **One field naming one help key twice**, which is one description with two
  owners and no way to say which of them a later edit meant.
- **A marker naming a key the English catalogue does not carry**, and **a key
  the catalogue carries that no page names** - a help text written for nobody.
- **Markup the reader cannot walk**, named with the page, rather than a stack
  trace nobody can act on.

## What the columns mean

- **Page** is the file under `SSO-Auth/Web/`. The census is per page on purpose:
  the C# rules in `LocalizationCatalogTests` are key-wise over every asset at
  once, so a key that survives on one page covers its own deletion from another.
  Ten keys sit on two pages and fourteen sit twice on the Providers page, which
  is exactly the population those rules cannot see.
- **Help key** is the `*_help` row of `SSO-Auth/Localization/en.json` the site
  names, through `data-i18n` or through `data-i18n-parts`. For a parts site the
  text counted is the sentence the element assembles, not the row with its
  `{0}` slots still in it.
- **Field** is the `id` of the control in the `inputContainer` or
  `checkboxContainer` around the marker. Sixteen help texts are about a SECTION
  rather than about a control - the two empty-state paragraphs, the sentence
  opening each provider form's starting-policy block, the panels on Accounts -
  and those carry the id of the nearest ancestor that has one, in parentheses.
  That is what separates the OIDC copy of an identical sentence from the SAML
  one.

## What this does not say

It reads bytes. It says nothing about what a browser renders, nothing about
`de.json` - the texts are compared against the English catalogue, because the
built-in English is what the markup ships - and nothing about whether a first
sentence derived at runtime is a good one. It cannot tell a help text that was
moved from one that was deleted and rewritten identically inside the same field.

And "the field that names it" is only as tight as the container the page itself
draws. The 117 control-level sites sit in scopes of about 1.5 KB at the median;
the 16 section-level ones reach 2.5 KB at the median, 10.2 KB for the security
options block, and 19.5 KB for each provider form's starting-policy block, which
is every `Tmpl-*` field of that form. For those, "elsewhere" means outside the
whole block rather than outside one field - a text moved WITHIN such a block is
not refused, though a field inside it that ends up with no text of its own still
is.

And it says nothing about what the fold a page grew is WORTH, which is the half
a reader of the run is most likely to take it for. Slice 1 of stage 2 landed on
the three small pages that carry a field description at all (#1662 - the one
help row Overview names is a link label inside a sentence, not a field), and the `behind a <details>` figure moved with it,
so that figure is a real count of how far the stage has come. What it is not is
a statement that any of those texts can be READ. It counts an element; a help
text sealed inside a fold nobody named, above a lead line that stays empty
because no applier ran, satisfies every refusal on this page exactly as well as
a working field does - the text is present, once, inside the field that names
it, and no reader ever sees it.

What holds that half is `tools/ui-condensed-help.js`, which reads the authored
markup and then LOADS `SSO-Auth/Web/i18n.js` and drives it over both catalogues:
it refuses a help text still written flat, a fold with no lead line to fill, a
summary named by anything but the row the folds share, a sentence under the
field that is not the first sentence of the text behind it, a fold hidden while
it holds more, a rail card answering a field that does not have focus, a rail
card with no heading, a fold authored inside a `<p>` - which `<details>` closes,
so a browser lifts the fold out of the block and the lead can never be filled -
and two help blocks resolving to one field, where the card answers for the first
of them wherever the focus lands and the second cannot be reached from it at
all. The two are complements. This one holds "nothing is deleted"; that one
holds "and what happened to it is what was promised".

Neither of them is a parser, and that is the bound to carry away from this page.
Both walk the tags as they are AUTHORED; a browser walks them as PARSED, and the
two part company wherever HTML implies an end tag. The `<p>` case is refused by
name because it happened - two folds on the Providers page were authored in one
and both readers called the page whole - and the class it belongs to is open.

Slice 2 took the Providers page (#1663), and the `behind a <details>` figure for
it stops one short of its site count for a reason this table can be read against
rather than guessed at: `config.saml_base_url_override_help` sits on a
`sso-callout sso-callout-warning`, which is a warning beside the SAML base-URL
field rather than that field's description. A warning is not condensed - folding
one hides the thing it exists to put in front of a reader - and the condensing
reader's subject is `fieldDescription`, so it neither moves nor refuses it.

The same slice is where the two readers stop covering the same population, which
is stated here because the census's own figure does not show it. A help text
whose body is marked `data-i18n-parts` has its `{n}` slots filled from the body's
own child elements, so the sentence on the screen is assembled on the page; the
condensing gate builds its runtime fixture from catalogue rows and has no such
children, so those bodies are judged by its MARKUP reader and not by its applier
run, and it prints how many per page. This table counts them as it always has.

| Page                 | Help key                                      | Field                                     |
| -------------------- | --------------------------------------------- | ----------------------------------------- |
| `accountsPage.html`  | `config.linked_accounts_help`                 | `(sso-linked-accounts)`                   |
| `accountsPage.html`  | `config.linked_accounts_filter_help`          | `LinkedAccountsFilter`                    |
| `accountsPage.html`  | `config.pending_approvals_help`               | `(sso-pending-approvals)`                 |
| `accountsPage.html`  | `config.link_transfer_help`                   | `(sso-link-transfer)`                     |
| `configPage.html`    | `config.about_link_help`                      | `(sso-config-page)`                       |
| `policiesPage.html`  | `config.profiles_select_help`                 | `selectProvisioningProfile`               |
| `policiesPage.html`  | `config.profiles_name_help`                   | `ProvisioningProfileName`                 |
| `policiesPage.html`  | `config.profiles_copy_help`                   | `ProvisioningProfileSource`               |
| `policiesPage.html`  | `config.template_bitrate_help`                | `profile-Tmpl-RemoteClientBitrateLimit`   |
| `policiesPage.html`  | `config.template_sessions_help`               | `profile-Tmpl-MaxActiveSessions`          |
| `policiesPage.html`  | `config.template_audio_language_help`         | `profile-Tmpl-AudioLanguagePreference`    |
| `policiesPage.html`  | `config.template_subtitle_language_help`      | `profile-Tmpl-SubtitleLanguagePreference` |
| `policiesPage.html`  | `config.template_subtitle_mode_help`          | `profile-Tmpl-SubtitleMode`               |
| `policiesPage.html`  | `config.template_play_default_audio_help`     | `profile-Tmpl-PlayDefaultAudioTrack`      |
| `policiesPage.html`  | `config.template_remember_audio_help`         | `profile-Tmpl-RememberAudioSelections`    |
| `policiesPage.html`  | `config.template_remember_subtitle_help`      | `profile-Tmpl-RememberSubtitleSelections` |
| `policiesPage.html`  | `config.template_home_sections_help`          | `profile-Tmpl-HomeSections`               |
| `policiesPage.html`  | `config.template_permissions_help`            | `(sso-provisioning-profiles)`             |
| `providersPage.html` | `config.oidc_empty_help`                      | `(sso-provider-empty)`                    |
| `providersPage.html` | `config.template_picker_help`                 | `OidPreset`                               |
| `providersPage.html` | `config.oid_name_help`                        | `OidProviderName`                         |
| `providersPage.html` | `config.oid_redirect_uri_help`                | `OidRedirectUri`                          |
| `providersPage.html` | `config.oidc_endpoint_help`                   | `OidEndpoint`                             |
| `providersPage.html` | `config.oid_client_id_help`                   | `OidClientId`                             |
| `providersPage.html` | `config.oidc_secret_help`                     | `OidSecret`                               |
| `providersPage.html` | `config.oid_scopes_help`                      | `OidScopes`                               |
| `providersPage.html` | `config.provider_hide_login_button_help`      | `HideLoginButton`                         |
| `providersPage.html` | `config.provider_login_button_text_help`      | `LoginButtonText`                         |
| `providersPage.html` | `config.oidc_post_logout_redirect_help`       | `PostLogoutRedirectUri`                   |
| `providersPage.html` | `config.enable_authorization_help`            | `EnableAuthorization`                     |
| `providersPage.html` | `config.default_username_claim_help`          | `DefaultUsernameClaim`                    |
| `providersPage.html` | `config.default_provider_help`                | `DefaultProvider`                         |
| `providersPage.html` | `config.avatar_url_format_help`               | `AvatarUrlFormat`                         |
| `providersPage.html` | `config.avatar_no_fetch_help`                 | `DisableAvatarFromPictureClaim`           |
| `providersPage.html` | `config.role_claim_help`                      | `RoleClaim`                               |
| `providersPage.html` | `config.role_claim_object_help`               | `RoleClaimIsObjectMap`                    |
| `providersPage.html` | `config.template_help`                        | `(sso-editor)`                            |
| `providersPage.html` | `config.provisioning_profile_help`            | `ProvisioningProfile`                     |
| `providersPage.html` | `config.template_bitrate_help`                | `Tmpl-RemoteClientBitrateLimit`           |
| `providersPage.html` | `config.template_sessions_help`               | `Tmpl-MaxActiveSessions`                  |
| `providersPage.html` | `config.template_audio_language_help`         | `Tmpl-AudioLanguagePreference`            |
| `providersPage.html` | `config.template_subtitle_language_help`      | `Tmpl-SubtitleLanguagePreference`         |
| `providersPage.html` | `config.template_subtitle_mode_help`          | `Tmpl-SubtitleMode`                       |
| `providersPage.html` | `config.template_play_default_audio_help`     | `Tmpl-PlayDefaultAudioTrack`              |
| `providersPage.html` | `config.template_remember_audio_help`         | `Tmpl-RememberAudioSelections`            |
| `providersPage.html` | `config.template_remember_subtitle_help`      | `Tmpl-RememberSubtitleSelections`         |
| `providersPage.html` | `config.template_home_sections_help`          | `Tmpl-HomeSections`                       |
| `providersPage.html` | `config.template_permissions_help`            | `(sso-editor)`                            |
| `providersPage.html` | `config.oid_roles_help`                       | `Roles`                                   |
| `providersPage.html` | `config.admin_roles_help`                     | `AdminRoles`                              |
| `providersPage.html` | `config.oidc_enable_all_folders_help`         | `EnableAllFolders`                        |
| `providersPage.html` | `config.enabled_folders_help`                 | `EnabledFolders`                          |
| `providersPage.html` | `config.oidc_enable_folder_roles_help`        | `EnableFolderRoles`                       |
| `providersPage.html` | `config.folder_role_mapping_help`             | `AddRoleMapping`                          |
| `providersPage.html` | `config.oidc_enable_live_tv_roles_help`       | `EnableLiveTvRoles`                       |
| `providersPage.html` | `config.livetv_roles_help`                    | `LiveTvRoles`                             |
| `providersPage.html` | `config.livetv_management_roles_help`         | `LiveTvManagementRoles`                   |
| `providersPage.html` | `config.livetv_access_help`                   | `EnableLiveTv`                            |
| `providersPage.html` | `config.livetv_manage_help`                   | `EnableLiveTvManagement`                  |
| `providersPage.html` | `config.oidc_do_not_load_profile_help`        | `DoNotLoadProfile`                        |
| `providersPage.html` | `config.oidc_scheme_override_help`            | `SchemeOverride`                          |
| `providersPage.html` | `config.oidc_port_override_help`              | `PortOverride`                            |
| `providersPage.html` | `config.base_url_override_help`               | `BaseUrlOverride`                         |
| `providersPage.html` | `config.require_pkce_help`                    | `RequirePkce`                             |
| `providersPage.html` | `config.acr_values_help`                      | `AcrValues`                               |
| `providersPage.html` | `config.prompt_help`                          | `Prompt`                                  |
| `providersPage.html` | `config.max_age_help`                         | `MaxAge`                                  |
| `providersPage.html` | `config.require_acr_help`                     | `RequireAcr`                              |
| `providersPage.html` | `config.allow_adoption_help`                  | `AllowExistingAccountLink`                |
| `providersPage.html` | `config.provision_disabled_help`              | `ProvisionNewUsersDisabled`               |
| `providersPage.html` | `config.follow_renames_help`                  | `SyncUsernameFromProvider`                |
| `providersPage.html` | `config.require_verified_email_adoption_help` | `RequireVerifiedEmailForAdoption`         |
| `providersPage.html` | `config.require_verified_email_login_help`    | `RequireVerifiedEmailForLogin`            |
| `providersPage.html` | `config.insecure_options_help`                | `(sso-security-section)`                  |
| `providersPage.html` | `config.disable_https_help`                   | `DisableHttps`                            |
| `providersPage.html` | `config.no_validate_endpoints_help`           | `DoNotValidateEndpoints`                  |
| `providersPage.html` | `config.allow_private_network_help`           | `AllowPrivateNetworkAddresses`            |
| `providersPage.html` | `config.no_validate_issuer_help`              | `DoNotValidateIssuerName`                 |
| `providersPage.html` | `config.no_validate_response_issuer_help`     | `DoNotValidateResponseIssuer`             |
| `providersPage.html` | `config.oid_test_help`                        | `(sso-editor)`                            |
| `providersPage.html` | `config.saml_empty_help`                      | `(saml-provider-empty)`                   |
| `providersPage.html` | `config.saml_template_help`                   | `saml-Preset`                             |
| `providersPage.html` | `config.saml_name_help`                       | `saml-provider-name`                      |
| `providersPage.html` | `config.saml_metadata_import_help`            | `saml-metadata-url`                       |
| `providersPage.html` | `config.saml_endpoint_help`                   | `saml-SamlEndpoint`                       |
| `providersPage.html` | `config.saml_slo_endpoint_help`               | `saml-SamlSloEndpoint`                    |
| `providersPage.html` | `config.saml_client_id_help`                  | `saml-SamlClientId`                       |
| `providersPage.html` | `config.saml_certificate_help`                | `saml-SamlCertificate`                    |
| `providersPage.html` | `config.saml_acs_url_help`                    | `saml-AcsUrl`                             |
| `providersPage.html` | `config.saml_metadata_url_help`               | `saml-MetadataUrl`                        |
| `providersPage.html` | `config.provider_hide_login_button_help`      | `saml-HideLoginButton`                    |
| `providersPage.html` | `config.provider_login_button_text_help`      | `saml-LoginButtonText`                    |
| `providersPage.html` | `config.saml_enable_authorization_help`       | `saml-EnableAuthorization`                |
| `providersPage.html` | `config.saml_default_provider_help`           | `saml-DefaultProvider`                    |
| `providersPage.html` | `config.saml_allow_adoption_help`             | `saml-AllowExistingAccountLink`           |
| `providersPage.html` | `config.saml_provision_disabled_help`         | `saml-ProvisionNewUsersDisabled`          |
| `providersPage.html` | `config.saml_follow_renames_help`             | `saml-SyncUsernameFromProvider`           |
| `providersPage.html` | `config.template_help`                        | `(saml-editor)`                           |
| `providersPage.html` | `config.provisioning_profile_help`            | `saml-ProvisioningProfile`                |
| `providersPage.html` | `config.template_bitrate_help`                | `saml-Tmpl-RemoteClientBitrateLimit`      |
| `providersPage.html` | `config.template_sessions_help`               | `saml-Tmpl-MaxActiveSessions`             |
| `providersPage.html` | `config.template_audio_language_help`         | `saml-Tmpl-AudioLanguagePreference`       |
| `providersPage.html` | `config.template_subtitle_language_help`      | `saml-Tmpl-SubtitleLanguagePreference`    |
| `providersPage.html` | `config.template_subtitle_mode_help`          | `saml-Tmpl-SubtitleMode`                  |
| `providersPage.html` | `config.template_play_default_audio_help`     | `saml-Tmpl-PlayDefaultAudioTrack`         |
| `providersPage.html` | `config.template_remember_audio_help`         | `saml-Tmpl-RememberAudioSelections`       |
| `providersPage.html` | `config.template_remember_subtitle_help`      | `saml-Tmpl-RememberSubtitleSelections`    |
| `providersPage.html` | `config.template_home_sections_help`          | `saml-Tmpl-HomeSections`                  |
| `providersPage.html` | `config.template_permissions_help`            | `(saml-editor)`                           |
| `providersPage.html` | `config.saml_roles_help`                      | `saml-Roles`                              |
| `providersPage.html` | `config.saml_admin_roles_help`                | `saml-AdminRoles`                         |
| `providersPage.html` | `config.saml_enable_all_folders_help`         | `saml-EnableAllFolders`                   |
| `providersPage.html` | `config.saml_enabled_folders_help`            | `saml-EnabledFolders`                     |
| `providersPage.html` | `config.saml_enable_folder_roles_help`        | `saml-EnableFolderRoles`                  |
| `providersPage.html` | `config.saml_folder_role_mapping_help`        | `saml-AddRoleMapping`                     |
| `providersPage.html` | `config.saml_enable_livetv_roles_help`        | `saml-EnableLiveTvRoles`                  |
| `providersPage.html` | `config.saml_livetv_roles_help`               | `saml-LiveTvRoles`                        |
| `providersPage.html` | `config.saml_scheme_override_help`            | `saml-SchemeOverride`                     |
| `providersPage.html` | `config.saml_port_override_help`              | `saml-PortOverride`                       |
| `providersPage.html` | `config.saml_base_url_override_help`          | `saml-BaseUrlOverride`                    |
| `providersPage.html` | `config.saml_validate_recipient_help`         | `saml-ValidateRecipient`                  |
| `providersPage.html` | `config.saml_validate_inresponseto_help`      | `saml-ValidateInResponseTo`               |
| `providersPage.html` | `config.saml_audience_help`                   | `saml-SamlAudience`                       |
| `providersPage.html` | `config.saml_sign_authn_help`                 | `saml-SignAuthnRequests`                  |
| `providersPage.html` | `config.saml_signing_key_help`                | `saml-SamlSigningKeyPfx`                  |
| `providersPage.html` | `config.saml_rollover_signing_key_help`       | `saml-SamlRolloverSigningKeyPfx`          |
| `providersPage.html` | `config.saml_secondary_certificate_help`      | `saml-SamlSecondaryCertificate`           |
| `providersPage.html` | `config.saml_insecure_options_help`           | `(saml-security-section)`                 |
| `providersPage.html` | `config.saml_no_validate_audience_help`       | `saml-DoNotValidateAudience`              |
| `providersPage.html` | `config.saml_test_help`                       | `(saml-editor)`                           |
| `serverPage.html`    | `config.server_transfer_help`                 | `(sso-config-transfer)`                   |
| `serverPage.html`    | `config.server_login_buttons_help`            | `ManageLoginPageButtons`                  |
| `serverPage.html`    | `config.server_slo_help`                      | `EnableSingleLogout`                      |
