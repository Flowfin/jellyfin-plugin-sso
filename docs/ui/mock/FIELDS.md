# Where every field of the configuration page goes

Stage 0 of the 4.4 surface (#1526). One row per form control of
`SSO-Auth/Web/configPage.html`, with the block it sits in today and the tab and
accordion it takes in the mock beside this file.

## How the number is kept honest

The count is read off the page rather than written here:

```
$ node tools/ui-mock-fields.js
configPage.html: 123 form controls outside HTML comments
FIELDS.md:       123 rows
fields.js:       123 entries
every field of the page has one row, and no row names a field the page lost
```

That check compares the id SETS of the three, not their sizes. A row kept for a
deleted field and a new field with no row cancel out in a count and do not
cancel out in a set, so it is the set comparison that catches the drift the
count exists for. It exits non-zero when the three disagree.

**123 and not 124.** A reader that greps the raw bytes of the page counts 124,
because the page documents its hidden `selectProvider` inside an HTML comment
that contains a second `<select>` tag. The check strips comments first, so the
number it prints is the set of controls an administrator can reach.

## What the columns mean

- **Field** is the `id` on the page. All 123 carry one and all 123 are distinct,
  which is what makes the id the key this table reconciles on.
- **Old block** is the `title` of the `verticalSection` the control sits in
  today, read off the page rather than typed here. Four controls sit outside
  every block and say so.
- **Marked** is the page's own classification, derived from the
  `sso-sensitive-region` and `sso-danger-zone` regions it already draws around
  those controls. Nothing here reclassifies a control.

## What is not a field

Four rows are the mechanism of a button rather than a setting, and they are in
the table anyway, because a table four short of the number cannot be reconciled
against it:

- `ImportConfigFile` - the file picker behind Import configuration, not a setting
- `ImportLinksFile` - the file picker behind Import account links, not a setting
- `selectProvider` - hidden state holder the save path reads back, not a setting
- `saml-selectProvider` - hidden state holder the save path reads back, not a setting

## Overview holds no field

Overview is a status view: a card per provider with enabled, tested and last
sign-in, the SSO-only state, and what to do next. Every one of those is read
from the server rather than set, so no row lands there. That follows the plan in
#1525 and is not a gap in this table.

## The table

| Field                                     | Type     | Old block                        | New tab   | New accordion         | Marked    | Note                                                                                 |
| ----------------------------------------- | -------- | -------------------------------- | --------- | --------------------- | --------- | ------------------------------------------------------------------------------------ |
| `selectProvider`                          | select   | (outside every block)            | Providers | Provider list         | -         | hidden state holder the save path reads back, not a setting                          |
| `saml-selectProvider`                     | select   | (outside every block)            | Providers | Provider list         | -         | hidden state holder the save path reads back, not a setting                          |
| `OidPreset`                               | select   | (outside every block)            | Providers | Wizard step 1         | -         | protocol and template, the first step of the add-provider wizard                     |
| `saml-Preset`                             | select   | (outside every block)            | Providers | Wizard step 1         | -         | protocol and template, the first step of the add-provider wizard                     |
| `OidProviderName`                         | text     | Connection                       | Providers | Basics                | -         |                                                                                      |
| `OidRedirectUri`                          | text     | Connection                       | Providers | Basics                | -         |                                                                                      |
| `OidEndpoint`                             | text     | Connection                       | Providers | Basics                | -         |                                                                                      |
| `OidClientId`                             | text     | Connection                       | Providers | Basics                | -         |                                                                                      |
| `OidSecret`                               | password | Connection                       | Providers | Basics                | -         |                                                                                      |
| `OidScopes`                               | text     | Connection                       | Providers | Basics                | -         |                                                                                      |
| `Enabled`                                 | checkbox | Connection                       | Providers | Basics                | -         |                                                                                      |
| `saml-provider-name`                      | text     | Connection                       | Providers | Basics                | -         |                                                                                      |
| `saml-metadata-url`                       | text     | Connection                       | Providers | Basics                | -         |                                                                                      |
| `saml-metadata-xml`                       | textarea | Connection                       | Providers | Basics                | -         |                                                                                      |
| `saml-SamlEndpoint`                       | text     | Connection                       | Providers | Basics                | -         |                                                                                      |
| `saml-SamlSloEndpoint`                    | text     | Connection                       | Providers | Basics                | -         |                                                                                      |
| `saml-SamlClientId`                       | text     | Connection                       | Providers | Basics                | -         |                                                                                      |
| `saml-SamlCertificate`                    | textarea | Connection                       | Providers | Basics                | -         |                                                                                      |
| `saml-AcsUrl`                             | text     | Connection                       | Providers | Basics                | -         |                                                                                      |
| `saml-MetadataUrl`                        | text     | Connection                       | Providers | Basics                | -         |                                                                                      |
| `saml-Enabled`                            | checkbox | Connection                       | Providers | Basics                | -         |                                                                                      |
| `HideLoginButton`                         | checkbox | Connection                       | Providers | Login button          | -         |                                                                                      |
| `LoginButtonText`                         | text     | Connection                       | Providers | Login button          | -         |                                                                                      |
| `saml-HideLoginButton`                    | checkbox | Connection                       | Providers | Login button          | -         |                                                                                      |
| `saml-LoginButtonText`                    | text     | Connection                       | Providers | Login button          | -         |                                                                                      |
| `EnableAuthorization`                     | checkbox | User provisioning                | Providers | Accounts and roles    | -         |                                                                                      |
| `DefaultUsernameClaim`                    | text     | User provisioning                | Providers | Accounts and roles    | -         |                                                                                      |
| `DefaultProvider`                         | text     | User provisioning                | Providers | Accounts and roles    | -         |                                                                                      |
| `AvatarUrlFormat`                         | text     | User provisioning                | Providers | Accounts and roles    | -         |                                                                                      |
| `DisableAvatarFromPictureClaim`           | checkbox | User provisioning                | Providers | Accounts and roles    | -         |                                                                                      |
| `RoleClaim`                               | text     | User provisioning                | Providers | Accounts and roles    | -         |                                                                                      |
| `RoleClaimIsObjectMap`                    | checkbox | User provisioning                | Providers | Accounts and roles    | -         |                                                                                      |
| `Roles`                                   | text     | Roles & access                   | Providers | Accounts and roles    | -         |                                                                                      |
| `AdminRoles`                              | text     | Roles & access                   | Providers | Accounts and roles    | -         |                                                                                      |
| `saml-EnableAuthorization`                | checkbox | User provisioning                | Providers | Accounts and roles    | -         |                                                                                      |
| `saml-DefaultProvider`                    | text     | User provisioning                | Providers | Accounts and roles    | -         |                                                                                      |
| `saml-AllowExistingAccountLink`           | checkbox | User provisioning                | Providers | Accounts and roles    | -         |                                                                                      |
| `saml-ProvisionNewUsersDisabled`          | checkbox | User provisioning                | Providers | Accounts and roles    | -         |                                                                                      |
| `saml-SyncUsernameFromProvider`           | checkbox | User provisioning                | Providers | Accounts and roles    | -         |                                                                                      |
| `saml-Roles`                              | text     | Roles & access                   | Providers | Accounts and roles    | -         |                                                                                      |
| `saml-AdminRoles`                         | text     | Roles & access                   | Providers | Accounts and roles    | -         |                                                                                      |
| `ProvisioningProfile`                     | select   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `Tmpl-RemoteClientBitrateLimit`           | number   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `Tmpl-MaxActiveSessions`                  | number   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `Tmpl-AudioLanguagePreference`            | text     | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `Tmpl-SubtitleLanguagePreference`         | text     | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `Tmpl-SubtitleMode`                       | select   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `Tmpl-PlayDefaultAudioTrack`              | select   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `Tmpl-RememberAudioSelections`            | select   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `Tmpl-RememberSubtitleSelections`         | select   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `Tmpl-HomeSections`                       | text     | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `saml-ProvisioningProfile`                | select   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `saml-Tmpl-RemoteClientBitrateLimit`      | number   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `saml-Tmpl-MaxActiveSessions`             | number   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `saml-Tmpl-AudioLanguagePreference`       | text     | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `saml-Tmpl-SubtitleLanguagePreference`    | text     | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `saml-Tmpl-SubtitleMode`                  | select   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `saml-Tmpl-PlayDefaultAudioTrack`         | select   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `saml-Tmpl-RememberAudioSelections`       | select   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `saml-Tmpl-RememberSubtitleSelections`    | select   | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `saml-Tmpl-HomeSections`                  | text     | Starting policy for new accounts | Providers | Starting policy       | -         |                                                                                      |
| `EnableAllFolders`                        | checkbox | Roles & access                   | Providers | Libraries and Live TV | -         |                                                                                      |
| `EnableFolderRoles`                       | checkbox | Roles & access                   | Providers | Libraries and Live TV | -         |                                                                                      |
| `EnableLiveTvRoles`                       | checkbox | Live TV                          | Providers | Libraries and Live TV | -         |                                                                                      |
| `LiveTvRoles`                             | text     | Live TV                          | Providers | Libraries and Live TV | -         |                                                                                      |
| `LiveTvManagementRoles`                   | text     | Live TV                          | Providers | Libraries and Live TV | -         |                                                                                      |
| `EnableLiveTv`                            | checkbox | Live TV                          | Providers | Libraries and Live TV | -         |                                                                                      |
| `EnableLiveTvManagement`                  | checkbox | Live TV                          | Providers | Libraries and Live TV | -         |                                                                                      |
| `saml-EnableAllFolders`                   | checkbox | Roles & access                   | Providers | Libraries and Live TV | -         |                                                                                      |
| `saml-EnableFolderRoles`                  | checkbox | Roles & access                   | Providers | Libraries and Live TV | -         |                                                                                      |
| `saml-EnableLiveTvRoles`                  | checkbox | Live TV                          | Providers | Libraries and Live TV | -         |                                                                                      |
| `saml-LiveTvRoles`                        | text     | Live TV                          | Providers | Libraries and Live TV | -         |                                                                                      |
| `saml-LiveTvManagementRoles`              | text     | Live TV                          | Providers | Libraries and Live TV | -         |                                                                                      |
| `saml-EnableLiveTv`                       | checkbox | Live TV                          | Providers | Libraries and Live TV | -         |                                                                                      |
| `saml-EnableLiveTvManagement`             | checkbox | Live TV                          | Providers | Libraries and Live TV | -         |                                                                                      |
| `PostLogoutRedirectUri`                   | text     | Connection                       | Providers | Advanced              | -         |                                                                                      |
| `DoNotLoadProfile`                        | checkbox | Compatibility & overrides        | Providers | Advanced              | -         |                                                                                      |
| `SchemeOverride`                          | text     | Compatibility & overrides        | Providers | Advanced              | -         |                                                                                      |
| `PortOverride`                            | text     | Compatibility & overrides        | Providers | Advanced              | -         |                                                                                      |
| `BaseUrlOverride`                         | text     | Compatibility & overrides        | Providers | Advanced              | -         |                                                                                      |
| `RequirePkce`                             | checkbox | Security & hardening             | Providers | Advanced              | -         | the page marks neither fold around it, and turning it on hardens rather than relaxes |
| `AcrValues`                               | text     | Security & hardening             | Providers | Advanced              | -         | the page marks neither fold around it, and turning it on hardens rather than relaxes |
| `Prompt`                                  | text     | Security & hardening             | Providers | Advanced              | -         | the page marks neither fold around it, and turning it on hardens rather than relaxes |
| `MaxAge`                                  | number   | Security & hardening             | Providers | Advanced              | -         | the page marks neither fold around it, and turning it on hardens rather than relaxes |
| `RequireAcr`                              | checkbox | Security & hardening             | Providers | Advanced              | -         | the page marks neither fold around it, and turning it on hardens rather than relaxes |
| `saml-SchemeOverride`                     | text     | Compatibility & overrides        | Providers | Advanced              | -         |                                                                                      |
| `saml-PortOverride`                       | text     | Compatibility & overrides        | Providers | Advanced              | -         |                                                                                      |
| `saml-BaseUrlOverride`                    | text     | Compatibility & overrides        | Providers | Advanced              | -         |                                                                                      |
| `saml-ValidateRecipient`                  | checkbox | Security & hardening             | Providers | Advanced              | -         | the page marks neither fold around it, and turning it on hardens rather than relaxes |
| `saml-ValidateInResponseTo`               | checkbox | Security & hardening             | Providers | Advanced              | -         | the page marks neither fold around it, and turning it on hardens rather than relaxes |
| `saml-SamlAudience`                       | text     | Security & hardening             | Providers | Advanced              | -         | the page marks neither fold around it, and turning it on hardens rather than relaxes |
| `saml-SignAuthnRequests`                  | checkbox | Security & hardening             | Providers | Advanced              | -         | the page marks neither fold around it, and turning it on hardens rather than relaxes |
| `saml-SamlSigningKeyPfx`                  | password | Security & hardening             | Providers | Advanced              | -         | the page marks neither fold around it, and turning it on hardens rather than relaxes |
| `saml-SamlRolloverSigningKeyPfx`          | password | Security & hardening             | Providers | Advanced              | -         | the page marks neither fold around it, and turning it on hardens rather than relaxes |
| `AllowExistingAccountLink`                | checkbox | Security & hardening             | Providers | Sensitive             | sensitive |                                                                                      |
| `ProvisionNewUsersDisabled`               | checkbox | Security & hardening             | Providers | Sensitive             | sensitive |                                                                                      |
| `SyncUsernameFromProvider`                | checkbox | Security & hardening             | Providers | Sensitive             | sensitive |                                                                                      |
| `RequireVerifiedEmailForAdoption`         | checkbox | Security & hardening             | Providers | Sensitive             | sensitive |                                                                                      |
| `RequireVerifiedEmailForLogin`            | checkbox | Security & hardening             | Providers | Sensitive             | sensitive |                                                                                      |
| `saml-SamlSecondaryCertificate`           | textarea | Security & hardening             | Providers | Sensitive             | sensitive |                                                                                      |
| `DisableHttps`                            | checkbox | Security & hardening             | Providers | Insecure              | insecure  |                                                                                      |
| `DisablePushedAuthorization`              | checkbox | Security & hardening             | Providers | Insecure              | insecure  |                                                                                      |
| `DoNotValidateEndpoints`                  | checkbox | Security & hardening             | Providers | Insecure              | insecure  |                                                                                      |
| `AllowPrivateNetworkAddresses`            | checkbox | Security & hardening             | Providers | Insecure              | insecure  |                                                                                      |
| `DoNotValidateIssuerName`                 | checkbox | Security & hardening             | Providers | Insecure              | insecure  |                                                                                      |
| `DoNotValidateResponseIssuer`             | checkbox | Security & hardening             | Providers | Insecure              | insecure  |                                                                                      |
| `saml-DoNotValidateAudience`              | checkbox | Security & hardening             | Providers | Insecure              | insecure  |                                                                                      |
| `ImportLinksFile`                         | file     | Export / Import Configuration    | Accounts  | Export and import     | -         | the file picker behind Import account links, not a setting                           |
| `selectProvisioningProfile`               | select   | Provisioning Profiles            | Policies  | Profile editor        | -         |                                                                                      |
| `ProvisioningProfileName`                 | text     | Provisioning Profiles            | Policies  | Profile editor        | -         |                                                                                      |
| `ProvisioningProfileSource`               | select   | Provisioning Profiles            | Policies  | Profile editor        | -         |                                                                                      |
| `profile-Tmpl-RemoteClientBitrateLimit`   | number   | Provisioning Profiles            | Policies  | Profile editor        | -         |                                                                                      |
| `profile-Tmpl-MaxActiveSessions`          | number   | Provisioning Profiles            | Policies  | Profile editor        | -         |                                                                                      |
| `profile-Tmpl-AudioLanguagePreference`    | text     | Provisioning Profiles            | Policies  | Profile editor        | -         |                                                                                      |
| `profile-Tmpl-SubtitleLanguagePreference` | text     | Provisioning Profiles            | Policies  | Profile editor        | -         |                                                                                      |
| `profile-Tmpl-SubtitleMode`               | select   | Provisioning Profiles            | Policies  | Profile editor        | -         |                                                                                      |
| `profile-Tmpl-PlayDefaultAudioTrack`      | select   | Provisioning Profiles            | Policies  | Profile editor        | -         |                                                                                      |
| `profile-Tmpl-RememberAudioSelections`    | select   | Provisioning Profiles            | Policies  | Profile editor        | -         |                                                                                      |
| `profile-Tmpl-RememberSubtitleSelections` | select   | Provisioning Profiles            | Policies  | Profile editor        | -         |                                                                                      |
| `profile-Tmpl-HomeSections`               | text     | Provisioning Profiles            | Policies  | Profile editor        | -         |                                                                                      |
| `ManageLoginPageButtons`                  | checkbox | Login Page Buttons               | Server    | Login buttons         | -         |                                                                                      |
| `EnableSingleLogout`                      | checkbox | Single Logout                    | Server    | Single logout         | -         |                                                                                      |
| `ImportConfigFile`                        | file     | Export / Import Configuration    | Server    | Export and import     | -         | the file picker behind Import configuration, not a setting                           |

## The two protocols keep their own controls

An OpenID provider and a SAML provider each carry their own set on the page
today, and the table gives each its own row: `Roles` and `saml-Roles` are two
fields rather than one field seen twice. The mock puts both under the same
accordion of the provider editor and shows one protocol at a time, which is how
one accordion set serves the 8 OpenID controls and the 49 SAML ones.
