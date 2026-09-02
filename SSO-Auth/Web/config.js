// The shared localization module (#913), set once its dynamic import resolves in localize() below.
// Until then, and permanently if the load fails, tr() returns the caller's built-in English, so the
// page never renders a bare catalog key.
let i18n = null;

// Localized text for a catalog key, falling back to the English default the call site carries. The
// default is the same wording the static markup holds, so a JS-set string and its HTML twin cannot drift.
function tr(key, englishDefault, params) {
  return i18n ? i18n.t(key, params, englishDefault) : englishDefault;
}

// The Jellyfin account routing that a revoke restores (#1121). The Unregister endpoint PERSISTS
// whatever the caller sends here onto the account, so a wrong string does not fail the request: it routes
// that account to core's InvalidAuthenticationProvider, which refuses every password, and nothing on this
// page would report it. The literal is pinned here and compared against
// SsoAuthenticationProviders.DefaultPasswordProviderId by LinkedAccountsRevoke_PostsThePinnedPasswordProviderId,
// so the page and the server cannot drift apart (#837 pinned the server side for the same reason).
const DEFAULT_PASSWORD_PROVIDER_ID =
  "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";

// Provider templates (#726): the single source of truth for the "Start from a template" pickers.
// Applying a preset writes ONLY into existing marker-classed fields by their id (OpenID: the property
// name; SAML: "saml-" + the property name) and pre-checks ONLY the compatibility toggles a given IdP
// genuinely needs. Presets are plain data so they are trivial to extend and to lock in with a fitness
// test (ProviderPresets_* in ArchitectureConformanceTests): every `fields` key / `toggles` entry must be
// a real config property, no preset may fill a secret, and toggles may only pre-check a known
// compatibility toggle. `fields` values are non-secret placeholders: endpoints use an example host and
// UPPERCASE tokens the admin replaces (realm/tenant/domain), never a hard-coded production host, so they
// never go stale. OidScopes holds the ADDITIONAL scopes only (one per line); the server always prepends
// "openid profile", so a preset lists just what a provider needs on top (e.g. "email", or "email\ngroups"
// where roles ride a groups scope), never "openid"/"profile" again. Every OpenID preset sets the SAME four
// fields (blank where a provider has none), so switching templates is idempotent, and no stale value survives;
// ProviderPresets_OidcPresetsShareTheSameFieldKeySet locks that shared-key-set invariant in.
const OIDC_PRESETS = {
  keycloak: {
    label: "Keycloak",
    note: "Keycloak realm client with the default mappers. Roles come from realm_access.roles (or resource_access.<clientId>.roles for client roles). Replace YOUR_REALM in the endpoint.",
    fields: {
      OidEndpoint:
        "https://keycloak.example.com/realms/YOUR_REALM/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "realm_access.roles",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: [],
  },
  authelia: {
    label: "Authelia",
    note: "Authelia OpenID Connect provider. Groups are exposed via the `groups` claim (add the `groups` scope in Authelia). Pushed Authorization Requests are disabled here because some Authelia versions do not support them.",
    fields: {
      OidEndpoint: "https://auth.example.com/.well-known/openid-configuration",
      OidScopes: "email\ngroups",
      RoleClaim: "groups",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: ["DisablePushedAuthorization"],
  },
  authentik: {
    label: "Authentik",
    note: "Authentik OAuth2/OpenID provider application. Groups are exposed via the `groups` claim. Replace YOUR_APP_SLUG in the endpoint with the application slug.",
    fields: {
      OidEndpoint:
        "https://authentik.example.com/application/o/YOUR_APP_SLUG/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "groups",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: [],
  },
  zitadel: {
    label: "Zitadel",
    note: "Zitadel project application. Its roles arrive as an OBJECT whose keys are the role names, so 'Role claim is an object map' is pre-checked; without it no role can ever match. The project must have 'Assert Roles on Authentication' on, and the application 'User roles inside ID Token', or the role claim is absent entirely. Replace YOUR_INSTANCE in the endpoint.",
    fields: {
      OidEndpoint:
        "https://YOUR_INSTANCE.zitadel.cloud/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "urn:zitadel:iam:org:project:roles",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: ["RoleClaimIsObjectMap"],
  },
  entra: {
    label: "Microsoft Entra ID (Azure AD)",
    note: "Entra ID app registration. App roles come from the `roles` claim (assign them under the app registration). Replace YOUR_TENANT_ID in the endpoint.",
    fields: {
      OidEndpoint:
        "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "roles",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: [],
  },
  google: {
    label: "Google",
    note: "Google issues no group or role claim, so Roles is left blank: grant access with folder/role mapping or leave it open. Endpoint validation is relaxed because Google's discovery document does not list every endpoint the strict check expects.",
    fields: {
      OidEndpoint:
        "https://accounts.google.com/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "",
      DefaultUsernameClaim: "email",
    },
    toggles: ["DoNotValidateEndpoints"],
  },
  auth0: {
    label: "Auth0",
    note: "Auth0 application. Roles require a custom claim added by an Auth0 Action/Rule under a namespace you choose. Set RoleClaim to that namespaced claim (e.g. https://your-app/roles). Replace YOUR_TENANT in the endpoint.",
    fields: {
      OidEndpoint:
        "https://YOUR_TENANT.us.auth0.com/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "",
      DefaultUsernameClaim: "nickname",
    },
    toggles: [],
  },
  okta: {
    label: "Okta",
    note: "Okta OIDC app. Groups come from the `groups` claim (add a groups claim + the `groups` scope in the Okta authorization server). Replace YOUR_DOMAIN in the endpoint.",
    fields: {
      OidEndpoint:
        "https://YOUR_DOMAIN.okta.com/.well-known/openid-configuration",
      OidScopes: "email\ngroups",
      RoleClaim: "groups",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: [],
  },
  gitlab: {
    label: "GitLab",
    note: "GitLab as an OpenID provider. Direct group paths come from the `groups_direct` claim. For self-managed GitLab, replace gitlab.com in the endpoint with your host.",
    fields: {
      OidEndpoint: "https://gitlab.com/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "groups_direct",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: [],
  },
  "generic-oidc": {
    label: "Generic OpenID Connect",
    note: "A standards-compliant OpenID provider. Point the endpoint at its discovery document and set the role claim to whatever your IdP issues (often `groups` or `roles`).",
    fields: {
      OidEndpoint: "https://idp.example.com/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: [],
  },
};

const SAML_PRESETS = {
  "generic-saml": {
    label: "Generic SAML 2.0",
    note: "A generic SAML 2.0 identity provider. Use the metadata import below to fill the SSO endpoint and signing certificate from your IdP's metadata, then set the SAML Client ID (this service provider's entity id) and review before saving.",
    fields: {
      SamlEndpoint: "https://idp.example.com/sso/saml",
    },
    toggles: [],
  },
};

// The compatibility/insecure toggles a preset is ALLOWED to pre-check. A preset never pre-checks a
// fail-closed HARDENING toggle (RequirePkce, RequireVerifiedEmail*, RequireAcr, SAML ValidateRecipient/
// ValidateInResponseTo/SignAuthnRequests), because enabling those is a deliberate admin decision, and silently
// turning them on could lock out a not-yet-ready IdP. This set is also what applyOidcPreset/applySamlPreset
// clear before applying, so switching templates never leaves a previous preset's toggle checked.
const OIDC_PRESET_MANAGED_TOGGLES = [
  "DisablePushedAuthorization",
  "DoNotValidateEndpoints",
  "DoNotValidateIssuerName",
  "DoNotValidateResponseIssuer",
  "DisableHttps",
  "DoNotLoadProfile",
  // Not an insecure toggle: it names the SHAPE of the RoleClaim path's terminal (#934). It is here because
  // every preset sets RoleClaim, so leaving a previous provider's shape flag ticked while the claim path is
  // replaced by an array-shaped one (Keycloak's realm_access.roles) would extract ZERO roles and lock the
  // whole userbase out on the next login. Clearing is correct for every shipped preset; a future
  // object-map preset can pre-check it from its own `toggles`; the Zitadel preset above does exactly that.
  "RoleClaimIsObjectMap",
];
const SAML_PRESET_MANAGED_TOGGLES = ["DoNotValidateAudience"];

const ssoConfigurationPage = {
  pluginUniqueId: "505ce9d1-d916-42fa-86ca-673ef241d7df",
  // Toggles that disable an OpenID Connect security defense. An active one is a downgrade the admin must
  // not miss, so loading a provider with any of these expands the "Insecure options" list and its
  // enclosing "Security & hardening" accordion.
  insecureFieldIds: [
    "DisableHttps",
    "DisablePushedAuthorization",
    "DoNotValidateEndpoints",
    "DoNotValidateIssuerName",
    "DoNotValidateResponseIssuer",
    "AllowPrivateNetworkAddresses",
  ],
  // The non-insecure settings whose ENABLED state is still a downgrade / attack-surface widening, so they
  // are surfaced the same way as the insecure toggles (card "Review" flag + auto-expand the enclosing
  // accordion). Only AllowExistingAccountLink qualifies: turning it ON lets a first SSO login adopt (take
  // over) a same-named local account. Deliberately EXCLUDES the fail-closed hardening toggles
  // (RequireVerifiedEmailForAdoption, RequireVerifiedEmailForLogin, RequirePkce): those are OFF by default
  // and enabling them makes the provider MORE secure, so flagging or force-surfacing them would be
  // backwards and would cause alert fatigue on well-configured providers. Do not add an OFF-direction
  // surfacing for them either: it would be noisy on the default.
  sensitiveFieldIds: ["AllowExistingAccountLink"],
  // #1104. Which providers a declarative source decided, as the server reports them (#1102). Fetched once
  // per configuration load and held as a promise, so an editor opened before the answer arrives still waits
  // for it instead of rendering an editable form over a managed provider.
  //
  // ADVISORY ONLY, and that is the reason the failure arm below gives up rather than defending. The guard is
  // on the server: a save to a managed provider keeps the stored value and is audited whether or not this
  // page ever learned the provider was managed. So a report that does not arrive leaves the page exactly as
  // it behaved before this existed, which costs a confusing edit; treating an unreachable report as "assume
  // everything is managed" would instead lock an administrator out of forms the server would have accepted.
  managedProviders: { OidConfigs: [], SamlConfigs: [] },
  managedProvidersLoaded: null,
  loadManagedProviders: () => {
    ssoConfigurationPage.managedProvidersLoaded = ApiClient.getJSON(
      ApiClient.getUrl("sso/Config/Managed"),
    ).then(
      (report) => {
        ssoConfigurationPage.managedProviders = {
          OidConfigs: Array.isArray(report && report.OidConfigs)
            ? report.OidConfigs
            : [],
          SamlConfigs: Array.isArray(report && report.SamlConfigs)
            ? report.SamlConfigs
            : [],
        };
      },
      () => {
        ssoConfigurationPage.managedProviders = {
          OidConfigs: [],
          SamlConfigs: [],
        };
      },
    );
    return ssoConfigurationPage.managedProvidersLoaded;
  },
  // The unit is the PROVIDER and not the field, which is the server's measurement rather than this page's
  // simplification: the declarative merge replaces a named provider whole, so a field the document omits
  // comes back at its default at the next start. A form that greyed out three fields and left the rest
  // editable would tell the administrator the opposite of what happens.
  isManagedProvider: (protocol, provider_name) => {
    if (!provider_name) {
      return false;
    }
    const names =
      protocol === "saml"
        ? ssoConfigurationPage.managedProviders.SamlConfigs
        : ssoConfigurationPage.managedProviders.OidConfigs;
    return Array.isArray(names) && names.indexOf(provider_name) !== -1;
  },
  // The controls that stay usable on a managed provider: they read, they never write a provider field, and
  // they are the ones an administrator most needs while diagnosing a provider they cannot edit here.
  managedReadOnlyActions: [
    "TestProvider",
    "CopyRedirectUri",
    "saml-TestProvider",
    "saml-CopyAcsUrl",
    "saml-CopyMetadataUrl",
  ],
  // Render the open editor as managed or as ordinary. Applied AFTER the provider has been loaded, because
  // the role-map and folder-list widgets create their controls during that load and a pass made before it
  // would leave every one of them editable. Always applied on both arms, so switching from a managed
  // provider to an ordinary one restores the form rather than leaving it frozen.
  applyManagedState: (page, protocol, provider_name) => {
    const formId =
      protocol === "saml" ? "sso-new-saml-provider" : "sso-new-oidc-provider";
    const noteId =
      protocol === "saml" ? "saml-managed-note" : "sso-managed-note";
    const form = page.querySelector("#" + formId);
    const note = page.querySelector("#" + noteId);
    if (!form) {
      return Promise.resolve();
    }

    const pending =
      ssoConfigurationPage.managedProvidersLoaded || Promise.resolve();
    return pending.then(() => {
      // The editor may have moved on while the report was in flight. The selector is the state holder the
      // save path already reads, so comparing against it is comparing against what would actually be saved.
      const selectorId =
        protocol === "saml" ? "#saml-selectProvider" : "#selectProvider";
      const selector = page.querySelector(selectorId);
      if (selector && selector.value !== provider_name) {
        return;
      }

      const managed = ssoConfigurationPage.isManagedProvider(
        protocol,
        provider_name,
      );

      form
        .querySelectorAll("input, select, textarea, button")
        .forEach((element) => {
          if (
            ssoConfigurationPage.managedReadOnlyActions.indexOf(element.id) !==
            -1
          ) {
            return;
          }
          element.disabled = managed;
        });

      if (note) {
        // textContent, never innerHTML (#221). The text is fixed and carries no provider value, so nothing
        // from the configuration reaches the DOM here at all.
        note.textContent = managed
          ? tr(
              "config.managed_by_file_note",
              "This provider is set by a configuration file or by environment variables, so it cannot be edited here. Change it at that source and restart Jellyfin. A save made here would keep the stored value and leave a record in the log.",
            )
          : "";
        note.hidden = !managed;
      }
    });
  },
  loadConfiguration: (page) => {
    // Refreshed with the configuration itself: a provider that stopped being declaratively managed between
    // two loads must not keep a frozen form, and one that started being managed must not keep an open one.
    ssoConfigurationPage.loadManagedProviders();
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        ssoConfigurationPage.populateProviders(page, config.OidConfigs);
        // Refresh the SAML workspace from the same configuration load (#725), so a SAML save/delete/import
        // reloads its provider list exactly as the OpenID one does.
        ssoConfigurationPage.populateSamlProviders(
          page,
          config.SamlConfigs || {},
        );
        // The GLOBAL login-page buttons opt-in (#722) rides the same configuration load. It is a root
        // PluginConfiguration flag, not a provider field, so it has its own save path (saveLoginButtons)
        // and no sso-* marker class.
        page.querySelector("#ManageLoginPageButtons").checked = Boolean(
          config.ManageLoginPageButtons,
        );
        // The GLOBAL Single Logout opt-in (#727) rides the same configuration load. Like
        // ManageLoginPageButtons it is a root PluginConfiguration flag, not a provider field, so it has its
        // own save path (saveSingleLogout) and no sso-* marker class.
        page.querySelector("#EnableSingleLogout").checked = Boolean(
          config.EnableSingleLogout,
        );
      },
    );

    const folder_container = page.querySelector("#EnabledFolders");
    ssoConfigurationPage.populateFolders(folder_container);
    // The SAML editor has its own available-folders checklist; populate it too (#725).
    const saml_folder_container = page.querySelector("#saml-EnabledFolders");
    if (saml_folder_container) {
      ssoConfigurationPage.populateFolders(saml_folder_container);
    }
  },
  populateProviders: (page, providers) => {
    const select = page.querySelector("#selectProvider");

    // Clear providers in case there are out of date ones
    select.querySelectorAll("option").forEach((option) => option.remove());

    // Add providers as options for the (hidden) selector. The selector is retained as the state holder the
    // save path already reads (saveProvider sets its value after a save); the visible affordance is the card
    // list rendered below.
    Object.keys(providers).forEach((provider_name) => {
      select.appendChild(new Option(provider_name, provider_name));
    });

    ssoConfigurationPage.renderProviderCards(page, providers);
  },
  // Render the provider LIST as cards (#365). Built with createElement/textContent (never innerHTML) so a
  // provider name is inert on the page (a name like `<img onerror=...>` cannot inject markup), mirroring
  // _populateFolders and the linking view (#221). Clicking a card loads that provider into the editor.
  renderProviderCards: (page, providers) => {
    const list = page.querySelector("#sso-provider-list");
    const empty = page.querySelector("#sso-provider-empty");
    list.replaceChildren();

    const names = Object.keys(providers);
    empty.hidden = names.length !== 0;

    names.forEach((provider_name) => {
      const provider = providers[provider_name] || {};

      const card = document.createElement("button");
      card.type = "button";
      card.classList.add("sso-provider-card");
      card.dataset.provider = provider_name;
      card.setAttribute("role", "listitem");

      const name = document.createElement("span");
      name.classList.add("sso-provider-card-name");
      name.textContent = provider_name;

      const badge = document.createElement("span");
      badge.classList.add("sso-badge", "sso-badge-type");
      badge.textContent = "OIDC";

      const enabled = Boolean(provider.Enabled);
      const pill = document.createElement("span");
      pill.classList.add(
        "sso-pill",
        enabled ? "sso-pill-enabled" : "sso-pill-disabled",
      );
      pill.textContent = enabled ? "Enabled" : "Disabled";

      card.append(name, badge, pill);

      // Flag a provider that carries an active insecure / sensitive setting, so an admin sees the downgrade
      // in the list without opening the editor (the setting itself lives behind the collapsed
      // "Security & hardening" accordion). Presentation only: the flag reads from the saved config and
      // changes nothing.
      const flagged = ssoConfigurationPage.insecureFieldIds
        .concat(ssoConfigurationPage.sensitiveFieldIds)
        .some((id) => Boolean(provider[id]));
      if (flagged) {
        card.classList.add("sso-provider-card-flagged");
        const warn = document.createElement("span");
        warn.classList.add("sso-badge", "sso-badge-warn");
        warn.textContent = "Review";
        warn.title =
          "This provider has an active insecure or sensitive setting.";
        card.append(warn);
      }

      list.appendChild(card);
    });
  },
  showEditor: (page) => {
    page.querySelector("#sso-editor").hidden = false;
  },
  hideEditor: (page) => {
    page.querySelector("#sso-editor").hidden = true;
  },
  setEditorTitle: (page, title) => {
    page.querySelector("#sso-editor-title").textContent = title;
  },
  // Load a card into the editor and reveal it. resetEditor gives a CLEAN SLATE first (the same way
  // addProvider does) so no field, toggle, or collapse state from the previously loaded provider can bleed
  // into this one: a text/array field the target provider does not set must not keep the previous
  // provider's value, or a later save would silently persist it (e.g. repoint OidEndpoint with no edit).
  // loadProvider then fills the target provider's actual values on top and re-syncs visibility at its tail.
  openProvider: (page, provider_name) => {
    page.querySelector("#selectProvider").value = provider_name;
    ssoConfigurationPage.resetEditor(page);
    ssoConfigurationPage.clearValidationErrors(page);
    ssoConfigurationPage.renderSaveStatus(page, "");
    ssoConfigurationPage.setEditorTitle(page, provider_name);
    ssoConfigurationPage.showEditor(page);
    ssoConfigurationPage.loadProvider(page, provider_name);
    page.querySelector("#sso-editor").scrollIntoView({ block: "start" });
  },
  // Open a blank editor for a NEW provider. Every toggle is reset OFF (fail closed), the same security
  // posture loadProvider enforces when switching providers, so a stale insecure toggle from a previous
  // edit can never be carried into a new provider and silently saved.
  addProvider: (page) => {
    page.querySelector("#selectProvider").value = "";
    ssoConfigurationPage.resetEditor(page);
    ssoConfigurationPage.clearValidationErrors(page);
    ssoConfigurationPage.renderSaveStatus(page, "");
    ssoConfigurationPage.setEditorTitle(
      page,
      tr("config.new_provider", "New provider"),
    );
    ssoConfigurationPage.syncDependentFields(page);
    // A new provider is never managed - no source has named it yet - so this arm exists to RESTORE a form
    // left frozen by a managed provider opened just before (#1104).
    ssoConfigurationPage.applyManagedState(page, "oid", "");
    ssoConfigurationPage.showEditor(page);
    page.querySelector("#sso-editor").scrollIntoView({ block: "start" });
    page.querySelector("#OidProviderName").focus();
  },
  resetEditor: (page) => {
    const form_elements = ssoConfigurationPage.listArgumentsByType(page);

    // A Test Connection result belongs to the provider it was run against (#1083). Clearing it here means
    // the next provider opened reads as "not yet tested" rather than inheriting a verdict about a
    // different endpoint.
    ssoConfigurationPage.readinessTestState.oid = null;

    page.querySelector("#OidProviderName").value = "";

    form_elements.text_fields.forEach((id) => {
      page.querySelector("#" + id).value = "";
    });
    form_elements.text_list_fields.forEach((id) => {
      page.querySelector("#" + id).value = "";
    });
    form_elements.check_fields.forEach((id) => {
      page.querySelector("#" + id).checked = false;
    });
    form_elements.folder_list_fields.forEach((id) => {
      ssoConfigurationPage.populateEnabledFolders(
        [],
        page.querySelector("#" + id),
      );
    });
    form_elements.role_map_fields.forEach((id) => {
      ssoConfigurationPage.populateRoleMappings(
        [],
        page.querySelector("#" + id),
      );
    });

    ssoConfigurationPage.fillProvisioningTemplate(page, "", null, null);

    // Clean slate for progressive disclosure and collapse state, so a previous provider's expanded danger
    // zone / accordion state cannot bleed into the next provider. Collapse the "Insecure options" list,
    // return every editor accordion to its authored default (data-expanded), then re-sync the
    // reveal-on-toggle groups now that every controlling toggle is off. loadProvider (openProvider) and the
    // explicit syncDependentFields (addProvider) re-expand only what the loaded/new provider actually needs.
    ssoConfigurationPage.setInsecureOptionsExpanded(page, false);
    ssoConfigurationPage.resetEditorSections(page);
    ssoConfigurationPage.syncDependentFields(page);
    // Clear the computed redirect URI back to its placeholder for the fresh/blank editor (#724).
    ssoConfigurationPage.updateRedirectUri(page);
    // Reset the template picker + its note so opening/adding a provider never shows a stale template (#726).
    const oidPreset = page.querySelector("#OidPreset");
    if (oidPreset) {
      oidPreset.value = "";
    }
    ssoConfigurationPage.renderPresetNote(page, "OidPreset-note", "");
  },
  // Return every accordion section INSIDE the editor to its authored default collapse state (the sections
  // with data-expanded="true" open, the rest, including "Security & hardening", collapsed). Scoped to
  // #sso-editor so the page-level About / Export collapses are untouched.
  resetEditorSections: (page) => {
    const editor = page.querySelector("#sso-editor");
    if (!editor) {
      return;
    }
    editor.querySelectorAll('[is="emby-collapse"]').forEach((section) => {
      ssoConfigurationPage.setCollapseExpanded(
        section,
        section.getAttribute("data-expanded") === "true",
      );
    });
  },
  // Drive an emby-collapse to a definite expanded/collapsed state. The host component tracks its open state
  // as the boolean `expanded` PROPERTY on its `.collapseContent` element and flips it by a click of the
  // generated `.emby-collapsible-button` (its own click handler runs the slide + hide-class toggle). We read
  // that property and click only when it differs from the target, so this is idempotent: clicking an
  // already-open section would wrongly collapse it. Null-guarded so it degrades to a no-op (rather than
  // throwing) if the section has not been upgraded yet or the host markup changes.
  setCollapseExpanded: (section, expanded) => {
    const button = section.querySelector(".emby-collapsible-button");
    const content = section.querySelector(".collapseContent");
    if (!button || !content) {
      return;
    }
    if (Boolean(content.expanded) !== expanded) {
      button.click();
    }
  },
  setSectionExpanded: (page, sectionId, expanded) => {
    const section = page.querySelector("#" + sectionId);
    if (!section) {
      return;
    }
    ssoConfigurationPage.setCollapseExpanded(section, expanded);
  },
  // Keep reveal-on-toggle groups in sync with their controlling checkbox. Presentation ONLY: it toggles the
  // `hidden` attribute on wrapper elements and never mutates a field's value or `.checked`, so every marked
  // field stays in the DOM and serializable (the hide-not-remove invariant, #365). The save path enumerates
  // the fields with querySelectorAll regardless of whether their group is hidden.
  setDependent: (page, checkboxId, groupId, revealWhenChecked) => {
    const checkbox = page.querySelector("#" + checkboxId);
    const group = page.querySelector("#" + groupId);
    if (!checkbox || !group) {
      return;
    }
    const reveal = revealWhenChecked ? checkbox.checked : !checkbox.checked;
    group.hidden = !reveal;
    checkbox.setAttribute("aria-expanded", String(reveal));
  },
  syncDependentFields: (page) => {
    // EnabledFolders is only meaningful when NOT all folders are enabled.
    ssoConfigurationPage.setDependent(
      page,
      "EnableAllFolders",
      "EnabledFolders-group",
      false,
    );
    ssoConfigurationPage.setDependent(
      page,
      "EnableFolderRoles",
      "FolderRoleMapping-group",
      true,
    );
    ssoConfigurationPage.setDependent(
      page,
      "EnableLiveTvRoles",
      "LiveTvRoles-group",
      true,
    );

    // Surface active insecure / sensitive settings so an admin cannot miss that a security defense is
    // disabled or an account-adoption path is widened. The "Security & hardening" accordion is collapsed by
    // default, and the insecure toggles are additionally behind a "Show insecure options" list, so a
    // downgrade on a loaded provider would otherwise be invisible behind two collapsed layers. Expand BOTH
    // the enclosing accordion section AND, for the insecure subset, the inner list. Expand-only: it never
    // AUTO-HIDES a set option; resetEditor returns the section to its default when switching to a provider
    // that has none.
    const isChecked = (id) => {
      const el = page.querySelector("#" + id);
      return Boolean(el && el.checked);
    };
    const anyInsecure = ssoConfigurationPage.insecureFieldIds.some(isChecked);
    const anySensitive =
      anyInsecure || ssoConfigurationPage.sensitiveFieldIds.some(isChecked);
    if (anyInsecure) {
      ssoConfigurationPage.setInsecureOptionsExpanded(page, true);
    }
    if (anySensitive) {
      ssoConfigurationPage.setSectionExpanded(
        page,
        "sso-security-section",
        true,
      );
    }
  },
  setInsecureOptionsExpanded: (page, expanded) => {
    const button = page.querySelector("#ShowInsecureOptions");
    const options = page.querySelector("#sso-insecure-options");
    if (!button || !options) {
      return;
    }
    options.hidden = !expanded;
    button.setAttribute("aria-expanded", String(expanded));
    button.querySelector("span").textContent = expanded
      ? "Hide insecure options"
      : "Show insecure options";
  },
  // On-blur inline validation (#365). These are pre-emptive WARNINGS that mirror the server's fail-closed
  // checks, surfaced beside the field before the round-trip; they never block the save (the server remains
  // the authority), so a false positive cannot lock an admin out of saving.
  clearValidationErrors: (page) => {
    [
      "OidProviderName",
      "OidEndpoint",
      "OidClientId",
      "RoleClaim",
      "OidScopes",
      "BaseUrlOverride",
    ].forEach((id) => ssoConfigurationPage.setFieldError(page, id, ""));
  },
  setFieldError: (page, id, message) => {
    const field = page.querySelector("#" + id);
    const box = page.querySelector("#" + id + "-error");
    if (!box || !field) {
      return;
    }
    if (message) {
      box.textContent = message;
      box.hidden = false;
      field.setAttribute("aria-invalid", "true");
    } else {
      box.textContent = "";
      box.hidden = true;
      field.removeAttribute("aria-invalid");
    }
  },
  validateRequired: (page, id, label) => {
    const value = page.querySelector("#" + id).value.trim();
    ssoConfigurationPage.setFieldError(
      page,
      id,
      value ? "" : label + " is required.",
    );
  },
  validateEndpoint: (page) => {
    const value = page.querySelector("#OidEndpoint").value.trim();
    if (!value) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidEndpoint",
        "OpenID Endpoint is required.",
      );
      return;
    }
    let url;
    try {
      url = new URL(value);
    } catch (e) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidEndpoint",
        "Enter an absolute URL, e.g. https://id.example.com",
      );
      return;
    }
    if (url.protocol === "http:") {
      ssoConfigurationPage.setFieldError(
        page,
        "OidEndpoint",
        "Uses http://, so discovery would be unencrypted. Prefer an https:// endpoint.",
      );
      return;
    }
    if (url.protocol !== "https:") {
      ssoConfigurationPage.setFieldError(
        page,
        "OidEndpoint",
        "Use an https:// URL for the OpenID endpoint.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "OidEndpoint", "");
  },
  validateBaseUrl: (page) => {
    const value = page.querySelector("#BaseUrlOverride").value.trim();
    if (!value) {
      // Optional field: blank is valid (the redirect URI then derives from the request host).
      ssoConfigurationPage.setFieldError(page, "BaseUrlOverride", "");
      return;
    }
    let url;
    try {
      url = new URL(value);
    } catch (e) {
      ssoConfigurationPage.setFieldError(
        page,
        "BaseUrlOverride",
        "Enter a full origin such as https://jellyfin.example.com (scheme + host only).",
      );
      return;
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      ssoConfigurationPage.setFieldError(
        page,
        "BaseUrlOverride",
        "Enter a full origin such as https://jellyfin.example.com",
      );
      return;
    }
    // Full origin only: no path, query or fragment (this is the base URL, not the redirect URI).
    if ((url.pathname && url.pathname !== "/") || url.search || url.hash) {
      ssoConfigurationPage.setFieldError(
        page,
        "BaseUrlOverride",
        "Enter the base URL only (no path), e.g. https://jellyfin.example.com, not the /sso/... redirect URI.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "BaseUrlOverride", "");
  },
  validateProviderName: (page) => {
    const value = page.querySelector("#OidProviderName").value;
    if (!value.trim()) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidProviderName",
        "A provider name is required.",
      );
      return;
    }
    // Mirror the server's fail-closed name checks (#336/#360) so they surface before the round-trip.
    // Control characters are detected by code point (not a regex escape) to keep this source ASCII-only.
    const hasControlChar = [...value].some((ch) => {
      const code = ch.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    });
    if (hasControlChar) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidProviderName",
        "Remove control characters (such as a tab or newline, often introduced by copy-paste) from the name.",
      );
      return;
    }
    // The backslash and the URI-reserved characters the server rejects.
    const reserved = ["\\", "/", "?", "#", "%"];
    if (reserved.some((c) => value.includes(c))) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidProviderName",
        "Remove backslash and URI-reserved characters (\\ / ? # %) from the name.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "OidProviderName", "");
  },
  renderSaveStatus: (page, message, ok) => {
    const box = page.querySelector("#sso-save-status");
    if (!box) {
      return;
    }
    box.textContent = message || "";
    box.classList.remove("sso-status-ok", "sso-status-fail");
    if (message) {
      box.classList.add(ok ? "sso-status-ok" : "sso-status-fail");
    }
  },
  populateEnabledFolders: (folder_list, container) => {
    container.querySelectorAll(".folder-checkbox").forEach((e) => {
      e.checked = folder_list.includes(e.dataset.id);
    });
  },
  serializeEnabledFolders: (container) => {
    return [...container.querySelectorAll(".folder-checkbox")]
      .filter((e) => e.checked)
      .map((e) => {
        return e.dataset.id;
      });
  },
  populateFolders: (container) => {
    return ApiClient.getJSON(
      ApiClient.getUrl("Library/MediaFolders", {
        IsHidden: false,
      }),
    ).then((folders) => {
      ssoConfigurationPage._populateFolders(container, folders);
    });
  },
  /*
  container: html element
  folders.Items: array of objects, with .Id & .Name
  */
  _populateFolders: (container, folders) => {
    container
      .querySelectorAll(".emby-checkbox-label")
      .forEach((e) => e.remove());

    const checkboxes = folders.Items.map((folder) => {
      // The library folder Name/Id come from the Jellyfin core API; build the row with
      // createElement/textContent (never innerHTML) so a folder named e.g. `<img onerror=...>`
      // stays inert on the config page (#221). Mirrors linking.js populateExistingLinks.
      const out = document.createElement("label");
      // Tag the row with the class the re-render cleanup (querySelectorAll above) removes, so a
      // second populate deterministically clears the old rows instead of relying on the
      // emby-checkbox upgrade to add it; otherwise folder IDs could be duplicated on re-populate.
      out.classList.add("emby-checkbox-label");

      // createElement's `is` option upgrades the customized built-in; the attribute is set as well
      // so CSS attribute selectors and the web-components polyfill see it.
      const checkbox = document.createElement("input", { is: "emby-checkbox" });
      checkbox.setAttribute("is", "emby-checkbox");
      checkbox.classList.add("folder-checkbox", "chkFolder");
      checkbox.type = "checkbox";
      checkbox.dataset.id = folder.Id;

      const label = document.createElement("span");
      label.textContent = folder.Name;

      out.append(checkbox, label);

      return out;
    });

    checkboxes.forEach((e) => {
      container.appendChild(e);
    });
  },

  populateRoleMappings: (folder_role_mappings, container) => {
    container
      .querySelectorAll(".sso-role-mapping-container")
      .forEach((e) => e.remove());

    const mapping_elements = folder_role_mappings.map((mapping) => {
      const elem = document.createElement("div");

      elem.classList.add("sso-role-mapping-container");
      elem.innerHTML = `
      <label
        class="inputLabel inputLabelUnfocused sso-role-mapping-input-label"
      >Role:</label>
      <div class="listItem">
        <input
          is="emby-input"
          required=""
          type="text"
          class="listItemBody sso-role-mapping-name"
        />
        <button
          type="button"
          is="paper-icon-button-light"
          class="listItemButton sso-remove-role-mapping"
        >
          <span class="material-icons remove_circle" aria-hidden="true"></span>
        </button>
      </div>
      <div
        class="checkboxList paperList sso-folder-list"
      ></div>
      `;

      const checklist = elem.querySelector(".sso-folder-list");
      const enabled_folders = mapping["Folders"];

      ssoConfigurationPage
        .populateFolders(checklist)
        .then(() =>
          ssoConfigurationPage.populateEnabledFolders(
            enabled_folders,
            checklist,
          ),
        );

      elem.querySelector(".sso-role-mapping-name").value = mapping["Role"];
      elem
        .querySelector(".sso-remove-role-mapping")
        .addEventListener(
          "click",
          ssoConfigurationPage.handleRoleMappingRemove,
        );

      return elem;
    });

    mapping_elements.forEach((e) => container.appendChild(e));
  },
  serializeRoleMappings: (container) => {
    const out = [];
    [...container.querySelectorAll(".sso-role-mapping-container")].forEach(
      (elem) => {
        const role = elem.querySelector(".sso-role-mapping-name").value;
        const checklist = elem.querySelector(".sso-folder-list");

        out.push({
          Role: role,
          Folders: ssoConfigurationPage.serializeEnabledFolders(checklist),
        });
      },
    );

    return out;
  },
  handleRoleMappingRemove: (evt) => {
    const targeted_mapping = evt.target.closest(".sso-role-mapping-container");
    targeted_mapping.remove();
  },
  // ---------------------------------------------------------------------------------------------------
  // The provisioning-template save contract (#1367).
  //
  // ProvisioningPolicyTemplate is a NESTED member of the provider config, so its controls cannot ride the
  // flat contract listArgumentsByType feeds (current_config[element.id] = value, one top-level member per
  // control). They carry their own marker classes instead - sso-tmpl-number, sso-tmpl-text, sso-tmpl-bool
  // and sso-tmpl-perms - and an id of "<prefix>Tmpl-" + the exact ProvisioningPolicyTemplate property they
  // write. readProvisioningTemplate below is the second serializer that assembles them into one object.
  //
  // Two failures this shape exists to prevent, both of which turn a DECLINED field into a set one:
  //  - a control the administrator never touched must contribute NO member, because null is what leaves
  //    Jellyfin's own default alone. That is why the three nullable bools are three-option lists and not
  //    checkboxes: a checkbox has two states where the model has three.
  //  - an all-unset form must send NO OBJECT rather than an object of nulls. ProviderConfigValidator
  //    refuses an inline template on a provider that names a provisioning profile, and the refusal is on
  //    the object being PRESENT rather than on it carrying values - so an always-assembled object would
  //    make every profile-using provider permanently unsaveable from this page, client id and secret
  //    included, over a section nobody touched.
  // ---------------------------------------------------------------------------------------------------
  templateFieldName: (prefix, element) =>
    element.id.slice((prefix + "Tmpl-").length),
  templateControls: (page, prefix) => {
    const form = page.querySelector(
      prefix ? "#sso-new-saml-provider" : "#sso-new-oidc-provider",
    );

    return {
      numbers: [...form.querySelectorAll(".sso-tmpl-number")],
      texts: [...form.querySelectorAll(".sso-tmpl-text")],
      bools: [...form.querySelectorAll(".sso-tmpl-bool")],
      permissions: form.querySelector(".sso-tmpl-perms"),
    };
  },
  readProvisioningTemplate: (page, prefix) => {
    const controls = ssoConfigurationPage.templateControls(page, prefix);
    const template = {};
    const name = (element) =>
      ssoConfigurationPage.templateFieldName(prefix, element);

    controls.texts.forEach((element) => {
      if (element.value !== "") {
        template[name(element)] = element.value;
      }
    });

    controls.numbers.forEach((element) => {
      const raw = element.value.trim();
      if (raw === "") {
        return;
      }

      // A value that is not a whole number is sent ON as typed rather than dropped or coerced. The server
      // refuses it and the save reports a failure, which is visible; Number("12e9") or a silent skip would
      // turn something the administrator DID set into an unset field, which is the failure this whole
      // contract is about.
      const parsed = Number(raw);
      template[name(element)] = Number.isInteger(parsed) ? parsed : raw;
    });

    // Only these two spellings are a value. Anything else - the empty option, or a value no option carries
    // - leaves the member out, so the field stays declined.
    controls.bools.forEach((element) => {
      if (element.value === "true") {
        template[name(element)] = true;
      } else if (element.value === "false") {
        template[name(element)] = false;
      }
    });

    const permissions = ssoConfigurationPage.serializeTemplatePermissions(
      controls.permissions,
    );
    if (permissions.length > 0) {
      template.Permissions = permissions;
    }

    return Object.keys(template).length === 0 ? null : template;
  },
  fillProvisioningTemplate: (page, prefix, template, profile) => {
    const controls = ssoConfigurationPage.templateControls(page, prefix);
    const values = template || {};

    [...controls.numbers, ...controls.texts, ...controls.bools].forEach(
      (element) => {
        const value =
          values[ssoConfigurationPage.templateFieldName(prefix, element)];
        element.value =
          value === null || value === undefined ? "" : String(value);
      },
    );

    ssoConfigurationPage.populateTemplatePermissions(
      page,
      prefix,
      values.Permissions || [],
    );

    // Where the provider names a provisioning profile the inline template is not this provider's policy.
    // The controls are disabled and the reason is put on the page, rather than leaving the administrator
    // to infer it from a save that changes nothing here.
    const named = Boolean(profile);
    const note = page.querySelector("#" + prefix + "Tmpl-profile-note");
    if (note) {
      note.hidden = !named;
    }

    [
      ...controls.numbers,
      ...controls.texts,
      ...controls.bools,
      ...page.querySelectorAll("#" + prefix + "Tmpl-Permissions-add"),
    ].forEach((element) => {
      element.disabled = named;
    });
  },
  // The mappable permission vocabulary, fetched once per page load from the one route that publishes it
  // (#1484). It is deliberately NOT a list kept in this file: a copy here drifts in three silent
  // directions - a name Jellyfin adds stays invisible, a name it removes stays offerable and is refused at
  // save, and a name added to the server's exclusion set keeps being offered.
  templatePermissionNames: null,
  loadTemplatePermissionNames: () => {
    if (ssoConfigurationPage.templatePermissionNames) {
      return ssoConfigurationPage.templatePermissionNames;
    }

    ssoConfigurationPage.templatePermissionNames = ApiClient.getJSON(
      ApiClient.getUrl("sso/Config/Permissions"),
    ).then(
      (doc) => (doc && doc.Permissions ? doc.Permissions : []),
      // A failed fetch resolves to no vocabulary rather than rejecting: a row still renders, carrying its
      // own stored name, so an unreachable route cannot silently drop a permission an administrator has
      // already configured on the next save.
      () => null,
    );

    return ssoConfigurationPage.templatePermissionNames;
  },
  populateTemplatePermissions: (page, prefix, entries) => {
    const container = ssoConfigurationPage.templateControls(
      page,
      prefix,
    ).permissions;
    const status = page.querySelector("#" + prefix + "Tmpl-Permissions-status");
    container.replaceChildren();
    if (status) {
      status.replaceChildren();
    }

    return ssoConfigurationPage.loadTemplatePermissionNames().then((names) => {
      if (names === null && status) {
        ssoConfigurationPage.renderTransferMessage(
          status,
          tr(
            "config.template_permissions_failed",
            "Could not load the list of permissions from the server. Rows already configured are shown as they are; make sure you are signed in as an administrator, then reload the page.",
          ),
        );
      }

      entries.forEach((entry) =>
        ssoConfigurationPage.renderTemplatePermissionRow(
          container,
          entry,
          names || [],
        ),
      );
    });
  },
  // Built with createElement/textContent, never innerHTML: a permission name is server data today, and the
  // same row renders whatever a stored configuration carries, which an administrator may have hand-edited
  // (#221).
  renderTemplatePermissionRow: (container, entry, names) => {
    const row = document.createElement("div");
    row.classList.add("sso-tmpl-permission-row", "listItem");

    const permission = document.createElement("select");
    permission.setAttribute("is", "emby-select");
    permission.classList.add(
      "sso-tmpl-permission-name",
      "emby-select-withcolor",
      "emby-select",
    );

    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = tr(
      "config.template_permission_choose",
      "Choose a permission",
    );
    permission.appendChild(placeholder);

    // The stored name is offered even when the vocabulary does not carry it - the fetch may have failed,
    // or the server may have stopped accepting the name. Dropping the option would silently rewrite the
    // row to "unset" on the next save; keeping it lets the administrator see it and lets the server refuse
    // it by name.
    const offered = names.includes(entry.Permission)
      ? names
      : [...names, entry.Permission].filter(Boolean);

    offered.forEach((option_name) => {
      const option = document.createElement("option");
      option.value = option_name;
      option.textContent = option_name;
      permission.appendChild(option);
    });
    permission.value = entry.Permission || "";

    const value = document.createElement("select");
    value.setAttribute("is", "emby-select");
    value.classList.add(
      "sso-tmpl-permission-value",
      "emby-select-withcolor",
      "emby-select",
    );
    [
      ["true", tr("config.template_permission_grant", "Grant")],
      ["false", tr("config.template_permission_deny", "Deny")],
    ].forEach(([option_value, label]) => {
      const option = document.createElement("option");
      option.value = option_value;
      option.textContent = label;
      value.appendChild(option);
    });
    value.value = entry.Granted === false ? "false" : "true";

    const remove = document.createElement("button");
    remove.setAttribute("is", "paper-icon-button-light");
    remove.type = "button";
    remove.classList.add("listItemButton", "sso-tmpl-permission-remove");
    remove.setAttribute(
      "aria-label",
      tr("config.template_permissions_remove", "Remove this permission"),
    );
    const icon = document.createElement("span");
    icon.classList.add("material-icons", "remove_circle");
    icon.setAttribute("aria-hidden", "true");
    remove.appendChild(icon);
    remove.addEventListener("click", (e) => {
      e.preventDefault();
      row.remove();
    });

    row.append(permission, value, remove);
    container.appendChild(row);
  },
  serializeTemplatePermissions: (container) => {
    const out = [];
    [...container.querySelectorAll(".sso-tmpl-permission-row")].forEach(
      (row) => {
        const permission = row.querySelector(".sso-tmpl-permission-name").value;
        if (permission === "") {
          return;
        }

        out.push({
          Permission: permission,
          Granted:
            row.querySelector(".sso-tmpl-permission-value").value === "true",
        });
      },
    );

    return out;
  },
  addTemplatePermissionRow: (page, prefix) => {
    const controls = ssoConfigurationPage.templateControls(page, prefix);
    const current = ssoConfigurationPage.serializeTemplatePermissions(
      controls.permissions,
    );
    current.push({ Permission: "", Granted: true });

    return ssoConfigurationPage.populateTemplatePermissions(
      page,
      prefix,
      current,
    );
  },
  // The provider form's save contract, made explicit (#365): every input in #sso-new-oidc-provider
  // that should persist carries an sso-* class AND an id spelled EXACTLY like the OidConfig property it
  // writes to (saveProvider does current_config[element.id] = value). A field with the wrong id, a
  // missing sso-* class, or placed outside this form renders fine but silently never saves, and the
  // server drops unknown JSON members too. The ArchitectureConformanceTests
  // ProviderFormFieldIds_MatchOidConfigProperties test locks this in: it fails the build if any
  // sso-*-classed field id is not a real OidConfig property.
  listArgumentsByType: (page) => {
    const toggle_class = ".sso-toggle";
    const text_class = ".sso-text";
    const text_list_class = ".sso-line-list";

    const folder_list_fields = ["EnabledFolders"];
    const role_map_fields = ["FolderRoleMapping"];

    const oidc_form = page.querySelector("#sso-new-oidc-provider");

    const text_fields = [...oidc_form.querySelectorAll(text_class)].map(
      (e) => e.id,
    );

    const text_list_fields = [
      ...oidc_form.querySelectorAll(text_list_class),
    ].map((e) => e.id);

    const check_fields = [...oidc_form.querySelectorAll(toggle_class)].map(
      (e) => e.id,
    );

    const output = {
      text_list_fields,
      text_fields,
      check_fields,
      folder_list_fields,
      role_map_fields,
    };

    return output;
  },
  fillTextList: (text_list, element) => {
    // text_list is an array of strings
    // element is an input element
    const val = text_list.join("\r\n");
    element.value = val;
  },
  parseTextList: (element) => {
    // Return the parsed text list
    const out = element.value
      .split("\n")
      .map((e) => e.trim())
      .filter(Boolean);
    return out;
  },
  loadProvider: (page, provider_name) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        const provider = config.OidConfigs[provider_name] || {};

        const form_elements = ssoConfigurationPage.listArgumentsByType(page);

        page.querySelector("#OidProviderName").value = provider_name;

        form_elements.text_fields.forEach((id) => {
          if (provider[id]) page.querySelector("#" + id).value = provider[id];
        });

        form_elements.text_list_fields.forEach((id) => {
          if (provider[id])
            ssoConfigurationPage.fillTextList(
              provider[id],
              page.querySelector("#" + id),
            );
        });

        form_elements.folder_list_fields.forEach((id) => {
          if (provider[id]) {
            ssoConfigurationPage.populateEnabledFolders(
              provider[id],
              page.querySelector(`#${id}`),
            );
          }
        });

        form_elements.check_fields.forEach((id) => {
          // Always set the checkbox from the loaded provider so switching providers
          // resets stale toggles. Setting it only when truthy left a previous
          // provider's checked box in place, which a later save could silently
          // persist as true, a security downgrade for toggles like
          // DoNotValidateEndpoints / DisableHttps.
          page.querySelector("#" + id).checked = Boolean(provider[id]);
        });

        form_elements.role_map_fields.forEach((id) => {
          const elem = page.querySelector(`#${id}`);
          if (provider[id])
            ssoConfigurationPage.populateRoleMappings(provider[id], elem);
        });

        ssoConfigurationPage.fillProvisioningTemplate(
          page,
          "",
          provider.ProvisioningPolicyTemplate,
          provider.ProvisioningProfile,
        );

        // Reflect the loaded toggles in the reveal-on-toggle groups (hide-not-remove) and surface any
        // active insecure option. Runs after the check_fields above are set from the loaded provider, so a
        // hidden-but-checked box is never left behind for the next save.
        ssoConfigurationPage.syncDependentFields(page);
        // Reflect the loaded provider's name + base-URL override in the computed redirect URI (#724).
        ssoConfigurationPage.updateRedirectUri(page);
        // Last, so the role-map and folder-list controls the calls above created are covered too (#1104).
        ssoConfigurationPage.applyManagedState(page, "oid", provider_name);
        // The panel summarises the fields and toggles this call just wrote (#1083).
        ssoConfigurationPage.refreshReadiness(page, "oid");
      },
    );
  },
  // Serial of the most recent redirect-URI request. A reply for an older provider name must never land in
  // the field after a newer one has already answered it, which per-keystroke requests otherwise allow.
  redirectUriSerial: 0,
  // Debounce handle for the same request: the field follows the provider-name and base-URL-override inputs,
  // and each update is now a round trip rather than a local computation.
  redirectUriTimer: null,
  // Live-updates the read-only redirect-URI field from the SERVER, the one producer of these bytes (#1303).
  // The page used to compose the value itself - the canonical base and the path spelling both - so what an
  // administrator registered at the identity provider was a second computation of what the login sends. A
  // divergence between the two does not fail here. It fails at the identity provider, as a redirect_uri
  // mismatch that reads as a plugin bug, and nothing in this repository ever learns about it. There is
  // deliberately NO local fallback: one would restore that second producer at the moment it is least likely
  // to be noticed. Sets .value only (never innerHTML, #221). Called on name/override input, on load, on
  // reset, and at init.
  updateRedirectUri: (page) => {
    const field = page.querySelector("#OidRedirectUri");
    if (!field) {
      return;
    }

    // A name/override change invalidates any previous "copied" confirmation.
    const status = page.querySelector("#OidRedirectUri-copied");
    if (status) {
      status.textContent = "";
    }

    const name = page.querySelector("#OidProviderName").value.trim();
    const serial = (ssoConfigurationPage.redirectUriSerial += 1);
    field.value = "";

    if (ssoConfigurationPage.redirectUriTimer) {
      clearTimeout(ssoConfigurationPage.redirectUriTimer);
      ssoConfigurationPage.redirectUriTimer = null;
    }

    if (!name) {
      field.placeholder = "Enter a provider name above to see the redirect URI";
      ssoConfigurationPage.refreshReadiness(page, "oid");
      return;
    }

    field.placeholder = "Loading the redirect URI…";
    ssoConfigurationPage.redirectUriTimer = setTimeout(() => {
      ApiClient.getJSON(
        ApiClient.getUrl("sso/OID/RedirectUri/" + encodeURIComponent(name)),
      ).then(
        (value) => {
          if (serial !== ssoConfigurationPage.redirectUriSerial) {
            return;
          }
          field.value = typeof value === "string" ? value : "";
          field.placeholder = "";
          ssoConfigurationPage.refreshReadiness(page, "oid");
        },
        // A rejection is a 404 for a provider that has not been saved yet, or a transport/authorization
        // failure. Say what to do; never show a value the server did not produce.
        () => {
          if (serial !== ssoConfigurationPage.redirectUriSerial) {
            return;
          }
          field.value = "";
          field.placeholder =
            "Save this provider to see its exact redirect URI";
          ssoConfigurationPage.refreshReadiness(page, "oid");
        },
      );
    }, 250);
  },
  copyRedirectUri: (page) => {
    const field = page.querySelector("#OidRedirectUri");
    const status = page.querySelector("#OidRedirectUri-copied");
    const value = field && field.value;
    if (!value) {
      return;
    }
    const announce = (message) => {
      if (status) {
        status.textContent = message;
      }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(
        () => announce("Redirect URI copied to the clipboard."),
        () => announce("Copy failed. Select the field and copy it manually."),
      );
      return;
    }
    // Fallback for a non-secure context without the async Clipboard API.
    field.removeAttribute("readonly");
    field.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) {
      ok = false;
    }
    field.setAttribute("readonly", "");
    announce(
      ok
        ? "Redirect URI copied to the clipboard."
        : "Copy failed. Select the field and copy it manually.",
    );
  },
  deleteProvider: (page, provider_name) => {
    if (
      !window.confirm(
        `Are you sure you want to delete the provider ${provider_name}?`,
      )
    ) {
      return;
    }
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        if (!config.OidConfigs.hasOwnProperty(provider_name)) {
          return;
        }

        delete config.OidConfigs[provider_name];
        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(
          function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            ssoConfigurationPage.loadConfiguration(page);
            // The deleted provider is gone from the list; close its now-stale editor.
            ssoConfigurationPage.hideEditor(page);

            Dashboard.alert("Provider removed");
          },
          // Report a genuine save failure rather than swallowing it. The delete
          // re-posts the whole configuration, so the server can now reject it for
          // a reason unrelated to this delete, e.g. a different provider whose
          // reserved-character name became "new" because it was removed from the
          // live config in the meantime (#336). Without this the PUT would reject
          // silently and the provider would appear undeleted with no explanation.
          function () {
            Dashboard.alert({
              title: "Delete failed",
              message:
                "Could not remove the provider. The saved configuration was rejected by the server; reload the page and try again.",
            });
          },
        );
      },
    );
  },
  // Save the GLOBAL login-page buttons opt-in (#722). ManageLoginPageButtons is a root
  // PluginConfiguration flag, so this fetches the live configuration, changes ONLY this flag, and
  // re-posts the whole document: the provider dictionaries and every other root setting ride along
  // unchanged, exactly as the provider save/delete paths do. The server reacts to the saved
  // configuration itself (LoginButtonManager listens for the configuration change), so no extra
  // endpoint call is needed: on save the managed block is injected/refreshed, or, with the flag
  // off, only the managed region is removed and the admin's own branding is preserved.
  saveLoginButtons: (page) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        config.ManageLoginPageButtons = page.querySelector(
          "#ManageLoginPageButtons",
        ).checked;

        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(
          function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            ssoConfigurationPage.loadConfiguration(page);
            Dashboard.alert("Settings saved.");
          },
          // Report a genuine save failure rather than swallowing it: this PUT re-posts the whole
          // configuration, so the server can reject it for a reason unrelated to this toggle (#336).
          function () {
            Dashboard.alert({
              title: "Save failed",
              message:
                "Could not save the login-page button setting. The saved configuration was rejected by the server; reload the page and try again.",
            });
          },
        );
      },
    );
  },
  // Save the GLOBAL Single Logout opt-in (#727). EnableSingleLogout is a root PluginConfiguration flag, so
  // this fetches the live configuration exactly like saveLoginButtons, changes ONLY this flag, and
  // re-posts the whole document, so the provider dictionaries and every other root setting ride along
  // unchanged. The per-provider post-logout redirect URL is saved with its provider, not here.
  saveSingleLogout: (page) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        config.EnableSingleLogout = page.querySelector(
          "#EnableSingleLogout",
        ).checked;

        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(
          function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            ssoConfigurationPage.loadConfiguration(page);
            Dashboard.alert("Settings saved.");
          },
          // Report a genuine save failure rather than swallowing it: this PUT re-posts the whole
          // configuration, so the server can reject it for a reason unrelated to this toggle (#336).
          function () {
            Dashboard.alert({
              title: "Save failed",
              message:
                "Could not save the Single Logout setting. The saved configuration was rejected by the server; reload the page and try again.",
            });
          },
        );
      },
    );
  },
  saveProvider: (page, provider_name) => {
    return new Promise((resolve, reject) => {
      const form_elements = ssoConfigurationPage.listArgumentsByType(page);

      ApiClient.getPluginConfiguration(
        ssoConfigurationPage.pluginUniqueId,
      ).then((config) => {
        let current_config = {};
        if (config.OidConfigs.hasOwnProperty(provider_name)) {
          current_config = config.OidConfigs[provider_name];
        }

        form_elements.text_fields.forEach((id) => {
          current_config[id] = page.querySelector("#" + id).value || null;
        });

        form_elements.check_fields.forEach((id) => {
          current_config[id] = page.querySelector("#" + id).checked;
        });

        form_elements.text_list_fields.forEach((id) => {
          current_config[id] = ssoConfigurationPage.parseTextList(
            page.querySelector("#" + id),
          );
        });

        form_elements.folder_list_fields.forEach((id) => {
          const elem = page.querySelector(`#${id}`);
          current_config[id] =
            ssoConfigurationPage.serializeEnabledFolders(elem);
        });

        form_elements.role_map_fields.forEach((id) => {
          const elem = page.querySelector(`#${id}`);
          current_config[id] = ssoConfigurationPage.serializeRoleMappings(elem);
        });

        // Untouched where the provider names a provisioning profile: the two are mutually exclusive by a
        // refusal on the OBJECT being present, so writing one here would make that provider unsaveable
        // from this page entirely - over a section the administrator never opened.
        if (!current_config.ProvisioningProfile) {
          current_config.ProvisioningPolicyTemplate =
            ssoConfigurationPage.readProvisioningTemplate(page, "");
        }

        config.OidConfigs[provider_name] = current_config;

        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(
          function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            ssoConfigurationPage.loadConfiguration(page);
            ssoConfigurationPage.loadProvider(page, provider_name);

            page.querySelector("#selectProvider").value = provider_name;
            Dashboard.alert("Settings saved.");
            resolve();
          },
          // Rejection handler attached directly to the save call, so it reports only a genuine save
          // failure and not an error thrown by the post-save UI work above. The server can refuse a
          // save for more than one reason (a malformed Base URL Override, #139; a provider name with
          // URI-reserved or control characters, #336/#360), so the message names both checks instead of
          // blaming one.
          function () {
            Dashboard.alert({
              title: "Save failed",
              message:
                "Could not save the provider. Check that the provider name has no control characters (such as a tab or newline, often introduced by copy-paste), no backslash, and none of the URI-reserved characters such as / ? # %, and that the Base URL Override is a full URL such as https://jellyfin.example.com (or blank).",
            });
            reject(new Error("Provider save failed"));
          },
        );
      });
    });
  },
  // Test-connection (#163). Calls the elevation-gated OID/Test endpoint for the SAVED provider and renders
  // the result. The endpoint reads the stored config server-side, fetches the discovery document over the
  // login's hardened path, and returns only non-secret facts (issuer, endpoints, JWKS reachability); the
  // client secret is never sent back. Everything is rendered with createElement/textContent (never
  // innerHTML) so a reflected issuer/endpoint string cannot inject markup, matching linking.js and
  // _populateFolders (#221).
  testProvider: (page, provider_name) => {
    const container = page.querySelector("#TestResult");
    if (!provider_name) {
      ssoConfigurationPage.renderTestMessage(
        container,
        "Enter a provider name and save it first, then test.",
      );
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTestMessage(container, "Testing…");

    return ApiClient.getJSON(
      ApiClient.getUrl("sso/OID/Test/" + encodeURIComponent(provider_name)),
    ).then(
      (result) => {
        ssoConfigurationPage.renderTestResult(container, result);
        ssoConfigurationPage.recordTestOutcome(
          page,
          "oid",
          Boolean(result && result.Ok),
        );
      },
      // A rejection is a transport/authorization failure or an unconfigured provider (404). Keep the
      // message generic and actionable: it never reflects a server-side secret.
      () => {
        ssoConfigurationPage.renderTestMessage(
          container,
          "Could not run the test. Make sure the provider is saved and that you are signed in as an administrator, then try again.",
        );
        ssoConfigurationPage.recordTestOutcome(page, "oid", false);
      },
    );
  },
  // Remember the outcome of a Test Connection so the readiness panel (#1083) can report reachability
  // without issuing a second request of its own. A rejection is recorded as a failure rather than left
  // unknown: the row must not read as "not yet tested" after a test the admin watched fail.
  recordTestOutcome: (page, key, ok) => {
    ssoConfigurationPage.readinessTestState[key] = ok;
    ssoConfigurationPage.refreshReadiness(page, key);
  },
  // ---- Readiness panel (#1083) ----
  // The last Test Connection outcome per protocol, so the reachability row can report it WITHOUT
  // re-issuing the request. null means "not yet tested in this page session", which is what a provider
  // that has never been tested must read as - not as a failure. resetEditor / resetSamlEditor clear it,
  // so a previous provider's result cannot be read as this one's.
  readinessTestState: { oid: null, saml: null },
  // What each editor's panel is made of. Everything here is an id that already exists on the form: the
  // panel adds no field, no request and no state of its own beyond the test outcome above.
  readinessSpecs: {
    oid: {
      listId: "OidReadinessList",
      testKey: "oid",
      requiredIds: ["OidProviderName", "OidEndpoint", "OidClientId"],
      errorIds: [
        "OidProviderName",
        "OidEndpoint",
        "OidClientId",
        "RoleClaim",
        "OidScopes",
        "BaseUrlOverride",
      ],
      urlId: "OidRedirectUri",
    },
    saml: {
      listId: "saml-ReadinessList",
      testKey: "saml",
      requiredIds: [
        "saml-provider-name",
        "saml-SamlEndpoint",
        "saml-SamlClientId",
        "saml-SamlCertificate",
      ],
      errorIds: [
        "saml-provider-name",
        "saml-SamlEndpoint",
        "saml-SamlClientId",
        "saml-SamlCertificate",
        "saml-SamlSecondaryCertificate",
        "saml-BaseUrlOverride",
      ],
      urlId: "saml-AcsUrl",
    },
  },
  // A field's human name, taken from the form's own <label>. Restating the names here would give the panel
  // a second copy of every label to drift against, and the label is already localized, so reading it keeps
  // the panel in the page's language for free.
  //
  // The two label idioms on this page are read differently, and both are needed: a text/textarea field has
  // a sibling `<label for=...>` whose OWN text is the name, with the required marker and the "(optional)"
  // hint as child elements to be dropped; a checkbox is WRAPPED in a bare `<label>` whose text lives in a
  // child `<span>`, so there the direct text nodes are empty and the whole label's text is the name. Taking
  // the direct text nodes first and falling back to the full text covers both without asking which is which.
  // The id is the last resort, so an unlabelled control still names itself rather than rendering blank.
  readinessFieldName: (page, id) => {
    const field = page.querySelector("#" + id);
    const label =
      page.querySelector('label[for="' + id + '"]') ||
      (field && field.closest("label"));
    if (!label) {
      return id;
    }
    const direct = [...label.childNodes]
      .filter((node) => node.nodeType === Node.TEXT_NODE)
      .map((node) => node.textContent)
      .join(" ");
    const text = (direct.trim() ? direct : label.textContent || "")
      .replace(/\s+/g, " ")
      .trim()
      .replace(/\(optional\)$/i, "")
      .trim()
      .replace(/[:*]+$/, "")
      .trim();
    return text || id;
  },
  // Which of the spec's fields are empty, and which are currently showing an inline validation message.
  // The empties are read from the VALUES rather than by re-running the validators, so typing into a blank
  // required field clears its row immediately and no premature "is required" error is forced onto a field
  // the admin has not left yet. The warnings are read from the validators' own output boxes, so the panel
  // and the message beside the field cannot disagree.
  readinessFieldStates: (page, spec) => {
    const named = (ids) =>
      ids.map((id) => ssoConfigurationPage.readinessFieldName(page, id));
    const missing = spec.requiredIds.filter((id) => {
      const field = page.querySelector("#" + id);
      return !field || !String(field.value || "").trim();
    });
    const warned = spec.errorIds.filter((id) => {
      const box = page.querySelector("#" + id + "-error");
      return Boolean(box && !box.hidden && box.textContent);
    });
    return { missing: named(missing), warned: named(warned) };
  },
  // The flagged security toggles that are currently ON. Reads `.checked`; it never assigns one, so the
  // danger-zone isolation the editor relies on is untouched by rendering this panel.
  readinessActiveToggles: (page, key) => {
    const ids =
      key === "saml"
        ? ssoConfigurationPage.samlInsecureFieldIds
            .concat(ssoConfigurationPage.samlSensitiveFieldIds)
            .map((id) => "saml-" + id)
        : ssoConfigurationPage.insecureFieldIds.concat(
            ssoConfigurationPage.sensitiveFieldIds,
          );
    return ids
      .filter((id) => {
        const el = page.querySelector("#" + id);
        return Boolean(el && el.checked);
      })
      .map((id) => ssoConfigurationPage.readinessFieldName(page, id));
  },
  // One row. The state word is part of the text, never a colour on its own (#221), and the row is built
  // with textContent so a value echoed into a field name could not reach the DOM as markup.
  appendReadinessRow: (list, ok, label, detail) => {
    const item = document.createElement("li");
    item.classList.add("fieldDescription");
    const state = ok
      ? tr("config.readiness_ready", "Ready")
      : tr("config.readiness_attention", "Needs attention");
    item.textContent = state + " - " + label + " - " + detail;
    list.appendChild(item);
  },
  // Rebuild a panel from the form's current state. Cheap and idempotent, so it is safe to call from a
  // field event; it issues no request and reads nothing the page does not already hold.
  refreshReadiness: (page, key) => {
    const spec = ssoConfigurationPage.readinessSpecs[key];
    const list = page.querySelector("#" + spec.listId);
    if (!list) {
      return;
    }
    list.replaceChildren();

    const states = ssoConfigurationPage.readinessFieldStates(page, spec);
    ssoConfigurationPage.appendReadinessRow(
      list,
      states.missing.length === 0,
      tr("config.readiness_required_row", "Required fields"),
      states.missing.length === 0
        ? tr(
            "config.readiness_required_ok",
            "Every required field on this form is filled in.",
          )
        : tr("config.readiness_required_missing", "Still empty: {fields}", {
            fields: states.missing.join(", "),
          }),
    );

    ssoConfigurationPage.appendReadinessRow(
      list,
      states.warned.length === 0,
      tr("config.readiness_warnings_row", "Field warnings"),
      states.warned.length === 0
        ? tr(
            "config.readiness_warnings_none",
            "No field on this form is reporting a problem.",
          )
        : tr(
            "config.readiness_warnings_some",
            "Reporting a problem: {fields}",
            { fields: states.warned.join(", ") },
          ),
    );

    const tested = ssoConfigurationPage.readinessTestState[spec.testKey];
    ssoConfigurationPage.appendReadinessRow(
      list,
      tested === true,
      tr("config.readiness_test_row", "Endpoint test"),
      tested === null
        ? tr(
            "config.readiness_test_untested",
            "Not yet tested. Save the provider, then use Test Connection.",
          )
        : tested
          ? tr(
              "config.readiness_test_pass",
              "The last Test Connection reached this provider.",
            )
          : tr(
              "config.readiness_test_fail",
              "The last Test Connection did not reach this provider.",
            ),
    );

    // The two computed URLs become available at DIFFERENT moments, so the row says which: the SAML reply
    // URL is composed on the page as soon as a name is typed, while the OpenID redirect URI is produced by
    // the server and answers 404 until the provider has been saved. Both branches carry their key and their
    // English at the tr() call itself rather than through the spec above: a key reached through a variable
    // is invisible to the catalog's own reference scan, which reports it as an orphan and would have to be
    // told about this indirection to stop.
    const urlField = page.querySelector("#" + spec.urlId);
    const urlShown = Boolean(urlField && String(urlField.value || "").trim());
    const urlReady = tr(
      "config.readiness_url_ready",
      "Shown on this form. Register it at your identity provider.",
    );
    ssoConfigurationPage.appendReadinessRow(
      list,
      urlShown,
      key === "saml"
        ? tr("config.readiness_acs_row", "Reply URL (ACS)")
        : tr("config.readiness_redirect_row", "Redirect URI"),
      urlShown
        ? urlReady
        : key === "saml"
          ? tr(
              "config.readiness_acs_pending",
              "Computed once the provider has a name. Register it at your identity provider.",
            )
          : tr(
              "config.readiness_redirect_pending",
              "Available once the provider is saved. Register it at your identity provider.",
            ),
    );

    const active = ssoConfigurationPage.readinessActiveToggles(page, key);
    ssoConfigurationPage.appendReadinessRow(
      list,
      active.length === 0,
      tr("config.readiness_toggles_row", "Insecure or sensitive options"),
      active.length === 0
        ? tr(
            "config.readiness_toggles_none",
            "None of the flagged options is active on this provider.",
          )
        : tr("config.readiness_toggles_some", "Active: {options}", {
            options: active.join(", "),
          }),
    );
  },
  // ---- Aggregate configuration check (#1084) ----
  // ONE action over every configured provider, answered by the server at `sso/Config/Check`. The evaluation
  // is NOT the per-provider panel above: that one reads the form in front of the administrator, and there is
  // exactly one form, so it can only ever answer about the provider currently loaded. Loading each provider
  // into the editor in turn to read the panel would end with the last one loaded, which this issue's own
  // acceptance forbids - a run must leave every provider's form values and toggles byte-identical. So the
  // aggregate is asked of the configuration rather than of the DOM.
  //
  // What IS reused is the naming: a missing setting is reported by the id the form gives that field, and the
  // label is read off the form through readinessFieldName, so the check speaks the page's language and a
  // relabelled field cannot drift against it.
  //
  // ADVISORY. This writes into its own list and nowhere else: no provider field, no toggle, no request that
  // changes anything. A failure leaves the page exactly as it was.
  renderCheckRow: (list, ok, label, detail) => {
    const item = document.createElement("li");
    item.classList.add("fieldDescription");
    const state = ok
      ? tr("config.readiness_ready", "Ready")
      : tr("config.readiness_attention", "Needs attention");
    // textContent: a provider name and a server refusal message both reach this line, and neither may
    // arrive as markup (#221).
    item.textContent = state + " - " + label + " - " + detail;
    list.appendChild(item);
  },
  renderCheckNote: (list, message) => {
    const item = document.createElement("li");
    item.classList.add("fieldDescription");
    item.textContent = message;
    list.appendChild(item);
  },
  // One row's detail sentence, in the order an administrator acts on it: what is empty, then what the save
  // path would refuse, then whether the provider is switched on at all. A provider an administrator turned
  // off is NOT reported as needing attention - it is a deliberate state, and flagging it would train them to
  // ignore the list - so the sentence says so and the row's own verdict is left alone.
  checkRowDetail: (page, row) => {
    const parts = [];
    const missing = Array.isArray(row.MissingFields) ? row.MissingFields : [];
    if (missing.length > 0) {
      const prefix = row.Protocol === "SAML" ? "saml-" : "";
      parts.push(
        tr("config.readiness_required_missing", "Still empty: {fields}", {
          fields: missing
            .map((field) =>
              ssoConfigurationPage.readinessFieldName(page, prefix + field),
            )
            .join(", "),
        }),
      );
    }

    if (row.Problem) {
      parts.push(String(row.Problem));
    }

    if (parts.length === 0) {
      parts.push(
        tr(
          "config.check_ready_detail",
          "Nothing in this provider's configuration would refuse a login.",
        ),
      );
    }

    if (!row.Enabled) {
      parts.push(
        tr(
          "config.check_disabled",
          "It is switched off, so no button for it appears on the sign-in page.",
        ),
      );
    }

    return parts.join(" ");
  },
  checkAllProviders: (page) => {
    const list = page.querySelector("#sso-config-check-result");
    if (!list) {
      return Promise.resolve();
    }

    list.replaceChildren();
    ssoConfigurationPage.renderCheckNote(
      list,
      tr("config.check_running", "Checking every configured provider…"),
    );

    return ApiClient.getJSON(ApiClient.getUrl("sso/Config/Check")).then(
      (report) => {
        const rows =
          report && Array.isArray(report.Providers) ? report.Providers : [];
        list.replaceChildren();

        if (rows.length === 0) {
          ssoConfigurationPage.renderCheckNote(
            list,
            tr(
              "config.check_none",
              "No provider is configured yet, so there is nothing to check.",
            ),
          );
          return;
        }

        rows.forEach((row) => {
          ssoConfigurationPage.renderCheckRow(
            list,
            row.Ready === true,
            String(row.Protocol || "") + " " + String(row.Provider || ""),
            ssoConfigurationPage.checkRowDetail(page, row),
          );
        });

        // Stated on every run rather than left out. The check makes no request to any identity provider, so
        // a list with no "needs attention" row does not mean every provider answers - and an administrator
        // reading silence as reachability is the one wrong conclusion this action could produce.
        ssoConfigurationPage.renderCheckNote(
          list,
          tr(
            "config.check_reachability",
            "Reachability was not checked. Use Test Connection in a provider's own editor to see whether it answers.",
          ),
        );
      },
      // Generic and input-independent, like the neighbouring admin actions: it never reflects a server value.
      () => {
        list.replaceChildren();
        ssoConfigurationPage.renderCheckNote(
          list,
          tr(
            "config.check_failed",
            "Could not run the check. Make sure you are signed in as an administrator, then try again.",
          ),
        );
      },
    );
  },
  renderTestMessage: (container, message) => {
    container.replaceChildren();
    const line = document.createElement("p");
    line.classList.add("fieldDescription");
    line.textContent = message;
    container.appendChild(line);
  },
  renderTestResult: (container, result) => {
    container.replaceChildren();

    const heading = document.createElement("p");
    heading.classList.add("fieldDescription");
    // Boolean coercion, not string interpolation: the label is fixed text, so no server value reaches the DOM here.
    heading.textContent =
      (result && result.Ok ? "✅ " : "⚠ ") +
      (result && result.Message ? result.Message : "No result returned.");
    container.appendChild(heading);

    const details =
      result && Array.isArray(result.Details) ? result.Details : [];
    if (details.length === 0) {
      return;
    }

    const list = document.createElement("ul");
    details.forEach((detail) => {
      const item = document.createElement("li");
      // textContent so an issuer/endpoint value echoed by the provider stays inert on the page.
      item.textContent = String(detail);
      list.appendChild(item);
    });
    container.appendChild(list);
  },
  // Config export (#161). Fetches the redacted export document from the elevation-gated endpoint (the
  // server withholds every secret and account-link map) and saves it as a JSON file via a Blob download,
  // never navigation, so the admin's auth header is sent and no secret is placed in a URL. The filename is
  // fixed text; nothing from the document reaches the DOM as markup.
  exportConfig: (page) => {
    const container = page.querySelector("#ConfigTransferResult");
    ssoConfigurationPage.renderTransferMessage(container, "Exporting…");

    return ApiClient.getJSON(ApiClient.getUrl("sso/Config/Export")).then(
      (document_json) => {
        const blob = new Blob([JSON.stringify(document_json, null, 2)], {
          type: "application/json",
        });
        const url = URL.createObjectURL(blob);
        const anchor = window.document.createElement("a");
        anchor.href = url;
        anchor.download = "sso-config-export.json";
        window.document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(url);
        ssoConfigurationPage.renderTransferMessage(
          container,
          "Exported. Provider secrets and account links are redacted from the file.",
        );
      },
      () =>
        ssoConfigurationPage.renderTransferMessage(
          container,
          "Could not export the configuration. Make sure you are signed in as an administrator, then try again.",
        ),
    );
  },
  // Config import (#161). Reads the chosen file as text, parses it locally (a parse error is reported, never
  // applied), and POSTs it to the elevation-gated import endpoint. The server validates and merges it
  // fail-closed, keeping each unchanged provider's stored secret and links (an OpenID provider whose
  // endpoint/client id the import changes has its links/secret cleared, the #186 repoint safety measure).
  // On success the provider list is reloaded so the merged providers appear; the admin re-enters secrets.
  importConfig: (page, file) => {
    const container = page.querySelector("#ConfigTransferResult");
    if (!file) {
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTransferMessage(container, "Importing…");
    return file
      .text()
      .then((text) => {
        let document_json;
        try {
          document_json = JSON.parse(text);
        } catch (e) {
          throw new Error("not-json");
        }

        return ApiClient.fetch({
          type: "POST",
          url: ApiClient.getUrl("sso/Config/Import"),
          data: JSON.stringify(document_json),
          contentType: "application/json",
        });
      })
      .then(() => {
        ssoConfigurationPage.loadConfiguration(page);
        ssoConfigurationPage.renderTransferMessage(
          container,
          "Imported. Re-enter each provider's secret and save it; secrets are never included in an export.",
        );
      })
      .catch((e) => {
        // A local parse failure and a server rejection (an invalid or unsupported document, an expired
        // session) are both fail-closed here: the message is generic and never reflects a server value.
        const message =
          e && e.message === "not-json"
            ? "That file is not valid JSON. Choose a configuration file exported from this plugin."
            : "Could not import the configuration. The file was rejected by the server, or you are not signed in as an administrator.";
        ssoConfigurationPage.renderTransferMessage(container, message);
      });
  },
  // Account-link export (#1131). The second half of a migration: the configuration export deliberately
  // withholds the link maps, and a rebuilt user database reissues every id the links are stored against, so
  // the links travel in their own username-keyed file. Same Blob download as exportConfig - never
  // navigation - so the admin's auth header is sent and nothing lands in a URL. The file is NOT redacted,
  // and the status line says so rather than leaving the admin to infer it from the config export's wording.
  exportLinks: (page) => {
    const container = page.querySelector("#LinkTransferResult");
    ssoConfigurationPage.renderTransferMessage(
      container,
      tr("config.link_export_running", "Exporting account links…"),
    );

    return ApiClient.getJSON(ApiClient.getUrl("sso/Config/Links/Export")).then(
      (document_json) => {
        const blob = new Blob([JSON.stringify(document_json, null, 2)], {
          type: "application/json",
        });
        const url = URL.createObjectURL(blob);
        const anchor = window.document.createElement("a");
        anchor.href = url;
        anchor.download = "sso-account-links.json";
        window.document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(url);
        ssoConfigurationPage.renderTransferMessage(
          container,
          tr(
            "config.link_export_done",
            "Exported. This file is not redacted: it carries usernames and the identity-provider subject identifier behind each link.",
          ),
        );
      },
      () =>
        ssoConfigurationPage.renderTransferMessage(
          container,
          tr(
            "config.link_export_failed",
            "Could not export the account links. Make sure you are signed in as an administrator, then try again.",
          ),
        ),
    );
  },
  // Account-link import (#1131). Parses locally first, so a file that is not JSON is reported here and
  // never sent. The server validates the whole document before writing a single link and persists nothing
  // when it refuses, so a rejection leaves the stored link table exactly as it was.
  //
  // Unlike importConfig, a refusal reports the SERVER's reason. The refusals that matter here name the
  // entry that could not be restored - an unknown username, an absent provider, a canonical name this
  // instance already links to a different account - and a generic message would leave an admin with a file
  // they cannot fix. The reason is admin-supplied data (it echoes the file the admin chose) returned to
  // that same admin, and it reaches the DOM through renderTransferMessage's textContent, so it is inert.
  // A rejection body that cannot be read falls back to the generic message rather than showing nothing.
  importLinks: (page, file) => {
    const container = page.querySelector("#LinkTransferResult");
    if (!file) {
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTransferMessage(
      container,
      tr("config.link_import_running", "Importing account links…"),
    );
    return file
      .text()
      .then((text) => {
        let document_json;
        try {
          document_json = JSON.parse(text);
        } catch (e) {
          throw new Error("not-json");
        }

        return ApiClient.fetch({
          type: "POST",
          url: ApiClient.getUrl("sso/Config/Links/Import"),
          data: JSON.stringify(document_json),
          contentType: "application/json",
        });
      })
      .then(() => {
        ssoConfigurationPage.renderTransferMessage(
          container,
          tr(
            "config.link_import_done",
            "Imported. Each link was restored onto the account this server holds for its username today.",
          ),
        );
      })
      .catch((e) => {
        if (e && e.message === "not-json") {
          ssoConfigurationPage.renderTransferMessage(
            container,
            tr(
              "config.link_import_not_json",
              "That file is not valid JSON. Choose an account-link file exported from this plugin.",
            ),
          );
          return;
        }

        // ApiClient.fetch rejects with the Response on a non-2xx status, so the refusal text is read off it
        // when it is there. Anything else - an expired session, a network failure, a rejection shape this
        // does not recognise - falls through to the generic message.
        const generic = tr(
          "config.link_import_failed",
          "Could not import the account links. The file was rejected by the server, or you are not signed in as an administrator.",
        );
        const body =
          e && typeof e.text === "function" ? e.text() : Promise.reject();

        return Promise.resolve(body).then(
          (reason) =>
            ssoConfigurationPage.renderTransferMessage(
              container,
              reason
                ? tr(
                    "config.link_import_rejected",
                    "The server rejected the file: {reason}",
                    { reason: String(reason) },
                  )
                : generic,
            ),
          () => ssoConfigurationPage.renderTransferMessage(container, generic),
        );
      });
  },
  // The admin linked-accounts panel (#1121). Read-only presentation over the elevation-gated aggregate
  // roster (SSOController.LinkedAccountRoster, #1119), plus the per-account revoke, which reuses the
  // EXISTING Unregister endpoint unchanged - same route, same rate-limit class, same audit line. It adds no
  // server route.
  //
  // Every value on a row is attacker-influenced: a canonical name is whatever the identity provider put in
  // its subject claim, and a provider name is admin-typed but travels through configuration import. So the
  // whole panel renders through textContent and never innerHTML, the same line linking.js already holds for
  // the self-service page - and this page is the higher-value target, because it is the one an
  // administrator opens.
  loadLinkedAccounts: (page) => {
    const container = page.querySelector("#LinkedAccountsResult");
    ssoConfigurationPage.renderTransferMessage(
      container,
      tr("config.linked_accounts_loading", "Loading the linked accounts…"),
    );

    return ApiClient.getJSON(ApiClient.getUrl("sso/Links/Roster")).then(
      (roster) =>
        ssoConfigurationPage.renderLinkedAccounts(page, container, roster),
      // Generic and input-independent, like the neighbouring admin actions: it never reflects a server value.
      () =>
        ssoConfigurationPage.renderTransferMessage(
          container,
          tr(
            "config.linked_accounts_failed",
            "Could not load the linked accounts. Make sure you are signed in as an administrator, then try again.",
          ),
        ),
    );
  },
  renderLinkedAccounts: (page, container, roster) => {
    const accounts =
      roster && Array.isArray(roster.Accounts) ? roster.Accounts : [];
    container.replaceChildren();

    // The empty state is a sentence rather than an empty table: a blank panel reads as a failed fetch, and
    // the failure branch above renders into this same region.
    if (accounts.length === 0) {
      ssoConfigurationPage.renderTransferMessage(
        container,
        tr(
          "config.linked_accounts_empty",
          "No Jellyfin account holds an SSO link on this server.",
        ),
      );
      return;
    }

    const table = document.createElement("table");
    const head = document.createElement("thead");
    const head_row = document.createElement("tr");
    [
      tr("config.linked_accounts_column_account", "Account"),
      tr("config.linked_accounts_column_links", "SSO links"),
      tr("config.linked_accounts_column_action", "Action"),
    ].forEach((label) => {
      const cell = document.createElement("th");
      cell.textContent = label;
      head_row.appendChild(cell);
    });
    head.appendChild(head_row);
    table.appendChild(head);

    const body = document.createElement("tbody");
    accounts.forEach((account) => {
      body.appendChild(
        ssoConfigurationPage.renderLinkedAccountRow(page, account),
      );
    });
    table.appendChild(body);
    container.appendChild(table);
  },
  renderLinkedAccountRow: (page, account) => {
    const row = document.createElement("tr");
    const exists = account && account.AccountExists === true;
    const username =
      account && account.Username ? String(account.Username) : "";

    const name_cell = document.createElement("td");
    // An orphaned row is the thing this panel exists to surface, so it is named as one rather than shown as
    // a nameless account: the roster reports it deliberately instead of dropping it, and the user id is the
    // only identifier it has left.
    name_cell.textContent = exists
      ? username
      : tr("config.linked_accounts_orphan_account", "Deleted account ({id})", {
          id: String((account && account.UserId) || ""),
        });
    row.appendChild(name_cell);

    const links_cell = document.createElement("td");
    const list = document.createElement("ul");
    const links = account && Array.isArray(account.Links) ? account.Links : [];
    links.forEach((link) => {
      const item = document.createElement("li");
      item.textContent = tr(
        "config.linked_accounts_link_line",
        "{provider} ({protocol}) - {canonical} - last SSO login: {last}",
        {
          provider: String((link && link.Provider) || ""),
          protocol: String((link && link.Protocol) || ""),
          canonical: String((link && link.CanonicalName) || ""),
          last: ssoConfigurationPage.formatLastSsoLogin(
            link && link.LastSsoLoginUtc,
          ),
        },
      );
      list.appendChild(item);
    });
    links_cell.appendChild(list);
    row.appendChild(links_cell);

    const action_cell = document.createElement("td");
    if (exists) {
      const button = document.createElement("button");
      button.setAttribute("is", "emby-button");
      button.setAttribute("type", "button");
      button.classList.add("raised", "button-alt", "emby-button");
      button.textContent = tr("config.linked_accounts_revoke", "Revoke");
      button.addEventListener("click", (e) => {
        ssoConfigurationPage.revokeLinkedAccount(page, username);
        e.preventDefault();
        return false;
      });
      action_cell.appendChild(button);
    } else {
      // No button rather than a disabled one: Unregister resolves the account by username, so on exactly
      // these rows it can only answer 404. A control that is present and always fails on the case the panel
      // was opened for is worse than none, and the row says why instead of leaving it to be discovered.
      const note = document.createElement("p");
      note.classList.add("fieldDescription");
      note.textContent = tr(
        "config.linked_accounts_orphan_note",
        "The Jellyfin account behind this link no longer exists, so it cannot be revoked from here: the revoke resolves the account by its username.",
      );
      action_cell.appendChild(note);
    }
    row.appendChild(action_cell);

    return row;
  },
  // Null means exactly "no successful SSO login has been recorded through this link since the stamp
  // existed" - never a login at an unknown time - so it renders as a word rather than as an epoch date.
  // The stamp is coalesced rather than written on every login, so it reads as "not later than" and this
  // panel does not present it as a session timeline.
  formatLastSsoLogin: (value) => {
    const never = tr("config.linked_accounts_never", "never");
    if (!value) {
      return never;
    }

    const when = new Date(value);
    return Number.isNaN(when.getTime()) ? never : when.toLocaleString();
  },
  // The revoke (#1121). It reuses POST sso/Unregister/{username} exactly as it stands - the elevation
  // policy, the "unregister" rate-limit class, RemoveUserEverywhere across both protocols and the token
  // revoke are all the endpoint's, and none of them is re-implemented or bypassed here.
  //
  // The confirmation NAMES the consequence rather than asking a bare "are you sure": the revoke switches
  // the account back to Jellyfin's built-in password provider, which re-opens native password login for
  // that one account even on a server running SSO-only (#165). That was decided on #1121 - warn, name the
  // consequence, proceed - because refusing the action on an SSO-only server would remove the control on
  // exactly the servers where cutting one account off matters most. The server-wide setting is untouched,
  // and the text says so, because an administrator reading "revoke" expects strictly less access.
  revokeLinkedAccount: (page, username) => {
    const result = page.querySelector("#LinkedAccountsRevokeResult");
    if (
      !window.confirm(
        tr(
          "config.linked_accounts_revoke_confirm",
          "Revoke every SSO link of {user}? This removes the links from all providers and ends every session that account holds, on every device. It also switches the account back to the built-in Jellyfin password provider, so {user} can sign in with a password again even while this server is otherwise SSO-only. The server-wide SSO-only setting is not changed.",
          { user: username },
        ),
      )
    ) {
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTransferMessage(
      result,
      tr(
        "config.linked_accounts_revoking",
        "Revoking the SSO links of {user}…",
        { user: username },
      ),
    );

    return ApiClient.fetch({
      type: "POST",
      url: ApiClient.getUrl("sso/Unregister/" + encodeURIComponent(username)),
      data: JSON.stringify(DEFAULT_PASSWORD_PROVIDER_ID),
      contentType: "application/json",
    }).then(
      () =>
        // Re-read rather than editing the rendered table: the roster is the server's answer, and a panel
        // that edits its own copy would keep showing a row the revoke did not actually remove.
        ssoConfigurationPage
          .loadLinkedAccounts(page)
          .then(() =>
            ssoConfigurationPage.renderTransferMessage(
              result,
              tr(
                "config.linked_accounts_revoked",
                "Revoked. That account holds no SSO link any more, and every session it held has been ended.",
              ),
            ),
          ),
      // Generic and input-independent: it never reflects a server value.
      () =>
        ssoConfigurationPage.renderTransferMessage(
          result,
          tr(
            "config.linked_accounts_revoke_failed",
            "Could not revoke the SSO links. Make sure you are signed in as an administrator, then try again.",
          ),
        ),
    );
  },
  renderTransferMessage: (container, message) => {
    container.replaceChildren();
    const line = window.document.createElement("p");
    line.classList.add("fieldDescription");
    line.textContent = message;
    container.appendChild(line);
  },
  addTextAreaStyle: (view) => {
    const style = document.createElement("link");
    style.rel = "stylesheet";
    style.href =
      ApiClient.getUrl("web/configurationpage") + "?name=SSO-Auth.css";
    view.appendChild(style);
  },

  // Localize the page's own labels (#913). Jellyfin core serves this configuration page from its own
  // URL base, so a relative import would not resolve to the plugin's assets; load the shared applier
  // from its absolute SSOViews URL, the same module the linking page uses, rather than duplicating
  // it here.
  //
  // Localization is strictly best-effort and must never take the page down with it: init calls this
  // BEFORE it wires the Save/Delete/Test handlers, so an escaping error would leave a fully rendered
  // but inert admin page. The try/catch is load-bearing and NOT redundant with the .catch below:
  // ApiClient.getUrl throws SYNCHRONOUSLY on a missing server address, while the argument is evaluated,
  // so no promise exists yet for .catch to see. Either way the markup keeps its built-in English.
  localize: (view) => {
    try {
      import(ApiClient.getUrl("SSOViews/i18n.js"))
        .then((module) =>
          module.loadCatalog().then(() => {
            i18n = module;
            module.applyTo(view);
          }),
        )
        .catch(() => {});
    } catch {
      // Keep the built-in English; the page's own functionality is unaffected.
    }
  },

  // ---- Provider templates (#726) ----
  // Fill a preset picker's options from its catalog (createElement/textContent; the labels are our own
  // fixed strings, but building them inertly keeps the one-DOM-construction idiom). The leading blank
  // "Choose a template" option authored in the HTML is preserved.
  populatePresetPicker: (page, selectId, presets) => {
    const select = page.querySelector("#" + selectId);
    if (!select) {
      return;
    }
    Object.keys(presets).forEach((key) => {
      const option = document.createElement("option");
      option.value = key;
      option.textContent = presets[key].label;
      select.appendChild(option);
    });
  },
  renderPresetNote: (page, noteId, message) => {
    const box = page.querySelector("#" + noteId);
    if (box) {
      box.textContent = message || "";
    }
  },
  // Apply an OpenID preset onto the editor. Writes ONLY into existing marker-classed fields by their id
  // (every field key is a real OidConfig property, pinned by ProviderPresets_ReferenceOnlyRealOidcProperties)
  // and pre-checks ONLY the listed compatibility toggles. It first clears every preset-managed toggle so
  // switching templates cannot leave a previous preset's toggle checked, never touches the secret, and
  // never saves. syncDependentFields then surfaces any pre-enabled insecure toggle in the auto-expanded
  // danger zone. The provider name and client secret the admin may have typed are left untouched.
  applyOidcPreset: (page, key) => {
    OIDC_PRESET_MANAGED_TOGGLES.forEach((prop) => {
      const el = page.querySelector("#" + prop);
      if (el) {
        el.checked = false;
      }
    });

    const preset = OIDC_PRESETS[key];
    if (!preset) {
      // The blank "choose a template" option: clear the note and re-sync (so a just-cleared toggle
      // collapses its danger-zone surfacing) without altering the admin's fields.
      ssoConfigurationPage.renderPresetNote(page, "OidPreset-note", "");
      ssoConfigurationPage.syncDependentFields(page);
      return;
    }

    Object.keys(preset.fields).forEach((prop) => {
      const el = page.querySelector("#" + prop);
      if (el) {
        el.value = preset.fields[prop];
      }
    });
    preset.toggles.forEach((prop) => {
      const el = page.querySelector("#" + prop);
      if (el) {
        el.checked = true;
      }
    });

    ssoConfigurationPage.syncDependentFields(page);
    ssoConfigurationPage.updateRedirectUri(page);
    ssoConfigurationPage.renderPresetNote(page, "OidPreset-note", preset.note);
  },
  // The SAML counterpart. Field ids are "saml-" + the SamlConfig property; toggles likewise. Same
  // clear-then-apply discipline, and syncSamlDependentFields surfaces a pre-enabled insecure toggle.
  applySamlPreset: (page, key) => {
    SAML_PRESET_MANAGED_TOGGLES.forEach((prop) => {
      const el = page.querySelector("#saml-" + prop);
      if (el) {
        el.checked = false;
      }
    });

    const preset = SAML_PRESETS[key];
    if (!preset) {
      ssoConfigurationPage.renderPresetNote(page, "saml-Preset-note", "");
      ssoConfigurationPage.syncSamlDependentFields(page);
      return;
    }

    Object.keys(preset.fields).forEach((prop) => {
      const el = page.querySelector("#saml-" + prop);
      if (el) {
        el.value = preset.fields[prop];
      }
    });
    preset.toggles.forEach((prop) => {
      const el = page.querySelector("#saml-" + prop);
      if (el) {
        el.checked = true;
      }
    });

    ssoConfigurationPage.syncSamlDependentFields(page);
    ssoConfigurationPage.updateSamlUrls(page);
    ssoConfigurationPage.renderPresetNote(
      page,
      "saml-Preset-note",
      preset.note,
    );
  },

  // ============================================================================
  // SAML provider workspace (#725)
  // ----------------------------------------------------------------------------
  // A lifecycle parallel to the OpenID one above, kept entirely separate so the OpenID workspace and its
  // JS are untouched (there is no JS runtime test harness; the adversarial review is the primary
  // verification, so isolation is the cheapest correctness guarantee). Every SAML persisting field id is
  // its SamlConfig property spelled with a "saml-" PREFIX (ids must be unique across the whole document,
  // and the OpenID fields already own the unprefixed spellings); the property is the id minus that prefix,
  // computed by samlPropOf. ProviderFormFieldIds_MatchSamlConfigProperties fails the build if any
  // saml-*-marked field id (after stripping the prefix) is not a real SamlConfig property, so a field that
  // would silently never save cannot land. The generic element-argument helpers above (setFieldError,
  // populateFolders / populateEnabledFolders / serializeEnabledFolders, populateRoleMappings /
  // serializeRoleMappings, fillTextList / parseTextList, setCollapseExpanded, setDependent,
  // setSectionExpanded, renderTestMessage / renderTestResult) are protocol-agnostic and reused as-is.
  // ============================================================================

  // Toggles/settings whose ENABLED state is a security downgrade the admin must not miss (mirrors
  // insecureFieldIds/sensitiveFieldIds for OpenID). DoNotValidateAudience disables the AudienceRestriction
  // check; AllowExistingAccountLink widens account adoption. Property names (no prefix): the flag is read
  // from the saved config (provider[prop]) and, when checking the live checkbox, queried as "#saml-"+prop.
  // ProvisionNewUsersDisabled is deliberately NOT flagged: it is a fail-closed hardening toggle (ON is
  // MORE secure), so surfacing it would be backwards and cause alert fatigue, exactly as for OpenID.
  samlInsecureFieldIds: ["DoNotValidateAudience"],
  samlSensitiveFieldIds: ["AllowExistingAccountLink"],
  samlPropOf: (id) => id.slice("saml-".length),
  populateSamlProviders: (page, providers) => {
    const select = page.querySelector("#saml-selectProvider");
    select.querySelectorAll("option").forEach((option) => option.remove());
    Object.keys(providers).forEach((provider_name) => {
      select.appendChild(new Option(provider_name, provider_name));
    });
    ssoConfigurationPage.renderSamlProviderCards(page, providers);
  },
  // SAML provider cards, same inert createElement/textContent construction as renderProviderCards (#221):
  // a provider name is never interpolated as markup, so a hostile name stays inert on the page.
  renderSamlProviderCards: (page, providers) => {
    const list = page.querySelector("#saml-provider-list");
    const empty = page.querySelector("#saml-provider-empty");
    list.replaceChildren();

    const names = Object.keys(providers);
    empty.hidden = names.length !== 0;

    names.forEach((provider_name) => {
      const provider = providers[provider_name] || {};

      const card = document.createElement("button");
      card.type = "button";
      card.classList.add("sso-provider-card");
      card.dataset.provider = provider_name;
      card.setAttribute("role", "listitem");

      const name = document.createElement("span");
      name.classList.add("sso-provider-card-name");
      name.textContent = provider_name;

      const badge = document.createElement("span");
      badge.classList.add("sso-badge", "sso-badge-type");
      badge.textContent = "SAML";

      const enabled = Boolean(provider.Enabled);
      const pill = document.createElement("span");
      pill.classList.add(
        "sso-pill",
        enabled ? "sso-pill-enabled" : "sso-pill-disabled",
      );
      pill.textContent = enabled ? "Enabled" : "Disabled";

      card.append(name, badge, pill);

      const flagged = ssoConfigurationPage.samlInsecureFieldIds
        .concat(ssoConfigurationPage.samlSensitiveFieldIds)
        .some((id) => Boolean(provider[id]));
      if (flagged) {
        card.classList.add("sso-provider-card-flagged");
        const warn = document.createElement("span");
        warn.classList.add("sso-badge", "sso-badge-warn");
        warn.textContent = "Review";
        warn.title =
          "This provider has an active insecure or sensitive setting.";
        card.append(warn);
      }

      list.appendChild(card);
    });
  },
  showSamlEditor: (page) => {
    page.querySelector("#saml-editor").hidden = false;
  },
  hideSamlEditor: (page) => {
    page.querySelector("#saml-editor").hidden = true;
  },
  setSamlEditorTitle: (page, title) => {
    page.querySelector("#saml-editor-title").textContent = title;
  },
  // Load a SAML card into the editor. resetSamlEditor gives a clean slate FIRST (same discipline as
  // openProvider) so no field, toggle, or collapse state from the previously loaded provider bleeds into
  // this one and gets silently re-saved.
  openSamlProvider: (page, provider_name) => {
    page.querySelector("#saml-selectProvider").value = provider_name;
    ssoConfigurationPage.resetSamlEditor(page);
    ssoConfigurationPage.clearSamlValidationErrors(page);
    ssoConfigurationPage.renderSamlSaveStatus(page, "");
    ssoConfigurationPage.setSamlEditorTitle(page, provider_name);
    ssoConfigurationPage.showSamlEditor(page);
    ssoConfigurationPage.loadSamlProvider(page, provider_name);
    page.querySelector("#saml-editor").scrollIntoView({ block: "start" });
  },
  addSamlProvider: (page) => {
    page.querySelector("#saml-selectProvider").value = "";
    ssoConfigurationPage.resetSamlEditor(page);
    ssoConfigurationPage.clearSamlValidationErrors(page);
    ssoConfigurationPage.renderSamlSaveStatus(page, "");
    ssoConfigurationPage.setSamlEditorTitle(
      page,
      tr("config.new_provider", "New provider"),
    );
    ssoConfigurationPage.syncSamlDependentFields(page);
    // Restores a form left frozen by a managed provider opened just before (#1104); a new one is never managed.
    ssoConfigurationPage.applyManagedState(page, "saml", "");
    ssoConfigurationPage.showSamlEditor(page);
    page.querySelector("#saml-editor").scrollIntoView({ block: "start" });
    page.querySelector("#saml-provider-name").focus();
  },
  resetSamlEditor: (page) => {
    // Same reason as resetEditor above (#1083).
    ssoConfigurationPage.readinessTestState.saml = null;

    const form_elements = ssoConfigurationPage.listSamlArgumentsByType(page);

    page.querySelector("#saml-provider-name").value = "";

    form_elements.text_fields.forEach((id) => {
      page.querySelector("#" + id).value = "";
    });
    form_elements.text_list_fields.forEach((id) => {
      page.querySelector("#" + id).value = "";
    });
    form_elements.check_fields.forEach((id) => {
      page.querySelector("#" + id).checked = false;
    });
    form_elements.folder_list_fields.forEach((id) => {
      ssoConfigurationPage.populateEnabledFolders(
        [],
        page.querySelector("#" + id),
      );
    });
    form_elements.role_map_fields.forEach((id) => {
      ssoConfigurationPage.populateRoleMappings(
        [],
        page.querySelector("#" + id),
      );
    });

    ssoConfigurationPage.fillProvisioningTemplate(page, "saml-", null, null);

    ssoConfigurationPage.setSamlInsecureOptionsExpanded(page, false);
    ssoConfigurationPage.resetSamlEditorSections(page);
    ssoConfigurationPage.syncSamlDependentFields(page);
    ssoConfigurationPage.updateSamlUrls(page);
    // Reset the template picker + its note so opening/adding a provider never shows a stale template (#726).
    const samlPreset = page.querySelector("#saml-Preset");
    if (samlPreset) {
      samlPreset.value = "";
    }
    ssoConfigurationPage.renderPresetNote(page, "saml-Preset-note", "");
  },
  // Return every accordion INSIDE the SAML editor to its authored default; scoped to #saml-editor so the
  // OpenID editor and the page-level collapses are untouched.
  resetSamlEditorSections: (page) => {
    const editor = page.querySelector("#saml-editor");
    if (!editor) {
      return;
    }
    editor.querySelectorAll('[is="emby-collapse"]').forEach((section) => {
      ssoConfigurationPage.setCollapseExpanded(
        section,
        section.getAttribute("data-expanded") === "true",
      );
    });
  },
  syncSamlDependentFields: (page) => {
    ssoConfigurationPage.setDependent(
      page,
      "saml-EnableAllFolders",
      "saml-EnabledFolders-group",
      false,
    );
    ssoConfigurationPage.setDependent(
      page,
      "saml-EnableFolderRoles",
      "saml-FolderRoleMapping-group",
      true,
    );
    ssoConfigurationPage.setDependent(
      page,
      "saml-EnableLiveTvRoles",
      "saml-LiveTvRoles-group",
      true,
    );

    // Surface active insecure / sensitive settings behind the collapsed "Security & hardening" accordion
    // (and, for the insecure subset, its inner list): expand-only, exactly like syncDependentFields.
    const isChecked = (id) => {
      const el = page.querySelector("#saml-" + id);
      return Boolean(el && el.checked);
    };
    const anyInsecure =
      ssoConfigurationPage.samlInsecureFieldIds.some(isChecked);
    const anySensitive =
      anyInsecure || ssoConfigurationPage.samlSensitiveFieldIds.some(isChecked);
    if (anyInsecure) {
      ssoConfigurationPage.setSamlInsecureOptionsExpanded(page, true);
    }
    if (anySensitive) {
      ssoConfigurationPage.setSectionExpanded(
        page,
        "saml-security-section",
        true,
      );
    }
  },
  setSamlInsecureOptionsExpanded: (page, expanded) => {
    const button = page.querySelector("#saml-ShowInsecureOptions");
    const options = page.querySelector("#saml-insecure-options");
    if (!button || !options) {
      return;
    }
    options.hidden = !expanded;
    button.setAttribute("aria-expanded", String(expanded));
    button.querySelector("span").textContent = expanded
      ? "Hide insecure options"
      : "Show insecure options";
  },
  // The SAML save contract, made explicit (mirrors listArgumentsByType): every input in
  // #sso-new-saml-provider that persists carries an sso-* marker class AND a "saml-"+property id. The
  // folder-list and role-map ids are the two that are not plain inputs, listed explicitly like the OpenID
  // side. saveSamlProvider/loadSamlProvider map id->property with samlPropOf.
  listSamlArgumentsByType: (page) => {
    const folder_list_fields = ["saml-EnabledFolders"];
    const role_map_fields = ["saml-FolderRoleMapping"];

    const form = page.querySelector("#sso-new-saml-provider");

    const text_fields = [...form.querySelectorAll(".sso-text")].map(
      (e) => e.id,
    );
    const text_list_fields = [...form.querySelectorAll(".sso-line-list")].map(
      (e) => e.id,
    );
    const check_fields = [...form.querySelectorAll(".sso-toggle")].map(
      (e) => e.id,
    );

    return {
      text_list_fields,
      text_fields,
      check_fields,
      folder_list_fields,
      role_map_fields,
    };
  },
  loadSamlProvider: (page, provider_name) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        const provider = (config.SamlConfigs || {})[provider_name] || {};

        const form_elements =
          ssoConfigurationPage.listSamlArgumentsByType(page);

        page.querySelector("#saml-provider-name").value = provider_name;

        form_elements.text_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          // The write-only signing keys (SamlSigningKeyPfx / SamlRolloverSigningKeyPfx) are serialized back
          // as null by the server (WriteOnlySecretConverter), so provider[prop] is falsy and the field stays
          // blank, and its "leave blank to keep" placeholder governs, exactly like the OpenID OidSecret.
          if (provider[prop]) {
            page.querySelector("#" + id).value = provider[prop];
          }
        });

        form_elements.text_list_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          if (provider[prop]) {
            ssoConfigurationPage.fillTextList(
              provider[prop],
              page.querySelector("#" + id),
            );
          }
        });

        form_elements.folder_list_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          if (provider[prop]) {
            ssoConfigurationPage.populateEnabledFolders(
              provider[prop],
              page.querySelector("#" + id),
            );
          }
        });

        form_elements.check_fields.forEach((id) => {
          // Always set from the loaded provider (not only when truthy) so a stale insecure toggle from a
          // previously loaded provider is never left checked to be silently re-saved, the exact reason the
          // OpenID loadProvider sets Boolean(provider[id]) unconditionally.
          const prop = ssoConfigurationPage.samlPropOf(id);
          page.querySelector("#" + id).checked = Boolean(provider[prop]);
        });

        form_elements.role_map_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          const elem = page.querySelector("#" + id);
          if (provider[prop]) {
            ssoConfigurationPage.populateRoleMappings(provider[prop], elem);
          }
        });

        ssoConfigurationPage.fillProvisioningTemplate(
          page,
          "saml-",
          provider.ProvisioningPolicyTemplate,
          provider.ProvisioningProfile,
        );

        ssoConfigurationPage.syncSamlDependentFields(page);
        ssoConfigurationPage.updateSamlUrls(page);
        // Last, for the same reason as the OpenID arm (#1104).
        ssoConfigurationPage.applyManagedState(page, "saml", provider_name);
        // The panel summarises the fields and toggles this call just wrote (#1083).
        ssoConfigurationPage.refreshReadiness(page, "saml");
      },
    );
  },
  // Canonical external base for the computed SAML URLs (mirrors the inline logic in computeRedirectUri,
  // #724): the Base URL Override when set, else this server's address, normalized the way the server's
  // CanonicalBaseUrl (System.Uri.GetLeftPart) is: origin lowercases scheme+host and elides the default
  // port, pathname keeps any sub-path, and the trailing slash is trimmed. When the override is blank the
  // shown URL reflects the browser's server address; the scheme/port overrides are a legacy mechanism the
  // Base URL Override supersedes (its callout steers the admin there).
  samlCanonicalBase: (page) => {
    const override = page.querySelector("#saml-BaseUrlOverride").value.trim();
    const raw = override || ApiClient.serverAddress() || "";
    try {
      const u = new URL(raw);
      return u.origin + u.pathname.replace(/\/+$/, "");
    } catch (e) {
      return raw.replace(/\/+$/, "");
    }
  },
  // Live-update the read-only ACS + SP-metadata URLs (#725/#569). The IdP POSTs to the new-path ACS
  // spelling the SP metadata advertises at index 0 (SamlAcsUrlBuilder.AcsUrl newPath=true => "post"); the
  // metadata document is served at /sso/SAML/metadata/<provider>. The provider name is appended raw, as the
  // server does (names exclude URI-reserved characters, #336). Sets .value only, never innerHTML (#221).
  updateSamlUrls: (page) => {
    const acs = page.querySelector("#saml-AcsUrl");
    const metadata = page.querySelector("#saml-MetadataUrl");
    const name = page.querySelector("#saml-provider-name").value.trim();
    const base = ssoConfigurationPage.samlCanonicalBase(page);

    if (acs) {
      acs.value = name ? base + "/sso/SAML/post/" + name : "";
      acs.placeholder = name
        ? ""
        : "Enter a provider name above to see the ACS URL";
    }
    if (metadata) {
      metadata.value = name ? base + "/sso/SAML/metadata/" + name : "";
      metadata.placeholder = name
        ? ""
        : "Enter a provider name above to see the metadata URL";
    }
    const status = page.querySelector("#saml-url-copied");
    if (status) {
      status.textContent = "";
    }
    ssoConfigurationPage.refreshReadiness(page, "saml");
  },
  // Copy a read-only computed SAML URL to the clipboard, with the same secure-context/execCommand fallback
  // and inert status announcement as copyRedirectUri (#724). fieldId/label identify which URL was copied.
  copySamlUrl: (page, fieldId, label) => {
    const field = page.querySelector("#" + fieldId);
    const status = page.querySelector("#saml-url-copied");
    const value = field && field.value;
    if (!value) {
      return;
    }
    const announce = (message) => {
      if (status) {
        status.textContent = message;
      }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(
        () => announce(label + " copied to the clipboard."),
        () => announce("Copy failed. Select the field and copy it manually."),
      );
      return;
    }
    field.removeAttribute("readonly");
    field.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) {
      ok = false;
    }
    field.setAttribute("readonly", "");
    announce(
      ok
        ? label + " copied to the clipboard."
        : "Copy failed. Select the field and copy it manually.",
    );
  },
  // Import IdP metadata (#735) from a URL (fetched server-side through the SSRF-hardened outbound client) or
  // pasted XML, and pre-fill the endpoint + signing certificate(s) for the admin to review and save. The
  // server returns the parsed values; NOTHING is applied server-side by this call. The IdP EntityId is
  // shown for reference only: it is NOT the SP SamlClientId, which the admin chooses.
  importSamlMetadata: (page, source) => {
    const status = page.querySelector("#saml-metadata-status");
    const url =
      source === "url"
        ? page.querySelector("#saml-metadata-url").value.trim()
        : "";
    const xml =
      source === "xml"
        ? page.querySelector("#saml-metadata-xml").value.trim()
        : "";
    if (!url && !xml) {
      ssoConfigurationPage.renderTransferMessage(
        status,
        source === "url"
          ? "Enter a metadata URL first."
          : "Paste the metadata XML first.",
      );
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTransferMessage(status, "Importing metadata…");
    return ApiClient.fetch({
      type: "POST",
      url: ApiClient.getUrl("sso/SAML/ImportMetadata"),
      data: JSON.stringify({ Url: url || null, Xml: xml || null }),
      contentType: "application/json",
      dataType: "json",
    }).then(
      (result) => {
        if (result && result.Endpoint) {
          page.querySelector("#saml-SamlEndpoint").value = result.Endpoint;
        }
        if (result && result.PrimaryCertificate) {
          page.querySelector("#saml-SamlCertificate").value =
            result.PrimaryCertificate;
        }
        if (result && result.SecondaryCertificate) {
          page.querySelector("#saml-SamlSecondaryCertificate").value =
            result.SecondaryCertificate;
        }
        // The endpoint/certificate are now filled; re-run their on-blur validation so a bad imported value
        // surfaces immediately rather than only on the next focus change.
        ssoConfigurationPage.validateSamlEndpoint(page);
        ssoConfigurationPage.validateSamlCertificate(
          page,
          "saml-SamlCertificate",
          "IdP Signing Certificate",
        );
        // EntityId is reference-only: shown as inert text, never written into a field.
        const entity = result && result.EntityId ? result.EntityId : "";
        ssoConfigurationPage.renderTransferMessage(
          status,
          entity
            ? "Imported the endpoint and certificate. The provider's entity id is " +
                entity +
                " (reference only; set the SAML Client ID yourself). Review the fields and Save."
            : "Imported the endpoint and certificate. Review the fields and Save.",
        );
      },
      () =>
        ssoConfigurationPage.renderTransferMessage(
          status,
          "Could not import the metadata. Check the URL or XML, make sure you are signed in as an administrator, and that the address is reachable and not a private/loopback host.",
        ),
    );
  },
  clearSamlValidationErrors: (page) => {
    [
      "saml-provider-name",
      "saml-SamlEndpoint",
      "saml-SamlClientId",
      "saml-SamlCertificate",
      "saml-SamlSecondaryCertificate",
      "saml-BaseUrlOverride",
    ].forEach((id) => ssoConfigurationPage.setFieldError(page, id, ""));
  },
  renderSamlSaveStatus: (page, message, ok) => {
    const box = page.querySelector("#saml-save-status");
    if (!box) {
      return;
    }
    box.textContent = message || "";
    box.classList.remove("sso-status-ok", "sso-status-fail");
    if (message) {
      box.classList.add(ok ? "sso-status-ok" : "sso-status-fail");
    }
  },
  // Mirror the server's fail-closed provider-name checks (#336/#360) before the round-trip, keeping the
  // source ASCII-only (control chars detected by code point, not a regex escape) as validateProviderName does.
  validateSamlProviderName: (page) => {
    const value = page.querySelector("#saml-provider-name").value;
    if (!value.trim()) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-provider-name",
        "A provider name is required.",
      );
      return;
    }
    const hasControlChar = [...value].some((ch) => {
      const code = ch.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    });
    if (hasControlChar) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-provider-name",
        "Remove control characters (such as a tab or newline, often introduced by copy-paste) from the name.",
      );
      return;
    }
    const reserved = ["\\", "/", "?", "#", "%"];
    if (reserved.some((c) => value.includes(c))) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-provider-name",
        "Remove backslash and URI-reserved characters (\\ / ? # %) from the name.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "saml-provider-name", "");
  },
  validateSamlRequired: (page, id, label) => {
    const value = page.querySelector("#" + id).value.trim();
    ssoConfigurationPage.setFieldError(
      page,
      id,
      value ? "" : label + " is required.",
    );
  },
  validateSamlEndpoint: (page) => {
    const value = page.querySelector("#saml-SamlEndpoint").value.trim();
    if (!value) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-SamlEndpoint",
        "SAML SSO Endpoint is required.",
      );
      return;
    }
    let url;
    try {
      url = new URL(value);
    } catch (e) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-SamlEndpoint",
        "Enter an absolute URL, e.g. https://idp.example.com/sso",
      );
      return;
    }
    if (url.protocol === "http:") {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-SamlEndpoint",
        "Uses http://, so the redirect would be unencrypted. Prefer an https:// endpoint.",
      );
      return;
    }
    if (url.protocol !== "https:") {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-SamlEndpoint",
        "Use an https:// URL for the SAML endpoint.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "saml-SamlEndpoint", "");
  },
  validateSamlBaseUrl: (page) => {
    const value = page.querySelector("#saml-BaseUrlOverride").value.trim();
    if (!value) {
      ssoConfigurationPage.setFieldError(page, "saml-BaseUrlOverride", "");
      return;
    }
    let url;
    try {
      url = new URL(value);
    } catch (e) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-BaseUrlOverride",
        "Enter a full origin such as https://jellyfin.example.com (scheme + host only).",
      );
      return;
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-BaseUrlOverride",
        "Enter a full origin such as https://jellyfin.example.com",
      );
      return;
    }
    if ((url.pathname && url.pathname !== "/") || url.search || url.hash) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-BaseUrlOverride",
        "Enter the base URL only (no path), e.g. https://jellyfin.example.com, not the /sso/... ACS URL.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "saml-BaseUrlOverride", "");
  },
  // Pre-emptive certificate shape check (WARNING only, never blocks the save; the server stays the
  // authority, so a false positive cannot lock an admin out). Accepts an empty optional field, a PEM block,
  // or a bare Base64 body; only an obviously malformed value (non-Base64 characters once PEM armor and
  // whitespace are stripped) is flagged. label/id let it serve both the primary and secondary certificate.
  validateSamlCertificate: (page, id, label) => {
    const raw = page.querySelector("#" + id).value.trim();
    if (!raw) {
      // Optional (the secondary) or required-checked elsewhere (the primary): an empty value is not a
      // SHAPE error here; requiredness for the primary is enforced by the server on save.
      ssoConfigurationPage.setFieldError(page, id, "");
      return;
    }
    const body = raw
      .replace(/-----BEGIN CERTIFICATE-----/g, "")
      .replace(/-----END CERTIFICATE-----/g, "")
      .replace(/\s+/g, "");
    if (!body || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) {
      ssoConfigurationPage.setFieldError(
        page,
        id,
        label +
          " is not valid Base64. Paste the certificate body (the text between the PEM BEGIN/END lines) or the whole PEM block.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, id, "");
  },
  deleteSamlProvider: (page, provider_name) => {
    if (
      !window.confirm(
        `Are you sure you want to delete the provider ${provider_name}?`,
      )
    ) {
      return;
    }
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        if (
          !config.SamlConfigs ||
          !config.SamlConfigs.hasOwnProperty(provider_name)
        ) {
          return;
        }

        delete config.SamlConfigs[provider_name];
        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(
          function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            ssoConfigurationPage.loadConfiguration(page);
            ssoConfigurationPage.hideSamlEditor(page);
            Dashboard.alert("Provider removed");
          },
          function () {
            Dashboard.alert({
              title: "Delete failed",
              message:
                "Could not remove the provider. The saved configuration was rejected by the server; reload the page and try again.",
            });
          },
        );
      },
    );
  },
  saveSamlProvider: (page, provider_name) => {
    return new Promise((resolve, reject) => {
      const form_elements = ssoConfigurationPage.listSamlArgumentsByType(page);

      ApiClient.getPluginConfiguration(
        ssoConfigurationPage.pluginUniqueId,
      ).then((config) => {
        if (!config.SamlConfigs) {
          config.SamlConfigs = {};
        }
        let current_config = {};
        if (config.SamlConfigs.hasOwnProperty(provider_name)) {
          current_config = config.SamlConfigs[provider_name];
        }

        form_elements.text_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          current_config[prop] = page.querySelector("#" + id).value || null;
        });

        form_elements.check_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          current_config[prop] = page.querySelector("#" + id).checked;
        });

        form_elements.text_list_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          current_config[prop] = ssoConfigurationPage.parseTextList(
            page.querySelector("#" + id),
          );
        });

        form_elements.folder_list_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          const elem = page.querySelector("#" + id);
          current_config[prop] =
            ssoConfigurationPage.serializeEnabledFolders(elem);
        });

        form_elements.role_map_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          const elem = page.querySelector("#" + id);
          current_config[prop] =
            ssoConfigurationPage.serializeRoleMappings(elem);
        });

        // Same rule as the OpenID arm above.
        if (!current_config.ProvisioningProfile) {
          current_config.ProvisioningPolicyTemplate =
            ssoConfigurationPage.readProvisioningTemplate(page, "saml-");
        }

        config.SamlConfigs[provider_name] = current_config;

        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(
          function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            ssoConfigurationPage.loadConfiguration(page);
            ssoConfigurationPage.loadSamlProvider(page, provider_name);

            page.querySelector("#saml-selectProvider").value = provider_name;
            Dashboard.alert("Settings saved.");
            resolve();
          },
          function () {
            Dashboard.alert({
              title: "Save failed",
              message:
                "Could not save the provider. Check that the provider name has no control characters (such as a tab or newline, often introduced by copy-paste), no backslash, and none of the URI-reserved characters such as / ? # %, and that the Base URL Override is a full URL such as https://jellyfin.example.com (or blank).",
            });
            reject(new Error("Provider save failed"));
          },
        );
      });
    });
  },
  // Test-connection for a SAVED SAML provider (#163). Calls the elevation-gated SAML/Test endpoint, which
  // parses the stored IdP signing certificate server-side and returns only its non-secret facts (never the
  // SP signing key). Reuses the OpenID renderTestResult/renderTestMessage (same Ok/Message/Details shape).
  testSamlProvider: (page, provider_name) => {
    const container = page.querySelector("#saml-TestResult");
    if (!provider_name) {
      ssoConfigurationPage.renderTestMessage(
        container,
        "Enter a provider name and save it first, then test.",
      );
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTestMessage(container, "Testing…");

    return ApiClient.getJSON(
      ApiClient.getUrl("sso/SAML/Test/" + encodeURIComponent(provider_name)),
    ).then(
      (result) => {
        ssoConfigurationPage.renderTestResult(container, result);
        ssoConfigurationPage.recordTestOutcome(
          page,
          "saml",
          Boolean(result && result.Ok),
        );
      },
      () => {
        ssoConfigurationPage.renderTestMessage(
          container,
          "Could not run the test. Make sure the provider is saved and that you are signed in as an administrator, then try again.",
        );
        ssoConfigurationPage.recordTestOutcome(page, "saml", false);
      },
    );
  },
};

export default function initSsoConfigurationPage(view) {
  ssoConfigurationPage.addTextAreaStyle(view);
  ssoConfigurationPage.loadConfiguration(view);
  ssoConfigurationPage.localize(view);

  view.querySelector("#SaveProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#OidProviderName").value;

    // The save alerts the admin on failure via Dashboard.alert; also surface the outcome inline in the
    // editor header. Handling the rejection here keeps a failed save from becoming an unhandled promise
    // rejection (the rejection still exists so callers can distinguish failure from success).
    ssoConfigurationPage.saveProvider(view, target_provider).then(
      () => {
        ssoConfigurationPage.renderSaveStatus(view, "Settings saved.", true);
        ssoConfigurationPage.setEditorTitle(view, target_provider);
      },
      () =>
        ssoConfigurationPage.renderSaveStatus(
          view,
          "Save failed. See the details in the alert.",
          false,
        ),
    );

    e.preventDefault();
    return false;
  });

  view.querySelector("#TestProvider").addEventListener("click", (e) => {
    // Test the provider named in the editor (the one just saved), not a load selector.
    const target_provider = view.querySelector("#OidProviderName").value;

    ssoConfigurationPage.testProvider(view, target_provider);

    e.preventDefault();
    return false;
  });

  // The provider LIST replaces the old select -> Load button: a click on a card loads that provider into
  // the editor. Event delegation, because the cards are re-rendered on every configuration reload.
  view.querySelector("#sso-provider-list").addEventListener("click", (e) => {
    const card = e.target.closest(".sso-provider-card");
    if (!card) {
      return;
    }
    ssoConfigurationPage.openProvider(view, card.dataset.provider);
  });

  view.querySelector("#AddProvider").addEventListener("click", (e) => {
    ssoConfigurationPage.addProvider(view);
    e.preventDefault();
    return false;
  });

  view.querySelector("#AddProviderEmpty").addEventListener("click", (e) => {
    ssoConfigurationPage.addProvider(view);
    e.preventDefault();
    return false;
  });

  view.querySelector("#DeleteProvider").addEventListener("click", (e) => {
    // Delete the provider currently loaded in the editor (its name is the editor's name field).
    const target_provider = view.querySelector("#OidProviderName").value;

    if (target_provider) {
      ssoConfigurationPage.deleteProvider(view, target_provider);
    } else {
      // A never-saved new provider: nothing to delete server-side, just discard the editor.
      ssoConfigurationPage.hideEditor(view);
    }

    e.preventDefault();
    return false;
  });

  view.querySelector("#AddRoleMapping").addEventListener("click", (e) => {
    const container = view.querySelector("#FolderRoleMapping");
    const current_mappings =
      ssoConfigurationPage.serializeRoleMappings(container);
    current_mappings.push({ Role: "", Folders: [] });
    ssoConfigurationPage.populateRoleMappings(current_mappings, container);
  });

  view.querySelector("#Tmpl-Permissions-add").addEventListener("click", (e) => {
    ssoConfigurationPage.addTemplatePermissionRow(view, "");
    e.preventDefault();
    return false;
  });

  // The insecure-options expander keeps the dangerous toggles in the DOM (hidden), never detached, so they
  // still serialize; it only flips the `hidden` attribute and the aria-expanded state.
  view.querySelector("#ShowInsecureOptions").addEventListener("click", (e) => {
    const collapsed = view.querySelector("#sso-insecure-options").hidden;
    ssoConfigurationPage.setInsecureOptionsExpanded(view, collapsed);
    e.preventDefault();
    return false;
  });

  // Reveal-on-toggle dependent groups react to their controlling checkbox. syncDependentFields only toggles
  // visibility (hide-not-remove) and never mutates a value, so nothing can be dropped from a later save.
  ["EnableAllFolders", "EnableFolderRoles", "EnableLiveTvRoles"].forEach(
    (id) => {
      view
        .querySelector("#" + id)
        .addEventListener("change", () =>
          ssoConfigurationPage.syncDependentFields(view),
        );
    },
  );

  // On-blur inline validation (not per-keystroke) pre-empts the generic round-trip save error.
  view
    .querySelector("#OidProviderName")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateProviderName(view),
    );
  view
    .querySelector("#OidEndpoint")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateEndpoint(view),
    );
  view
    .querySelector("#OidClientId")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateRequired(
        view,
        "OidClientId",
        "OpenID Client ID",
      ),
    );
  view
    .querySelector("#RoleClaim")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateRequired(view, "RoleClaim", "Role Claim"),
    );
  view
    .querySelector("#OidScopes")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateRequired(
        view,
        "OidScopes",
        "Additional Scopes",
      ),
    );
  view
    .querySelector("#BaseUrlOverride")
    .addEventListener("blur", () => ssoConfigurationPage.validateBaseUrl(view));

  // Live-update the computed redirect URI (#724) as the provider name or the base-URL override changes, so
  // the value shown always matches what the login will send. `input` (per-keystroke) not `blur`, since the
  // field is purely informational: reflecting immediately is the point.
  ["OidProviderName", "BaseUrlOverride"].forEach((id) => {
    view
      .querySelector("#" + id)
      .addEventListener("input", () =>
        ssoConfigurationPage.updateRedirectUri(view),
      );
  });

  view.querySelector("#CopyRedirectUri").addEventListener("click", (e) => {
    ssoConfigurationPage.copyRedirectUri(view);
    e.preventDefault();
    return false;
  });

  // Populate the redirect URI once at init (the blank editor shows its placeholder until a name is typed).
  ssoConfigurationPage.updateRedirectUri(view);

  view.querySelector("#SaveLoginButtons").addEventListener("click", (e) => {
    ssoConfigurationPage.saveLoginButtons(view);
    e.preventDefault();
    return false;
  });

  view.querySelector("#SaveSingleLogout").addEventListener("click", (e) => {
    ssoConfigurationPage.saveSingleLogout(view);
    e.preventDefault();
    return false;
  });

  // The aggregate configuration check (#1084). Read-only: it fetches a report and paints its own list.
  view.querySelector("#CheckAllProviders").addEventListener("click", (e) => {
    ssoConfigurationPage.checkAllProviders(view);
    e.preventDefault();
    return false;
  });

  view.querySelector("#ExportConfig").addEventListener("click", (e) => {
    ssoConfigurationPage.exportConfig(view);
    e.preventDefault();
    return false;
  });

  // The visible Import button drives the hidden file input; selecting a file runs the import.
  view.querySelector("#ImportConfig").addEventListener("click", (e) => {
    view.querySelector("#ImportConfigFile").click();
    e.preventDefault();
    return false;
  });

  view.querySelector("#ImportConfigFile").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    // Clear the input so choosing the same file again re-triggers change.
    e.target.value = "";
    ssoConfigurationPage.importConfig(view, file);
  });

  // Account-link transfer (#1131): the exact parallel of the configuration pair above, against its own
  // endpoints and its own status region, so one file's outcome never overwrites the other's.
  view.querySelector("#ExportLinks").addEventListener("click", (e) => {
    ssoConfigurationPage.exportLinks(view);
    e.preventDefault();
    return false;
  });

  view.querySelector("#ImportLinks").addEventListener("click", (e) => {
    view.querySelector("#ImportLinksFile").click();
    e.preventDefault();
    return false;
  });

  view.querySelector("#ImportLinksFile").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    // Clear the input so choosing the same file again re-triggers change.
    e.target.value = "";
    ssoConfigurationPage.importLinks(view, file);
  });

  // The linked-accounts panel (#1121). Read-only on arrival: the roster is fetched once when the page
  // initialises, so an administrator sees who is linked without pressing anything, and the button re-reads
  // it. The revoke is bound per row in renderLinkedAccountRow, because the row is what carries the username.
  view
    .querySelector("#RefreshLinkedAccounts")
    .addEventListener("click", (e) => {
      ssoConfigurationPage.loadLinkedAccounts(view);
      e.preventDefault();
      return false;
    });

  ssoConfigurationPage.loadLinkedAccounts(view);

  view.querySelector("#sso-self-service-link").href =
    ApiClient.getUrl("/SSOViews/linking");

  // ---- SAML workspace bindings (#725): the exact parallel of the OpenID bindings above ----
  view.querySelector("#saml-SaveProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#saml-provider-name").value;

    ssoConfigurationPage.saveSamlProvider(view, target_provider).then(
      () => {
        ssoConfigurationPage.renderSamlSaveStatus(
          view,
          "Settings saved.",
          true,
        );
        ssoConfigurationPage.setSamlEditorTitle(view, target_provider);
      },
      () =>
        ssoConfigurationPage.renderSamlSaveStatus(
          view,
          "Save failed. See the details in the alert.",
          false,
        ),
    );

    e.preventDefault();
    return false;
  });

  view.querySelector("#saml-TestProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#saml-provider-name").value;
    ssoConfigurationPage.testSamlProvider(view, target_provider);
    e.preventDefault();
    return false;
  });

  view.querySelector("#saml-provider-list").addEventListener("click", (e) => {
    const card = e.target.closest(".sso-provider-card");
    if (!card) {
      return;
    }
    ssoConfigurationPage.openSamlProvider(view, card.dataset.provider);
  });

  view.querySelector("#saml-AddProvider").addEventListener("click", (e) => {
    ssoConfigurationPage.addSamlProvider(view);
    e.preventDefault();
    return false;
  });

  view
    .querySelector("#saml-AddProviderEmpty")
    .addEventListener("click", (e) => {
      ssoConfigurationPage.addSamlProvider(view);
      e.preventDefault();
      return false;
    });

  view.querySelector("#saml-DeleteProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#saml-provider-name").value;
    if (target_provider) {
      ssoConfigurationPage.deleteSamlProvider(view, target_provider);
    } else {
      ssoConfigurationPage.hideSamlEditor(view);
    }
    e.preventDefault();
    return false;
  });

  view.querySelector("#saml-AddRoleMapping").addEventListener("click", (e) => {
    const container = view.querySelector("#saml-FolderRoleMapping");
    const current_mappings =
      ssoConfigurationPage.serializeRoleMappings(container);
    current_mappings.push({ Role: "", Folders: [] });
    ssoConfigurationPage.populateRoleMappings(current_mappings, container);
    e.preventDefault();
    return false;
  });

  view
    .querySelector("#saml-Tmpl-Permissions-add")
    .addEventListener("click", (e) => {
      ssoConfigurationPage.addTemplatePermissionRow(view, "saml-");
      e.preventDefault();
      return false;
    });

  view
    .querySelector("#saml-ShowInsecureOptions")
    .addEventListener("click", (e) => {
      const collapsed = view.querySelector("#saml-insecure-options").hidden;
      ssoConfigurationPage.setSamlInsecureOptionsExpanded(view, collapsed);
      e.preventDefault();
      return false;
    });

  [
    "saml-EnableAllFolders",
    "saml-EnableFolderRoles",
    "saml-EnableLiveTvRoles",
  ].forEach((id) => {
    view
      .querySelector("#" + id)
      .addEventListener("change", () =>
        ssoConfigurationPage.syncSamlDependentFields(view),
      );
  });

  view
    .querySelector("#saml-provider-name")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlProviderName(view),
    );
  view
    .querySelector("#saml-SamlEndpoint")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlEndpoint(view),
    );
  view
    .querySelector("#saml-SamlClientId")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlRequired(
        view,
        "saml-SamlClientId",
        "SAML Client ID",
      ),
    );
  view
    .querySelector("#saml-SamlCertificate")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlCertificate(
        view,
        "saml-SamlCertificate",
        "IdP Signing Certificate",
      ),
    );
  view
    .querySelector("#saml-SamlSecondaryCertificate")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlCertificate(
        view,
        "saml-SamlSecondaryCertificate",
        "Secondary IdP Signing Certificate",
      ),
    );
  view
    .querySelector("#saml-BaseUrlOverride")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlBaseUrl(view),
    );

  // Live-update the computed ACS + SP-metadata URLs as the provider name or base-URL override changes.
  ["saml-provider-name", "saml-BaseUrlOverride"].forEach((id) => {
    view
      .querySelector("#" + id)
      .addEventListener("input", () =>
        ssoConfigurationPage.updateSamlUrls(view),
      );
  });

  view.querySelector("#saml-CopyAcsUrl").addEventListener("click", (e) => {
    ssoConfigurationPage.copySamlUrl(view, "saml-AcsUrl", "ACS URL");
    e.preventDefault();
    return false;
  });
  view.querySelector("#saml-CopyMetadataUrl").addEventListener("click", (e) => {
    ssoConfigurationPage.copySamlUrl(view, "saml-MetadataUrl", "Metadata URL");
    e.preventDefault();
    return false;
  });

  view
    .querySelector("#saml-ImportMetadataUrl")
    .addEventListener("click", (e) => {
      ssoConfigurationPage.importSamlMetadata(view, "url");
      e.preventDefault();
      return false;
    });
  view
    .querySelector("#saml-ImportMetadataXml")
    .addEventListener("click", (e) => {
      ssoConfigurationPage.importSamlMetadata(view, "xml");
      e.preventDefault();
      return false;
    });

  // Populate the computed URLs once at init (blank editor shows the placeholders until a name is typed).
  ssoConfigurationPage.updateSamlUrls(view);

  // ---- Readiness panel (#1083) ----
  // Advisory and read-only: these handlers re-read the form and rebuild the panel. They set no value,
  // check no box, and issue no request, so nothing here can change what a Save would send.
  [
    ["#sso-editor", "oid"],
    ["#saml-editor", "saml"],
  ].forEach(([selector, key]) => {
    const editor = view.querySelector(selector);
    if (!editor) {
      return;
    }
    ["input", "change"].forEach((type) =>
      editor.addEventListener(type, () =>
        ssoConfigurationPage.refreshReadiness(view, key),
      ),
    );
    ssoConfigurationPage.refreshReadiness(view, key);
  });

  // ---- Provider template pickers (#726) ----
  ssoConfigurationPage.populatePresetPicker(view, "OidPreset", OIDC_PRESETS);
  ssoConfigurationPage.populatePresetPicker(view, "saml-Preset", SAML_PRESETS);
  view.querySelector("#OidPreset").addEventListener("change", (e) => {
    ssoConfigurationPage.applyOidcPreset(view, e.target.value);
  });
  view.querySelector("#saml-Preset").addEventListener("change", (e) => {
    ssoConfigurationPage.applySamlPreset(view, e.target.value);
  });
}
