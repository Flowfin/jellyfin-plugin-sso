// The shared localization module (#913), set once localize() resolves; until then tr() returns the
// caller's English default.
let i18n = null;

// Localized text for a catalog key, falling back to the English default the call site carries.
// The fallback fills placeholders too, so a page without the catalog never shows raw braces (#1529).
// The substitution is inlined because this is the branch where the i18n module is absent.
function tr(key, englishDefault, params) {
  if (i18n) {
    return i18n.t(key, params, englishDefault);
  }

  if (!params) {
    return englishDefault;
  }

  return String(englishDefault).replace(/\{(\w+)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(params, name) ? params[name] : match,
  );
}

// What the tracked controls of each page held when last marked clean (#1572), keyed on the page element.
// markPageClean is the only writer; weak so a discarded view takes its entry with it.
const pageBaselines = new WeakMap();

// Creates a customized built-in element in a way both the 10.11 and the Jellyfin 12 client accept (#1607).
// The Jellyfin 12 client throws on the options form, so the plain form is the fallback and callers set `is`.
function customizedBuiltIn(tag, is) {
  try {
    return document.createElement(tag, { is });
  } catch {
    return document.createElement(tag);
  }
}

// Settles a promise without acting on it, for loads that wait on a request whose failure they ignore.
const noop = () => {};

// The Jellyfin account routing a revoke restores (#1121). The server persists whatever is sent, so a wrong
// value routes the account to a provider that refuses every password; a test pins it to the server (#837).
const DEFAULT_PASSWORD_PROVIDER_ID =
  "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";

// Provider templates (#726) for the "Start from a template" pickers, as plain data.
// A preset writes only into marked fields by id (SAML ids carry a "saml-" prefix), never fills a secret,
// and pre-checks only known compatibility toggles; conformance tests lock these rules in.
// Values are placeholders with UPPERCASE tokens to replace. OidScopes lists only the scopes beyond the
// "openid profile" the server always adds. Every OpenID preset sets the same four fields, so switching
// templates leaves no stale value.
const OIDC_PRESETS = {
  keycloak: {
    label: "Keycloak",
    noteKey: "config.preset_note_keycloak",
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
    noteKey: "config.preset_note_authelia",
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
    noteKey: "config.preset_note_authentik",
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
    noteKey: "config.preset_note_zitadel",
    note: "Zitadel project application. Its roles arrive as an OBJECT whose keys are the role names, so 'Roles as object map' is pre-checked; without it no role can ever match. The project must have 'Assert Roles on Authentication' on, and the application 'User roles inside ID Token', or the role claim is absent entirely. Replace YOUR_INSTANCE in the endpoint.",
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
    noteKey: "config.preset_note_entra",
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
    noteKey: "config.preset_note_google",
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
    noteKey: "config.preset_note_auth0",
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
    noteKey: "config.preset_note_okta",
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
    noteKey: "config.preset_note_gitlab",
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
    labelKey: "config.preset_label_generic_oidc",
    label: "Generic OpenID Connect",
    noteKey: "config.preset_note_generic_oidc",
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
    labelKey: "config.preset_label_generic_saml",
    label: "Generic SAML 2.0",
    noteKey: "config.preset_note_generic_saml",
    note: "A generic SAML 2.0 identity provider. Use the metadata import below to fill the SSO endpoint and signing certificate from your IdP's metadata, then set the SAML Client ID (this service provider's entity id) and review before saving.",
    fields: {
      SamlEndpoint: "https://idp.example.com/sso/saml",
    },
    toggles: [],
  },
};

// The compatibility toggles a preset may pre-check, also cleared before a preset is applied.
// Hardening toggles are never pre-checked, because turning them on could lock out an IdP that is not ready.
const OIDC_PRESET_MANAGED_TOGGLES = [
  "DisablePushedAuthorization",
  "DoNotValidateEndpoints",
  "DoNotValidateIssuerName",
  "DoNotValidateResponseIssuer",
  "DisableHttps",
  "DoNotLoadProfile",
  // Not an insecure toggle but the shape of the RoleClaim terminal (#934). Clearing it on every preset
  // switch avoids extracting zero roles from an array-shaped claim; an object-map preset re-checks it.
  "RoleClaimIsObjectMap",
];
const SAML_PRESET_MANAGED_TOGGLES = ["DoNotValidateAudience"];

// The one list the readiness panel writes into (#1664), shared by both protocol specs.
const RAIL_READINESS_LIST = "sso-rail-readiness-list";

const ssoConfigurationPage = {
  pluginUniqueId: "505ce9d1-d916-42fa-86ca-673ef241d7df",
  // Toggles that disable an OpenID Connect defense; loading a provider with one active expands the insecure
  // options and their accordion.
  insecureFieldIds: [
    "DisableHttps",
    "DisablePushedAuthorization",
    "DoNotValidateEndpoints",
    "DoNotValidateIssuerName",
    "DoNotValidateResponseIssuer",
    "AllowPrivateNetworkAddresses",
  ],
  // Settings whose enabled state widens the attack surface, surfaced like the insecure toggles.
  // AllowExistingAccountLink lets a first SSO login adopt a same-named local account. Hardening toggles are
  // excluded because enabling them makes a provider more secure.
  sensitiveFieldIds: ["AllowExistingAccountLink"],
  // Which providers a declarative source owns, as the server reports them (#1104, #1102), held as a promise
  // so an editor opened early waits for it. Advisory only: the server guards managed providers itself.
  // A failed read keeps the last set read rather than emptying it (#1589), and managedReportUnread lets both
  // editors say the report could not be read.
  managedProviders: {
    OidConfigs: [],
    SamlConfigs: [],
    ProvisioningProfiles: [],
  },
  managedProvidersLoaded: null,
  // Whether the last managed-set read to settle failed, so the editors can tell "nothing owns this" apart
  // from "this page could not find out". It never decides the freeze; the set does.
  managedReportUnread: false,
  // The note an unfrozen editor carries while the managed report is unread.
  // It names closing the editor and reloading, because returning to the tab with an editor open issues no
  // read. Suppressed on the blank add-new editor at the call sites.
  unreadReportNote: () =>
    tr(
      "config.managed_report_unread_note",
      "Which providers and profiles a configuration file sets could not be read, so this form is editable without confirming that nothing sets it. Close any open editor and return to this tab, or reload the dashboard, to try again. If a configuration file does set it, a save made here would keep the stored value and leave a record in the log.",
    ),
  // The note an editor carries while the report is unread: the residual for an unfrozen editor, and for a
  // frozen one or a refusal the caveat that the freeze rests on the last answer read. Empty for a nameless
  // add-new form and while the report reads fine.
  unreadNoteFor: (name) =>
    name && ssoConfigurationPage.managedReportUnread
      ? ssoConfigurationPage.unreadReportNote()
      : "",
  staleReportSuffix: () =>
    ssoConfigurationPage.managedReportUnread
      ? " " +
        tr(
          "config.managed_report_stale_suffix",
          "This is the last answer the server gave: the most recent attempt to re-read it failed, so it may be out of date. Close any open editor and return to this tab, or reload the dashboard, to try again.",
        )
      : "",
  loadManagedProviders: () => {
    ssoConfigurationPage.managedProvidersLoaded = ApiClient.getJSON(
      ApiClient.getUrl("sso/Config/Managed"),
    ).then(
      (report) => {
        // Keeps each member null until it is seen to be a list, so an empty report and a non-report differ (#1597).
        const listOrNothing = (member) =>
          Array.isArray(member) ? member : null;
        const oid = listOrNothing(report && report.OidConfigs);
        const saml = listOrNothing(report && report.SamlConfigs);
        const profiles = listOrNothing(report && report.ProvisioningProfiles);

        if (oid === null && saml === null && profiles === null) {
          // A 200 carrying none of the three members is not the report; reading it as "nothing managed" would fail
          // open (#1589).
          ssoConfigurationPage.managedReportUnread = true;
          return;
        }

        ssoConfigurationPage.managedProviders = {
          OidConfigs: oid || [],
          SamlConfigs: saml || [],
          ProvisioningProfiles: profiles || [],
        };
        ssoConfigurationPage.managedReportUnread = false;
      },
      () => {
        // The set is left alone: emptying it fails open (#1589), filling it locks out.
        ssoConfigurationPage.managedReportUnread = true;
      },
    );
    return ssoConfigurationPage.managedProvidersLoaded;
  },
  // Whether a provider is declaratively managed. The unit is the whole provider, because the declarative
  // merge replaces a named provider whole.
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
  // Whether a declarative source defined this profile (#1498); a save to it keeps the stored value.
  isManagedProfile: (name) => {
    const names = ssoConfigurationPage.managedProviders.ProvisioningProfiles;
    return Boolean(name) && Array.isArray(names) && names.indexOf(name) !== -1;
  },
  // The acts a managed profile freezes beside its policy fields; Add and the selector stay usable.
  managedProfileActs: [
    "RenameProvisioningProfile",
    "DeleteProvisioningProfile",
    "SaveProvisioningProfile",
  ],
  // Renders the profile editor as managed or ordinary, after the fill that creates the permission rows.
  applyManagedProfileState: (page, name) => {
    const pending =
      ssoConfigurationPage.managedProvidersLoaded || Promise.resolve();
    return pending.then(() => {
      // The editor may have moved on while the report was in flight; the selector is what a save reads.
      const selector = page.querySelector("#selectProvisioningProfile");
      if (selector && selector.value !== name) {
        return;
      }

      const managed = ssoConfigurationPage.isManagedProfile(name);
      const controls = ssoConfigurationPage.templateControls(page, "profile-");
      [
        ...controls.numbers,
        ...controls.texts,
        ...controls.bools,
        ...controls.lists,
        ...controls.permissions.querySelectorAll("input, select, button"),
        ...page.querySelectorAll("#profile-Tmpl-Permissions-add"),
        ...ssoConfigurationPage.managedProfileActs.map((id) =>
          page.querySelector("#" + id),
        ),
      ].forEach((element) => {
        if (element) {
          element.disabled = managed;
          // Records why the control is frozen, for the Save gate to read (#1572).
          element.dataset.ssoManaged = managed ? "true" : "";
        }
      });

      // Re-asserts the Save gate, since the freeze may run after it and overwrite `disabled` (#1572).
      ssoConfigurationPage.updateSaveAvailability(page);

      const note = page.querySelector("#profile-managed-note");
      if (note) {
        // Set as text only (#221).
        note.textContent = managed
          ? tr(
              "config.managed_profile_note",
              "This profile is defined by a configuration file or by environment variables, so it cannot be edited, renamed or deleted here. Change it at that source and restart Jellyfin. A save made here would keep the stored value and leave a record in the log.",
            ) + ssoConfigurationPage.staleReportSuffix()
          : ssoConfigurationPage.unreadNoteFor(name);
        note.hidden = note.textContent === "";
      }
    });
  },
  // Controls that stay usable on a managed provider: they read and never write a provider field.
  managedReadOnlyActions: [
    "TestProvider",
    "CopyRedirectUri",
    "saml-TestProvider",
    "saml-CopyAcsUrl",
    "saml-CopyMetadataUrl",
  ],
  // Renders the open editor as managed or ordinary, after the load that creates the widget controls.
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
      // The editor may have moved on while the report was in flight; the selector is what a save reads.
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
          // Records why the control is frozen, for the Save gate to read (#1572).
          element.dataset.ssoManaged = managed ? "true" : "";
        });

      // Re-asserts the Save gate, since the freeze may run after it and overwrite `disabled` (#1572).
      ssoConfigurationPage.updateSaveAvailability(page);

      if (note) {
        // textContent, never innerHTML (#221).
        note.textContent = managed
          ? tr(
              "config.managed_by_file_note",
              "This provider is set by a configuration file or by environment variables, so it cannot be edited here. Change it at that source and restart Jellyfin. A save made here would keep the stored value and leave a record in the log.",
            ) + ssoConfigurationPage.staleReportSuffix()
          : ssoConfigurationPage.unreadNoteFor(provider_name);
        note.hidden = note.textContent === "";
      }
    });
  },
  // Shows whether the server is running on defaults because it could not read the stored configuration
  // (#1543). Fails quiet: an unreachable check leaves the banner hidden.
  showUnreadableConfigurationNotice: (page) => {
    const notice = page.querySelector("#sso-unreadable-config");
    if (!notice) {
      return Promise.resolve();
    }

    return ApiClient.getJSON(ApiClient.getUrl("sso/Config/Check"))
      .then((report) => {
        const unreadable = report && report.ConfigurationUnreadable === true;
        // textContent, never markup (#221).
        notice.textContent = unreadable
          ? tr(
              "config.unreadable_configuration",
              "This server could not read its SSO configuration when it started, so it is running on default settings: no provider, no account link and no stored secret. Every SSO sign-in is refused until a configuration arrives - save a provider here, import one, or let a declarative source supply it. The server log says where the unreadable file was kept; keep that copy. If nobody can sign in at all, move the unreadable configuration file out of the way and delete the marker file beside it - its name is the configuration file plus .unreadable, with no timestamp on the end - then restart, and SSO will answer as it did before this check existed. Deleting the marker alone is not enough while the configuration file is still unreadable.",
            )
          : "";
        notice.hidden = !unreadable;
      })
      .catch(() => {
        notice.hidden = true;
      });
  },
  // Loads the stored configuration into whichever sections the page holds, one load path for all pages
  // (#1527). Each section is gated on the control it writes to.
  // `options.refreshing` marks a return to a tab (#1576): the library checklists are not repopulated, and
  // the write is skipped if the page is no longer replaceable.
  loadConfiguration: (page, options) => {
    const refreshing = Boolean(options && options.refreshing);
    // Refreshed with the configuration, so a provider's managed state follows the server.
    ssoConfigurationPage.loadManagedProviders();
    // Re-asked on every load, since a save or import ends the serve-defaults state.
    ssoConfigurationPage.showUnreadableConfigurationNotice(page);

    // Not on a refresh (#1576): repopulating would clear the ticks that only loadProvider restores.
    // Issued before the configuration request, since the baseline below waits on all three.
    const folderFills = [];
    if (!refreshing) {
      const folder_container = page.querySelector("#EnabledFolders");
      if (folder_container) {
        folderFills.push(
          ssoConfigurationPage.populateFolders(folder_container),
        );
      }

      // The SAML editor has its own available-folders checklist (#725).
      const saml_folder_container = page.querySelector("#saml-EnabledFolders");
      if (saml_folder_container) {
        folderFills.push(
          ssoConfigurationPage.populateFolders(saml_folder_container),
        );
      }
    }

    const load = ApiClient.getPluginConfiguration(
      ssoConfigurationPage.pluginUniqueId,
    ).then((config) => {
      // Asks again right before the first write, since an editor may have opened while this was in flight (#1576).
      if (refreshing && !ssoConfigurationPage.mayReplacePageContents(page)) {
        return;
      }
      // The two provider workspaces (Providers). Both or neither: they are one tab.
      if (page.querySelector("#selectProvider")) {
        ssoConfigurationPage.populateProviders(page, config.OidConfigs);
        // Refreshes the SAML provider list from the same load (#725).
        ssoConfigurationPage.populateSamlProviders(
          page,
          config.SamlConfigs || {},
        );
      }
      // The global login-page buttons opt-in (#722), a root flag saved by saveServerSettings.
      const manage_buttons = page.querySelector("#ManageLoginPageButtons");
      if (manage_buttons) {
        manage_buttons.checked = Boolean(config.ManageLoginPageButtons);
        // What the switch was filled with, so the save can tell a moved switch from an untouched one (#1572).
        manage_buttons.dataset.ssoLoaded = String(manage_buttons.checked);
      }

      // The global Single Logout opt-in (#727), a root flag saved by saveServerSettings.
      const single_logout = page.querySelector("#EnableSingleLogout");
      if (single_logout) {
        single_logout.checked = Boolean(config.EnableSingleLogout);
        single_logout.dataset.ssoLoaded = String(single_logout.checked);
      }

      // The global provisioning profile set (#1105), a root member filled here so every save, delete and import
      // refreshes the profile editor and the provider-form selectors on whichever tab holds them (#1527).
      ssoConfigurationPage.populateProvisioningProfiles(page, config);

      // Overview reads the same configuration, so it cannot disagree with the editor.
      ssoConfigurationPage.renderOverviewFrom(page, config);

      // Re-runs the Save gate against the filled values; the baseline is taken once the whole load settles.
      ssoConfigurationPage.updateSaveAvailability(page);

      // Takes the baseline after all three requests settle, since the checklists add id-less rows the signature
      // counts (#1576). A rejected checklist read settles too, so the page is never left without a baseline
      // (the empty checklist it leaves is #1587).
      return Promise.all(folderFills.map((fill) => fill.then(noop, noop))).then(
        () => ssoConfigurationPage.markPageClean(page),
      );
    });

    // A failed refresh leaves the page showing what it last read; other callers keep their rejection.
    if (refreshing) {
      load.then(noop, noop);
    }
  },
  // Adds an option for a provider saved for the first time, so the selector names it before the reads a
  // save issues (#1710, #1696, #1693).
  nameSelectedProvider: (page, selectorId, provider_name) => {
    const select = page.querySelector(selectorId);
    const held = [...select.querySelectorAll("option")].some(
      (option) => option.value === provider_name,
    );
    if (!held) {
      select.appendChild(new Option(provider_name, provider_name));
    }
    select.value = provider_name;
  },
  populateProviders: (page, providers) => {
    const select = page.querySelector("#selectProvider");

    // Keeps the selected provider across the re-populate (#1693): removing the selected option empties
    // `value`, and re-adding one does not restore it.
    const chosen = select.value;

    // Clear providers in case there are out of date ones
    select.querySelectorAll("option").forEach((option) => option.remove());

    // The hidden selector stays the state holder the save path reads; the cards below are the visible list.
    Object.keys(providers).forEach((provider_name) => {
      select.appendChild(new Option(provider_name, provider_name));
    });
    select.value = chosen;

    ssoConfigurationPage.renderProviderCards(page, providers);
  },
  // Renders the provider list as cards (#365), built with textContent so a provider name stays inert (#221).
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

      // Flags a provider with an active insecure or sensitive setting, read from the saved config.
      const flagged = ssoConfigurationPage.insecureFieldIds
        .concat(ssoConfigurationPage.sensitiveFieldIds)
        .some((id) => Boolean(provider[id]));
      if (flagged) {
        card.classList.add("sso-provider-card-flagged");
        const warn = document.createElement("span");
        warn.classList.add("sso-badge", "sso-badge-warn");
        warn.textContent = "Review";
        warn.title = tr(
          "config.insecure_option_active",
          "This provider has an active insecure or sensitive setting.",
        );
        card.append(warn);
      }

      list.appendChild(card);
    });
  },
  // Shows the OpenID editor and closes the SAML one, so only one workspace and one Save is open (#1527).
  // Closing discards like any editor switch, since opening an editor already resets it.
  showEditor: (page) => {
    ssoConfigurationPage.hideSamlEditor(page);
    page.querySelector("#sso-editor").hidden = false;
    ssoConfigurationPage.railReadiness(page);
  },
  hideEditor: (page) => {
    page.querySelector("#sso-editor").hidden = true;
    ssoConfigurationPage.railReadiness(page);
  },
  setEditorTitle: (page, title) => {
    page.querySelector("#sso-editor-title").textContent = title;
  },
  // Loads a card into a freshly reset editor, so no value from the previous provider survives into a save.
  openProvider: (page, provider_name) => {
    page.querySelector("#selectProvider").value = provider_name;
    ssoConfigurationPage.resetEditor(page);
    ssoConfigurationPage.clearValidationErrors(page);
    ssoConfigurationPage.renderSaveStatus(page, "");
    // Clears the outcome of the last delete, which was about another provider (#1572).
    ssoConfigurationPage.renderPageStatus(page, "");
    ssoConfigurationPage.setEditorTitle(page, provider_name);
    ssoConfigurationPage.showEditor(page);
    ssoConfigurationPage.loadProvider(page, provider_name);
    // Opening is a read, so the page is clean until loadProvider re-marks it after its fill (#1572).
    ssoConfigurationPage.markPageClean(page);
    page.querySelector("#sso-editor").scrollIntoView({ block: "start" });
  },
  // Opens a blank editor for a new provider with every toggle off (fail closed).
  addProvider: (page) => {
    page.querySelector("#selectProvider").value = "";
    ssoConfigurationPage.resetEditor(page);
    ssoConfigurationPage.clearValidationErrors(page);
    ssoConfigurationPage.renderSaveStatus(page, "");
    ssoConfigurationPage.renderPageStatus(page, "");
    ssoConfigurationPage.setEditorTitle(
      page,
      tr("config.new_provider", "New provider"),
    );
    ssoConfigurationPage.syncDependentFields(page);
    // A new provider is never managed; this restores a form a managed provider left frozen (#1104).
    ssoConfigurationPage.applyManagedState(page, "oid", "");
    ssoConfigurationPage.showEditor(page);
    // A blank editor is clean, and its Save stays closed until the required fields are filled (#1572).
    ssoConfigurationPage.markPageClean(page);
    page.querySelector("#sso-editor").scrollIntoView({ block: "start" });
    page.querySelector("#OidProviderName").focus();
  },
  resetEditor: (page) => {
    const form_elements = ssoConfigurationPage.listArgumentsByType(page);

    // A Test Connection result belongs to the provider it ran against (#1083).
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

    // Resets the insecure list and every editor accordion to their defaults, then re-syncs the reveal groups,
    // so no expanded state bleeds into the next provider.
    ssoConfigurationPage.setInsecureOptionsExpanded(page, false);
    ssoConfigurationPage.resetEditorSections(page);
    ssoConfigurationPage.syncDependentFields(page);
    // Clear the computed redirect URI back to its placeholder for the fresh/blank editor (#724).
    ssoConfigurationPage.updateRedirectUri(page);
    // Reset the template picker and its note so a provider never shows a stale template (#726).
    const oidPreset = page.querySelector("#OidPreset");
    if (oidPreset) {
      oidPreset.value = "";
    }
    ssoConfigurationPage.renderPresetNote(page, "OidPreset-note", "");
  },
  // Returns every accordion inside the editor to its authored default state (data-expanded).
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
  // Drives an emby-collapse to a given state by clicking its button only when `expanded` differs, so it is
  // idempotent. A no-op on markup that is not upgraded yet.
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
  // Shows or hides a reveal-on-toggle group for its checkbox. Presentation only: fields stay in the DOM and
  // serializable (#365).
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

    // Expands the security accordion, and the insecure list for insecure toggles, when an active downgrade
    // would otherwise hide behind collapsed layers. Expand only; resetEditor restores the defaults.
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

    // A load ticks boxes without events, so the fold counts are refreshed here for both protocols.
    ssoConfigurationPage.refreshOptionFoldCounts(page);
  },
  // Opens or closes the insecure options fold, a native `<details>` since #1666.
  setInsecureOptionsExpanded: (page, expanded) => {
    const fold = page.querySelector("#sso-insecure-options");
    if (!fold) {
      return;
    }
    fold.open = expanded;
  },
  // On-blur inline warnings that mirror the server's checks (#365); they never block the save.
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
      value
        ? ""
        : tr("config.validation_required", "{label} is required.", { label }),
    );
  },
  validateEndpoint: (page) => {
    const value = page.querySelector("#OidEndpoint").value.trim();
    if (!value) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidEndpoint",
        tr(
          "config.validation_endpoint_required",
          "OpenID Endpoint is required.",
        ),
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
        tr(
          "config.validation_endpoint_absolute",
          "Enter an absolute URL, e.g. https://id.example.com",
        ),
      );
      return;
    }
    if (url.protocol === "http:") {
      ssoConfigurationPage.setFieldError(
        page,
        "OidEndpoint",
        tr(
          "config.validation_endpoint_insecure",
          "Uses http://, so discovery would be unencrypted. Prefer an https:// endpoint.",
        ),
      );
      return;
    }
    if (url.protocol !== "https:") {
      ssoConfigurationPage.setFieldError(
        page,
        "OidEndpoint",
        tr(
          "config.validation_endpoint_https",
          "Use an https:// URL for the OpenID endpoint.",
        ),
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
        tr(
          "config.validation_base_origin_only",
          "Enter a full URL such as https://jellyfin.example.com (scheme and host; add Jellyfin's path base if it has one).",
        ),
      );
      return;
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      ssoConfigurationPage.setFieldError(
        page,
        "BaseUrlOverride",
        tr(
          "config.validation_base_origin",
          "Enter a full origin such as https://jellyfin.example.com",
        ),
      );
      return;
    }
    // Allows a path base (#1712) but not a plugin route, a query or a fragment.
    if (url.search || url.hash || ssoConfigurationPage.isPluginRoute(url)) {
      ssoConfigurationPage.setFieldError(
        page,
        "BaseUrlOverride",
        tr(
          "config.validation_base_not_the_redirect",
          "Enter the base URL, not the /sso/... redirect URI: the origin plus Jellyfin's path base if it runs under one, e.g. https://jellyfin.example.com or https://jellyfin.example.com/jellyfin, with no query or fragment.",
        ),
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "BaseUrlOverride", "");
  },
  // Whether a URL's path is /sso or below it, case-insensitively like the server's routes.
  isPluginRoute: (url) => /^\/sso(\/|$)/i.test(url.pathname),
  validateProviderName: (page) => {
    const value = page.querySelector("#OidProviderName").value;
    if (!value.trim()) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidProviderName",
        tr("config.validation_name_required", "A provider name is required."),
      );
      return;
    }
    // Mirrors the server's name checks (#336/#360). Control characters are found by code point to keep this
    // source ASCII-only.
    const hasControlChar = [...value].some((ch) => {
      const code = ch.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    });
    if (hasControlChar) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidProviderName",
        tr(
          "config.validation_name_control_chars",
          "Remove control characters (such as a tab or newline, often introduced by copy-paste) from the name.",
        ),
      );
      return;
    }
    // The backslash and the URI-reserved characters the server rejects.
    const reserved = ["\\", "/", "?", "#", "%"];
    if (reserved.some((c) => value.includes(c))) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidProviderName",
        tr(
          "config.validation_name_reserved",
          "Remove the backslash and the characters / ? # % from the name.",
        ),
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "OidProviderName", "");
  },
  // The unsaved-changes state (#1572), which the indicator, the Save gate and the safe re-read share.
  // An event only triggers the check; a comparison of the tracked controls against the last baseline
  // answers it, because host controls dispatch their own synthetic events.
  // The listener is in the capture phase because emby-select's change event does not bubble.
  // File inputs and the navigating selectors are not tracked; changing a selector resets the page to clean.
  navigationControlIds: [
    "selectProvider",
    "saml-selectProvider",
    "selectProvisioningProfile",
  ],
  // Every control an administrator can edit and a Save would commit. Empty on Accounts, which is never dirty.
  editableControls: (page) =>
    [...page.querySelectorAll("input, select, textarea")].filter(
      (element) =>
        element.type !== "file" &&
        // Read-only controls hold computed addresses no save reads, and the redirect URI fills after the baseline
        // (#1701). Deriving this from readOnly covers future computed fields too.
        element.readOnly !== true &&
        ssoConfigurationPage.navigationControlIds.indexOf(element.id) === -1,
    ),
  // What the tracked controls hold now, as one comparable string that carries each id.
  // A separator no value can contain keeps id-less rows from colliding (#1576).
  controlSignature: (page) =>
    ssoConfigurationPage
      .editableControls(page)
      .map(
        (element) =>
          element.id +
          "=" +
          (element.type === "checkbox" || element.type === "radio"
            ? String(element.checked)
            : String(element.value)),
      )
      .join("\n"),
  isPageDirty: (page) => page.classList.contains("sso-page-dirty"),
  markPageDirty: (page) => {
    page.classList.add("sso-page-dirty");
    ssoConfigurationPage.renderUnsavedNotice(page);
    ssoConfigurationPage.updateSaveAvailability(page);
  },
  // Marks the page clean, the one place the baseline is taken, and re-runs the Save gate.
  markPageClean: (page) => {
    pageBaselines.set(page, ssoConfigurationPage.controlSignature(page));
    page.classList.remove("sso-page-dirty");
    ssoConfigurationPage.renderUnsavedNotice(page);
    ssoConfigurationPage.updateSaveAvailability(page);
  },
  // Whether the page holds something other than the last baseline; no baseline counts as edited.
  pageDiffersFromBaseline: (page) => {
    const baseline = pageBaselines.get(page);
    return (
      baseline === undefined ||
      baseline !== ssoConfigurationPage.controlSignature(page)
    );
  },
  // The unsaved-changes indicator text, about this page only. Set as textContent (#221).
  unsavedNoticeText: () =>
    tr(
      "config.unsaved",
      "Unsaved changes in this editor. Save them before you open another provider or leave this page, or they are lost.",
    ),
  renderUnsavedNotice: (page) => {
    const box = page.querySelector("#sso-unsaved");
    if (!box) {
      return;
    }
    const dirty = ssoConfigurationPage.isPageDirty(page);
    // Unhides before writing, since text set on a hidden live region is not announced.
    if (dirty) {
      box.hidden = false;
      box.textContent = ssoConfigurationPage.unsavedNoticeText();
      return;
    }
    box.textContent = "";
    box.hidden = true;
  },
  // What each Save needs before it can be pressed, derived from the readiness specs. A gate whose region is
  // hidden is skipped.
  saveGates: () => [
    {
      button: "#SaveProvider",
      region: "#sso-editor",
      requiredIds: ssoConfigurationPage.readinessSpecs.oid.requiredIds,
    },
    {
      button: "#saml-SaveProvider",
      region: "#saml-editor",
      requiredIds: ssoConfigurationPage.readinessSpecs.saml.requiredIds,
    },
    {
      // Gated on the selector, which the profile save keys off, rather than on the rename box.
      button: "#SaveProvisioningProfile",
      region: null,
      requiredIds: ["selectProvisioningProfile"],
    },
    { button: "#SaveServerSettings", region: null, requiredIds: [] },
  ],
  // The gate's empty required fields, read from the values like the readiness panel. Only an empty
  // required field closes a Save; the guessing validators keep warning without blocking (#365).
  saveGateEmpties: (page, gate) =>
    gate.requiredIds.filter((id) => {
      const field = page.querySelector("#" + id);
      return field && !String(field.value || "").trim();
    }),
  // Sets a Save's disabled state from this gate and the freeze's recorded reason (#1104), so the gate never
  // hands back a Save the freeze closed. The freeze functions are the only other writers of `disabled`.
  setSaveBlocked: (button, blocked) => {
    button.disabled = blocked || button.dataset.ssoManaged === "true";
  },
  updateSaveAvailability: (page) => {
    ssoConfigurationPage.saveGates().forEach((gate) => {
      const button = page.querySelector(gate.button);
      if (!button) {
        return;
      }
      const region = gate.region ? page.querySelector(gate.region) : null;
      if (region && region.hidden) {
        return;
      }
      ssoConfigurationPage.setSaveBlocked(
        button,
        ssoConfigurationPage.saveGateEmpties(page, gate).length > 0,
      );
    });
  },
  // What a closed fold says about what it hides (#1666): the summary carries a count derived from the
  // region's own option boxes. An option is in use when ticked or carrying a value. Presentation only.
  optionFoldControls: (fold) =>
    Array.from(fold.querySelectorAll(".checkboxContainer, .inputContainer"))
      .map((box) => box.querySelector("input, select, textarea"))
      .filter((control) => control !== null),
  optionInUse: (control) =>
    control.type === "checkbox" || control.type === "radio"
      ? control.checked
      : String(control.value || "").trim() !== "",
  refreshOptionFoldCounts: (page) => {
    page.querySelectorAll(".sso-option-fold").forEach((fold) => {
      const count = fold.querySelector(".sso-fold-count");
      if (!count) {
        return;
      }
      const controls = ssoConfigurationPage.optionFoldControls(fold);
      count.textContent = tr(
        "config.option_fold_count",
        "{active} of {total} in use",
        {
          active: String(
            controls.filter(ssoConfigurationPage.optionInUse).length,
          ),
          total: String(controls.length),
        },
      );
    });
  },
  // Keeps the fold counts current without a save, delegated in the capture phase like the change tracking.
  bindOptionFoldCounts: (page) => {
    const recount = () => ssoConfigurationPage.refreshOptionFoldCounts(page);
    page.addEventListener("input", recount, true);
    page.addEventListener("change", recount, true);
  },
  // One delegated capture-phase listener per page, so late-rendered controls are tracked and non-bubbling
  // or stopped events still arrive.
  bindUnsavedChangeTracking: (page) => {
    const observe = (event) => {
      if (!event.target) {
        return;
      }
      if (
        ssoConfigurationPage.navigationControlIds.indexOf(event.target.id) !==
        -1
      ) {
        ssoConfigurationPage.markPageClean(page);
        return;
      }
      if (
        ssoConfigurationPage.editableControls(page).indexOf(event.target) === -1
      ) {
        return;
      }
      // The event only asks; the values answer, since host controls dispatch synthetic events on real input.
      if (ssoConfigurationPage.pageDiffersFromBaseline(page)) {
        ssoConfigurationPage.markPageDirty(page);
      } else {
        ssoConfigurationPage.markPageClean(page);
      }
    };
    page.addEventListener("input", observe, true);
    page.addEventListener("change", observe, true);
  },
  // The refresh on return to a tab (#1576). A second load could empty the library checklists under an open
  // editor, miss removed rows that fire no event, and overwrite edits made while in flight.
  // Three guards answer these: an open editor refuses the refresh, the decision recomputes the signature
  // from the live controls, and the same checks run again right before the fill writes.
  editorRegionIds: ["sso-editor", "saml-editor"],
  anyEditorOpen: (page) =>
    ssoConfigurationPage.editorRegionIds.some((id) => {
      const region = page.querySelector("#" + id);
      return region !== null && region.hidden !== true;
    }),
  // Whether the page may be replaced by a fresh read, asked before the fetch and again before the write.
  mayReplacePageContents: (page) =>
    !ssoConfigurationPage.anyEditorOpen(page) &&
    !ssoConfigurationPage.pageDiffersFromBaseline(page),
  refreshOnShow: (page) => {
    if (ssoConfigurationPage.anyEditorOpen(page)) {
      return;
    }
    if (ssoConfigurationPage.pageDiffersFromBaseline(page)) {
      // The tab holds something the last read did not put there, so mark it dirty and leave it untouched.
      ssoConfigurationPage.markPageDirty(page);
      return;
    }
    ssoConfigurationPage.loadConfiguration(page, { refreshing: true });
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
  // Serializes the ticked folders, or null when the container has no rows because the fill never ran
  // (#1607). Saving that as "no libraries" would remove library access for every user of the provider.
  serializeEnabledFolders: (container) => {
    const rows = [...container.querySelectorAll(".folder-checkbox")];
    if (rows.length === 0) {
      return null;
    }

    return rows.filter((e) => e.checked).map((e) => e.dataset.id);
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
  // Fills a folder checklist from folders.Items, each with Id and Name.
  _populateFolders: (container, folders) => {
    container
      .querySelectorAll(".emby-checkbox-label")
      .forEach((e) => e.remove());

    const checkboxes = folders.Items.map((folder) => {
      // Built with textContent so a folder name stays inert (#221), as in linking.js.
      const out = document.createElement("label");
      // Tags the row for the cleanup above, so a second populate does not duplicate folder ids.
      out.classList.add("emby-checkbox-label");

      // See customizedBuiltIn for the Jellyfin 12 fallback (#1607); the `is` attribute is set either way.
      const checkbox = customizedBuiltIn("input", "emby-checkbox");
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

        // A row whose checklist never drew is saved as an empty set rather than dropped, which would delete the
        // mapping (#1607).
        out.push({
          Role: role,
          Folders:
            ssoConfigurationPage.serializeEnabledFolders(checklist) || [],
        });
      },
    );

    return out;
  },
  handleRoleMappingRemove: (evt) => {
    const targeted_mapping = evt.target.closest(".sso-role-mapping-container");
    targeted_mapping.remove();
  },
  // The provisioning-template save contract (#1367). The nested template has its own sso-tmpl-* classes and
  // "<prefix>Tmpl-" ids, assembled by readProvisioningTemplate.
  // An untouched control contributes no member, and an all-unset form sends no object, since the validator
  // refuses any inline template on a provider that names a profile.
  templateFieldName: (prefix, element) =>
    element.id.slice((prefix + "Tmpl-").length),
  // The form each template-control prefix lives in, including the global profile editor (#1105).
  templateFormSelectors: {
    "": "#sso-new-oidc-provider",
    "saml-": "#sso-new-saml-provider",
    "profile-": "#sso-provisioning-profiles",
  },
  templateControls: (page, prefix) => {
    const form = page.querySelector(
      ssoConfigurationPage.templateFormSelectors[prefix],
    );

    return {
      numbers: [...form.querySelectorAll(".sso-tmpl-number")],
      texts: [...form.querySelectorAll(".sso-tmpl-text")],
      bools: [...form.querySelectorAll(".sso-tmpl-bool")],
      lists: [...form.querySelectorAll(".sso-tmpl-list")],
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

    // A list control (#1101) is one entry per line; a box with no entry contributes no member.
    controls.lists.forEach((element) => {
      const lines = element.value
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line !== "");
      if (lines.length > 0) {
        template[name(element)] = lines;
      }
    });

    controls.numbers.forEach((element) => {
      const raw = element.value.trim();
      if (raw === "") {
        return;
      }

      // A value that is not a whole number is sent as typed, so the server refuses it visibly.
      const parsed = Number(raw);
      template[name(element)] = Number.isInteger(parsed) ? parsed : raw;
    });

    // Only these two spellings are a value; anything else leaves the field declined.
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
  fillProvisioningTemplate: (page, prefix, template, profile, profiles) => {
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

    controls.lists.forEach((element) => {
      const value =
        values[ssoConfigurationPage.templateFieldName(prefix, element)];
      element.value = Array.isArray(value) ? value.join("\n") : "";
    });

    // Set unconditionally so no previous provider's profile carries over (#1105); a stored name missing from
    // the profile set is still offered, so it stays visible.
    const selector = page.querySelector("#" + prefix + "ProvisioningProfile");
    if (selector) {
      // Without a name list the caller is clearing the form, so the options stay and only the value clears.
      if (profiles) {
        ssoConfigurationPage.populateProvisioningProfileOptions(
          selector,
          profiles,
          profile || "",
        );
      } else {
        selector.value = profile || "";
      }
    }

    ssoConfigurationPage.syncProvisioningProfileState(page, prefix);

    return ssoConfigurationPage.populateTemplatePermissions(
      page,
      prefix,
      values.Permissions || [],
    );
  },
  // Disables the inline template controls when the selector names a profile, and says why.
  syncProvisioningProfileState: (page, prefix, managed) => {
    const controls = ssoConfigurationPage.templateControls(page, prefix);
    const selector = page.querySelector("#" + prefix + "ProvisioningProfile");
    // Also disabled on a managed provider (#1104), since this runs after applyManagedState.
    const named = Boolean(selector && selector.value) || Boolean(managed);

    const note = page.querySelector("#" + prefix + "Tmpl-profile-note");
    if (note) {
      note.hidden = !named;
    }

    [
      ...controls.numbers,
      ...controls.texts,
      ...controls.bools,
      ...controls.lists,
      ...page.querySelectorAll("#" + prefix + "Tmpl-Permissions-add"),
    ].forEach((element) => {
      element.disabled = named;
    });
  },
  // Builds profile options with textContent, never innerHTML (#221).
  populateProvisioningProfileOptions: (select, names, selected) => {
    const offered =
      selected && !names.includes(selected) ? [...names, selected] : names;

    select.replaceChildren();
    const none = window.document.createElement("option");
    none.value = "";
    none.textContent = "(none)";
    select.appendChild(none);

    offered.forEach((name) => {
      const option = window.document.createElement("option");
      option.value = name;
      option.textContent = name;
      select.appendChild(option);
    });

    select.value = selected || "";
  },
  // The provisioning-profile editor (#1105). Every act fetches the live configuration, changes the
  // ProvisioningProfiles member and re-posts the document.
  // A delete of a referenced profile is refused with the references shown, and a rename repoints every
  // reference in the same document.
  provisioningProfileNames: (config) =>
    Object.keys(config.ProvisioningProfiles || {}).sort(),
  // The name to select once the reload rebuilds the list, consumed once.
  provisioningProfileWanted: null,
  // Whether a plain assignment creates an own property for this name, which rules out "__proto__".
  provisioningProfileNameIsAssignable: (name) => {
    const probe = {};
    probe[name] = true;
    return Object.prototype.hasOwnProperty.call(probe, name);
  },
  provisioningProfileStatus: (page, message) =>
    ssoConfigurationPage.renderTransferMessage(
      page.querySelector("#ProvisioningProfileResult"),
      message,
    ),
  // Every provider and role rule that names a profile, each marked if its provider is managed.
  provisioningProfileReferences: (config, name) => {
    const found = [];
    [
      ["oid", "OpenID", config.OidConfigs],
      ["saml", "SAML", config.SamlConfigs],
    ].forEach(([key, protocol, providers]) => {
      Object.keys(providers || {}).forEach((provider) => {
        const provider_config = providers[provider] || {};
        const managed = ssoConfigurationPage.isManagedProvider(key, provider);
        if (provider_config.ProvisioningProfile === name) {
          found.push({ label: `${protocol} provider "${provider}"`, managed });
        }

        // Trimmed, because the server resolves a role row's name trimmed.
        (provider_config.ProvisioningProfileRoleMappings || []).forEach(
          (row) => {
            if (row && (row.Profile || "").trim() === name) {
              found.push({
                label: `${protocol} provider "${provider}" (a role rule)`,
                managed,
              });
            }
          },
        );
      });
    });

    return found;
  },
  repointProvisioningProfile: (config, from, to) => {
    [config.OidConfigs, config.SamlConfigs].forEach((providers) => {
      Object.keys(providers || {}).forEach((provider) => {
        const provider_config = providers[provider] || {};
        if (provider_config.ProvisioningProfile === from) {
          provider_config.ProvisioningProfile = to;
        }

        // Trimmed like the reference walk, so every row the server resolves is repointed.
        (provider_config.ProvisioningProfileRoleMappings || []).forEach(
          (row) => {
            if (row && (row.Profile || "").trim() === from) {
              row.Profile = to;
            }
          },
        );
      });
    });
  },
  // The providers with an inline template, as the sources an Add can copy.
  provisioningProfileSources: (config) => {
    const sources = [];
    [
      ["oid", "OpenID", config.OidConfigs],
      ["saml", "SAML", config.SamlConfigs],
    ].forEach(([key, protocol, providers]) => {
      Object.keys(providers || {})
        .sort()
        .forEach((provider) => {
          if ((providers[provider] || {}).ProvisioningPolicyTemplate) {
            sources.push({
              value: `${key}:${provider}`,
              label: `${protocol}: ${provider}`,
            });
          }
        });
    });

    return sources;
  },
  provisioningProfileSourceTemplate: (config, value) => {
    const separator = value.indexOf(":");
    if (separator < 0) {
      return null;
    }

    const providers =
      value.slice(0, separator) === "saml"
        ? config.SamlConfigs
        : config.OidConfigs;
    const provider = (providers || {})[value.slice(separator + 1)] || {};

    // A copy, so the profile and the provider's template stay independent.
    return provider.ProvisioningPolicyTemplate
      ? JSON.parse(JSON.stringify(provider.ProvisioningPolicyTemplate))
      : null;
  },
  // Fills the profile editor and both provider-form selectors from one configuration load, each half gated
  // on its own control (#1527). Returns the fill promise only where it started one.
  populateProvisioningProfiles: (page, config) => {
    const names = ssoConfigurationPage.provisioningProfileNames(config);
    const select = page.querySelector("#selectProvisioningProfile");
    if (select) {
      const wanted = ssoConfigurationPage.provisioningProfileWanted;
      ssoConfigurationPage.provisioningProfileWanted = null;
      const chosen =
        wanted && names.includes(wanted)
          ? wanted
          : names.includes(select.value)
            ? select.value
            : names[0] || "";
      ssoConfigurationPage.populateProvisioningProfileOptions(
        select,
        names,
        chosen,
      );
    }

    // An open provider form keeps its current selection.
    ["ProvisioningProfile", "saml-ProvisioningProfile"].forEach((id) => {
      const selector = page.querySelector("#" + id);
      if (selector) {
        ssoConfigurationPage.populateProvisioningProfileOptions(
          selector,
          names,
          selector.value,
        );
      }
    });

    const source_select = page.querySelector("#ProvisioningProfileSource");
    if (!source_select) {
      // No editor on this page. provisioningProfileFill is left alone: it lives on the shared object and guards
      // the Policies Save, so writing it here would release that guard from another tab.
      return;
    }

    const sources = ssoConfigurationPage.provisioningProfileSources(config);
    source_select.replaceChildren();
    const empty = window.document.createElement("option");
    empty.value = "";
    empty.textContent = tr(
      "config.profile_none_start_empty",
      "Nothing - start empty",
    );
    source_select.appendChild(empty);
    sources.forEach((source) => {
      const option = window.document.createElement("option");
      option.value = source.value;
      option.textContent = source.label;
      source_select.appendChild(option);
    });

    ssoConfigurationPage.provisioningProfileFill = ssoConfigurationPage
      .showSelectedProvisioningProfile(page, config)
      .then(() => true);

    return ssoConfigurationPage.provisioningProfileFill;
  },
  // Whether the editor shows the profile the selector names, as a promise of true or false. A Save waits on
  // it so it never serializes unrendered permission rows or the previous profile's fields. Assigned
  // synchronously by the change handler, so it covers its own fetch.
  provisioningProfileFill: null,
  selectProvisioningProfile: (page) => {
    const pending = ApiClient.getPluginConfiguration(
      ssoConfigurationPage.pluginUniqueId,
    ).then(
      (config) =>
        ssoConfigurationPage
          .showSelectedProvisioningProfile(page, config)
          .then(() => true),
      // Resolves false rather than rejecting, so no rejection goes unhandled.
      () => {
        ssoConfigurationPage.provisioningProfileStatus(
          page,
          tr(
            "config.profile_load_failed",
            "Could not load the profile you chose. The fields below still show the previous one, so nothing will be saved until the page is reloaded.",
          ),
        );
        return false;
      },
    );

    ssoConfigurationPage.provisioningProfileFill = pending;
    return pending;
  },
  showSelectedProvisioningProfile: (page, config) => {
    const name = page.querySelector("#selectProvisioningProfile").value;
    page.querySelector("#ProvisioningProfileName").value = name;

    return (
      ssoConfigurationPage
        .fillProvisioningTemplate(
          page,
          "profile-",
          (config.ProvisioningProfiles || {})[name] || null,
          null,
          [],
        )
        .then(() => ssoConfigurationPage.applyManagedProfileState(page, name))
        // The editor holds the stored profile, so the page is clean (#1572).
        .then(() => ssoConfigurationPage.markPageClean(page))
    );
  },
  // Re-posts the whole configuration and reloads the view; a rejected PUT is reported in this section's
  // status region.
  putProvisioningProfiles: (page, config, message) =>
    ApiClient.updatePluginConfiguration(
      ssoConfigurationPage.pluginUniqueId,
      config,
    ).then(
      (result) => {
        Dashboard.processPluginConfigurationUpdateResult(result);
        ssoConfigurationPage.loadConfiguration(page);
        ssoConfigurationPage.provisioningProfileStatus(page, message);
      },
      () => {
        ssoConfigurationPage.provisioningProfileStatus(
          page,
          tr(
            "config.profile_refused",
            "The server refused the profile, so nothing was changed. It follows the rules of an inline starting policy, described above. Reload and try again.",
          ),
        );
      },
    ),
  addProvisioningProfile: (page) => {
    const name = page.querySelector("#ProvisioningProfileName").value.trim();
    if (name === "") {
      ssoConfigurationPage.provisioningProfileStatus(
        page,
        tr(
          "config.profile_name_needed",
          "Type the name the new profile should have. A name is the only thing a provider can point at, so an unnamed profile could never be selected.",
        ),
      );
      return;
    }

    if (!ssoConfigurationPage.provisioningProfileNameIsAssignable(name)) {
      ssoConfigurationPage.provisioningProfileStatus(
        page,
        `"${name}" cannot be used as a profile name: a JavaScript object cannot carry it as an ordinary member, so the profile would be reported as created and would not exist. Choose a different name.`,
      );
      return;
    }

    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        const profiles = config.ProvisioningProfiles || {};
        if (Object.prototype.hasOwnProperty.call(profiles, name)) {
          ssoConfigurationPage.provisioningProfileStatus(
            page,
            `A profile called "${name}" already exists. Choose it above to edit it, or type a different name.`,
          );
          return;
        }

        // Add copies the chosen provider's inline policy (#1105), since an empty profile would do nothing.
        // It creates and does not select, so no provider changes policy until pointed at the profile.
        const source = page.querySelector("#ProvisioningProfileSource").value;
        const template = source
          ? ssoConfigurationPage.provisioningProfileSourceTemplate(
              config,
              source,
            )
          : null;

        profiles[name] = template || {};
        config.ProvisioningProfiles = profiles;
        ssoConfigurationPage.provisioningProfileWanted = name;

        ssoConfigurationPage.putProvisioningProfiles(
          page,
          config,
          template
            ? `Added the profile "${name}" as a copy of that provider's own starting policy. No provider uses it yet: point one at it in its own Starting policy section.`
            : `Added the empty profile "${name}". It writes nothing onto a new account until you set a field below and save it.`,
        );
      },
    );
  },
  renameProvisioningProfile: (page) => {
    const from = page.querySelector("#selectProvisioningProfile").value;
    const to = page.querySelector("#ProvisioningProfileName").value.trim();
    if (from === "") {
      ssoConfigurationPage.provisioningProfileStatus(
        page,
        tr(
          "config.profile_choose_to_rename",
          "Choose the profile to rename first.",
        ),
      );
      return;
    }

    // A managed profile is restored under its old name after the save, so a rename would leave an unmanaged
    // copy (#1498).
    if (ssoConfigurationPage.isManagedProfile(from)) {
      ssoConfigurationPage.provisioningProfileStatus(
        page,
        `"${from}" cannot be renamed here: it is defined by a configuration file or by environment variables, and the server would restore it under this name after the save, leaving an unmanaged copy under the new one. Rename it at that source and restart Jellyfin.` +
          ssoConfigurationPage.staleReportSuffix(),
      );
      return;
    }

    if (to === "" || to === from) {
      ssoConfigurationPage.provisioningProfileStatus(
        page,
        tr(
          "config.profile_rename_needs_new_name",
          "Type the new name in Profile name. A rename needs a name that is not the current one.",
        ),
      );
      return;
    }

    if (!ssoConfigurationPage.provisioningProfileNameIsAssignable(to)) {
      ssoConfigurationPage.provisioningProfileStatus(
        page,
        `"${to}" cannot be used as a profile name, for the reason Add gives. Refused here BEFORE anything moves: the rename deletes the source name, so renaming onto a name that cannot be assigned would lose the profile and report that it had moved.`,
      );
      return;
    }

    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        const profiles = config.ProvisioningProfiles || {};
        if (!Object.prototype.hasOwnProperty.call(profiles, from)) {
          ssoConfigurationPage.provisioningProfileStatus(
            page,
            `The profile "${from}" is no longer in the saved configuration. Reload the page.`,
          );
          return;
        }

        if (Object.prototype.hasOwnProperty.call(profiles, to)) {
          ssoConfigurationPage.provisioningProfileStatus(
            page,
            `A profile called "${to}" already exists, and renaming onto it would silently replace its policy. Choose a different name.`,
          );
          return;
        }

        const references = ssoConfigurationPage.provisioningProfileReferences(
          config,
          from,
        );
        // A managed provider is restored whole after the save, so its reference would keep the old name and make
        // every later save fail validation. Refused here with the repair named.
        const frozen = references.filter((reference) => reference.managed);
        if (frozen.length > 0) {
          ssoConfigurationPage.provisioningProfileStatus(
            page,
            `"${from}" cannot be renamed: it is named by ${frozen.map((reference) => reference.label).join("; ")}, which a configuration file or environment variables decide. That name would be restored after the save and would then point at a profile this configuration no longer defines, which makes every later save fail. Rename it at that source, or leave this profile's name as it is.` +
              ssoConfigurationPage.staleReportSuffix(),
          );
          return;
        }

        profiles[to] = profiles[from];
        delete profiles[from];
        config.ProvisioningProfiles = profiles;
        // Repointed in the same document, so no provider ever names a missing profile.
        ssoConfigurationPage.repointProvisioningProfile(config, from, to);
        ssoConfigurationPage.provisioningProfileWanted = to;

        ssoConfigurationPage.putProvisioningProfiles(
          page,
          config,
          references.length === 0
            ? `Renamed "${from}" to "${to}". Nothing pointed at it.`
            : `Renamed "${from}" to "${to}" and repointed ${references.length} reference(s): ${references.map((reference) => reference.label).join("; ")}.`,
        );
      },
    );
  },
  deleteProvisioningProfile: (page) => {
    const name = page.querySelector("#selectProvisioningProfile").value;
    if (name === "") {
      ssoConfigurationPage.provisioningProfileStatus(
        page,
        tr(
          "config.profile_choose_to_delete",
          "Choose the profile to delete first.",
        ),
      );
      return;
    }

    if (ssoConfigurationPage.isManagedProfile(name)) {
      ssoConfigurationPage.provisioningProfileStatus(
        page,
        `"${name}" cannot be deleted here: it is defined by a configuration file or by environment variables, and the server would put it back after the save. Remove it at that source and restart Jellyfin.` +
          ssoConfigurationPage.staleReportSuffix(),
      );
      return;
    }

    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        const references = ssoConfigurationPage.provisioningProfileReferences(
          config,
          name,
        );
        if (references.length > 0) {
          // Refused rather than cascaded, since clearing references would change what new accounts get.
          ssoConfigurationPage.provisioningProfileStatus(
            page,
            `"${name}" is still in use, so it was not deleted: ${references.map((reference) => reference.label).join("; ")}. Point each of them at another profile first, or clear the name to go back to that provider's own inline policy.`,
          );
          return;
        }

        if (
          !window.confirm(
            `Are you sure you want to delete the provisioning profile ${name}?`,
          )
        ) {
          return;
        }

        const profiles = config.ProvisioningProfiles || {};
        delete profiles[name];
        config.ProvisioningProfiles = profiles;

        ssoConfigurationPage.putProvisioningProfiles(
          page,
          config,
          `Deleted the profile "${name}".`,
        );
      },
    );
  },
  saveProvisioningProfile: (page) => {
    const name = page.querySelector("#selectProvisioningProfile").value;
    if (name === "") {
      ssoConfigurationPage.provisioningProfileStatus(
        page,
        tr(
          "config.profile_choose_before_saving",
          "Choose a profile above, or add one, before saving. This section edits a named profile; it is not a provider's own starting policy.",
        ),
      );
      return;
    }

    if (ssoConfigurationPage.isManagedProfile(name)) {
      ssoConfigurationPage.provisioningProfileStatus(
        page,
        `"${name}" cannot be saved here: it is defined by a configuration file or by environment variables, and the server would keep the stored value and record the ignored write. Change it at that source and restart Jellyfin.` +
          ssoConfigurationPage.staleReportSuffix(),
      );
      return;
    }

    // Waits for the fill, so the save serializes the loaded profile plus edits and nothing older.
    Promise.resolve(ssoConfigurationPage.provisioningProfileFill).then(
      (filled) => {
        if (filled === false) {
          ssoConfigurationPage.provisioningProfileStatus(
            page,
            tr(
              "config.profile_fields_stale",
              "The fields below do not show the profile you chose, because loading it failed, so nothing was saved. Reload the page and try again.",
            ),
          );
          return undefined;
        }

        return ApiClient.getPluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
        ).then((config) => {
          const profiles = config.ProvisioningProfiles || {};
          if (!Object.prototype.hasOwnProperty.call(profiles, name)) {
            ssoConfigurationPage.provisioningProfileStatus(
              page,
              `The profile "${name}" is no longer in the saved configuration. Reload the page.`,
            );
            return;
          }

          // An all-declined profile is an empty object, never null, since the profile is the object.
          profiles[name] =
            ssoConfigurationPage.readProvisioningTemplate(page, "profile-") ||
            {};
          config.ProvisioningProfiles = profiles;

          ssoConfigurationPage.putProvisioningProfiles(
            page,
            config,
            `Saved the profile "${name}".`,
          );
        });
      },
    );
  },
  // Confirms choosing a profile on a provider form, since the save then clears the inline policy.
  // Declining puts the selector back on (none).
  chooseProvisioningProfile: (page, prefix) => {
    const selector = page.querySelector("#" + prefix + "ProvisioningProfile");
    const inline = ssoConfigurationPage.readProvisioningTemplate(page, prefix);

    if (
      selector.value !== "" &&
      inline !== null &&
      !window.confirm(
        `This provider has its own starting policy. Taking it from the profile "${selector.value}" instead clears those fields when you save, because a provider's new accounts get exactly one policy. Add a profile from this provider's policy first if you want to keep it.`,
      )
    ) {
      selector.value = "";
    }

    ssoConfigurationPage.syncProvisioningProfileState(page, prefix);
  },
  // The mappable permission names, fetched once from the server (#1484) rather than copied here.
  templatePermissionNames: null,
  loadTemplatePermissionNames: () => {
    if (ssoConfigurationPage.templatePermissionNames) {
      return ssoConfigurationPage.templatePermissionNames;
    }

    ssoConfigurationPage.templatePermissionNames = ApiClient.getJSON(
      ApiClient.getUrl("sso/Config/Permissions"),
    ).then(
      (doc) => (doc && doc.Permissions ? doc.Permissions : []),
      // A failed fetch yields no vocabulary; rows still render their stored names, so nothing is dropped on save.
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
            "Could not load the permission list from the server. Sign in as an administrator and reload the page; configured rows are shown as they are.",
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
  // Renders a permission row with textContent, never innerHTML (#221).
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

    // The stored name is offered even if the vocabulary lacks it, so a save never silently unsets the row.
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
  // The provider form's save contract (#365): every persisted input carries an sso-* class and an id equal
  // to the OidConfig property it writes. A conformance test locks the ids in.
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
    const read = ApiClient.getPluginConfiguration(
      ssoConfigurationPage.pluginUniqueId,
    ).then(
      (config) => {
        // A reply for a provider the editor has since left writes nothing (#1693).
        if (
          !ssoConfigurationPage.replyStillSpeaksFor(page, "oid", provider_name)
        ) {
          return;
        }
        // A 200 that is not the configuration is handled rather than thrown (#1694).
        if (!ssoConfigurationPage.isProviderConfiguration(config, "oid")) {
          ssoConfigurationPage.hideEditor(page);
          ssoConfigurationPage.reportUnrecognisedProviderConfiguration(page);
          ssoConfigurationPage.markPageClean(page);
          return;
        }
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
          // Always set from the loaded provider, so a previous provider's insecure toggle never persists.
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
          ssoConfigurationPage.provisioningProfileNames(config),
        );

        // Syncs the reveal groups and insecure surfacing to the toggles just loaded.
        ssoConfigurationPage.syncDependentFields(page);
        // Reflect the loaded provider's name and base-URL override in the computed redirect URI (#724).
        ssoConfigurationPage.updateRedirectUri(page);
        // Last, so the widgets created above are covered (#1104), with the profile state re-applied after it
        // because applyManagedState re-enables every control.
        ssoConfigurationPage
          .applyManagedState(page, "oid", provider_name)
          .then(() =>
            ssoConfigurationPage.syncProvisioningProfileState(
              page,
              "",
              ssoConfigurationPage.isManagedProvider("oid", provider_name),
            ),
          );
        // The panel summarises the fields and toggles this call just wrote (#1083).
        ssoConfigurationPage.refreshReadiness(page, "oid");
        // The editor holds the stored provider, so the page is clean (#1572).
        ssoConfigurationPage.markPageClean(page);
      },
      // The read failed, so there is nothing to fill (#1681). A second argument rather than a catch, so a
      // throw from the fill is not reported as an unreachable server.
      () => {
        // A failure for a provider the editor has since left says nothing (#1693).
        if (
          !ssoConfigurationPage.replyStillSpeaksFor(page, "oid", provider_name)
        ) {
          return;
        }
        ssoConfigurationPage.hideEditor(page);
        ssoConfigurationPage.reportUnreadableProviderConfiguration(page);
        // The form is gone, so nothing in it is unsaved (#1572).
        ssoConfigurationPage.markPageClean(page);
      },
    );
    // Settles a throw from the fill (#1694); the read's own rejection was handled by the second argument.
    // A separate statement keeps Prettier from re-indenting the fill.
    read.catch(() => {
      ssoConfigurationPage.hideEditor(page);
      ssoConfigurationPage.reportUnfillableProviderForm(page);
      ssoConfigurationPage.markPageClean(page);
    });
  },
  // Serial of the latest redirect-URI request, so an older reply never overwrites a newer one.
  redirectUriSerial: 0,
  // Debounce handle for the redirect-URI request.
  redirectUriTimer: null,
  // Updates the read-only redirect-URI field from the server, its one producer (#1303). No local fallback,
  // so the value never diverges from what the login sends. Sets .value only (#221).
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
      field.placeholder = tr(
        "config.redirect_uri_needs_name",
        "Enter a provider name above to see the redirect URI",
      );
      ssoConfigurationPage.refreshReadiness(page, "oid");
      return;
    }

    field.placeholder = tr(
      "config.redirect_uri_loading",
      "Loading the redirect URI…",
    );
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
        // An unsaved provider or a failed request: say what to do, never show a value the server did not produce.
        () => {
          if (serial !== ssoConfigurationPage.redirectUriSerial) {
            return;
          }
          field.value = "";
          field.placeholder = tr(
            "config.redirect_uri_needs_save",
            "Save this provider to see its exact redirect URI",
          );
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
        () =>
          announce(
            tr(
              "config.redirect_uri_copied",
              "Redirect URI copied to the clipboard.",
            ),
          ),
        () =>
          announce(
            tr(
              "config.copy_failed",
              "Copy failed. Select the field and copy it manually.",
            ),
          ),
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
        ? tr(
            "config.redirect_uri_copied",
            "Redirect URI copied to the clipboard.",
          )
        : tr(
            "config.copy_failed",
            "Copy failed. Select the field and copy it manually.",
          ),
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
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId)
      .then((config) => {
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

            // The page region, since the editor and its status box were just hidden (#1572).
            ssoConfigurationPage.renderPageStatus(
              page,
              tr("config.provider_removed", "Provider removed."),
              true,
            );
          },
          // Reports a save failure, since the re-posted configuration can be refused for another reason (#336).
          // The editor stays open, so the outcome goes in its own region (#1572).
          function () {
            ssoConfigurationPage.renderSaveStatus(
              page,
              tr(
                "config.provider_remove_failed",
                "Could not remove the provider: the server refused the saved configuration, so nothing was changed. Reload the page and try again.",
              ),
              false,
            );
          },
        );
      })
      // The read before the delete can fail too (#1577); reported in the still-open editor's region.
      .catch(() =>
        ssoConfigurationPage.renderSaveStatus(
          page,
          tr(
            "config.config_read_failed",
            "Could not read the stored configuration, so nothing was changed. Reload the page and try again.",
          ),
          false,
        ),
      );
  },
  // One Save for both global switches, ManageLoginPageButtons (#722) and EnableSingleLogout (#727) (#1572).
  // Both are members of one document, read once and posted once, so the pair is stored whole or not at all.
  // The rest of the document rides along unchanged; the outcome is rendered inline.
  saveServerSettings: (page) => {
    ssoConfigurationPage.renderPageStatus(page, "");
    return ApiClient.getPluginConfiguration(
      ssoConfigurationPage.pluginUniqueId,
    ).then(
      (config) => {
        // Writes only a switch the administrator moved, so a concurrent change elsewhere is not undone.
        ssoConfigurationPage.applyMovedSwitch(
          page,
          config,
          "#ManageLoginPageButtons",
          "ManageLoginPageButtons",
        );
        ssoConfigurationPage.applyMovedSwitch(
          page,
          config,
          "#EnableSingleLogout",
          "EnableSingleLogout",
        );

        return ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(
          (result) => {
            Dashboard.processPluginConfigurationUpdateResult(result);
            ssoConfigurationPage.loadConfiguration(page);
            ssoConfigurationPage.renderPageStatus(
              page,
              tr("config.server_settings_saved", "Both server settings saved."),
              true,
            );
          },
          // Reports a save failure, since the re-posted configuration can be refused for another reason (#336).
          () =>
            ssoConfigurationPage.renderPageStatus(
              page,
              tr(
                "config.server_settings_save_failed",
                "The server refused the configuration, so neither switch was changed; both are written together or not at all. Reload the page and try again.",
              ),
              false,
            ),
        );
      },
      // The read before the write failed, so nothing was posted; say so.
      () =>
        ssoConfigurationPage.renderPageStatus(
          page,
          tr(
            "config.server_settings_read_failed",
            "Could not read the stored configuration, so nothing was saved and neither switch was changed. Reload the page and try again.",
          ),
          false,
        ),
    );
  },
  // Writes one switch onto the document only where it differs from what the page loaded.
  applyMovedSwitch: (page, config, selector, property) => {
    const control = page.querySelector(selector);
    if (!control || control.dataset.ssoLoaded === undefined) {
      return;
    }
    if (String(control.checked) !== control.dataset.ssoLoaded) {
      config[property] = control.checked;
    }
  },
  // Renders an outcome in the page's own status region, parallel to renderSaveStatus on Providers.
  renderPageStatus: (page, message, ok) => {
    const box = page.querySelector("#sso-page-status");
    if (!box) {
      return;
    }
    box.textContent = message || "";
    box.classList.remove("sso-status-ok", "sso-status-fail");
    if (message) {
      box.classList.add(ok ? "sso-status-ok" : "sso-status-fail");
    }
  },
  // Whether a reply about `provider_name` on `key` still speaks for the open editor (#1693).
  // It compares what the editor is about rather than a request counter, since closing the editor or
  // switching protocol issues no read.
  replyStillSpeaksFor: (page, key, provider_name) => {
    if (ssoConfigurationPage.openEditorKey(page) !== key) {
      return false;
    }
    const selector = page.querySelector(
      key === "saml" ? "#saml-selectProvider" : "#selectProvider",
    );
    return selector !== null && selector.value === provider_name;
  },
  // Whether a 200 body is this plugin's configuration (#1694): the protocol's member must be an object,
  // though it may be empty.
  isProviderConfiguration: (config, key) => {
    if (config === null || typeof config !== "object") {
      return false;
    }
    const member = key === "saml" ? config.SamlConfigs : config.OidConfigs;
    return member !== null && typeof member === "object";
  },
  // Reports a body that is not the configuration (#1694), worded apart from a failed read.
  reportUnrecognisedProviderConfiguration: (page) => {
    ssoConfigurationPage.renderPageStatus(
      page,
      tr(
        "config.provider_read_not_configuration",
        "The server answered, but what it sent is not this plugin's configuration, so this form was closed rather than filled from it. Reload the page and try again; if it keeps happening, check whether something in front of Jellyfin is answering for it.",
      ),
      false,
    );
  },
  // Reports a fill that threw part way (#1694); the form is closed rather than left half filled.
  reportUnfillableProviderForm: (page) => {
    ssoConfigurationPage.renderPageStatus(
      page,
      tr(
        "config.provider_fill_failed",
        "The stored configuration was read, but this form could not be filled from it and was closed. Reload the page and try again.",
      ),
      false,
    );
  },
  // Reports a read that failed while an editor was being filled (#1681); the editor is closed so no blanks
  // read as the provider, and the outcome goes to the page region.
  reportUnreadableProviderConfiguration: (page) => {
    ssoConfigurationPage.renderPageStatus(
      page,
      tr(
        "config.provider_read_failed",
        "Could not read the stored configuration, so this form was closed rather than showing values that are not stored. Reload the page and try again.",
      ),
      false,
    );
  },
  // Whether a save dropped the stored client secret (#1872), from the OidSecretStored readings before and
  // after the save; the server drops it when the endpoint or client id changes. Null when the provider did
  // not come back.
  secretDroppedByThisSave: (secret_was_stored, saved_provider) => {
    if (secret_was_stored !== true) {
      return false;
    }
    if (!saved_provider) {
      return null;
    }
    return saved_provider.OidSecretStored !== true;
  },
  // The status sentence and colour for a save outcome (#1872); a dropped secret or an unanswered read-back
  // is never a plain "saved" (#221).
  saveStatusFor: (outcome) => {
    const dropped = (outcome || {}).secretDropped;
    if (dropped === true) {
      return {
        message: tr(
          "config.provider_saved_secret_dropped",
          "Saved, and the stored client secret was dropped: the discovery endpoint or the client id changed while the secret field was blank, and a stored secret is never carried over to a re-identified provider. This provider signs nobody in until you enter its client secret here and save again.",
        ),
        ok: false,
      };
    }
    if (dropped === null) {
      return {
        message: tr(
          "config.provider_saved_secret_unknown",
          "Saved, but whether the stored client secret is still there could not be read back. If you changed the discovery endpoint or the client id with a blank secret field, the stored secret was dropped: enter the client secret here and save again.",
        ),
        ok: false,
      };
    }
    return {
      message: tr("config.provider_saved", "Settings saved."),
      ok: true,
    };
  },
  saveProvider: (page, provider_name) => {
    return new Promise((resolve, reject) => {
      const form_elements = ssoConfigurationPage.listArgumentsByType(page);

      ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId)
        .then((config) => {
          let current_config = {};
          if (config.OidConfigs.hasOwnProperty(provider_name)) {
            current_config = config.OidConfigs[provider_name];
          }

          // Read before the loops below mutate the stored provider in place (#1872).
          const secret_was_stored = current_config.OidSecretStored === true;

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
            const folders = ssoConfigurationPage.serializeEnabledFolders(elem);
            // A checklist that never drew leaves the stored restriction alone (#1607).
            if (folders !== null) {
              current_config[id] = folders;
            }
          });

          form_elements.role_map_fields.forEach((id) => {
            const elem = page.querySelector(`#${id}`);
            current_config[id] =
              ssoConfigurationPage.serializeRoleMappings(elem);
          });

          // The named profile and the inline template are written together (#1105): a save carrying both is
          // refused, so choosing a profile discards the template, confirmed in chooseProvisioningProfile.
          current_config.ProvisioningProfile =
            page.querySelector("#ProvisioningProfile").value || null;
          current_config.ProvisioningPolicyTemplate =
            current_config.ProvisioningProfile === null
              ? ssoConfigurationPage.readProvisioningTemplate(page, "")
              : null;

          config.OidConfigs[provider_name] = current_config;

          ApiClient.updatePluginConfiguration(
            ssoConfigurationPage.pluginUniqueId,
            config,
          ).then(
            function (result) {
              Dashboard.processPluginConfigurationUpdateResult(result);
              ssoConfigurationPage.nameSelectedProvider(
                page,
                "#selectProvider",
                provider_name,
              );
              ssoConfigurationPage.loadConfiguration(page);
              ssoConfigurationPage.loadProvider(page, provider_name);
              // Reads back whether the secret survived (#1872), as a promise the caller's status sentence waits on;
              // a failed read-back leaves the question unanswered rather than reporting "saved".
              const secret_dropped = ApiClient.getPluginConfiguration(
                ssoConfigurationPage.pluginUniqueId,
              ).then(
                (saved) =>
                  ssoConfigurationPage.secretDroppedByThisSave(
                    secret_was_stored,
                    ((saved || {}).OidConfigs || {})[provider_name],
                  ),
                // A failed read-back is decided as if no provider came back.
                () =>
                  ssoConfigurationPage.secretDroppedByThisSave(
                    secret_was_stored,
                    undefined,
                  ),
              );
              resolve({ secretDropped: secret_dropped });
            },
            // Attached to the save call so only a real save failure is reported; the message names both server
            // checks (#139, #336/#360).
            function () {
              reject(
                new Error(
                  tr("config.provider_save_failed", "Provider save failed"),
                ),
              );
            },
          );
        })
        // Settles a failed configuration read, or a throw from the fill, so a pressed Save always reports (#1577).
        .catch(() =>
          reject(
            new Error(
              tr("config.provider_save_failed", "Provider save failed"),
            ),
          ),
        );
    });
  },
  // Tests the saved provider through the elevated OID/Test endpoint (#163) and renders the non-secret facts
  // with textContent (#221).
  testProvider: (page, provider_name) => {
    const container = page.querySelector("#TestResult");
    if (!provider_name) {
      ssoConfigurationPage.renderTestMessage(
        container,
        tr(
          "config.test_needs_saved_provider",
          "Enter a provider name and save it first, then test.",
        ),
      );
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTestMessage(
      container,
      tr("config.test_running", "Testing…"),
    );

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
      // A transport or authorization failure, or an unconfigured provider; the message stays generic.
      () => {
        ssoConfigurationPage.renderTestMessage(
          container,
          tr(
            "config.test_failed",
            "Could not run the test. Make sure the provider is saved and that you are signed in as an administrator, then try again.",
          ),
        );
        ssoConfigurationPage.recordTestOutcome(page, "oid", false);
      },
    );
  },
  // Records a Test Connection outcome for the readiness panel (#1083); a rejection counts as a failure.
  recordTestOutcome: (page, key, ok) => {
    ssoConfigurationPage.readinessTestState[key] = ok;
    ssoConfigurationPage.readinessTestSubject[key] =
      ssoConfigurationPage.providerTestSubject(
        page,
        ssoConfigurationPage.readinessSpecs[key],
      );
    ssoConfigurationPage.refreshReadiness(page, key);
  },
  // Readiness panel (#1083), answered once in the rail (#1664).
  // Which protocol's editor is open, or null, computed from the two editors' `hidden` state (#1527).
  openEditorKey: (page) => {
    const oid = page.querySelector("#sso-editor");
    const saml = page.querySelector("#saml-editor");
    if (!oid || !saml) {
      return null;
    }
    return !oid.hidden ? "oid" : !saml.hidden ? "saml" : null;
  },
  // Brings the rail into line with the open editor, or shows the invitation when none is open.
  railReadiness: (page) => {
    const list = page.querySelector("#" + RAIL_READINESS_LIST);
    const empty = page.querySelector("#sso-rail-readiness");
    if (!list || !empty) {
      return;
    }
    const open = ssoConfigurationPage.openEditorKey(page);
    if (open === null) {
      list.replaceChildren();
      list.hidden = true;
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    list.hidden = false;
    ssoConfigurationPage.refreshReadiness(page, open);
  },
  // The last Test Connection outcome per protocol; null means not yet tested. Cleared on editor reset.
  readinessTestState: { oid: null, saml: null },
  // What the last test was about, so the wizard can tell whether it still speaks for the form (#1665).
  // Read only where the outcome is true, so it is not reset.
  readinessTestSubject: { oid: null, saml: null },
  // The fields a test depends on, the spec's required ids, as one comparable string using the
  // controlSignature separator (#1576). Reads `value` only, since every required id is a text field.
  providerTestSubject: (page, spec) =>
    spec.requiredIds
      .map((id) => {
        const field = page.querySelector("#" + id);
        return id + "=" + String((field && field.value) || "");
      })
      .join("\n"),
  // What each editor's panel is made of, all ids that already exist on the form.
  readinessSpecs: {
    oid: {
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
      enabledId: "Enabled",
    },
    saml: {
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
      enabledId: "saml-Enabled",
    },
  },
  // A field's human name, read from its localized label: the label's own text for a `for` label, the full
  // text for a wrapping checkbox label, and the id as the last resort.
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
  // Which fields are empty, read from the values, and which show an inline warning, read from the
  // validators' own output.
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
  // The flagged security toggles that are on; reads `.checked` and never assigns it.
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
  // Appends one row; the state word is in the text, never colour alone (#221), and set as textContent.
  appendReadinessRow: (list, ok, label, detail) => {
    const item = document.createElement("li");
    item.classList.add("fieldDescription");
    const state = ok
      ? tr("config.readiness_ready", "Ready")
      : tr("config.readiness_attention", "Needs attention");
    item.textContent = state + " - " + label + " - " + detail;
    list.appendChild(item);
  },
  // Rebuilds a panel from the form's current state; idempotent and request-free.
  refreshReadiness: (page, key) => {
    // Only the open editor may write (#1664): late async replies for the other protocol are dropped, since
    // the panel is rebuilt on the next open anyway.
    if (ssoConfigurationPage.openEditorKey(page) !== key) {
      return;
    }
    const spec = ssoConfigurationPage.readinessSpecs[key];
    // Read from the shared constant, so the two specs cannot point at different lists.
    const list = page.querySelector("#" + RAIL_READINESS_LIST);
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

    // The SAML reply URL exists once a name is typed, the OpenID redirect URI only after a save. Keys are
    // literal at each tr() call so the catalog's reference scan finds them.
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
  // The provider wizard (#1665): a conductor over the existing editor that holds no field and issues no
  // request of its own; it adds an order with a refusal at each step.
  // The save is inside step 2 because the redirect URI and the test need a stored provider, and Enable
  // comes last, so a provider is enabled only after a successful test.
  // The step is read from `data-step` on #sso-wizard; the protocol is openEditorKey.
  wizardStep: (page) => {
    const wizard = page.querySelector("#sso-wizard");
    const step = wizard ? Number(wizard.getAttribute("data-step")) : 0;
    return Number.isInteger(step) && step >= 0 ? step : 0;
  },
  // The wizard panels, which give the step count and order. A new step needs its stepper row too.
  wizardPanels: (page) => [...page.querySelectorAll(".sso-wizard-panel")],
  // Whether the Overview card asked for the wizard, via a flag on the dashboard's hash route.
  wizardRequested: () => /[?&]wizard=1(?:&|$)/.test(window.location.hash || ""),
  startWizard: (page) => {
    page.querySelector("#sso-wizard").hidden = false;
    page.querySelector("#sso-wizard-start").hidden = true;
    // Always starts at step one, so no earlier test outcome is asserted about a changed form.
    ssoConfigurationPage.setWizardStep(page, 0);
  },
  // Closes the wizard and changes nothing in the editor; unsaved edits keep the page dirty (#1572).
  closeWizard: (page) => {
    // Clears any refusal, so the next open does not show a stale sentence.
    ssoConfigurationPage.renderWizardRefusal(page, "");
    page.querySelector("#sso-wizard").hidden = true;
    page.querySelector("#sso-wizard-start").hidden = false;
  },
  setWizardStep: (page, step) => {
    page.querySelector("#sso-wizard").setAttribute("data-step", String(step));
    ssoConfigurationPage.renderWizard(page);
  },
  // Step one's action: opens the blank editor for the chosen protocol without advancing. Asks for
  // confirmation first when the page holds an edit, since addProvider discards it.
  wizardPick: (page, key) => {
    // Checks both the dirty class and the baseline, since a removed row fires no event.
    if (
      (ssoConfigurationPage.isPageDirty(page) ||
        ssoConfigurationPage.pageDiffersFromBaseline(page)) &&
      !window.confirm(
        tr(
          "config.wizard_switch_confirm",
          "This empties the editor, and what has been typed into it is not saved anywhere. Change the protocol anyway?",
        ),
      )
    ) {
      return;
    }

    if (key === "saml") {
      ssoConfigurationPage.addSamlProvider(page);
    } else {
      ssoConfigurationPage.addProvider(page);
    }

    // Scrolls the wizard back into view above the editor the opener scrolled to.
    const wizard = page.querySelector("#sso-wizard");
    if (wizard) {
      wizard.scrollIntoView({ block: "start" });
    }
    ssoConfigurationPage.renderWizard(page);
  },
  // What stops this step opening the next, or null, shared by Next and Finish. Read from the page at the
  // moment of asking, with the required fields from readinessFieldStates and their localized labels.
  wizardStepRefusal: (page, step) => {
    const key = ssoConfigurationPage.openEditorKey(page);
    // No open editor means no protocol, at every step.
    if (key === null) {
      return tr(
        "config.wizard_refuse_protocol",
        "No protocol is chosen yet. Pick OpenID Connect or SAML 2.0 above, and the editor below opens on the one you pick.",
      );
    }

    const spec = ssoConfigurationPage.readinessSpecs[key];

    if (step === 1) {
      const missing = ssoConfigurationPage.readinessFieldStates(
        page,
        spec,
      ).missing;
      return missing.length === 0
        ? null
        : tr(
            "config.wizard_refuse_required",
            "Still empty: {fields}. Fill every one of them in the editor below, then press Save.",
            { fields: missing.join(", ") },
          );
    }

    if (step === 2) {
      const url = page.querySelector("#" + spec.urlId);
      if (url && String(url.value || "").trim()) {
        return null;
      }
      return key === "saml"
        ? tr(
            "config.wizard_refuse_url_saml",
            "The ACS URL is still empty. It is computed from the provider name, so fill the name in the editor below.",
          )
        : tr(
            "config.wizard_refuse_url_oid",
            "The redirect URI is still empty. This server computes it for a provider it already holds, so press Save in the editor below and the field fills itself.",
          );
    }

    if (step === 3) {
      const tested = ssoConfigurationPage.readinessTestState[spec.testKey];
      if (tested === true) {
        // A green test counts only while the tested fields are unchanged.
        return ssoConfigurationPage.readinessTestSubject[spec.testKey] ===
          ssoConfigurationPage.providerTestSubject(page, spec)
          ? null
          : tr(
              "config.wizard_refuse_test_stale",
              "The connection fields have changed since the last Test Connection, so that result is not about the provider this form now describes. Save, and run Test Connection again.",
            );
      }
      // Not tested and tested-and-failed get different sentences.
      return tested === false
        ? tr(
            "config.wizard_refuse_test_failed",
            "The last Test Connection failed; this wizard does not enable a provider whose endpoint has not answered. Save the provider, then test again.",
          )
        : tr(
            "config.wizard_refuse_untested",
            "Nothing has been tested yet. Press Test Connection in the editor below; this step opens the next only on a test that succeeded.",
          );
    }

    if (step === 4) {
      const toggle = page.querySelector("#" + spec.enabledId);
      // A managed provider's toggle is disabled (#1104), so the refusal does not ask to tick it.
      if (toggle && toggle.disabled) {
        return tr(
          "config.wizard_refuse_managed",
          "This provider is owned by a configuration source outside Jellyfin, so it cannot be enabled from this page. Enable it where it is declared, or leave the wizard.",
        );
      }
      if (!toggle || !toggle.checked) {
        return tr(
          "config.wizard_refuse_disabled",
          "The provider is not enabled yet. Tick Enabled in the editor below, then press Save.",
        );
      }
      // Ticked is not saved; the page must be clean to finish.
      return ssoConfigurationPage.isPageDirty(page)
        ? tr(
            "config.wizard_refuse_unsaved",
            "The editor still holds changes nothing has saved. Press Save in the editor below, then finish.",
          )
        : null;
    }

    // Step one. Reaching here means an editor is open, which is what this step is for.
    return null;
  },
  // The first refusal of this step or any step before it. Cumulative, because the form can change under
  // a passed step, for example a card click clearing the test outcome.
  wizardRefusal: (page, step) => {
    for (let at = 0; at <= step; at += 1) {
      const refusal = ssoConfigurationPage.wizardStepRefusal(page, at);
      if (refusal !== null) {
        return refusal;
      }
    }
    return null;
  },
  // Moves between steps; going back is never refused, since every step reads the page afresh.
  wizardGo: (page, delta) => {
    const step = ssoConfigurationPage.wizardStep(page);
    const last = ssoConfigurationPage.wizardPanels(page).length - 1;

    if (delta < 0) {
      ssoConfigurationPage.setWizardStep(page, Math.max(0, step - 1));
      return;
    }

    const refusal = ssoConfigurationPage.wizardRefusal(page, step);
    if (refusal !== null) {
      ssoConfigurationPage.wizardRefuse(page, refusal);
      return;
    }

    ssoConfigurationPage.setWizardStep(page, Math.min(last, step + 1));
  },
  // Finishes after the last step's refusal check, reporting in the page region (#1572).
  wizardFinish: (page) => {
    const refusal = ssoConfigurationPage.wizardRefusal(
      page,
      ssoConfigurationPage.wizardStep(page),
    );
    if (refusal !== null) {
      ssoConfigurationPage.wizardRefuse(page, refusal);
      return;
    }

    ssoConfigurationPage.closeWizard(page);
    ssoConfigurationPage.renderPageStatus(
      page,
      tr(
        "config.wizard_done",
        "The provider is tested, enabled and saved. It is offered on the sign-in page from now on.",
      ),
      true,
    );
  },
  renderWizard: (page) => {
    // Guarded because the localization callback calls this on pages without a wizard.
    if (!page.querySelector("#sso-wizard")) {
      return;
    }

    const step = ssoConfigurationPage.wizardStep(page);
    const panels = ssoConfigurationPage.wizardPanels(page);
    const states = [...page.querySelectorAll(".sso-wizard-state")];
    const total = panels.length;

    panels.forEach((panel, index) => {
      panel.hidden = index !== step;
    });

    // The state is a word, not a colour (#221), with the position; aria-current marks the current row.
    states.forEach((state, index) => {
      const word =
        index < step
          ? tr("config.wizard_state_done", "done")
          : index === step
            ? tr("config.wizard_state_here", "you are here")
            : tr("config.wizard_state_todo", "not yet");
      state.textContent = tr(
        "config.wizard_step_state",
        "({state}, step {n} of {total})",
        { state: word, n: index + 1, total },
      );
      const row = state.parentNode;
      if (row) {
        if (index === step) {
          row.setAttribute("aria-current", "step");
        } else {
          row.removeAttribute("aria-current");
        }
      }
    });

    page.querySelector("#sso-wizard-back").disabled = step === 0;
    page.querySelector("#sso-wizard-next").hidden = step === total - 1;
    page.querySelector("#sso-wizard-finish").hidden = step !== total - 1;

    // A refusal is about the press that earned it, so moving steps clears it.
    ssoConfigurationPage.renderWizardRefusal(page, "");
  },
  // Shows a refusal on the step holding the control it names, moving there first because renderWizard
  // clears the region.
  wizardRefuse: (page, message) => {
    if (ssoConfigurationPage.openEditorKey(page) === null) {
      ssoConfigurationPage.setWizardStep(page, 0);
    }
    ssoConfigurationPage.renderWizardRefusal(page, message);
  },
  renderWizardRefusal: (page, message) => {
    const box = page.querySelector("#sso-wizard-refusal");
    if (!box) {
      return;
    }
    // Unhides before writing, since text set on a hidden live region is not announced.
    if (message) {
      box.hidden = false;
      box.textContent = message;
      return;
    }
    box.textContent = "";
    box.hidden = true;
  },
  // Aggregate configuration check (#1084), answered by the server at sso/Config/Check so no provider is
  // loaded into the form. Labels come from readinessFieldName. Advisory: writes only its own list.
  // Appends one check row.
  renderCheckRow: (list, ok, label, detail) => {
    const item = document.createElement("li");
    item.classList.add("fieldDescription");
    const state = ok
      ? tr("config.readiness_ready", "Ready")
      : tr("config.readiness_attention", "Needs attention");
    // textContent, since provider names and server messages reach this line (#221).
    item.textContent = state + " - " + label + " - " + detail;
    list.appendChild(item);
  },
  renderCheckNote: (list, message) => {
    const item = document.createElement("li");
    item.classList.add("fieldDescription");
    item.textContent = message;
    list.appendChild(item);
  },
  // One row's detail: what is empty, what a save would refuse, then whether the provider is off. A disabled
  // provider is stated but not flagged.
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
        // Shown first, since an unreadable configuration is why the list is empty (#1543).
        if (report && report.ConfigurationUnreadable === true) {
          ssoConfigurationPage.renderCheckNote(
            list,
            tr(
              "config.unreadable_configuration",
              "This server could not read its SSO configuration when it started, so it is running on default settings: no provider, no account link and no stored secret. Every SSO sign-in is refused until a configuration arrives - save a provider here, import one, or let a declarative source supply it. The server log says where the unreadable file was kept; keep that copy. If nobody can sign in at all, move the unreadable configuration file out of the way and delete the marker file beside it - its name is the configuration file plus .unreadable, with no timestamp on the end - then restart, and SSO will answer as it did before this check existed. Deleting the marker alone is not enough while the configuration file is still unreadable.",
            ),
          );
        }

        // Not when the unreadable line above already explains the empty list (#1543).
        if (
          rows.length === 0 &&
          !(report && report.ConfigurationUnreadable === true)
        ) {
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

        // Stated on every run: the check contacts no identity provider, so silence is not reachability.
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
  // Renders a server-named catalogue key (#1728) through the local catalogue; an unknown key renders as
  // itself. A fact's value fills {value}, and a missing value reads as not advertised.
  testText: (key, value) =>
    tr(String(key), String(key), {
      value:
        value === null || value === undefined
          ? tr("test.not_advertised", "(not advertised)")
          : String(value),
    }),
  renderTestResult: (container, result) => {
    container.replaceChildren();

    const heading = document.createElement("p");
    heading.classList.add("fieldDescription");
    // Boolean coercion; the label is fixed text, so no server value reaches the DOM here.
    heading.textContent =
      (result && result.Ok ? "✅ " : "⚠ ") +
      (result && result.Key
        ? ssoConfigurationPage.testText(result.Key)
        : tr("config.test_no_result", "No result returned."));
    container.appendChild(heading);

    const facts = result && Array.isArray(result.Facts) ? result.Facts : [];
    if (facts.length === 0) {
      return;
    }

    const list = document.createElement("ul");
    facts.forEach((fact) => {
      const item = document.createElement("li");
      // textContent so an issuer/endpoint value echoed by the provider stays inert on the page.
      item.textContent = ssoConfigurationPage.testText(
        fact && fact.Key,
        fact && fact.Value,
      );
      list.appendChild(item);
    });
    container.appendChild(list);
  },
  // Config export (#161): downloads the redacted document as a Blob, never by navigation, so no secret
  // lands in a URL.
  exportConfig: (page) => {
    const container = page.querySelector("#ConfigTransferResult");
    ssoConfigurationPage.renderTransferMessage(
      container,
      tr("config.config_exporting", "Exporting…"),
    );

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
          tr(
            "config.config_exported",
            "Exported. Provider secrets and account links are redacted from the file.",
          ),
        );
      },
      () =>
        ssoConfigurationPage.renderTransferMessage(
          container,
          tr(
            "config.config_export_failed",
            "Could not export the configuration. Make sure you are signed in as an administrator, then try again.",
          ),
        ),
    );
  },
  // Config import (#161): parses locally, then posts to the elevated endpoint, which merges fail-closed
  // (#186). Reloads the provider list on success.
  importConfig: (page, file) => {
    const container = page.querySelector("#ConfigTransferResult");
    if (!file) {
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTransferMessage(
      container,
      tr("config.config_importing", "Importing…"),
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
          url: ApiClient.getUrl("sso/Config/Import"),
          data: JSON.stringify(document_json),
          contentType: "application/json",
        });
      })
      .then(() => {
        ssoConfigurationPage.loadConfiguration(page);
        ssoConfigurationPage.renderTransferMessage(
          container,
          tr(
            "config.config_imported",
            "Imported. Re-enter each provider's secret and save it; secrets are never included in an export.",
          ),
        );
      })
      .catch((e) => {
        // Both parse and server failures show a generic message that never reflects a server value.
        const message =
          e && e.message === "not-json"
            ? tr(
                "config.config_import_not_json",
                "That file is not valid JSON. Choose a configuration file exported from this plugin.",
              )
            : tr(
                "config.config_import_failed",
                "Could not import the configuration. The file was rejected by the server, or you are not signed in as an administrator.",
              );
        ssoConfigurationPage.renderTransferMessage(container, message);
      });
  },
  // Account-link export (#1131) as a Blob download. The file is not redacted, and the status says so.
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
  // Account-link import (#1131): parses locally, and the server writes nothing if it refuses.
  // A refusal shows the server's reason, which names the entry to fix, through textContent.
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
      .then((answer) => {
        // No dataType on the fetch, so a refusal string arrives unquoted and a 2xx without JSON reaches the
        // uncounted branch.
        return Promise.resolve(answer)
          .then((body) =>
            body && typeof body.json === "function" ? body.json() : null,
          )
          .catch(() => null);
      })
      .then((result) => {
        // The restored count comes from the answer (#1520, #1517): a count, a zero, or no count at all.
        const restored =
          result && typeof result.Restored === "number"
            ? result.Restored
            : null;
        ssoConfigurationPage.renderTransferMessage(
          container,
          restored === null
            ? tr(
                "config.link_import_done_uncounted",
                "Imported, but this server did not say how many links it restored. The [SSO Audit] line in the server log carries the count.",
              )
            : restored === 0
              ? tr(
                  "config.link_import_done_none",
                  "Imported, and no link was restored. This file named none that could be restored here - check that it is the account-link export rather than the configuration export.",
                )
              : tr(
                  "config.link_import_done",
                  "Imported {count} account link(s). Each was restored onto the account this server holds for its username today.",
                  { count: String(restored) },
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

        // A non-2xx rejects with the Response, whose text is the refusal; anything else is generic.
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
  // The admin linked-accounts panel (#1121) over the elevated roster (#1119), with revoke through the
  // existing Unregister endpoint. Every value is attacker-influenced, so it renders through textContent.
  loadLinkedAccounts: (page) => {
    const container = page.querySelector("#LinkedAccountsResult");
    // The pending list (#1529) is a second view of the same roster read; both containers are written on
    // both arms.
    const pending = page.querySelector("#PendingApprovalsResult");
    ssoConfigurationPage.renderTransferMessage(
      container,
      tr("config.linked_accounts_loading", "Loading the linked accounts…"),
    );
    ssoConfigurationPage.renderTransferMessage(
      pending,
      tr(
        "config.pending_approvals_loading",
        "Loading the accounts waiting for approval…",
      ),
    );

    // Resolves to whether the roster was read, so an action's result never rests on a stale roster.
    return ApiClient.getJSON(ApiClient.getUrl("sso/Links/Roster")).then(
      (roster) => {
        ssoConfigurationPage.renderLinkedAccounts(page, container, roster);
        ssoConfigurationPage.renderPendingApprovals(page, pending);
        return true;
      },
      // Generic and input-independent, like the neighbouring admin actions: it never reflects a server value.
      () => {
        const failed = tr(
          "config.linked_accounts_failed",
          "Could not load the linked accounts. Make sure you are signed in as an administrator, then try again.",
        );
        ssoConfigurationPage.renderTransferMessage(container, failed);
        ssoConfigurationPage.renderTransferMessage(pending, failed);
        return false;
      },
    );
  },
  // The last roster read, kept so the filter re-renders without a request (#1529).
  linkedAccountRoster: null,
  // The searchable text of one row: username, provider, protocol and subject.
  linkedAccountHaystack: (account) =>
    [
      account && account.Username,
      account && account.UserId,
      ...(account && Array.isArray(account.Links) ? account.Links : []).flatMap(
        (link) => [
          link && link.Provider,
          link && link.Protocol,
          link && link.CanonicalName,
        ],
      ),
    ]
      .filter((part) => part !== null && part !== undefined)
      .join(" ")
      .toLowerCase(),
  filteredLinkedAccounts: (accounts, needle) => {
    const wanted = String(needle || "")
      .trim()
      .toLowerCase();
    if (wanted === "") {
      return accounts;
    }

    return accounts.filter((account) =>
      ssoConfigurationPage.linkedAccountHaystack(account).includes(wanted),
    );
  },
  renderLinkedAccounts: (page, container, roster) => {
    if (roster !== undefined) {
      ssoConfigurationPage.linkedAccountRoster = roster;
    }

    const held = ssoConfigurationPage.linkedAccountRoster;
    const accounts = held && Array.isArray(held.Accounts) ? held.Accounts : [];
    const filter = page.querySelector("#LinkedAccountsFilter");
    const shown = ssoConfigurationPage.filteredLinkedAccounts(
      accounts,
      filter && filter.value,
    );
    container.replaceChildren();

    // The empty state is a sentence, so it cannot be mistaken for a failed fetch.
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

    // A filter matching nothing gets its own sentence, distinct from "no account holds a link".
    if (shown.length === 0) {
      ssoConfigurationPage.renderTransferMessage(
        container,
        tr(
          "config.linked_accounts_filter_empty",
          "No linked account matches the filter. {total} are loaded.",
          { total: String(accounts.length) },
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
    shown.forEach((account) => {
      body.appendChild(
        ssoConfigurationPage.renderLinkedAccountRow(page, account),
      );
    });
    table.appendChild(body);
    container.appendChild(table);

    // The count line shows while a filter narrows the table, so a filtered table is not read as complete.
    if (shown.length !== accounts.length) {
      const count = document.createElement("div");
      count.className = "fieldDescription";
      count.textContent = tr(
        "config.linked_accounts_filter_count",
        "Showing {shown} of {total} linked accounts.",
        { shown: String(shown.length), total: String(accounts.length) },
      );
      container.appendChild(count);
    }
  },
  renderLinkedAccountRow: (page, account) => {
    const row = document.createElement("tr");
    const exists = account && account.AccountExists === true;
    const username =
      account && account.Username ? String(account.Username) : "";

    const name_cell = document.createElement("td");
    // An orphaned row is named as one, with the user id as its only identifier.
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
      // No button on an orphan row, since Unregister resolves by username and would only answer 404.
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
  // Formats the coalesced last-SSO-login stamp; null means no recorded login, rendered as a word.
  formatLastSsoLogin: (value) => {
    const never = tr("config.linked_accounts_never", "never");
    if (!value) {
      return never;
    }

    const when = new Date(value);
    return Number.isNaN(when.getTime()) ? never : when.toLocaleString();
  },
  // Revokes an account's link through the existing POST sso/Unregister/{username} (#1121).
  // The confirmation names the consequence: native password login reopens for that account even on an
  // SSO-only server (#165). The server refuses an administrator's revoke of their own last way in (#1741).
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
        // Re-read rather than edited, so the table shows only what the server reports.
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
      // Generic, except the self-revoke refusal (#1741), matched on its clause and shown in catalogue words.
      // The generic sentence goes up before the body is read, since the body can stall.
      (rejection) => {
        ssoConfigurationPage.renderTransferMessage(
          result,
          tr(
            "config.linked_accounts_revoke_failed",
            "Could not revoke the SSO links. Make sure you are signed in as an administrator, then try again.",
          ),
        );
        const status =
          rejection && typeof rejection.status === "number"
            ? rejection.status
            : 0;
        const body =
          rejection && typeof rejection.text === "function"
            ? Promise.resolve(rejection.text()).catch(() => "")
            : Promise.resolve("");
        return body.then((text) => {
          if (
            status === 403 &&
            /no other administrator on this server/i.test(String(text || ""))
          ) {
            ssoConfigurationPage.renderTransferMessage(
              result,
              tr(
                "config.linked_accounts_revoke_refused_would_strand_server",
                "The server refused to revoke your own SSO links: no other administrator on this server holds an SSO link that can sign them in, so the revoke could have left this server with no administrator able to reach it. Ask another administrator to revoke them for you, link another administrator account to a provider first and then revoke your own, or set a password on an administrator account from the Jellyfin dashboard - a password this server generated for an account is not one anybody can sign in with. Nothing was changed.",
              ),
            );
          }
        });
      },
    );
  },
  // The most pending rows drawn (#1529); a line says what was cut.
  PENDING_APPROVALS_BOUND: 100,
  // Every link the server reports as waiting, as (account, link) pairs in roster order. The server decides
  // what waiting means; a disabled flag alone is never read as pending.
  pendingApprovals: (roster) => {
    const accounts =
      roster && Array.isArray(roster.Accounts) ? roster.Accounts : [];
    return accounts.flatMap((account) => {
      // One row per account, on its first waiting link, so the count is a count of accounts.
      const waiting = (
        account && Array.isArray(account.Links) ? account.Links : []
      ).find((link) => link && link.PendingApprovalSinceUtc);
      return waiting ? [{ account, link: waiting }] : [];
    });
  },
  renderPendingApprovals: (page, container) => {
    const waiting = ssoConfigurationPage.pendingApprovals(
      ssoConfigurationPage.linkedAccountRoster,
    );
    container.replaceChildren();

    // Its own empty sentence, distinct from the linked-accounts one.
    if (waiting.length === 0) {
      ssoConfigurationPage.renderTransferMessage(
        container,
        tr(
          "config.pending_approvals_empty",
          "No account is waiting for approval.",
        ),
      );
      return;
    }

    const shown = waiting.slice(
      0,
      ssoConfigurationPage.PENDING_APPROVALS_BOUND,
    );
    const table = document.createElement("table");
    const head = document.createElement("thead");
    const head_row = document.createElement("tr");
    [
      tr("config.linked_accounts_column_account", "Account"),
      tr("config.pending_approvals_column_identity", "Identity"),
      tr("config.pending_approvals_column_since", "Waiting since"),
      tr("config.linked_accounts_column_action", "Action"),
    ].forEach((label) => {
      const cell = document.createElement("th");
      cell.textContent = label;
      head_row.appendChild(cell);
    });
    head.appendChild(head_row);
    table.appendChild(head);

    const body = document.createElement("tbody");
    shown.forEach(({ account, link }) => {
      body.appendChild(
        ssoConfigurationPage.renderPendingApprovalRow(page, account, link),
      );
    });
    table.appendChild(body);
    container.appendChild(table);

    if (shown.length !== waiting.length) {
      const note = document.createElement("div");
      note.className = "fieldDescription";
      note.textContent = tr(
        "config.pending_approvals_truncated",
        "Showing the first {shown} of {total} accounts waiting for approval. Approve or revoke some to see the rest.",
        { shown: String(shown.length), total: String(waiting.length) },
      );
      container.appendChild(note);
    }
  },
  renderPendingApprovalRow: (page, account, link) => {
    const row = document.createElement("tr");
    const username =
      account && account.Username ? String(account.Username) : "";

    // Every value is attacker-influenced, so the row is textContent (#221).
    const name_cell = document.createElement("td");
    name_cell.textContent = username;
    row.appendChild(name_cell);

    const identity_cell = document.createElement("td");
    identity_cell.textContent = tr(
      "config.pending_approvals_identity_line",
      "{provider} ({protocol}) - {canonical}",
      {
        provider: String((link && link.Provider) || ""),
        protocol: String((link && link.Protocol) || ""),
        canonical: String((link && link.CanonicalName) || ""),
      },
    );
    row.appendChild(identity_cell);

    // The provisioning instant, which the column heading names.
    const since_cell = document.createElement("td");
    since_cell.textContent = ssoConfigurationPage.formatLastSsoLogin(
      link && link.PendingApprovalSinceUtc,
    );
    row.appendChild(since_cell);

    // Always a button: the server reports a pending instant only for rows approve will accept.
    const action_cell = document.createElement("td");
    const button = document.createElement("button");
    button.setAttribute("is", "emby-button");
    button.setAttribute("type", "button");
    button.classList.add("raised", "button-submit", "emby-button");
    button.textContent = tr("config.pending_approvals_approve", "Approve");
    button.addEventListener("click", (e) => {
      ssoConfigurationPage.approvePendingAccount(page, account, link);
      e.preventDefault();
      return false;
    });
    action_cell.appendChild(button);
    row.appendChild(action_cell);

    return row;
  },
  // Approves a pending account through POST sso/Links/Approve/{mode}/{provider} (#1529). The confirmation
  // says the account is enabled and nothing else changes.
  approvePendingAccount: (page, account, link) => {
    const result = page.querySelector("#PendingApprovalsActionResult");
    const username =
      account && account.Username ? String(account.Username) : "";
    const userId = account && account.UserId;
    const provider = String((link && link.Provider) || "");
    if (
      !window.confirm(
        tr(
          "config.pending_approvals_confirm",
          "Approve {user}? This enables the account so it can sign in through {provider}. Nothing else changes: its permissions stay as the provisioning set them.",
          { user: username, provider },
        ),
      )
    ) {
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTransferMessage(
      result,
      tr("config.pending_approvals_approving", "Approving {user}…", {
        user: username,
      }),
    );

    // The mode is the protocol's short name; the canonical name travels in the body, since it may hold a slash.
    const mode = link && link.Protocol === "SAML" ? "SAML" : "OID";
    return ApiClient.fetch({
      type: "POST",
      url: ApiClient.getUrl(
        "sso/Links/Approve/" + mode + "/" + encodeURIComponent(provider),
      ),
      data: JSON.stringify(String((link && link.CanonicalName) || "")),
      contentType: "application/json",
    }).then(
      () =>
        // Re-read, so the row disappears because the server no longer reports it.
        ssoConfigurationPage.loadLinkedAccounts(page).then((read) => {
          // A failed re-read leaves the old roster, so no sentence is chosen from it.
          if (!read) {
            ssoConfigurationPage.renderTransferMessage(
              result,
              tr(
                "config.linked_accounts_failed",
                "Could not load the linked accounts. Make sure you are signed in as an administrator, then try again.",
              ),
            );
            return;
          }

          // A 204 can also mean the account had gone, so the sentence is chosen from the re-read roster.
          const held = ssoConfigurationPage.linkedAccountRoster;
          const rows =
            held && Array.isArray(held.Accounts) ? held.Accounts : [];
          const gone = rows.some(
            (row) =>
              row && row.UserId === userId && row.AccountExists === false,
          );
          ssoConfigurationPage.renderTransferMessage(
            result,
            gone
              ? tr(
                  "config.pending_approvals_account_gone",
                  "That account no longer exists, so nothing was enabled. The list has been re-read.",
                )
              : tr(
                  "config.pending_approvals_approved",
                  "Approved. {user} can sign in now.",
                  { user: username },
                ),
          );
        }),
      (e) => {
        // A non-2xx rejects with the Response. Two refusals get their own sentence, the administrator one matched
        // on the endpoint's own words; everything else is generic.
        const status = e && typeof e.status === "number" ? e.status : 0;
        const body =
          e && typeof e.text === "function"
            ? Promise.resolve(e.text()).catch(() => "")
            : Promise.resolve("");
        return body.then((text) => {
          const administrator =
            status === 403 && /is an administrator/i.test(String(text || ""));
          const stale = status === 404;
          const message = administrator
            ? tr(
                "config.pending_approvals_refused_administrator",
                "That account is an administrator and is not approved from here. Enable it in the Jellyfin dashboard.",
              )
            : stale
              ? tr(
                  "config.pending_approvals_not_pending",
                  "That account is no longer waiting for approval. The list has been re-read.",
                )
              : tr(
                  "config.pending_approvals_failed",
                  "Could not approve the account. Make sure you are signed in as an administrator, then try again.",
                );
          // A stale row is re-read so it is not offered again.
          const refresh = stale
            ? ssoConfigurationPage.loadLinkedAccounts(page)
            : Promise.resolve();
          const say = () =>
            ssoConfigurationPage.renderTransferMessage(result, message);
          return refresh.then(say, say);
        });
      },
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

  // Localizes the page's labels (#913) with the shared applier, loaded from its absolute SSOViews URL.
  // Best-effort: the try/catch covers ApiClient.getUrl throwing synchronously, the .catch the import.
  localize: (view) => {
    try {
      import(ApiClient.getUrl("SSOViews/i18n.js"))
        .then((module) =>
          module.loadCatalog().then(() => {
            i18n = module;
            module.applyTo(view);
            // Repaints the wizard rows, which tr() may have written before the catalogue arrived (#1665).
            ssoConfigurationPage.renderWizard(view);
          }),
        )
        .catch(() => {});
    } catch {
      // Keep the built-in English; the page's own functionality is unaffected.
    }
  },

  // Provider templates (#726).
  // Fills a preset picker from its catalog, keeping the authored blank option.
  populatePresetPicker: (page, selectId, presets) => {
    const select = page.querySelector("#" + selectId);
    if (!select) {
      return;
    }
    Object.keys(presets).forEach((key) => {
      const option = document.createElement("option");
      option.value = key;
      option.textContent = presets[key].label;
      // A marker rather than a tr() call, so the label is translated when the catalog lands (#1602). Only
      // descriptive labels carry a key; product names do not.
      if (presets[key].labelKey) {
        option.setAttribute("data-i18n", presets[key].labelKey);
      }

      select.appendChild(option);
    });
  },
  renderPresetNote: (page, noteId, message) => {
    const box = page.querySelector("#" + noteId);
    if (box) {
      box.textContent = message || "";
    }
  },
  // Applies an OpenID preset: clears the managed toggles, fills the marked fields and pre-checks the listed
  // toggles. Never touches the name or secret and never saves.
  applyOidcPreset: (page, key) => {
    OIDC_PRESET_MANAGED_TOGGLES.forEach((prop) => {
      const el = page.querySelector("#" + prop);
      if (el) {
        el.checked = false;
      }
    });

    const preset = OIDC_PRESETS[key];
    if (!preset) {
      // The blank option clears the note and re-syncs without touching the fields.
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
    ssoConfigurationPage.renderPresetNote(
      page,
      "OidPreset-note",
      tr(preset.noteKey, preset.note),
    );
  },
  // The SAML counterpart, with "saml-" prefixed ids and the same clear-then-apply order.
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
      tr(preset.noteKey, preset.note),
    );
  },

  // SAML provider workspace (#725), a lifecycle parallel to the OpenID one and kept separate.
  // Each persisted field id is "saml-" plus its SamlConfig property (see samlPropOf), locked by a
  // conformance test. The element-argument helpers above are reused as they are.

  // SAML settings whose enabled state is a downgrade, as property names without the prefix.
  // ProvisionNewUsersDisabled is hardening and not flagged.
  samlInsecureFieldIds: ["DoNotValidateAudience"],
  samlSensitiveFieldIds: ["AllowExistingAccountLink"],
  samlPropOf: (id) => id.slice("saml-".length),
  populateSamlProviders: (page, providers) => {
    const select = page.querySelector("#saml-selectProvider");
    // The same preservation its OpenID twin does, for the same reason (#1693).
    const chosen = select.value;
    select.querySelectorAll("option").forEach((option) => option.remove());
    Object.keys(providers).forEach((provider_name) => {
      select.appendChild(new Option(provider_name, provider_name));
    });
    select.value = chosen;
    ssoConfigurationPage.renderSamlProviderCards(page, providers);
  },
  // SAML provider cards, built with textContent like renderProviderCards (#221).
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
        warn.title = tr(
          "config.insecure_option_active",
          "This provider has an active insecure or sensitive setting.",
        );
        card.append(warn);
      }

      list.appendChild(card);
    });
  },
  // The other half of the one-workspace rule stated at showEditor (#1527).
  showSamlEditor: (page) => {
    ssoConfigurationPage.hideEditor(page);
    page.querySelector("#saml-editor").hidden = false;
    ssoConfigurationPage.railReadiness(page);
  },
  hideSamlEditor: (page) => {
    page.querySelector("#saml-editor").hidden = true;
    ssoConfigurationPage.railReadiness(page);
  },
  setSamlEditorTitle: (page, title) => {
    page.querySelector("#saml-editor-title").textContent = title;
  },
  // Loads a SAML card into a freshly reset editor, like openProvider.
  openSamlProvider: (page, provider_name) => {
    page.querySelector("#saml-selectProvider").value = provider_name;
    ssoConfigurationPage.resetSamlEditor(page);
    ssoConfigurationPage.clearSamlValidationErrors(page);
    ssoConfigurationPage.renderSamlSaveStatus(page, "");
    ssoConfigurationPage.renderPageStatus(page, "");
    ssoConfigurationPage.setSamlEditorTitle(page, provider_name);
    ssoConfigurationPage.showSamlEditor(page);
    ssoConfigurationPage.loadSamlProvider(page, provider_name);
    // Opening is a read; loadSamlProvider re-marks the page clean after its fill (#1572).
    ssoConfigurationPage.markPageClean(page);
    page.querySelector("#saml-editor").scrollIntoView({ block: "start" });
  },
  addSamlProvider: (page) => {
    page.querySelector("#saml-selectProvider").value = "";
    ssoConfigurationPage.resetSamlEditor(page);
    ssoConfigurationPage.clearSamlValidationErrors(page);
    ssoConfigurationPage.renderSamlSaveStatus(page, "");
    ssoConfigurationPage.renderPageStatus(page, "");
    ssoConfigurationPage.setSamlEditorTitle(
      page,
      tr("config.new_provider", "New provider"),
    );
    ssoConfigurationPage.syncSamlDependentFields(page);
    // Restores a form left frozen by a managed provider opened just before (#1104); a new one is never managed.
    ssoConfigurationPage.applyManagedState(page, "saml", "");
    ssoConfigurationPage.showSamlEditor(page);
    // A blank editor is clean (#1572); its Save stays closed until the required fields are filled.
    ssoConfigurationPage.markPageClean(page);
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
    // Reset the template picker and its note so a provider never shows a stale template (#726).
    const samlPreset = page.querySelector("#saml-Preset");
    if (samlPreset) {
      samlPreset.value = "";
    }
    ssoConfigurationPage.renderPresetNote(page, "saml-Preset-note", "");
  },
  // Returns every accordion inside the SAML editor to its authored default.
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

    // Expands the security accordion, and the insecure list, for active downgrades, like syncDependentFields.
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

    ssoConfigurationPage.refreshOptionFoldCounts(page);
  },
  // The SAML half of setInsecureOptionsExpanded.
  setSamlInsecureOptionsExpanded: (page, expanded) => {
    const fold = page.querySelector("#saml-insecure-options");
    if (!fold) {
      return;
    }
    fold.open = expanded;
  },
  // The SAML save contract, mirroring listArgumentsByType: marked inputs with "saml-" plus property ids.
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
    const read = ApiClient.getPluginConfiguration(
      ssoConfigurationPage.pluginUniqueId,
    ).then(
      (config) => {
        // The same drop the OpenID loader makes, for the same reason (#1693).
        if (
          !ssoConfigurationPage.replyStillSpeaksFor(page, "saml", provider_name)
        ) {
          return;
        }
        // The same check the OpenID loader makes (#1694).
        if (!ssoConfigurationPage.isProviderConfiguration(config, "saml")) {
          ssoConfigurationPage.hideSamlEditor(page);
          ssoConfigurationPage.reportUnrecognisedProviderConfiguration(page);
          ssoConfigurationPage.markPageClean(page);
          return;
        }
        const provider = (config.SamlConfigs || {})[provider_name] || {};

        const form_elements =
          ssoConfigurationPage.listSamlArgumentsByType(page);

        page.querySelector("#saml-provider-name").value = provider_name;

        form_elements.text_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          // The write-only signing keys come back null, so the field stays blank and keeps the stored key.
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
          // Always set from the loaded provider, like the OpenID loader, so no stale toggle is re-saved.
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
          ssoConfigurationPage.provisioningProfileNames(config),
        );

        ssoConfigurationPage.syncSamlDependentFields(page);
        ssoConfigurationPage.updateSamlUrls(page);
        // Last, for the same reason as the OpenID arm (#1104), including the profile re-sync after it.
        ssoConfigurationPage
          .applyManagedState(page, "saml", provider_name)
          .then(() =>
            ssoConfigurationPage.syncProvisioningProfileState(
              page,
              "saml-",
              ssoConfigurationPage.isManagedProvider("saml", provider_name),
            ),
          );
        // The panel summarises the fields and toggles this call just wrote (#1083).
        ssoConfigurationPage.refreshReadiness(page, "saml");
        // The editor holds the stored provider, so the page is clean (#1572).
        ssoConfigurationPage.markPageClean(page);
      },
      // The same failure arm as the OpenID loader (#1681).
      () => {
        if (
          !ssoConfigurationPage.replyStillSpeaksFor(page, "saml", provider_name)
        ) {
          return;
        }
        ssoConfigurationPage.hideSamlEditor(page);
        ssoConfigurationPage.reportUnreadableProviderConfiguration(page);
        ssoConfigurationPage.markPageClean(page);
      },
    );
    // The same catch its OpenID twin carries, for the same reason (#1694).
    read.catch(() => {
      ssoConfigurationPage.hideSamlEditor(page);
      ssoConfigurationPage.reportUnfillableProviderForm(page);
      ssoConfigurationPage.markPageClean(page);
    });
  },
  // The canonical external base for the SAML URLs (#724): the Base URL Override or this server's address,
  // normalized like the server's CanonicalBaseUrl.
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
  // Updates the read-only ACS and SP-metadata URLs (#725/#569) from the provider name, as the server builds
  // them (#336). Sets .value only (#221).
  updateSamlUrls: (page) => {
    const acs = page.querySelector("#saml-AcsUrl");
    const metadata = page.querySelector("#saml-MetadataUrl");
    const name = page.querySelector("#saml-provider-name").value.trim();
    const base = ssoConfigurationPage.samlCanonicalBase(page);

    if (acs) {
      acs.value = name ? base + "/sso/SAML/post/" + name : "";
      acs.placeholder = name
        ? ""
        : tr(
            "config.acs_url_needs_name",
            "Enter a provider name above to see the ACS URL",
          );
    }
    if (metadata) {
      metadata.value = name ? base + "/sso/SAML/metadata/" + name : "";
      metadata.placeholder = name
        ? ""
        : tr(
            "config.metadata_url_needs_name",
            "Enter a provider name above to see the metadata URL",
          );
    }
    const status = page.querySelector("#saml-url-copied");
    if (status) {
      status.textContent = "";
    }
    ssoConfigurationPage.refreshReadiness(page, "saml");
  },
  // Copies a computed SAML URL to the clipboard, like copyRedirectUri (#724).
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
    const copied = () =>
      tr("config.saml_url_copied", "{label} copied to the clipboard.", {
        label,
      });
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(
        () => announce(copied()),
        () =>
          announce(
            tr(
              "config.copy_failed",
              "Copy failed. Select the field and copy it manually.",
            ),
          ),
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
        ? copied()
        : tr(
            "config.copy_failed",
            "Copy failed. Select the field and copy it manually.",
          ),
    );
  },
  // Imports IdP metadata (#735) from a URL or pasted XML and pre-fills the endpoint and certificates for
  // review. Nothing is saved; the IdP EntityId is shown for reference only.
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
          ? tr("config.metadata_needs_url", "Enter a metadata URL first.")
          : tr("config.metadata_needs_xml", "Paste the metadata XML first."),
      );
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTransferMessage(
      status,
      tr("config.metadata_importing", "Importing metadata…"),
    );
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
        // Re-runs validation on the imported values so a bad one shows at once.
        ssoConfigurationPage.validateSamlEndpoint(page);
        ssoConfigurationPage.validateSamlCertificate(
          page,
          "saml-SamlCertificate",
          tr("config.idp_signing_certificate", "IdP Signing Certificate"),
        );
        // EntityId is reference-only: shown as inert text, never written into a field.
        const entity = result && result.EntityId ? result.EntityId : "";
        ssoConfigurationPage.renderTransferMessage(
          status,
          entity
            ? tr(
                "config.metadata_imported_with_entity",
                "Imported the endpoint and certificate. The provider's entity id is {entity} (reference only; set the SAML Client ID yourself). Review the fields and Save.",
                { entity },
              )
            : tr(
                "config.metadata_imported",
                "Imported the endpoint and certificate. Review the fields and Save.",
              ),
        );
      },
      () =>
        ssoConfigurationPage.renderTransferMessage(
          status,
          tr(
            "config.metadata_import_failed",
            "Could not import the metadata. Check the URL or XML, sign in as an administrator, and use a reachable, non-private address.",
          ),
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
  // Mirrors the server's provider-name checks (#336/#360), as validateProviderName does.
  validateSamlProviderName: (page) => {
    const value = page.querySelector("#saml-provider-name").value;
    if (!value.trim()) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-provider-name",
        tr("config.validation_name_required", "A provider name is required."),
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
        tr(
          "config.validation_name_control_chars",
          "Remove control characters (such as a tab or newline, often introduced by copy-paste) from the name.",
        ),
      );
      return;
    }
    const reserved = ["\\", "/", "?", "#", "%"];
    if (reserved.some((c) => value.includes(c))) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-provider-name",
        tr(
          "config.validation_name_reserved",
          "Remove the backslash and the characters / ? # % from the name.",
        ),
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
      value
        ? ""
        : tr("config.validation_required", "{label} is required.", { label }),
    );
  },
  validateSamlEndpoint: (page) => {
    const value = page.querySelector("#saml-SamlEndpoint").value.trim();
    if (!value) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-SamlEndpoint",
        tr(
          "config.validation_saml_endpoint_required",
          "SAML SSO Endpoint is required.",
        ),
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
        tr(
          "config.validation_saml_endpoint_absolute",
          "Enter an absolute URL, e.g. https://idp.example.com/sso",
        ),
      );
      return;
    }
    if (url.protocol === "http:") {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-SamlEndpoint",
        tr(
          "config.validation_saml_endpoint_insecure",
          "Uses http://, so the redirect would be unencrypted. Prefer an https:// endpoint.",
        ),
      );
      return;
    }
    if (url.protocol !== "https:") {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-SamlEndpoint",
        tr(
          "config.validation_saml_endpoint_https",
          "Use an https:// URL for the SAML endpoint.",
        ),
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
        tr(
          "config.validation_base_origin_only",
          "Enter a full URL such as https://jellyfin.example.com (scheme and host; add Jellyfin's path base if it has one).",
        ),
      );
      return;
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-BaseUrlOverride",
        tr(
          "config.validation_base_origin",
          "Enter a full origin such as https://jellyfin.example.com",
        ),
      );
      return;
    }
    // A path base is accepted and the plugin's own route is not, for the reason validateBaseUrl gives (#1712).
    if (url.search || url.hash || ssoConfigurationPage.isPluginRoute(url)) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-BaseUrlOverride",
        tr(
          "config.validation_base_not_the_acs",
          "Enter the base URL, not the /sso/... ACS URL: the origin plus Jellyfin's path base if it runs under one, e.g. https://jellyfin.example.com or https://jellyfin.example.com/jellyfin, with no query or fragment.",
        ),
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "saml-BaseUrlOverride", "");
  },
  // Warns on a certificate that is neither PEM nor bare Base64; never blocks the save.
  validateSamlCertificate: (page, id, label) => {
    const raw = page.querySelector("#" + id).value.trim();
    if (!raw) {
      // An empty value is not a shape error; the server enforces the primary's presence.
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
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId)
      .then((config) => {
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
            // The page region, since this editor was just closed (#1572).
            ssoConfigurationPage.renderPageStatus(
              page,
              tr("config.provider_removed", "Provider removed."),
              true,
            );
          },
          // The editor is still open, so the outcome goes beside the button.
          function () {
            ssoConfigurationPage.renderSamlSaveStatus(
              page,
              tr(
                "config.provider_remove_failed",
                "Could not remove the provider: the server refused the saved configuration, so nothing was changed. Reload the page and try again.",
              ),
              false,
            );
          },
        );
      })
      // The read can fail on its own (#1577); reported in the still-open editor.
      .catch(() =>
        ssoConfigurationPage.renderSamlSaveStatus(
          page,
          tr(
            "config.config_read_failed",
            "Could not read the stored configuration, so nothing was changed. Reload the page and try again.",
          ),
          false,
        ),
      );
  },
  saveSamlProvider: (page, provider_name) => {
    return new Promise((resolve, reject) => {
      const form_elements = ssoConfigurationPage.listSamlArgumentsByType(page);

      ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId)
        .then((config) => {
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

          // Same rule as the OpenID arm above, including the discard.
          current_config.ProvisioningProfile =
            page.querySelector("#saml-ProvisioningProfile").value || null;
          current_config.ProvisioningPolicyTemplate =
            current_config.ProvisioningProfile === null
              ? ssoConfigurationPage.readProvisioningTemplate(page, "saml-")
              : null;

          config.SamlConfigs[provider_name] = current_config;

          ApiClient.updatePluginConfiguration(
            ssoConfigurationPage.pluginUniqueId,
            config,
          ).then(
            function (result) {
              Dashboard.processPluginConfigurationUpdateResult(result);
              ssoConfigurationPage.nameSelectedProvider(
                page,
                "#saml-selectProvider",
                provider_name,
              );
              ssoConfigurationPage.loadConfiguration(page);
              ssoConfigurationPage.loadSamlProvider(page, provider_name);
              // The outcome is rendered inline by the caller, in the editor's own status region (#1572).
              resolve();
            },
            function () {
              reject(
                new Error(
                  tr("config.provider_save_failed", "Provider save failed"),
                ),
              );
            },
          );
        })
        // Settles a failed read so a pressed Save always reports, as in saveProvider (#1577).
        .catch(() =>
          reject(
            new Error(
              tr("config.provider_save_failed", "Provider save failed"),
            ),
          ),
        );
    });
  },
  // Tests a saved SAML provider through the elevated SAML/Test endpoint (#163), which returns only
  // non-secret certificate facts; rendered like the OpenID test.
  testSamlProvider: (page, provider_name) => {
    const container = page.querySelector("#saml-TestResult");
    if (!provider_name) {
      ssoConfigurationPage.renderTestMessage(
        container,
        tr(
          "config.test_needs_saved_provider",
          "Enter a provider name and save it first, then test.",
        ),
      );
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTestMessage(
      container,
      tr("config.test_running", "Testing…"),
    );

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
          tr(
            "config.test_failed",
            "Could not run the test. Make sure the provider is saved and that you are signed in as an administrator, then try again.",
          ),
        );
        ssoConfigurationPage.recordTestOutcome(page, "saml", false);
      },
    );
  },
  // The Overview tab (#1527), a status view that holds no setting.
  // sso/Config/Check says whether a provider is complete and enabled, never whether it is reachable;
  // sso/Links/Roster gives the newest sign-in per provider. Built with textContent (#221).
  // A failed read is said in words and never shown as an empty server.
  renderOverview: (page) => {
    const cards = page.querySelector("#sso-overview-providers");
    if (!cards) {
      return Promise.resolve();
    }

    // Reads the configuration here, so one painter draws the cards with their downgrade mark (#1727).
    // A failed read answers null and the cards are drawn without the mark.
    return Promise.all([
      ApiClient.getJSON(ApiClient.getUrl("sso/Config/Check")).catch(() => null),
      ApiClient.getJSON(ApiClient.getUrl("sso/Links/Roster")).catch(() => null),
      ApiClient.getPluginConfiguration(
        ssoConfigurationPage.pluginUniqueId,
      ).catch(() => null),
    ]).then(([report, roster, config]) =>
      ssoConfigurationPage.paintOverview(page, report, roster, config),
    );
  },

  // One status line of an Overview card; states rather than verdicts, so not renderCheckRow.
  appendOverviewRow: (list, ok, label) => {
    const item = document.createElement("li");
    item.classList.add("fieldDescription");
    item.dataset.state = ok ? "ok" : "bad";
    item.textContent = label;
    list.appendChild(item);
  },

  // The downgrade classes one provider has on, as catalogue keys of the Providers form headings (#1727),
  // read through the same id lists as the Providers "Review" flag. No count, since the fold counts differ.
  activeDowngradeClasses: (protocol, provider) => {
    if (!provider) {
      return [];
    }

    const saml = protocol === "SAML";
    const classes = [
      {
        ids: saml
          ? ssoConfigurationPage.samlInsecureFieldIds
          : ssoConfigurationPage.insecureFieldIds,
        name: tr("config.security_insecure_heading", "Insecure options"),
      },
      {
        ids: saml
          ? ssoConfigurationPage.samlSensitiveFieldIds
          : ssoConfigurationPage.sensitiveFieldIds,
        name: tr(
          "config.security_adoption_heading",
          "Account adoption (sensitive)",
        ),
      },
    ];

    return classes
      .filter((one) => one.ids.some((id) => Boolean(provider[id])))
      .map((one) => one.name);
  },
  // The stored configuration of the provider a report row names, keyed by the report's protocol spelling,
  // or null where the configuration did not load.
  storedProviderFor: (row, config) => {
    if (!config) {
      return null;
    }

    const providers =
      (row.Protocol === "SAML" ? config.SamlConfigs : config.OidConfigs) || {};
    return providers[row.Provider] || null;
  },
  // The newest recorded SSO sign-in per "protocol/provider"; a provider with no sign-in yields nothing.
  lastSsoLoginByProvider: (roster) => {
    const newest = {};
    const accounts = (roster && roster.Accounts) || [];
    accounts.forEach((account) => {
      ((account && account.Links) || []).forEach((link) => {
        if (!link || !link.LastSsoLoginUtc) {
          return;
        }

        const key = link.Protocol + "/" + link.Provider;
        if (!newest[key] || newest[key] < link.LastSsoLoginUtc) {
          newest[key] = link.LastSsoLoginUtc;
        }
      });
    });
    return newest;
  },

  paintOverview: (page, report, roster, config) => {
    const cards = page.querySelector("#sso-overview-providers");
    const empty = page.querySelector("#sso-overview-providers-empty");
    const next = page.querySelector("#sso-overview-next");
    const state = page.querySelector("#sso-overview-state");

    // The four overview elements are one region; all or none.
    if (!cards || !empty || !next || !state) {
      return;
    }

    cards.replaceChildren();
    next.replaceChildren();

    if (!report) {
      empty.hidden = true;
      ssoConfigurationPage.renderTransferMessage(
        state,
        tr(
          "overview.check_failed",
          "Could not read this server's SSO state. Make sure you are signed in as an administrator, then reload the page.",
        ),
      );
      return;
    }

    const rows = report.Providers || [];
    const newest = ssoConfigurationPage.lastSsoLoginByProvider(roster);
    empty.hidden = rows.length !== 0;

    const enabled = rows.filter((row) => row.Enabled).length;
    const unready = rows.filter((row) => !row.Ready).length;
    // Concatenated rather than substituted, since tr() leaves braces when the catalog failed to load.
    ssoConfigurationPage.renderTransferMessage(
      state,
      rows.length === 0
        ? tr(
            "overview.state_none",
            "No provider is configured, so single sign-on is not offered at the login page.",
          )
        : tr("overview.state_configured", "Configured providers:") +
            " " +
            String(rows.length) +
            ". " +
            tr("overview.state_enabled", "Offered at the login page:") +
            " " +
            String(enabled) +
            ". " +
            tr(
              "overview.state_incomplete",
              "With an incomplete configuration:",
            ) +
            " " +
            String(unready) +
            ".",
    );

    rows.forEach((row) => {
      const card = document.createElement("div");
      card.classList.add("sso-provider-card", "sso-overview-card");
      card.setAttribute("role", "listitem");

      const name = document.createElement("span");
      name.classList.add("sso-provider-name");
      name.textContent = row.Provider;
      card.appendChild(name);

      const badge = document.createElement("span");
      badge.classList.add("sso-provider-badge");
      badge.textContent = row.Protocol;
      card.appendChild(badge);

      const list = document.createElement("ul");
      list.classList.add("sso-check-list");
      ssoConfigurationPage.appendOverviewRow(
        list,
        row.Enabled,
        row.Enabled
          ? tr("overview.enabled", "Offered at the login page")
          : tr("overview.disabled", "Not offered at the login page"),
      );
      ssoConfigurationPage.appendOverviewRow(
        list,
        row.Ready,
        row.Ready
          ? tr("overview.config_ok", "Configuration complete")
          : tr("overview.config_incomplete", "Configuration incomplete"),
      );

      const when = newest[row.Protocol + "/" + row.Provider];
      ssoConfigurationPage.appendOverviewRow(
        list,
        Boolean(when),
        when
          ? tr("overview.last_login", "Last SSO sign-in:") +
              " " +
              ssoConfigurationPage.formatLastSsoLogin(when)
          : tr("overview.never_signed_in", "No SSO sign-in recorded yet"),
      );

      // Marks a provider with a security defense off (#1727), only when a class is on. The sentence is the
      // Providers flag's own, concatenated with the classes.
      const downgrades = ssoConfigurationPage.activeDowngradeClasses(
        row.Protocol,
        ssoConfigurationPage.storedProviderFor(row, config),
      );
      if (downgrades.length !== 0) {
        ssoConfigurationPage.appendOverviewRow(
          list,
          false,
          tr(
            "config.insecure_option_active",
            "This provider has an active insecure or sensitive setting.",
          ) +
            " " +
            downgrades.join(", "),
        );
      }

      card.appendChild(list);
      cards.appendChild(card);
    });

    ssoConfigurationPage.paintOverviewNextSteps(next, report, rows);
  },

  // Paints what to do next, each entry tied to a condition in the report; an empty list is a sentence.
  paintOverviewNextSteps: (next, report, rows) => {
    const todo = [];

    rows
      .filter((row) => !row.Ready)
      .forEach((row) =>
        todo.push(
          row.Provider +
            " " +
            tr(
              "overview.next_incomplete",
              "is missing a required setting. Open it on the Providers tab.",
            ),
        ),
      );

    rows
      .filter((row) => row.Ready && !row.Enabled)
      .forEach((row) =>
        todo.push(
          row.Provider +
            " " +
            tr(
              "overview.next_disabled",
              "is configured and switched off. Enable it, or delete it so the list says what the server actually serves.",
            ),
        ),
      );

    if (report.ConfigurationUnreadable) {
      todo.push(
        tr(
          "overview.next_unreadable",
          "This server could not read its stored configuration when it started, so every setting shown here is a default and not this server’s. Save a provider on the Providers tab, import a configuration on the Server tab, or move the unreadable file aside and remove the marker beside it, then restart.",
        ),
      );
    }

    if (todo.length === 0) {
      ssoConfigurationPage.renderCheckNote(
        next,
        rows.length === 0
          ? tr(
              "overview.next_none_configured",
              "Add a provider on the Providers tab to offer single sign-on.",
            )
          : tr(
              "overview.next_nothing",
              "Every configured provider is complete and switched on. Whether each one answers is what Test Connection on the Providers tab reports.",
            ),
      );
      return;
    }

    todo.forEach((line) =>
      ssoConfigurationPage.appendOverviewRow(next, false, line),
    );
  },

  // Renders the SSO-only line from the shared configuration load; a no-op on tabs without an overview.
  renderOverviewFrom: (page, config) => {
    const line = page.querySelector("#sso-overview-sso-only");
    if (!line) {
      return;
    }

    line.textContent = config.DisablePasswordLogin
      ? tr(
          "overview.sso_only_on",
          "SSO-only is ON: Jellyfin password sign-in is refused for the accounts this plugin manages.",
        )
      : tr(
          "overview.sso_only_off",
          "SSO-only is off. Local Jellyfin passwords still work.",
        );
  },
};

// The five page controllers (#1527). Each function only wires the controls of its own page, since an
// unguarded handler on a missing control would throw. docs/ui/mock/FIELDS.md and tools/ui-mock-fields.js
// hold that partition to the markup.

/**
 * The calls every page with controls makes: the stylesheet, the configuration, the localized labels, the
 * unsaved-changes tracking, and the re-read on return to the tab (#1576).
 * The listener is registered after the first load, since the first `viewshow` fires before it exists.
 *
 * @param {Element} view The page element Jellyfin hands the controller.
 */
function initSharedPage(view) {
  ssoConfigurationPage.addTextAreaStyle(view);
  ssoConfigurationPage.loadConfiguration(view);
  ssoConfigurationPage.localize(view);
  ssoConfigurationPage.bindUnsavedChangeTracking(view);
  ssoConfigurationPage.bindOptionFoldCounts(view);
  ssoConfigurationPage.refreshOptionFoldCounts(view);
  ssoConfigurationPage.markPageClean(view);
  view.addEventListener("viewshow", () =>
    ssoConfigurationPage.refreshOnShow(view),
  );
}

// Registers the permission adder for each template-control prefix whose form this page carries (#1527).
function bindTemplatePermissionAdders(view) {
  Object.keys(ssoConfigurationPage.templateFormSelectors).forEach((prefix) => {
    const add = view.querySelector("#" + prefix + "Tmpl-Permissions-add");
    if (!add) {
      return;
    }

    add.addEventListener("click", (e) => {
      ssoConfigurationPage.addTemplatePermissionRow(view, prefix);
      e.preventDefault();
      return false;
    });
  });
}

/**
 * The Overview tab: a status view that holds no setting of its own.
 * It loads at init and on every `viewshow`, since cached views do not re-run their controller and the
 * first `viewshow` is missed. It holds no control, so the re-read needs no guard (#1576).
 */
function initOverviewPage(view) {
  ssoConfigurationPage.addTextAreaStyle(view);
  ssoConfigurationPage.localize(view);

  view.querySelector("#sso-self-service-link").href =
    ApiClient.getUrl("/SSOViews/linking");

  const read = () => {
    ssoConfigurationPage.loadConfiguration(view);
    ssoConfigurationPage.renderOverview(view);
  };

  read();
  view.addEventListener("viewshow", read);
}

/** The Providers tab: both provider workspaces, their editors and the readiness panel. */
function initProvidersPage(view) {
  initSharedPage(view);
  bindTemplatePermissionAdders(view);

  // The provider wizard (#1665): stateless registrations whose ids tools/ui-mock-fields.js holds to this page.
  view.querySelector("#sso-wizard-start").addEventListener("click", (e) => {
    ssoConfigurationPage.startWizard(view);
    e.preventDefault();
    return false;
  });

  view.querySelector("#sso-wizard-leave").addEventListener("click", (e) => {
    ssoConfigurationPage.closeWizard(view);
    e.preventDefault();
    return false;
  });

  view.querySelector("#sso-wizard-pick-oid").addEventListener("click", (e) => {
    ssoConfigurationPage.wizardPick(view, "oid");
    e.preventDefault();
    return false;
  });

  view.querySelector("#sso-wizard-pick-saml").addEventListener("click", (e) => {
    ssoConfigurationPage.wizardPick(view, "saml");
    e.preventDefault();
    return false;
  });

  view.querySelector("#sso-wizard-back").addEventListener("click", (e) => {
    ssoConfigurationPage.wizardGo(view, -1);
    e.preventDefault();
    return false;
  });

  view.querySelector("#sso-wizard-next").addEventListener("click", (e) => {
    ssoConfigurationPage.wizardGo(view, 1);
    e.preventDefault();
    return false;
  });

  view.querySelector("#sso-wizard-finish").addEventListener("click", (e) => {
    ssoConfigurationPage.wizardFinish(view);
    e.preventDefault();
    return false;
  });

  // Opens the wizard for Overview's deep link, at construction and on every later show (#1721, #1665),
  // but only while the wizard is closed, so an open wizard keeps its step.
  const openWizardIfRequested = () => {
    if (
      ssoConfigurationPage.wizardRequested() &&
      view.querySelector("#sso-wizard").hidden
    ) {
      ssoConfigurationPage.startWizard(view);
    }
  };
  openWizardIfRequested();
  view.addEventListener("viewshow", openWizardIfRequested);

  // The aggregate configuration check (#1084), on this tab because its rows use the form's localized labels.
  view.querySelector("#CheckAllProviders").addEventListener("click", (e) => {
    ssoConfigurationPage.checkAllProviders(view);
    e.preventDefault();
    return false;
  });

  view.querySelector("#SaveProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#OidProviderName").value;

    // The outcome is rendered in the editor's own status region (#1572); the rejection is handled here.
    ssoConfigurationPage.saveProvider(view, target_provider).then(
      (outcome) => {
        ssoConfigurationPage.setEditorTitle(view, target_provider);
        // The sentence waits for the secret read-back and comes from saveStatusFor (#1872).
        Promise.resolve((outcome || {}).secretDropped).then((dropped) => {
          const status = ssoConfigurationPage.saveStatusFor({
            secretDropped: dropped,
          });
          ssoConfigurationPage.renderSaveStatus(
            view,
            status.message,
            status.ok,
          );
        });
      },
      () =>
        ssoConfigurationPage.renderSaveStatus(
          view,
          tr(
            "config.provider_save_refused",
            "Could not save the provider: the name holds a control, backslash or URI-reserved character, or the Base URL Override is not a full URL.",
          ),
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

  // A click on a provider card loads it, delegated because the cards are re-rendered on every reload.
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
  // Reveal-on-toggle groups follow their checkbox; visibility only, so nothing is dropped from a save.
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
        tr("config.oid_client_id_name", "OpenID Client ID"),
      ),
    );
  view
    .querySelector("#RoleClaim")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateRequired(
        view,
        "RoleClaim",
        tr("config.role_claim_name", "Role Claim"),
      ),
    );
  view
    .querySelector("#OidScopes")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateRequired(
        view,
        "OidScopes",
        tr("config.oid_scopes_name", "Additional Scopes"),
      ),
    );
  view
    .querySelector("#BaseUrlOverride")
    .addEventListener("blur", () => ssoConfigurationPage.validateBaseUrl(view));

  // Updates the computed redirect URI (#724) on every keystroke in the name or base-URL override.
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
  // SAML workspace bindings (#725), parallel to the OpenID bindings above.
  view.querySelector("#saml-SaveProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#saml-provider-name").value;

    ssoConfigurationPage.saveSamlProvider(view, target_provider).then(
      () => {
        ssoConfigurationPage.renderSamlSaveStatus(
          view,
          tr("config.provider_saved", "Settings saved."),
          true,
        );
        ssoConfigurationPage.setSamlEditorTitle(view, target_provider);
      },
      // The whole reason inline (#1572), naming both server checks.
      () =>
        ssoConfigurationPage.renderSamlSaveStatus(
          view,
          tr(
            "config.provider_save_refused",
            "Could not save the provider: the name holds a control, backslash or URI-reserved character, or the Base URL Override is not a full URL.",
          ),
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
        tr("config.saml_client_id_name", "SAML Client ID"),
      ),
    );
  view
    .querySelector("#saml-SamlCertificate")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlCertificate(
        view,
        "saml-SamlCertificate",
        tr("config.idp_signing_certificate", "IdP Signing Certificate"),
      ),
    );
  view
    .querySelector("#saml-SamlSecondaryCertificate")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlCertificate(
        view,
        "saml-SamlSecondaryCertificate",
        tr(
          "config.idp_signing_certificate_secondary",
          "Secondary IdP Signing Certificate",
        ),
      ),
    );
  view
    .querySelector("#saml-BaseUrlOverride")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlBaseUrl(view),
    );

  // Live-update the computed ACS and SP-metadata URLs as the provider name or base-URL override changes.
  ["saml-provider-name", "saml-BaseUrlOverride"].forEach((id) => {
    view
      .querySelector("#" + id)
      .addEventListener("input", () =>
        ssoConfigurationPage.updateSamlUrls(view),
      );
  });

  view.querySelector("#saml-CopyAcsUrl").addEventListener("click", (e) => {
    ssoConfigurationPage.copySamlUrl(
      view,
      "saml-AcsUrl",
      tr("config.acs_url_name", "ACS URL"),
    );
    e.preventDefault();
    return false;
  });
  view.querySelector("#saml-CopyMetadataUrl").addEventListener("click", (e) => {
    ssoConfigurationPage.copySamlUrl(
      view,
      "saml-MetadataUrl",
      tr("config.metadata_url_name", "Metadata URL"),
    );
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

  // Readiness panel (#1083), in the rail (#1664): these handlers only re-read the form and rebuild it.
  // No priming call at init, since no editor is open then.
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
  });
  // The per-provider profile selectors: confirm before discarding the inline policy, then sync the state.
  [
    ["#ProvisioningProfile", ""],
    ["#saml-ProvisioningProfile", "saml-"],
  ].forEach(([selector, prefix]) => {
    view
      .querySelector(selector)
      .addEventListener("change", () =>
        ssoConfigurationPage.chooseProvisioningProfile(view, prefix),
      );
  });
  // Provider template pickers (#726).
  ssoConfigurationPage.populatePresetPicker(view, "OidPreset", OIDC_PRESETS);
  ssoConfigurationPage.populatePresetPicker(view, "saml-Preset", SAML_PRESETS);
  view.querySelector("#OidPreset").addEventListener("change", (e) => {
    ssoConfigurationPage.applyOidcPreset(view, e.target.value);
  });
  view.querySelector("#saml-Preset").addEventListener("change", (e) => {
    ssoConfigurationPage.applySamlPreset(view, e.target.value);
  });
}

/** The Accounts tab: who is linked, and the account-link transfer pair. */
function initAccountsPage(view) {
  initSharedPage(view);

  // Account-link transfer (#1131), with its own endpoints and status region.
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

  // The linked-accounts panel (#1121), read once at init and re-read by the button.
  view
    .querySelector("#RefreshLinkedAccounts")
    .addEventListener("click", (e) => {
      ssoConfigurationPage.loadLinkedAccounts(view);
      e.preventDefault();
      return false;
    });

  // The filter re-renders from the held roster on `input` (#1529). The container is looked up per event,
  // since the region is replaced on every load.
  view.querySelector("#LinkedAccountsFilter").addEventListener("input", () => {
    ssoConfigurationPage.renderLinkedAccounts(
      view,
      view.querySelector("#LinkedAccountsResult"),
    );
  });

  ssoConfigurationPage.loadLinkedAccounts(view);

  // Re-reads the roster on every show (#1576); it writes no control, so nothing can be discarded.
  view.addEventListener("viewshow", () =>
    ssoConfigurationPage.loadLinkedAccounts(view),
  );
}

/** The Policies tab: the named provisioning-profile editor. */
function initPoliciesPage(view) {
  initSharedPage(view);
  bindTemplatePermissionAdders(view);

  // Provisioning profiles (#1105): the four acts and the selection, each against the live configuration.
  // The buttons are type="button", so a throw before preventDefault cannot reload the dashboard.
  [
    ["#AddProvisioningProfile", "addProvisioningProfile"],
    ["#RenameProvisioningProfile", "renameProvisioningProfile"],
    ["#DeleteProvisioningProfile", "deleteProvisioningProfile"],
    ["#SaveProvisioningProfile", "saveProvisioningProfile"],
  ].forEach(([selector, act]) => {
    view.querySelector(selector).addEventListener("click", (e) => {
      ssoConfigurationPage[act](view);
      e.preventDefault();
      return false;
    });
  });

  view
    .querySelector("#selectProvisioningProfile")
    .addEventListener("change", () =>
      ssoConfigurationPage.selectProvisioningProfile(view),
    );
}

/** The Server tab: the server-wide switches and the configuration transfer pair. */
function initServerPage(view) {
  initSharedPage(view);

  // One Save for both switches (#1572); see saveServerSettings.
  view.querySelector("#SaveServerSettings").addEventListener("click", (e) => {
    ssoConfigurationPage.saveServerSettings(view);
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
}

export default ssoConfigurationPage;

/**
 * The controller for each registered page, keyed by the name its markup asks for.
 */
export const pageControllers = {
  overview: initOverviewPage,
  providers: initProvidersPage,
  accounts: initAccountsPage,
  policies: initPoliciesPage,
  server: initServerPage,
};
