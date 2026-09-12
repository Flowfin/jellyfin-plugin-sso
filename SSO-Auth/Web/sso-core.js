// The shared localization module (#913), set once its dynamic import resolves in localize() below.
// Until then, and permanently if the load fails, tr() returns the caller's built-in English, so the
// page never renders a bare catalog key.
let i18n = null;

// Localized text for a catalog key, falling back to the English default the call site carries. The
// default is the same wording the static markup holds, so a JS-set string and its HTML twin cannot drift.
//
// THE FALLBACK SUBSTITUTES TOO, and that is a fix rather than a flourish (#1529). It used to return the
// default verbatim, so every parameterised call rendered its braces: before the catalog arrived, and
// permanently on a server whose fetch fails, a reader saw "Deleted account ({id})" and "Showing {shown} of
// {total} linked accounts." The default is the SAME string the catalog carries, placeholders included, so
// the only question was whether anything filled them, and on this path nothing did. Found by the arm in
// tools/ui-account-filter.js, which drives the renderer with no localization module loaded at all - which
// is precisely the state this branch describes.
//
// The substitution is written here rather than imported because this is the branch where the module is
// ABSENT; reaching into it for the helper is the one thing this path cannot do. An absent parameter is
// left as it stands, exactly as i18n.js does, so a mismatched call never drops text.
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

// What the tracked controls of a page held the last time it was read (#1572), keyed on the page element.
// The unsaved-changes state is the difference between this and what they hold now; markPageClean is the
// only writer, and what that means is argued where it is defined. Weak, so a view the dashboard discards
// takes its entry with it, and module-scope rather than an attribute because a 123-control signature is
// this module's bookkeeping and not a fact about the page.
const pageBaselines = new WeakMap();

// Builds a customized built-in the way BOTH clients accept (#1607). The options form is what upgrades
// the element on 10.11, and the Jellyfin 12 client REFUSES that argument outright: createElement throws
// `t.toLowerCase is not a function` for any `is` value, a registered name and an invented one alike, and
// that client registers no emby-* element at all. The throw landed before the first row existed, so every
// library checklist on the provider page came up empty and a save then wrote the empty set over the
// provider's folder restriction. The fallback carries the `is` attribute, which both clients take and
// which every call site sets on the next line anyway; what it gives up on 10.11 is nothing, because the
// upgrading form is tried first and only a client that refuses it ever reaches the second line.
function customizedBuiltIn(tag, is) {
  try {
    return document.createElement(tag, { is });
  } catch {
    return document.createElement(tag);
  }
}

// Settles a promise without deciding anything about it. Used where a load has to WAIT for a request
// whose failure it deliberately does not act on - the checklist fills the baseline waits for, and the
// configuration read of a refresh, which leaves the page showing what it last read.
const noop = () => {};

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

// The one list the readiness panel writes into (#1664). It is named once because both protocol specs
// point at it now: a second spelling is a second place for the two forms to disagree about where the
// answer goes, and the whole point of the move is that there is only one.
const RAIL_READINESS_LIST = "sso-rail-readiness-list";

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
  // ADVISORY ONLY. The guard is on the server: a save to a managed provider keeps the stored value and is
  // audited whether or not this page ever learned the provider was managed. That is why an unreachable
  // report is never read as "assume everything is managed" - that answer would lock an administrator out of
  // every form the server would have accepted, on a page whose own report is the thing that is broken.
  //
  // A FAILED READ NO LONGER EMPTIES THE SET (#1589). It used to, and the emptying was the fail-open
  // direction of the same reasoning: a 500, an expired dashboard session or a restart turned every provider
  // a file owns into an ordinary editable form, an administrator edited it, pressed Save and was told
  // "Settings saved." while the server kept the stored value and logged an ignored write. #1576 made that
  // reachable on every return to a settings tab rather than once per page construction. So the last set that
  // WAS read survives a failure, which is the only answer that is neither an invention nor a lockout: it
  // freezes exactly what the server last said it owns and nothing else.
  //
  // What survives no failure is a set that was never read, and that residual is carried rather than hidden:
  // `managedReportUnread` says the read failed, and BOTH arms of the editor then say so - an unfrozen form
  // stops looking identical to a provider nothing owns, and a frozen one stops claiming a certainty the
  // page has just admitted it does not have.
  //
  // The other cost of keeping the set is stated rather than left to be discovered: a provider REMOVED at
  // the file source while the report is unreadable stays frozen until a read succeeds. That direction
  // refuses a save the server would have accepted, which is one dashboard reload away from repaired and is
  // the side of the trade this page is allowed to be wrong on.
  managedProviders: {
    OidConfigs: [],
    SamlConfigs: [],
    ProvisioningProfiles: [],
  },
  managedProvidersLoaded: null,
  // Whether the last managed-set read to SETTLE failed. Read by the two editors to tell "nothing owns this"
  // apart from "this page could not find out", which are the same empty form without it.
  //
  // Settled rather than most recently STARTED, and the difference is deliberate. Two reads can be in flight
  // at once - the refresh on a tab show and a save's reload - and the flag follows whichever answers last.
  // So a rejection followed by a success clears it, which is correct: a set that was read is a set that was
  // read. A success followed by a rejection sets it over a fresh set, which over-warns and clears itself on
  // the next successful read. Neither ordering unfreezes anything, because the freeze is decided by the set
  // and never by this flag.
  managedReportUnread: false,
  // The sentence an unfrozen editor carries while the report is unread, in ONE place because both editors
  // say the same thing for the same reason. It states the residual rather than softening it: the form is
  // editable, the page does not know whether anything owns it, and the server is still the party that
  // decides - a save it refuses keeps the stored value and is recorded.
  //
  // WHY IT NAMES TWO ROUTES AND NOT "REOPEN THIS TAB". Measured: `refreshOnShow` returns early while any
  // editor region is open, so returning to the Providers tab with the frozen editor in front of you issues
  // no read at all - the shortest instruction would have been the one that does nothing in the state it is
  // printed in. Closing the editor and coming back, visiting another SSO tab, and reloading the dashboard
  // all re-read; the note names the two an administrator can act on without knowing the code.
  //
  // Suppressed on a form with no name - the blank add-new editor - at the call sites. Nothing owns a
  // provider that does not exist yet, so the sentence there would be noise in a live region on every tab
  // that has one.
  unreadReportNote: () =>
    tr(
      "config.managed_report_unread_note",
      "Which providers and profiles a configuration file sets could not be read, so this form is editable without confirming that nothing sets it. Close any open editor and return to this tab, or reload the dashboard, to try again. If a configuration file does set it, a save made here would keep the stored value and leave a record in the log.",
    ),
  // What a FROZEN editor adds while the report is unread, and what the four refusals that block a rename,
  // a delete or a profile save add for the same reason. The freeze then rests on the last answer the server
  // gave rather than on a current one, and a message that went on asserting "this is set by a configuration
  // file" would state a certainty this page has just recorded that it does not have. It is appended at the
  // blocking messages as well as at the advisory notes, because a refusal is where that certainty costs
  // something: it sends an administrator to a source that may no longer define what they are being refused.
  // Empty while the report reads fine, so every one of those messages is unchanged in the ordinary case.
  // The note an editor carries when it is NOT frozen, in one function so both editors and the proof ask the
  // same question. Empty on a form with no name - the blank add-new editor - because nothing can own a
  // provider that does not exist yet, and a live region repeating that on every tab would be noise.
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
        // AN EMPTY REPORT AND SOMETHING THAT IS NOT THE REPORT ARE NOT THE SAME ANSWER (#1597). Each member
        // is kept as `null` until it is seen to be a list, so the arm can tell the two apart; a report
        // naming any one of the three is the report, whatever the other two are, because a server with no
        // SAML provider legitimately sends an empty list for that member.
        const listOrNothing = (member) =>
          Array.isArray(member) ? member : null;
        const oid = listOrNothing(report && report.OidConfigs);
        const saml = listOrNothing(report && report.SamlConfigs);
        const profiles = listOrNothing(report && report.ProvisioningProfiles);

        if (oid === null && saml === null && profiles === null) {
          // A 200 carrying none of the three is a body that reached this page instead of the report - a
          // proxy's error page that happens to parse, a version-skewed endpoint, a truncated body. Reading
          // it as "nothing is managed" is the #1589 fail-open arriving through the arm that believes it
          // succeeded, and it is worse there, because that arm also clears the flag that would have said so.
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
        // The set is deliberately left alone. See the note above: replacing it with an empty one is the
        // fail-open #1589 is about, and replacing it with "everything" is the lockout.
        ssoConfigurationPage.managedReportUnread = true;
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
  // A profile a declarative source defined (#1498). The freeze is the one a managed provider gets - the save
  // keeps the stored value and records the ignored write - and until the report named profiles this editor
  // printed "Saved" over a value the server had already put back.
  isManagedProfile: (name) => {
    const names = ssoConfigurationPage.managedProviders.ProvisioningProfiles;
    return Boolean(name) && Array.isArray(names) && names.indexOf(name) !== -1;
  },
  // The three acts a managed profile freezes beside its policy fields. Add stays usable, because a new profile
  // under another name is not a write to this one, and so does the selector, so the frozen policy can be read.
  managedProfileActs: [
    "RenameProvisioningProfile",
    "DeleteProvisioningProfile",
    "SaveProvisioningProfile",
  ],
  // Render the profile editor as managed or as ordinary, AFTER the fill: the permission rows are created by
  // the fill, so a pass made before it would leave every one of them editable. Always applied on both arms,
  // so choosing an ordinary profile after a managed one restores the editor rather than leaving it frozen.
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
          // The freeze's own record of why (#1572). The Save gate reads it rather than remembering what
          // it disabled: two owners writing one boolean cannot compose, and the direction that fails is
          // the gate handing a frozen Save back. Written by the party that knows.
          element.dataset.ssoManaged = managed ? "true" : "";
        }
      });

      // The freeze runs as a microtask, so on the paths that call it after the gate - addProvider,
      // addSamlProvider, a profile selected while the report was in flight - it writes `disabled`
      // directly and clears whatever the gate had just decided. Re-asserting here is what makes the
      // composition hold in BOTH orders rather than in the one that happened to be tested (#1572).
      ssoConfigurationPage.updateSaveAvailability(page);

      const note = page.querySelector("#profile-managed-note");
      if (note) {
        // Set as text only (#221). Both texts are fixed and carry no profile value.
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
          // The freeze's own record of why (#1572), read by the Save gate. See the same line in
          // applyManagedProfileState for the reason it is written here rather than remembered there.
          element.dataset.ssoManaged = managed ? "true" : "";
        });

      // Same reason as applyManagedProfileState: this pass lands after the gate on the add paths and
      // writes `disabled` directly, so the gate is re-asserted once the freeze has had its say.
      ssoConfigurationPage.updateSaveAvailability(page);

      if (note) {
        // textContent, never innerHTML (#221). Both texts are fixed and carry no provider value, so nothing
        // from the configuration reaches the DOM here at all.
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
  // Whether the server is running on a default configuration because it could not read the stored one
  // (#1543). Read from the aggregate check, which is the report that already answers "would a login work"
  // - and on such a server the answer is no for a reason no provider row can carry, because there are no
  // provider rows. Without this the page would show an empty workspace and read as "nothing configured"
  // to an operator whose providers are on disk in a file the server refused.
  //
  // Fail QUIET rather than fail loud: a check that cannot be fetched leaves the banner hidden. The state it
  // reports is already an Error line in the server log and a 503 on every SSO sign-in, so a page that
  // cannot reach the server is not the surface to invent an alarm on.
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
  // ONE load path for five pages since #1527, and every section it fills is gated on that section being
  // in front of it. The gate is the presence of the section's own control rather than a page name: a
  // page is identified by what it holds, so moving a section between tabs moves its load with it and
  // this function does not have to learn the new arrangement. What it must never become is a load that
  // SKIPS a section the page does have - so each test names the exact control the branch below writes
  // to, not a container that could survive the control being dropped.
  //
  // `options.refreshing` marks the ONE caller that is re-running this against a page an administrator is
  // already looking at - the return to a tab, #1576 - and it changes two things and nothing else. The
  // library checklists are not repopulated, because only `loadProvider` ticks them and nothing here would
  // put the ticks back; and the write is re-gated on the page still being replaceable, because the
  // decision to refresh was taken before this fetch went out. Every other caller is a save, a delete or
  // an import that has just changed the stored configuration and is reading it back, and those replace
  // the page unconditionally as they always have.
  loadConfiguration: (page, options) => {
    const refreshing = Boolean(options && options.refreshing);
    // Refreshed with the configuration itself: a provider that stopped being declaratively managed between
    // two loads must not keep a frozen form, and one that started being managed must not keep an open one.
    ssoConfigurationPage.loadManagedProviders();
    // Same refresh reason: a save or an import ends the serve-defaults state, so the banner has to be
    // re-asked rather than left standing from the load that found it. It is on every page, because the
    // statement it makes - that the settings in front of you are not this server's - is true of all five.
    ssoConfigurationPage.showUnreadableConfigurationNotice(page);

    // NOT ON A REFRESH, and this is the guard that keeps a returning tab from costing users their
    // libraries (#1576). populateFolders rebuilds the checklist from Library/MediaFolders with nothing
    // ticked; loadProvider is what ticks it, and a refresh does not run loadProvider. Skipping it is
    // safe because both checklists live inside an editor, a refresh only happens with every editor
    // closed, and opening one runs loadProvider - which is where the ticks come from either way. What
    // it costs is a media library added while the dashboard has been left open on this tab: the
    // checklist is the one this load put there, until the next save, import or reload of the page.
    //
    // Issued BEFORE the configuration request rather than after it, because the baseline below waits on
    // all three and the order they go out in is the order they tend to come back in.
    const folderFills = [];
    if (!refreshing) {
      const folder_container = page.querySelector("#EnabledFolders");
      if (folder_container) {
        folderFills.push(
          ssoConfigurationPage.populateFolders(folder_container),
        );
      }

      // The SAML editor has its own available-folders checklist; populate it too (#725).
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
      // THE SECOND ASKING, and the whole answer to the check-then-act the review refused (#1576). The
      // refresh decided to run before this request went out; an administrator can open an editor or
      // type into a control while it is in flight, and every line below writes a control. So the
      // question is put again HERE, at the last moment before the first write, and a refresh that has
      // been overtaken does nothing at all rather than overwriting what arrived.
      if (refreshing && !ssoConfigurationPage.mayReplacePageContents(page)) {
        return;
      }
      // The two provider workspaces (Providers). Both or neither: they are one tab.
      if (page.querySelector("#selectProvider")) {
        ssoConfigurationPage.populateProviders(page, config.OidConfigs);
        // Refresh the SAML workspace from the same configuration load (#725), so a SAML save/delete/import
        // reloads its provider list exactly as the OpenID one does.
        ssoConfigurationPage.populateSamlProviders(
          page,
          config.SamlConfigs || {},
        );
      }
      // The GLOBAL login-page buttons opt-in (#722) rides the same configuration load. It is a root
      // PluginConfiguration flag, not a provider field, so it has the Server page's save path (saveServerSettings)
      // and no sso-* marker class. On the Server tab since #1527.
      const manage_buttons = page.querySelector("#ManageLoginPageButtons");
      if (manage_buttons) {
        manage_buttons.checked = Boolean(config.ManageLoginPageButtons);
        // What this switch was FILLED with, so the save can tell a switch the administrator moved from
        // one they never touched (#1572). See saveServerSettings for why that distinction is the whole
        // difference between one Save and one lost update.
        manage_buttons.dataset.ssoLoaded = String(manage_buttons.checked);
      }

      // The GLOBAL Single Logout opt-in (#727) rides the same configuration load. Like
      // ManageLoginPageButtons it is a root PluginConfiguration flag, not a provider field, so it has its
      // own save path (saveServerSettings, together with the flag above) and no sso-* marker class.
      const single_logout = page.querySelector("#EnableSingleLogout");
      if (single_logout) {
        single_logout.checked = Boolean(config.EnableSingleLogout);
        single_logout.dataset.ssoLoaded = String(single_logout.checked);
      }

      // The GLOBAL provisioning profile set (#1105) rides the same configuration load, for the
      // reason the two flags above do: it is a root PluginConfiguration member with its own save
      // path. Doing it here means every existing save, delete and import route refreshes the
      // editor and both provider-form selectors without knowing that they exist. Since #1527 the
      // editor is on Policies and the two provider-form selectors are on Providers, so this runs on
      // both tabs and fills whichever half is there.
      ssoConfigurationPage.populateProvisioningProfiles(page, config);

      // The Overview tab reads the same configuration rather than a second endpoint, so what it says
      // about a provider and what the editor shows for it cannot come apart.
      ssoConfigurationPage.renderOverviewFrom(page, config);

      // The Save gate is re-run against the values just filled in. The BASELINE is taken below rather
      // than here, because this is one of the load's three requests and not the whole of it.
      ssoConfigurationPage.updateSaveAvailability(page);

      // THE BASELINE COVERS THE WHOLE LOAD, AND TAKING IT HERE ALONE WAS A DEFECT THE REVIEW
      // REPRODUCED AGAINST THE SHIPPED FILE (#1576). A load is three requests: the two checklists are
      // filled by their own, and each appends one ID-LESS checkbox per media library that
      // controlSignature counts. Whenever the configuration answered first, the baseline was taken
      // before those controls existed and nothing corrected it, so the Providers page differed from
      // its own baseline for the life of the view. Under #1572 that was invisible, because only a user
      // event consulted the comparison. Under the refresh it decides everything: the tab would have
      // refused to re-read for good, and would have asserted unsaved changes on a page nobody had
      // touched - training away the one indicator that says a real edit is about to be lost.
      //
      // A rejected checklist read settles here too, so a failed fill cannot leave the page with no
      // baseline at all - which pageDiffersFromBaseline reads as edited, and which would refuse every
      // refresh from then on. What that read leaves behind is a checklist with no rows, and what a
      // save then writes for it is its own defect on a different path; it is #1587 rather than this.
      return Promise.all(folderFills.map((fill) => fill.then(noop, noop))).then(
        () => ssoConfigurationPage.markPageClean(page),
      );
    });

    // A refresh that could not read the configuration leaves the page showing what it last read, which
    // is what a failed refresh should leave. Attached ONLY for the refresh: every other caller has just
    // written something and is reading it back, and its failure is not this function's to swallow.
    if (refreshing) {
      load.then(noop, noop);
    }
  },
  populateProviders: (page, providers) => {
    const select = page.querySelector("#selectProvider");

    // WHICH PROVIDER THE PAGE IS ABOUT SURVIVES THE RE-POPULATE (#1693). The comment below
    // calls this selector the state holder the save path reads, and a browser empties
    // `value` the moment the selected `<option>` is removed - re-adding an option with the
    // same value does not restore the selection. So a read of the configuration landing after
    // a save silently took the page's own record of its subject away, and everything that
    // compares against it - applyManagedState, and since #1693 both loaders - then compared
    // against the empty string. Read before, restored after, with no branch: assigning a
    // value no option carries leaves it empty, which is what it would have been anyway.
    const chosen = select.value;

    // Clear providers in case there are out of date ones
    select.querySelectorAll("option").forEach((option) => option.remove());

    // Add providers as options for the (hidden) selector. The selector is retained as the state holder the
    // save path already reads (saveProvider sets its value after a save); the visible affordance is the card
    // list rendered below.
    Object.keys(providers).forEach((provider_name) => {
      select.appendChild(new Option(provider_name, provider_name));
    });
    select.value = chosen;

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
        warn.title = tr(
          "config.insecure_option_active",
          "This provider has an active insecure or sensitive setting.",
        );
        card.append(warn);
      }

      list.appendChild(card);
    });
  },
  // ONE WORKSPACE AT A TIME (#1527), and the two lines that enforce it are here and at showSamlEditor.
  //
  // This page carries two protocol editors side by side and each one has its own Save. Opening one while
  // the other is open put BOTH on the screen, under a single page-wide unsaved-changes notice that cannot
  // say which of the two it is about - so the reader is shown two buttons and told, once, that something
  // is unsaved. Read off a live Jellyfin 12 during the stage-1 walk: an OpenID provider opened beside a
  // SAML one gave a 21163px page carrying #SaveProvider and #saml-SaveProvider at the same time.
  //
  // CLOSING THE OTHER ONE RATHER THAN REFUSING TO OPEN THIS ONE, because opening an editor is ALREADY an
  // act that discards: openProvider and addProvider both call resetEditor before they fill, so switching
  // provider within a protocol drops whatever was typed and marks the page clean again. Crossing the
  // protocol boundary is the same act and now behaves the same way, rather than being the one direction
  // that quietly keeps a second form alive.
  //
  // Both editors ship in the same markup - providersPage.html is the only page that declares either - so
  // the sibling lookup is as safe as the one on the line below it, and a page missing one is missing both.
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
    // The page-level region still holds the outcome of the last delete, which was about a provider that
    // is gone (#1572). Opening another one is a new act, so it starts with nothing asserted.
    ssoConfigurationPage.renderPageStatus(page, "");
    ssoConfigurationPage.setEditorTitle(page, provider_name);
    ssoConfigurationPage.showEditor(page);
    ssoConfigurationPage.loadProvider(page, provider_name);
    // Opening an editor is a read, not an edit: whatever the previous provider left behind is gone with
    // resetEditor, and loadProvider marks the page clean again once its own fill lands (#1572). This call
    // covers the window before that, so a Save is never live over a half-reset form.
    ssoConfigurationPage.markPageClean(page);
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
    ssoConfigurationPage.renderPageStatus(page, "");
    ssoConfigurationPage.setEditorTitle(
      page,
      tr("config.new_provider", "New provider"),
    );
    ssoConfigurationPage.syncDependentFields(page);
    // A new provider is never managed - no source has named it yet - so this arm exists to RESTORE a form
    // left frozen by a managed provider opened just before (#1104).
    ssoConfigurationPage.applyManagedState(page, "oid", "");
    ssoConfigurationPage.showEditor(page);
    // A blank editor holds nothing anybody typed, so the page is clean and its Save is closed until the
    // three required fields carry a value (#1572).
    ssoConfigurationPage.markPageClean(page);
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
      ? tr("config.insecure_hide", "Hide insecure options")
      : tr("config.insecure_show", "Show insecure options");
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
          "Enter a full origin such as https://jellyfin.example.com (scheme + host only).",
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
    // Full origin only: no path, query or fragment (this is the base URL, not the redirect URI).
    if ((url.pathname && url.pathname !== "/") || url.search || url.hash) {
      ssoConfigurationPage.setFieldError(
        page,
        "BaseUrlOverride",
        tr(
          "config.validation_base_no_path",
          "Enter the base URL only (no path), e.g. https://jellyfin.example.com, not the /sso/... redirect URI.",
        ),
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
        tr("config.validation_name_required", "A provider name is required."),
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
  // ---- The unsaved-changes state (#1572) ----
  //
  // WHAT IT IS FOR, AND WHY THE THREE THINGS BELOW ARE ONE THING. The dashboard keeps three views alive
  // and hands a cached one back rather than building it again, so a tab returned to has NOT re-run its
  // controller and still shows whatever it last loaded. #1527 made Overview re-read on every show and
  // left the other four alone deliberately, because re-reading them re-fills form controls and would
  // silently discard an edit an administrator had made and not yet saved. Knowing whether the page is
  // dirty is exactly what makes the safe re-read possible, and it is the same state the indicator needs
  // and the same state the Save gate needs - so the three arrive together rather than this being built
  // three times or the refresh being built on a guess.
  //
  // THE EVENT IS THE TRIGGER AND THE VALUES ARE THE AUTHORITY, AND THE FIRST DRAFT HAD IT THE OTHER WAY
  // ROUND. That draft marked the page dirty on an `input` or `change` whose `isTrusted` was true, on the
  // reasoning that this page's own fills write `.value` and `.checked` directly and fire nothing. The
  // reasoning was about THIS file and the controls are the host's. Two of them dispatch their own
  // synthetic events, which carry `isTrusted` false, and both were measured in jellyfin-web rather than
  // supposed: `emby-checkbox` toggles `checked` and dispatches a bubbling `CustomEvent('change')` when
  // the control is operated from the KEYBOARD, and `emby-select` dispatches `new Event('change', {
  // bubbles: false })` when its value is set through the action sheet. Under the first draft a keyboard
  // user could change every switch on the Server page, have the page go on reading as clean, and lose
  // the lot to the re-read on the next return to the tab - the exact failure this state exists to stop,
  // aimed at the people least able to work around it.
  //
  // So an event only asks the question, and what answers it is a comparison of the tracked controls
  // against what the last fill left on them. That is correct whoever dispatched the event and whatever
  // flag it carries: a fill that fires an event compares equal and stays clean, a person who changes a
  // control compares different and is dirty, and a person who changes one back is clean again.
  //
  // THE LISTENER IS IN THE CAPTURE PHASE AND THAT IS LOAD-BEARING, not defensive. `emby-select`'s event
  // sets `bubbles: false`, so a bubble-phase listener on the page never sees it at all. Measured in a
  // browser rather than reasoned: a non-bubbling event dispatched on a descendant IS delivered to a
  // capture-phase listener on an ancestor, and is NOT delivered to a bubble-phase one.
  //
  // WHAT IS DELIBERATELY NOT TRACKED. A file input is a transfer trigger rather than a setting: it is
  // cleared to "" after every use and nothing saves it. The provider and profile selectors NAVIGATE -
  // changing one refills the form from the stored configuration, so what it leaves behind is a fresh
  // read and not an unsaved edit, and those reset the page to clean instead of dirtying it.
  navigationControlIds: [
    "selectProvider",
    "saml-selectProvider",
    "selectProvisioningProfile",
  ],
  // Every control on the page an administrator can edit and a Save on that page would commit. Accounts
  // holds exactly one control, a hidden file input, so this is empty there and that page can never be
  // dirty - which is why it re-reads on every show alongside Overview.
  editableControls: (page) =>
    [...page.querySelectorAll("input, select, textarea")].filter(
      (element) =>
        element.type !== "file" &&
        // A READ-ONLY CONTROL IS NOT ONE AN ADMINISTRATOR EDITS, which is what this function is
        // named for, and leaving the three this surface has in it cost the notice that says work is
        // about to be lost (#1701). All three are computed addresses no save reads: the OpenID
        // redirect URI the SERVER answers with, and the two SAML URLs. The first is the one that
        // bit. `loadProvider` empties it, schedules the request behind a debounce, and calls
        // `markPageClean` twenty lines later - so the baseline is taken with the field EMPTY and the
        // reply writes into it a quarter of a second afterwards, with no second baseline. From the
        // first load onwards `pageDiffersFromBaseline` therefore answered true on a page nobody had
        // typed into: the tab asserted an edit that did not exist, and `refreshOnShow` took its
        // edit-protecting arm every time, so it stopped re-reading for the life of the view.
        //
        // EXCLUDED HERE RATHER THAN BY RE-TAKING THE BASELINE, because the other repair swallows
        // real work: a keystroke made while the address was in flight falls inside the window a
        // blind re-take covers, and would afterwards read as part of what the server put there.
        // This direction cannot lose an edit, because the fields it drops are ones no edit reaches.
        //
        // DERIVED FROM THE CONTROL rather than from a list of three ids, so a computed field added
        // tomorrow is covered by being read-only, which is the property that makes it one.
        element.readOnly !== true &&
        ssoConfigurationPage.navigationControlIds.indexOf(element.id) === -1,
    ),
  // What the tracked controls hold right now, as one comparable string. A checkbox is read from
  // `checked` and everything else from `value`, and the id rides along so a control appearing or
  // disappearing - a permission row, a folder checklist filled from the server - is a difference rather
  // than something two lengths could cancel out.
  //
  // SEPARATED, AND THE EMPTY JOIN IT REPLACED WAS A COLLISION (#1576). The rows a page renders from a
  // server list carry no id, so two of them contribute "=a" and "=b=c" where two others contribute
  // "=a=b" and "=c" - the same string, a different page. Under #1572 that could only miss an edit; under
  // the refresh, "the same signature" is the permission to REPLACE what is on the page, so a collision
  // is a discarded edit rather than an unmarked one. A separator no value can contain removes the class
  // for one character, which is cheaper than reasoning about which pairs are reachable.
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
  // Back to clean, which is what every fill path and every successful save leaves behind, and the ONE
  // place the baseline is taken: clean means "what is on the page is what the last read put there", so
  // the two statements cannot come apart. It re-runs the Save gate too, because a fill changes the
  // values that gate reads.
  //
  // The baseline is held in a module-scope map keyed on the view rather than on the element, because it
  // is this module's bookkeeping and not a fact about the page - and because a 123-control signature is
  // not something to put in an attribute. The map is weak, so a view the dashboard discards takes its
  // entry with it.
  markPageClean: (page) => {
    pageBaselines.set(page, ssoConfigurationPage.controlSignature(page));
    page.classList.remove("sso-page-dirty");
    ssoConfigurationPage.renderUnsavedNotice(page);
    ssoConfigurationPage.updateSaveAvailability(page);
  },
  // Whether the page now holds something other than what the last read left on it. A page whose baseline
  // was never taken is treated as EDITED rather than clean: the only way to get there is a controller
  // that did not finish wiring, and the safe answer to "may I replace what is on this page" is no.
  pageDiffersFromBaseline: (page) => {
    const baseline = pageBaselines.get(page);
    return (
      baseline === undefined ||
      baseline !== ssoConfigurationPage.controlSignature(page)
    );
  },
  // The indicator. It says what is true of this page and promises nothing about another one: opening a
  // different provider in the editor still replaces what is in it, which is what it has always done and
  // is not this change's to alter. textContent, never innerHTML (#221); the text carries no
  // configuration value.
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
    // UNHIDE FIRST, THEN WRITE. `hidden` takes the element out of the accessibility tree, so text set
    // while it is hidden changes a live region nothing is watching, and the unhide that follows is not
    // itself a text change for the region to announce. Doing it in this order is what gives the
    // announcement a chance; whether a particular screen reader takes it is not something this tree can
    // measure, and nothing here claims it does.
    if (dirty) {
      box.hidden = false;
      box.textContent = ssoConfigurationPage.unsavedNoticeText();
      return;
    }
    box.textContent = "";
    box.hidden = true;
  },
  // What each Save on a page needs before it can be pressed, DERIVED from the readiness specs rather
  // than restated, so a required field added to an editor closes its Save without a second edit here. A
  // gate whose region is hidden is skipped: the button is not reachable, and touching it would fight
  // whoever hid it.
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
      // The SELECTOR and not the name box: saveProvisioningProfile keys off `#selectProvisioningProfile`
      // and the name box is the add/rename parameter, so gating on the name closed the Save when an
      // administrator cleared the rename field and left it open when no profile was selected at all -
      // both backwards.
      button: "#SaveProvisioningProfile",
      region: null,
      requiredIds: ["selectProvisioningProfile"],
    },
    { button: "#SaveServerSettings", region: null, requiredIds: [] },
  ],
  // WHICH FAILURES CLOSE A SAVE, AND WHY NOT ALL OF THEM. #365 put the validators beside the fields as
  // pre-emptive WARNINGS and argued they must never block, because a false positive would lock an
  // administrator out of saving a value the server would have accepted. That argument is about the
  // validators that GUESS - an endpoint shape, a base URL - and it still holds for them: they go on
  // warning and go on not blocking. It does not reach an EMPTY REQUIRED FIELD, which the server refuses
  // every time, so a Save left live for one is a Save that exists to fail. The emptiness is read from
  // the VALUES rather than from the validators' output boxes, exactly as the readiness panel reads it,
  // so typing into a blank field re-opens the Save on the keystroke instead of on the next blur.
  saveGateEmpties: (page, gate) =>
    gate.requiredIds.filter((id) => {
      const field = page.querySelector("#" + id);
      return field && !String(field.value || "").trim();
    }),
  // ONE WRITER, TWO DECLARED REASONS, AND WHY THE FIRST DRAFT OF THIS WAS A FAIL-OPEN.
  //
  // Two parties want this button disabled: this gate, while a required field is empty, and the
  // declarative-source freeze (#1104), because a provider or a profile a configuration file owns may not
  // be edited here. A boolean with two owners cannot compose, and the draft that tried to remember what
  // it had disabled handed a frozen Save back: opening the Policies tab with no profile selected left the
  // gate holding the button down, and selecting a MANAGED profile then filled the name, so the gate saw
  // nothing left to block and released a Save the freeze had just closed - `applyManagedProfileState`
  // runs before the fill's `markPageClean`, so its disable was the one being cleared.
  //
  // So the freeze records its own reason on the button and this reads it. The write is in one place and
  // each reason is asserted by the party that knows it; a reason nobody wrote is nobody's, and the only
  // other writers of `disabled` on these buttons are the two freeze functions, which now both mark.
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
  // One delegated listener per page rather than one per control, so a control the page renders later - a
  // permission row, a folder checkbox - is tracked from the moment it exists. Capture phase for the two
  // reasons written at the top of this section: a non-bubbling event reaches nothing else, and a handler
  // that stops propagation on its own control would otherwise hide the edit from this.
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
      // The event only asks; the values answer. `isTrusted` is deliberately NOT read - two of the host's
      // own controls dispatch synthetic events on real user input, and the reason is at the top of this
      // section.
      if (ssoConfigurationPage.pageDiffersFromBaseline(page)) {
        ssoConfigurationPage.markPageDirty(page);
      } else {
        ssoConfigurationPage.markPageClean(page);
      }
    };
    page.addEventListener("input", observe, true);
    page.addEventListener("change", observe, true);
  },
  // ---- The refresh on return to a tab (#1576) ----
  //
  // WHAT WAS REFUSED AND WHY IT IS NOT THE DIRTY STATE'S FAULT. #1572 built the state so a clean tab
  // could re-read the server on `viewshow`, and the review took the re-read out again: the danger was
  // never in the state, it was in what `loadConfiguration` does when it runs a SECOND time, having been
  // written to run once at construction while the editors are still hidden. Three ways, and each of the
  // three has its own guard below rather than one guard credited with all of them.
  //
  // ONE. `loadConfiguration` re-populates both library checklists from `Library/MediaFolders` with
  // nothing ticked, and it does not re-run `loadProvider`, which is what ticks them. A return to
  // Providers with an editor open therefore emptied the checklist while the editor still showed its
  // provider, and the next save serialises that checklist unconditionally and persists
  // `EnabledFolders: []` - after which `SessionMinter` writes that empty set on every login while
  // `EnableAllFolders` is off, and every user of that provider loses library access at their next
  // sign-in. That is the worst outcome on this surface and it needed no race and no typing.
  //
  // TWO. Removing a permission row or a role-mapping row is a button click: `row.remove()`, no `input`,
  // no `change`. So the tracking never runs and the page is never MARKED dirty, while holding a real
  // edit that the Policies re-read would render straight back out of storage.
  //
  // THREE. The check was check-then-act: the dirty test ran first and the fill landed at the end of an
  // asynchronous chain, so an edit made inside that window was overwritten and the page then reported
  // itself clean.
  //
  // THE THREE GUARDS, IN THE ORDER THEY BITE.
  //
  //   - An OPEN EDITOR refuses the refresh outright, which is what answers ONE. Nothing is re-read while
  //     an editor is on screen: not the checklists, not the hidden `#selectProvider` the save path reads
  //     its target from - `populateProviders` clears that selector's options, and clearing them drops
  //     its value - and not the profile selectors inside the two provider forms. An open editor is work
  //     in progress, and the cost of refusing is staleness behind a panel the administrator is looking
  //     through anyway.
  //   - The decision reads `pageDiffersFromBaseline`, which recomputes the SIGNATURE from the live
  //     controls, and NOT `isPageDirty`, which reads a class something has to have set. That is what
  //     answers TWO without the tracking having to see a click: the signature carries each control's id,
  //     so a row that is no longer in the page is a difference by construction. The marked state is
  //     brought into line at the same moment, so the indicator says why the tab did not refresh.
  //   - The same two questions are asked AGAIN inside the fill, immediately before anything is written,
  //     which answers THREE: an edit made while the configuration was in flight leaves the fill with
  //     nothing to do rather than being overwritten by it.
  //
  // WHAT THIS SETTLES ABOUT THE INDICATOR'S GRANULARITY, which #1576 asks for as its own condition. The
  // indicator is page-wide and the Providers page carries two editors, so opening one still clears the
  // other's state - unchanged, and it does not matter here: the refresh does not depend on the state
  // being per-editor, because ANY open editor refuses it wholesale. The granularity question is about
  // what the indicator promises, and it promises the same thing it did before this.
  editorRegionIds: ["sso-editor", "saml-editor"],
  anyEditorOpen: (page) =>
    ssoConfigurationPage.editorRegionIds.some((id) => {
      const region = page.querySelector("#" + id);
      return region !== null && region.hidden !== true;
    }),
  // Whether the page may have its contents replaced by a fresh read. Asked twice per refresh, before the
  // fetch and again before the write, because the answer can change in between.
  mayReplacePageContents: (page) =>
    !ssoConfigurationPage.anyEditorOpen(page) &&
    !ssoConfigurationPage.pageDiffersFromBaseline(page),
  refreshOnShow: (page) => {
    if (ssoConfigurationPage.anyEditorOpen(page)) {
      return;
    }
    if (ssoConfigurationPage.pageDiffersFromBaseline(page)) {
      // The tab holds something the last read did not put there - possibly a removed row nothing
      // dispatched an event for. Say so where it is read, which is the same notice an ordinary edit
      // raises, and leave the page exactly as the administrator left it.
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
  // NO ROWS IS NOT AN EMPTY SELECTION (#1607). An administrator who clears the list leaves the rows on
  // screen and unticked; a container holding no rows at all is one the fill never reached - the client
  // refused the row construction, or Library/MediaFolders did not answer. Writing that as "no libraries"
  // while EnableAllFolders is off is the save this file already names as the worst outcome on this
  // surface, in the refresh guards above: SessionMinter then writes the empty set on every login and
  // every user of the provider loses library access at their next sign-in. So the two cases are told
  // apart here and the caller decides; null means the question could not be answered.
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

      // The `is` option upgrades the customized built-in where the client accepts it, and is refused
      // outright on Jellyfin 12 (#1607) - see customizedBuiltIn. The attribute is set either way, so
      // CSS attribute selectors and the web-components polyfill see it.
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

        // A row whose checklist never drew is written as the empty set rather than skipped (#1607).
        // The two are different failures and the smaller one is chosen deliberately: an empty mapping
        // grants that role no libraries, which the administrator sees on the row in front of them,
        // while dropping the row would silently delete a mapping they never touched.
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
  // ---------------------------------------------------------------------------------------------------
  // The provisioning-template save contract (#1367).
  //
  // ProvisioningPolicyTemplate is a NESTED member of the provider config, so its controls cannot ride the
  // flat contract listArgumentsByType feeds (current_config[element.id] = value, one top-level member per
  // control). They carry their own marker classes instead - sso-tmpl-number, sso-tmpl-text, sso-tmpl-bool,
  // sso-tmpl-list and sso-tmpl-perms - and an id of "<prefix>Tmpl-" + the exact ProvisioningPolicyTemplate
  // property they write. readProvisioningTemplate below is the second serializer that assembles them into
  // one object.
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
  // The form each template-control prefix lives in. The global profile editor (#1105) renders the same
  // ten controls a THIRD time, outside both provider forms, so the two-way ternary this replaced could
  // not name it: "is it the SAML prefix" is a different question from "which form is this prefix in", and
  // the first one silently answers the OpenID form for every prefix that is not "saml-".
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

    // A list control (#1101) is one entry per line, in order. Blank lines are not entries, and a box with
    // no entry contributes no member - the same declined state as an empty text control - so the server
    // never sees an empty list where "keep Jellyfin's own layout" was meant.
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

    // The named-profile selector is filled here rather than by the flat load path (#1105). That path sets
    // a text field ONLY when the loaded provider carries a value, so a provider naming no profile would
    // keep the previously loaded provider's name selected and a later save would write it onto the second
    // provider - the same stale-value failure the check_fields loop above is written unconditionally for.
    // Set unconditionally for exactly that reason, and the stored name is offered even when the profile
    // set does not carry it, so a name that has gone missing is visible instead of silently reading as
    // "no profile" and being saved that way.
    const selector = page.querySelector("#" + prefix + "ProvisioningProfile");
    if (selector) {
      // A caller that supplies no name list is clearing the form rather than describing the configuration -
      // resetEditor and resetSamlEditor do exactly that - so the OPTIONS are kept and only the value is
      // cleared. Rebuilding them from an empty list instead emptied the selector on every new provider, and
      // a new provider could then not be pointed at a profile at all until it was saved and reopened.
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
  // Where the provider names a provisioning profile the inline template is not this provider's policy.
  // The controls are disabled and the reason is put on the page, rather than leaving the administrator to
  // infer it from a save that changes nothing here. Read off the SELECTOR rather than off a value passed
  // in, so choosing a profile updates the page immediately instead of only after the next load; the
  // profile editor's own prefix has neither a selector nor a note, so it reads as "no profile named" and
  // leaves its controls enabled, which is what a profile is.
  syncProvisioningProfileState: (page, prefix, managed) => {
    const controls = ssoConfigurationPage.templateControls(page, prefix);
    const selector = page.querySelector("#" + prefix + "ProvisioningProfile");
    // Disabled where a profile supersedes the fields OR where the whole form is frozen by a declarative
    // source (#1104). The second half is not optional: this call runs AFTER applyManagedState, so a plain
    // `= named` re-enables exactly these ten controls on a managed provider and tells the administrator
    // the opposite of what a save does - the inverse of the invariant applyManagedState exists for.
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
  // Options are built with createElement/textContent, never innerHTML (#221): a profile name is
  // administrator-supplied configuration and is rendered as literal text wherever it appears.
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
  // ---------------------------------------------------------------------------------------------------
  // The provisioning-profile editor (#1105).
  //
  // ProvisioningProfiles is a root PluginConfiguration member - a named set of ProvisioningPolicyTemplate -
  // so every act here fetches the live configuration, changes only that member (and, on a rename, the
  // references to it), and re-posts the whole document, exactly as saveServerSettings does. Nothing here adds
  // a server route.
  //
  // Two of the four acts can break a provider, and both are checked against the live configuration BEFORE
  // the PUT rather than left to ProviderConfigValidator's refusal:
  //  - DELETE of a profile some provider or role rule still names is refused here and the references are
  //    shown. The server refuses the same state; what this adds is telling the administrator before they
  //    lose the edit, which is courtesy rather than the guard.
  //  - RENAME repoints every reference in the same document, so the configuration is never posted in the
  //    state the validator refuses. A rename that left the references behind would be a delete with extra
  //    steps.
  // ---------------------------------------------------------------------------------------------------
  provisioningProfileNames: (config) =>
    Object.keys(config.ProvisioningProfiles || {}).sort(),
  // The name the act that is running wants selected once the reload has rebuilt the list. It cannot be
  // written onto the select before then: assigning a value no option carries leaves the element on
  // selectedIndex -1 with an empty value, so the rebuild read "" and fell back to the FIRST profile - the
  // editor then showed one profile while the administrator believed it showed the one just added or
  // renamed, and the next Save wrote there. Consumed once, so a later ordinary reload does not re-apply it.
  provisioningProfileWanted: null,
  // A name an ordinary assignment does not turn into an own property is not usable as a profile name, and
  // "__proto__" is the one that reaches this page: profiles["__proto__"] = template sets the prototype and
  // creates nothing, so an Add would report success over an empty set and a rename would DELETE the source
  // profile while reporting that it had moved. Derived by probing an assignment rather than listed by name,
  // so a second spelling with the same asymmetry is refused without anybody having to think of it first.
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
  // Every provider and every role rule that names a profile, as readable subjects, each carrying whether
  // the provider holding it is decided by a declarative source. Used to refuse a delete, to refuse a rename
  // it cannot carry out, and to report what a rename moved; the walk is one function so the three cannot
  // disagree about what counts as a reference.
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

        // Trimmed, because the server resolves a ROLE ROW's name trimmed - a row reading " Staff " is a
        // live reference to Staff for ProviderConfigValidator and would be invisible to an exact
        // comparison. Such a row can only arrive from a configuration file or an import; this page has no
        // editor for them, which is why it must not assume the shape it would have written.
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

        // Trimmed on the same reading as the reference walk, so a rename repoints every row the server
        // would have resolved rather than posting a document the validator then refuses.
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
  // The providers that carry an inline template, as the sources an Add can copy. Only those: a source with
  // no policy of its own would produce an empty profile under a label that promised one.
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

    // A COPY, not the live object: the profile and the provider's own template are two independent policies
    // from the moment the profile exists, and sharing one object would make the next edit to either of them
    // change both inside this one PUT.
    return provider.ProvisioningPolicyTemplate
      ? JSON.parse(JSON.stringify(provider.ProvisioningPolicyTemplate))
      : null;
  },
  // Fills the editor and both provider-form selectors from one configuration load. Called from
  // loadConfiguration, so every existing save, delete and import path refreshes the editor for free.
  //
  // THE TWO HALVES ARE ON DIFFERENT TABS SINCE #1527 and each is gated on its own control. The editor
  // is on Policies and the two provider-form selectors are on Providers, so this runs on both and fills
  // whichever half is in front of it. It returns the fill promise a Save waits on only where it started
  // one; on a page with no editor it returns nothing and, more importantly, WRITES nothing - the branch
  // below says what that costs when it does.
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

    // An open provider form keeps whatever it has selected, so a profile added here appears in its list
    // without discarding a choice the administrator has already made and not yet saved.
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
      // No editor on this page, so there is nothing left to fill: the provider-form selectors above are
      // this page's whole share of the profile set.
      //
      // AND `provisioningProfileFill` IS LEFT ALONE, WHICH IS WHAT THIS BRANCH IS FOR. It first wrote
      // `Promise.resolve(true)` here, on the reading that a page with no editor has no fill to be
      // mid-way through. That reading is wrong for one reason: the field is not this page's. It lives
      // on the shared object, the dashboard is a single-page application, so one instance of that
      // object serves every tab of a session - and the only reader is the Policies Save. A page that
      // can never save a profile was reaching across and overwriting the guard of the page that can,
      // always in the direction of "go ahead".
      //
      // What that cost was demonstrated rather than argued. Policies is opened while another tab's
      // configuration fetch is still outstanding; that fetch lands after Policies has assigned its own
      // fill promise; the guard is then permanently true; and a Save in that window PUTs the profile
      // with its permission rows cleared and not yet re-rendered - every grant and deny stripped,
      // under a success message. Those denials are what new SSO-provisioned accounts are given, so an
      // administrator's restriction quietly stops applying.
      //
      // Leaving the field is what the single page did, because there was nothing else to write it: it
      // is null until the editor's own load sets it, and the page that has the editor always sets it
      // before a Save on that page is possible.
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
  // Whether the editor currently shows the profile the selector names, as a promise resolving true or
  // false. A Save must wait on it for two reasons, and only the whole chain covers both: the permission
  // rows are cleared synchronously and re-rendered only once sso/Config/Permissions answers, so a Save in
  // that window serializes no rows and drops every grant and deny the profile carries; and the fill itself
  // begins with a configuration fetch, so between choosing a profile and that fetch answering the selector
  // names one profile while the fields still hold another. Assigned SYNCHRONOUSLY by the change handler,
  // covering its own fetch - a promise assigned after the fetch resolved would be the PREVIOUS profile's,
  // already settled, and the Save would sail straight through it and write the previous policy under the
  // new name.
  provisioningProfileFill: null,
  selectProvisioningProfile: (page) => {
    const pending = ApiClient.getPluginConfiguration(
      ssoConfigurationPage.pluginUniqueId,
    ).then(
      (config) =>
        ssoConfigurationPage
          .showSelectedProvisioningProfile(page, config)
          .then(() => true),
      // Resolves FALSE rather than rejecting: a rejection nobody is waiting for is an unhandled one, and
      // what the Save needs to know is not the error but that the fields no longer describe the selection.
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
        // The editor now holds the selected profile as it is stored, so the page is clean and the Save gate
        // is re-run against the name that was just filled in (#1572).
        .then(() => ssoConfigurationPage.markPageClean(page))
    );
  },
  // The one write path of the four acts: re-post the whole configuration, then reload the page's view of it.
  // A rejected PUT is reported in this section's own status region rather than swallowed - the server can
  // refuse for a reason this act did not cause, and a silent failure here reads as a save that worked.
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
            "The server refused the saved configuration, so nothing was changed. A profile is checked by exactly the rules an inline starting policy is: the administrator, all-folders and Live TV permissions keep their own settings on a provider and are not written from here, and no account can be created disabled from here. Reload the page and try again.",
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

        // Add COPIES the chosen provider's inline policy rather than creating an empty profile (#1105,
        // decided 2026-09-02): an empty profile writes nothing onto a new account, so the control would
        // appear to do something and not do it. The copy works for the reason the automatic load-time hoist
        // declined on 2026-08-31 did not - the administrator supplies the name that could not be derived.
        // It CREATES and does not SELECT: no provider changes policy until somebody points it at this
        // profile, so the two acts stay distinct in the record and on the page.
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

    // A managed profile is restored under its old name after the save (DeclarativeManagedProviders.Reinject),
    // so a rename would leave a copy under the new name that the source no longer decides (#1498).
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
        // A provider a declarative source decided is restored WHOLE after this configuration is validated
        // (DeclarativeManagedProviders.Reinject), so a repoint of one does not survive the save: the
        // profile ends up renamed and that provider keeps naming the old name. That state is refused by
        // ProviderConfigValidator on every LATER save, so the whole plugin configuration becomes
        // unsaveable from this page - over a rename that reported success. Refused here instead, with the
        // repair named, because nothing downstream can undo it.
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
        // In the SAME document, so the configuration is never posted with a provider pointing at a name
        // that no longer exists - the state ProviderConfigValidator refuses.
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
          // Refused rather than cascaded. Clearing the references here would silently switch every one of
          // those providers to a different starting policy - for a provider with no inline template, to none
          // at all - which is a change to what new accounts get, made from a delete button.
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

    // Waits for the fill above, so what is serialized is the profile as it was loaded plus the
    // administrator's edits - never a permission list that has not been rendered yet, and never a previous
    // profile's policy under this name.
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

          // An all-declined profile is an EMPTY OBJECT here, never null. The provider arm sends no object at
          // all for that state, because an object present beside a named profile is refused; a profile IS the
          // object, so removing it would delete the profile and break every provider pointing at it.
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
  // Choosing a profile on a PROVIDER form is the only act here that discards something: the provider's own
  // inline policy stops being its policy, and the save clears it, because a configuration carrying both is
  // refused. Asked here, at the moment of the choice, where those fields are still on screen - not at Save,
  // where the administrator has already committed. Declining puts the selector back on (none).
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
    const read = ApiClient.getPluginConfiguration(
      ssoConfigurationPage.pluginUniqueId,
    ).then(
      (config) => {
        // A reply for a provider the editor has since left writes nothing (#1693). Dropped
        // rather than queued, because it is stale by then: whatever the editor is about now
        // was filled by its own read.
        if (
          !ssoConfigurationPage.replyStillSpeaksFor(page, "oid", provider_name)
        ) {
          return;
        }
        // A 200 that is not the configuration is a state the page can reach, rather than a
        // TypeError on the next line that nobody handles (#1694).
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
          ssoConfigurationPage.provisioningProfileNames(config),
        );

        // Reflect the loaded toggles in the reveal-on-toggle groups (hide-not-remove) and surface any
        // active insecure option. Runs after the check_fields above are set from the loaded provider, so a
        // hidden-but-checked box is never left behind for the next save.
        ssoConfigurationPage.syncDependentFields(page);
        // Reflect the loaded provider's name + base-URL override in the computed redirect URI (#724).
        ssoConfigurationPage.updateRedirectUri(page);
        // Last, so the role-map and folder-list controls the calls above created are covered too (#1104),
        // and the profile state is re-applied after it: applyManagedState disables or ENABLES every
        // control in the form, so for an unmanaged provider it re-enables the template controls this load
        // had just disabled for a provider whose policy comes from a profile - the fields would look
        // editable and their contents would then be discarded by the save. Chained on its promise,
        // because it waits for the managed-set report before it touches anything.
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
        // The editor now holds the stored provider, so the page is clean and the Save gate is re-run
        // against what was filled in rather than against what stood here before (#1572).
        ssoConfigurationPage.markPageClean(page);
      },
      // The read failed, so there is nothing to fill the form from (#1681). Attached as the SECOND
      // argument to then rather than as a catch, for the reason saveProvider states at its own handler:
      // a catch here would also fire for anything thrown by the fill above, and a fill that threw
      // halfway would then be reported as a server that could not be reached.
      () => {
        // And a failure for a provider the editor has since left closes nothing and says
        // nothing (#1693): the editor on screen was filled by its own read, and a sentence
        // about the provider before it would explain the loss of a form the reader is working
        // in by naming one they have already left.
        if (
          !ssoConfigurationPage.replyStillSpeaksFor(page, "oid", provider_name)
        ) {
          return;
        }
        ssoConfigurationPage.hideEditor(page);
        ssoConfigurationPage.reportUnreadableProviderConfiguration(page);
        // The form is gone, so nothing in it is unsaved, and the notice that says otherwise would
        // outlive the editor it is about (#1572).
        ssoConfigurationPage.markPageClean(page);
      },
    );
    // A THROW FROM THE FILL IS SETTLED HERE AND NOWHERE ELSE (#1694). This catch is on the
    // promise the two arms above RETURN, so it sees what the fulfilled arm threw and never the
    // original rejection - that one was handled by the second argument, which is the separation
    // #1689 asked for and could not express. A fill that threw used to run off the end of the
    // promise: the editor stayed open over blanks, the rail asserted "Still empty" about a
    // configured provider, and the only trace was in the browser console.
    //
    // A SECOND STATEMENT RATHER THAN A THIRD LINK, so the arms above keep the depth they had.
    // As a chain, Prettier breaks the call onto its own lines and re-indents two hundred
    // untouched lines of fill with it, which buries the three lines that changed.
    read.catch(() => {
      ssoConfigurationPage.hideEditor(page);
      ssoConfigurationPage.reportUnfillableProviderForm(page);
      ssoConfigurationPage.markPageClean(page);
    });
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
        // A rejection is a 404 for a provider that has not been saved yet, or a transport/authorization
        // failure. Say what to do; never show a value the server did not produce.
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

            // The PAGE region and not the editor's (#1572): the line above just hid the editor and the
            // editor's status box lives inside it, so an outcome written there would be invisible. That
            // is what an outcome needs now that it is no longer raised as a modal alert.
            ssoConfigurationPage.renderPageStatus(
              page,
              tr("config.provider_removed", "Provider removed."),
              true,
            );
          },
          // Report a genuine save failure rather than swallowing it. The delete
          // re-posts the whole configuration, so the server can now reject it for
          // a reason unrelated to this delete, e.g. a different provider whose
          // reserved-character name became "new" because it was removed from the
          // live config in the meantime (#336). Without this the PUT would reject
          // silently and the provider would appear undeleted with no explanation.
          // The FAILED arm does not hide the editor, so its outcome goes in the editor's own region, beside
          // the Delete button that was pressed - not in the page region, which is where the success arm
          // speaks because the success arm has just closed that editor (#1572).
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
      // The read that precedes the delete can fail on its own (#1577), and a delete that says nothing
      // reads as one that worked. The editor is still open on this arm - nothing was removed - so the
      // message goes in the editor's own region, exactly where the write-failure arm above puts its own.
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
  // ONE SAVE FOR THE SERVER PAGE (#1572), AND THE PARTIAL FAILURE IT DOES NOT HAVE.
  //
  // The two GLOBAL switches this page carries - ManageLoginPageButtons (#722) and EnableSingleLogout
  // (#727) - each had their own button and their own handler, and each handler re-read the whole
  // configuration, set its own flag and posted the result. One Save over two such handlers would be two
  // writes with no transaction between them: a failure on the second leaves the first applied while the
  // page shows a single outcome for a half-written pair, which is why #1527 refused to merge the buttons
  // and left the write path to this issue.
  //
  // WHAT REMOVES THE HAZARD IS NOT A TRANSACTION, IT IS THERE BEING ONE WRITE. Both flags are members of
  // the SAME root PluginConfiguration document, so this reads that document once, sets both flags on it,
  // and posts it once. There is no moment at which one flag is stored and the other is not: the server
  // writes the document whole or refuses it whole. A rejected PUT therefore leaves BOTH switches exactly
  // as they were stored, which is what the failure message says, and the reload that follows a success
  // is what re-reads the stored pair rather than trusting what was posted.
  //
  // What rides along unchanged is the rest of the document - the provider dictionaries, the provisioning
  // profiles, every other root setting - exactly as the provider save and delete paths carry them, so a
  // save here is not a way to lose a setting this page does not show. The server reacts to the saved
  // configuration itself (LoginButtonManager listens for the configuration change), so no extra endpoint
  // call is needed: on save the managed login block is injected or refreshed, or, with the flag off,
  // only that managed region is removed and an administrator's own branding is preserved.
  //
  // The outcome is rendered INLINE in this page's own status region rather than raised as an alert
  // (#1572): a modal that has to be dismissed says nothing a reader can come back to, and the failure
  // sentence here is the one that has to survive being re-read.
  saveServerSettings: (page) => {
    ssoConfigurationPage.renderPageStatus(page, "");
    return ApiClient.getPluginConfiguration(
      ssoConfigurationPage.pluginUniqueId,
    ).then(
      (config) => {
        // ONLY WHAT THE ADMINISTRATOR MOVED, WHICH IS WHAT THE TWO OLD HANDLERS DID BY ACCIDENT OF BEING
        // TWO. Each of them set its own flag on the freshly-read document and left the other alone, so a
        // change made elsewhere between this page's load and its save survived. Writing both from the
        // form takes that away: a second administrator who turns Single Logout on is silently undone by
        // the first pressing Save over a page loaded before it - a security flag switched off by somebody
        // who never touched it. So the merge keeps the property rather than the shape: a switch still
        // showing what it was loaded with is not written at all, and the value the read returned stands.
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
          // Report a genuine save failure rather than swallowing it: this PUT re-posts the whole
          // configuration, so the server can reject it for a reason neither switch caused (#336).
          () =>
            ssoConfigurationPage.renderPageStatus(
              page,
              tr(
                "config.server_settings_save_failed",
                "The server refused the saved configuration, so NEITHER switch was changed - the two ride one document and are written together or not at all. Reload the page to see what is stored, and try again.",
              ),
              false,
            ),
        );
      },
      // The read that precedes the write can fail on its own, and a page that says nothing after a
      // pressed Save reads as a save that worked. Nothing was posted in this arm, so nothing changed.
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
  // Writes one switch onto the document being saved, and ONLY where it differs from what the page was
  // loaded with. A switch nobody moved leaves the read value in place, so this Save cannot carry a stale
  // view of a flag its user never touched. A control the load never reached carries no loaded value, and
  // is left alone for the same reason: nothing here knows what it means.
  applyMovedSwitch: (page, config, selector, property) => {
    const control = page.querySelector(selector);
    if (!control || control.dataset.ssoLoaded === undefined) {
      return;
    }
    if (String(control.checked) !== control.dataset.ssoLoaded) {
      config[property] = control.checked;
    }
  },
  // The Server page's own status region, the exact parallel of renderSaveStatus on Providers, so one
  // page's outcome can never be written over another's.
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
  // THE ONE ANSWER TO A CONFIGURATION READ THAT FAILED WHILE AN EDITOR WAS BEING FILLED (#1681).
  //
  // Both loaders fill a form from a read that can fail, and until this existed neither had a rejection
  // arm at all: the editor was already open over the fields resetEditor had blanked, so the form read as
  // an empty provider, the readiness rail had been rebuilt from those blanks and asserted "Still empty"
  // about a provider that is saved and fully configured, and the rejection surfaced in the browser
  // console and nowhere a reader of the page will look. The rail is the part worth stating plainly: since
  // #1664 it is the only place readiness appears, so it was not silent, it was confidently wrong, and
  // what it said was the opposite of the truth.
  //
  // THE EDITOR IS CLOSED RATHER THAN ANNOTATED, and that is the decision. A note above a form full of
  // blanks leaves the blanks on screen, one Save away from writing them over a provider that is fine, and
  // leaves the rail answering about them. Closing it takes all three at once: nothing reads as the
  // provider's values, the Save goes with the form, and hideEditor / hideSamlEditor put the rail back to
  // its invitation through railReadiness, which is the state that matches a page with no editor open.
  //
  // THE PAGE REGION AND NOT THE EDITOR'S, for the reason deleteProvider states where it does the same
  // thing: the editor's status box lives inside the element that was just hidden, so an outcome written
  // there would be invisible.
  /*
   * Whether a reply about `provider_name` on `key` still speaks for what is on screen (#1693).
   *
   * A LOADER'S REPLY CAN BE ABOUT A PROVIDER NOBODY IS LOOKING AT ANY MORE, and a failing
   * request is typically the slower of two, so this is the ordinary ordering rather than an
   * exotic one: an administrator clicks a, its read stalls, they click b, b answers and fills
   * the form, and then a's read settles. Before this, a's FAILURE closed b's editor and put a
   * sentence about a on the page, and a's SUCCESS wrote a's values into b's form under b's
   * title. The second is the worse of the two, because a Save then persists it.
   *
   * THE SUBJECT AND NOT A COUNTER. A serial bumped when a read is issued answers "has another
   * read started", which is three of the four ways a reply goes stale and not the fourth: the
   * editor being CLOSED, or the other protocol being opened, issues no read at all. What the
   * editor is currently ABOUT answers all four at once - another provider opened, a blank New
   * provider form opened, the editor closed, the protocol switched - and it is read from the
   * same two places every other part of this page reads it from. `redirectUriSerial` twenty
   * lines below is the counter shape, for a question where the subject cannot move: that field
   * follows what is typed rather than which provider is loaded.
   *
   * applyManagedState compares the selector's value for the same reason, and this is that
   * comparison with the open-editor half added.
   */
  replyStillSpeaksFor: (page, key, provider_name) => {
    if (ssoConfigurationPage.openEditorKey(page) !== key) {
      return false;
    }
    const selector = page.querySelector(
      key === "saml" ? "#saml-selectProvider" : "#selectProvider",
    );
    return selector !== null && selector.value === provider_name;
  },
  /*
   * Whether a body a 200 carried is this plugin's configuration at all (#1694).
   *
   * A FULFILLED READ IS NOT A READ THAT WORKED. A proxy's error page that happens to parse, a
   * version-skewed endpoint, a truncated body: each arrives as a resolved promise, and the
   * first line of the fill then reads a member of undefined. The OpenID loader threw a
   * TypeError there and ran off the end of the promise, so the editor stayed open over the
   * fields resetEditor blanked, the rail asserted "Still empty" about a provider that is saved
   * and fully configured, and the only trace was in the browser console. The SAML loader read
   * `(config.SamlConfigs || {})` and so presented a blank provider as successfully read, which
   * is quieter and no better.
   *
   * THE MEMBER FOR THE PROTOCOL BEING READ, AND AN OBJECT. PluginConfiguration declares
   * OidConfigs and SamlConfigs as dictionaries that are always serialized, so a body missing
   * the one this loader needs is not the document whatever else it holds. Empty is fine and
   * must stay fine - a server with no provider of that protocol is the commonest installation
   * there is, and refusing it would close the editor on every one of them.
   */
  isProviderConfiguration: (config, key) => {
    if (config === null || typeof config !== "object") {
      return false;
    }
    const member = key === "saml" ? config.SamlConfigs : config.OidConfigs;
    return member !== null && typeof member === "object";
  },
  // A body that arrived and is not the configuration (#1694). A SECOND SENTENCE RATHER THAN
  // THE ONE ABOVE: the server answered, so "could not read the stored configuration" would
  // describe the wrong failure to whoever has to act on it - the thing to look at is what is
  // answering for Jellyfin, not whether Jellyfin is up.
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
  // And a fill that threw part way (#1694). A third state, because the two above are both
  // about the ANSWER and this one is about this page: the document was the document and
  // something in it was not the shape this form expects, so the form is closed rather than
  // left holding half of a provider.
  reportUnfillableProviderForm: (page) => {
    ssoConfigurationPage.renderPageStatus(
      page,
      tr(
        "config.provider_fill_failed",
        "The stored configuration was read, but this form could not be filled from it, so it was closed rather than left half filled. Reload the page and try again.",
      ),
      false,
    );
  },
  reportUnreadableProviderConfiguration: (page) => {
    ssoConfigurationPage.renderPageStatus(
      page,
      tr(
        "config.provider_read_failed",
        "Could not read the stored configuration, so this form was closed rather than left showing values that are not the stored ones. Reload the page and try again.",
      ),
      false,
    );
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
            // A checklist that never drew leaves the stored restriction alone rather than replacing it
            // with nothing (#1607). The key is left off the object entirely, so the stored value is what
            // the server keeps; assigning null here would be the same destructive write in another shape.
            if (folders !== null) {
              current_config[id] = folders;
            }
          });

          form_elements.role_map_fields.forEach((id) => {
            const elem = page.querySelector(`#${id}`);
            current_config[id] =
              ssoConfigurationPage.serializeRoleMappings(elem);
          });

          // The named profile and the inline template are ONE decision and are written together (#1105).
          // The selector is read here rather than by the flat loop above, for the reason
          // fillProvisioningTemplate states; the template follows it, because a save carrying both is
          // refused by ProviderConfigValidator - one account-creation policy has one source. Leaving the
          // stored template in place beside a newly chosen profile name would therefore make the provider
          // unsaveable from this page, client id and secret included, so the discard is deliberate; it is
          // confirmed at the moment the profile is chosen (chooseProvisioningProfile) rather than here,
          // where the administrator has already pressed Save.
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
              ssoConfigurationPage.loadConfiguration(page);
              ssoConfigurationPage.loadProvider(page, provider_name);

              page.querySelector("#selectProvider").value = provider_name;
              // The outcome is rendered inline by the caller, in the editor's own status region (#1572).
              resolve();
            },
            // Rejection handler attached directly to the save call, so it reports only a genuine save
            // failure and not an error thrown by the post-save UI work above. The server can refuse a
            // save for more than one reason (a malformed Base URL Override, #139; a provider name with
            // URI-reserved or control characters, #336/#360), so the message the caller renders names both
            // checks instead of blaming one.
            function () {
              reject(
                new Error(
                  tr("config.provider_save_failed", "Provider save failed"),
                ),
              );
            },
          );
        })
        // THE READ CAN FAIL ON ITS OWN, AND WITHOUT THIS NOTHING SETTLES (#1577). The rejection arm above
        // belongs to the WRITE. If the configuration read that precedes it fails - an expired dashboard
        // token, a 500, the server restart this editor itself asks for after a save - this promise never
        // settles, so neither of the caller's status arms runs and a pressed Save produces nothing at all:
        // the one failure a page can make that reads exactly like a save that worked. It also settles a
        // throw from inside the fill above, which would otherwise hang in the same way. A reject after a
        // resolve is a no-op, so the success path is untouched.
        .catch(() =>
          reject(
            new Error(
              tr("config.provider_save_failed", "Provider save failed"),
            ),
          ),
        );
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
        tr(
          "config.test_needs_saved_provider",
          "Enter a provider name and save it first, then test.",
        ),
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
          tr(
            "config.test_failed",
            "Could not run the test. Make sure the provider is saved and that you are signed in as an administrator, then try again.",
          ),
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
  // ---- Readiness panel (#1083), answered once in the rail (#1664) ----
  // WHICH PROTOCOL THE PAGE IS CURRENTLY ABOUT, or null when it is about neither. COMPUTED RATHER THAN
  // REMEMBERED: the two editors are mutually exclusive (#1527) and every route that opens one hides the
  // other, so this is a function of two `hidden` attributes and never of a variable somebody has to keep
  // in step.
  //
  // ONE READING, USED BY THE RAIL AND BY THE PANEL ITSELF, because two readings disagreeing is the
  // failure this arrangement can have: one list shared by both forms shows whatever was written into it
  // last, whichever form is on screen.
  openEditorKey: (page) => {
    const oid = page.querySelector("#sso-editor");
    const saml = page.querySelector("#saml-editor");
    if (!oid || !saml) {
      return null;
    }
    return !oid.hidden ? "oid" : !saml.hidden ? "saml" : null;
  },
  // The rail, brought into line with whatever is on screen. Both openers and both closers call it, and a
  // doubled call is a rebuild of the same list - which the panel was already safe for, being idempotent
  // and request-free.
  //
  // BOTH HIDDEN IS THE INVITATION, not an empty panel: a headed list with no rows reads as a provider
  // that answered nothing, which is the opposite of the truth when no provider is open.
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
  // The last Test Connection outcome per protocol, so the reachability row can report it WITHOUT
  // re-issuing the request. null means "not yet tested in this page session", which is what a provider
  // that has never been tested must read as - not as a failure. resetEditor / resetSamlEditor clear it,
  // so a previous provider's result cannot be read as this one's.
  readinessTestState: { oid: null, saml: null },
  // What each editor's panel is made of. Everything here is an id that already exists on the form: the
  // panel adds no field, no request and no state of its own beyond the test outcome above.
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
    // ONLY THE OPEN EDITOR MAY WRITE, and this is not belt-and-braces on top of
    // railReadiness - it is the half railReadiness cannot cover (#1664). Three callers
    // reach here ASYNCHRONOUSLY with a protocol decided when the request went out: the
    // redirect-URI debounce, the two loadProvider replies, and recordTestOutcome. While
    // each protocol wrote into its own list inside its own editor those late writes were
    // harmless - they landed in a hidden panel and were rebuilt on the next open. One
    // shared list removed that isolation, so an OpenID reply arriving after the
    // administrator clicked a SAML provider painted the OpenID answer under the SAML
    // form, including "Ready - Endpoint test", and it stood until the next keystroke.
    // Found by a review that drove it rather than by a reading of this file.
    //
    // A LATE WRITE IS DROPPED RATHER THAN QUEUED, because it is stale by then: the panel
    // is rebuilt from the form on the next open and on every field event, so nothing is
    // owed to the reply that lost the race.
    if (ssoConfigurationPage.openEditorKey(page) !== key) {
      return;
    }
    const spec = ssoConfigurationPage.readinessSpecs[key];
    // THE LIST IS READ FROM THE CONSTANT AND NOT FROM THE SPEC, so the two cannot diverge.
    // Each spec carried a listId until the review of 2026-09-12 pointed out that both had come
    // to hold the same value: a per-protocol field that no longer varies is a place for one of
    // them to be edited alone, and that is the last route left to the shape this card is
    // supposed to be free of - railReadiness unhides the list and hands over, so a lookup that
    // misses below leaves a headed panel with no rows. Driven on a tree with the old literals
    // put back, it produced exactly that. One name, one lookup, no divergence to have.
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
        // #1543 first, because it is the reason the list below is empty. Without it this action - the one
        // an operator clicks to find out why SSO is down - answers "nothing is configured yet" on a server
        // whose providers are on disk in a file it refused, which is the sentence the flag exists to stop.
        if (report && report.ConfigurationUnreadable === true) {
          ssoConfigurationPage.renderCheckNote(
            list,
            tr(
              "config.unreadable_configuration",
              "This server could not read its SSO configuration when it started, so it is running on default settings: no provider, no account link and no stored secret. Every SSO sign-in is refused until a configuration arrives - save a provider here, import one, or let a declarative source supply it. The server log says where the unreadable file was kept; keep that copy. If nobody can sign in at all, move the unreadable configuration file out of the way and delete the marker file beside it - its name is the configuration file plus .unreadable, with no timestamp on the end - then restart, and SSO will answer as it did before this check existed. Deleting the marker alone is not enough while the configuration file is still unreadable.",
            ),
          );
        }

        // Not when the reason is already on the line above (#1543): telling an operator that nothing is
        // configured, directly under a line saying the configuration could not be read, is the sentence
        // the flag exists to stop - printed twice over.
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
          tr(
            "config.config_imported",
            "Imported. Re-enter each provider's secret and save it; secrets are never included in an export.",
          ),
        );
      })
      .catch((e) => {
        // A local parse failure and a server rejection (an invalid or unsupported document, an expired
        // session) are both fail-closed here: the message is generic and never reflects a server value.
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
      .then((answer) => {
        // NO dataType ON THE FETCH ABOVE, AND THAT IS TWO DECISIONS RATHER THAN AN OMISSION. It would
        // put `accept: application/json` on the REQUEST, and the refusal body is a plain string: under
        // that header the server writes it as a JSON string, quotes included, so the sentence the toast
        // below shows an operator would arrive wrapped in them - and those sentences are quoted verbatim
        // by both migration pages and pinned by LinkImportTests. Without it the client hands back the
        // Response itself, so the JSON is read HERE, and a 2xx carrying no readable JSON - a rolled-back
        // server answering 204 to a page served from cache - reaches the uncounted branch instead of
        // being reported as a failure that did not happen.
        return Promise.resolve(answer)
          .then((body) =>
            body && typeof body.json === "function" ? body.json() : null,
          )
          .catch(() => null);
      })
      .then((result) => {
        // The number comes from the ANSWER now (#1520). Until it did, one fixed sentence stood over every
        // outcome, so a restore that rebound nothing read exactly like one that rebound everything - which
        // is how #1517 shipped unnoticed through every beta it was in. Three states, because they are three
        // different facts: a count, a zero worth acting on, and an answer that carried no count at all.
        // The last one is not reported as zero: claiming a number the server did not send is the shape this
        // whole issue is about.
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
    // The pending list (#1529) is a second view of the SAME roster read, never a second request: the
    // roster is elevation-gated, and the two panels answer one question each about one
    // document. Both containers are written on both arms, so neither panel is left showing "loading"
    // when the other has an answer.
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

    // Resolves to whether the roster was actually read, because a caller that re-reads after an action
    // must not word its result off the OLD held roster when the re-read failed: the panels then show the
    // failure sentence, and the action's own line has to agree with them rather than claim a state it
    // could not confirm.
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
  // THE ROSTER IS KEPT so the filter can re-render without asking the server again (#1529). Held on the
  // module rather than on the page because the page is a DOM node the client may replace, and a filter
  // keystroke must not turn into a request: the roster is elevation-gated and read under the config lock, and typing six
  // characters would spend six calls on data that has not changed.
  linkedAccountRoster: null,
  // Everything on one row that a reader might search by. The Jellyfin username, the provider name, the
  // protocol, and the identity-provider subject - which is the one an administrator usually arrives with,
  // because it is what the provider's own console shows them.
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

    // A FILTER THAT MATCHES NOTHING IS ITS OWN SENTENCE, and not the one above. "No account holds a link"
    // is a statement about the server; "nothing matches what you typed" is a statement about the box. A
    // reader who saw the first one after typing would conclude the links were gone.
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

    // THE COUNT LINE IS WHAT MAKES A FILTERED TABLE HONEST. Without it a narrowed table looks exactly like
    // a complete one, and an administrator counting rows to answer "how many accounts are linked" gets the
    // filter's answer instead of the server's. Rendered only while a filter is narrowing something, so an
    // unfiltered table gains no furniture.
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
  // THE BOUND on the pending list (#1529). A provider whose audience is wider than the one meant for
  // Jellyfin - the case the feature exists for - fills this list as fast as it can log in, and a table
  // of ten thousand rows is the page that breaks under the load it was built to absorb. So the first
  // hundred are drawn and a line says what was cut; nothing is hidden silently.
  PENDING_APPROVALS_BOUND: 100,
  // Every link the server reports as waiting, as (account, link) pairs in roster order. The SERVER
  // decides what waiting means - this plugin's own record of having provisioned the account inert, still
  // naming the account the link points at, on an account that is still disabled - and this reads only
  // the one field that carries its answer. Nothing here infers a pending account from a disabled flag,
  // because the flag does not say who set it, and the account somebody disabled on purpose is exactly
  // the row this list must not contain.
  pendingApprovals: (roster) => {
    const accounts =
      roster && Array.isArray(roster.Accounts) ? roster.Accounts : [];
    return accounts.flatMap((account) => {
      // ONE ROW PER ACCOUNT, on its first waiting link, so the count the panel reports is a count of
      // accounts - which is what its sentences say. An account cannot in practice carry two records,
      // because a record is written only by the create arm and an account is created once; the dedupe
      // is what keeps the sentence true even if that ever changed.
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

    // Its own sentence, and not the linked-accounts one: "no account holds a link" and "no account is
    // waiting" are different facts about the server, and a reader who came to approve somebody must not
    // be told the links are gone.
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

    // Every value on a row is attacker-influenced - the subject is whatever the identity provider put in
    // its claim - so the whole row is textContent, the same line the linked-accounts table holds (#221).
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

    // The PROVISIONING instant, which is what the column heading says: how long somebody has been
    // waiting is the question this list is opened with.
    const since_cell = document.createElement("td");
    since_cell.textContent = ssoConfigurationPage.formatLastSsoLogin(
      link && link.PendingApprovalSinceUtc,
    );
    row.appendChild(since_cell);

    // Always a button: the server withholds the pending instant from an orphan row and from an account
    // that is already enabled, so a row that reaches here is one the approve action will accept.
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
  // The approve (#1529). It drives POST sso/Links/Approve/{mode}/{provider} exactly as it stands - the
  // elevation policy, the link rate-limit class, the record check, the administrator refusal and the
  // audit line are all the endpoint's, and none of them is re-implemented or bypassed here. The
  // confirmation NAMES what the button does and what it does not: the account is enabled, and nothing
  // else about it changes.
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

    // The route's mode token is the protocol's short name, not the roster's display name; the canonical
    // name travels in the body because a subject may contain a slash.
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
        // Re-read rather than editing the rendered table: the roster is the server's answer, and the row
        // must disappear because the server no longer reports it, not because the page assumed so.
        ssoConfigurationPage.loadLinkedAccounts(page).then((read) => {
          // A re-read that failed leaves the OLD roster held, and a sentence chosen from it would claim a
          // state nobody confirmed - for a 204 that cleared a record because the account had gone, it
          // would say a deleted account can sign in. The panels show the failure; this line agrees.
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

          // A 204 is also the endpoint's answer for a record it cleared because the account had gone,
          // and the reader must not be told a deleted account can sign in. The re-read roster is the
          // server's word on whether the account still exists, so the sentence is chosen from it.
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
        // ApiClient.fetch rejects with the Response on a non-2xx status. Two refusals mean something to
        // the reader and get their own sentence; everything else is the generic one, which never reflects
        // a server value. The administrator refusal is told apart from an elevation refusal - both are
        // 403 - by the sentence the endpoint writes for it, matched on its own words rather than on the
        // bare word: an elevation refusal leaves the body empty, and a proxy's own 403 page can say
        // "administrator" about something else entirely.
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
          // A stale row is re-read rather than left standing: the server no longer offers it, and a
          // list that kept showing it would offer the same press again.
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
      // A MARKER RATHER THAN A tr() CALL, and the difference is timing (#1602). This picker is filled
      // once, during init, while the catalog is still arriving on localize()'s own promise - so a lookup
      // here reads the English and keeps it for the life of the page, which is exactly what the first
      // draft of this did. The marker rides the pass that retranslates the markup when the catalog lands
      // (i18n.applyTo), which is the mechanism the rest of the page already uses, and the English sits
      // there until it does.
      // Only the DESCRIPTIVE labels carry a key. A product name is the same string in every language, and
      // a catalog row saying Microsoft Entra ID in every locale is a row nobody could ever change.
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
    ssoConfigurationPage.renderPresetNote(
      page,
      "OidPreset-note",
      tr(preset.noteKey, preset.note),
    );
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
      tr(preset.noteKey, preset.note),
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
    // The same preservation its OpenID twin does, for the same reason (#1693).
    const chosen = select.value;
    select.querySelectorAll("option").forEach((option) => option.remove());
    Object.keys(providers).forEach((provider_name) => {
      select.appendChild(new Option(provider_name, provider_name));
    });
    select.value = chosen;
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
  // Load a SAML card into the editor. resetSamlEditor gives a clean slate FIRST (same discipline as
  // openProvider) so no field, toggle, or collapse state from the previously loaded provider bleeds into
  // this one and gets silently re-saved.
  openSamlProvider: (page, provider_name) => {
    page.querySelector("#saml-selectProvider").value = provider_name;
    ssoConfigurationPage.resetSamlEditor(page);
    ssoConfigurationPage.clearSamlValidationErrors(page);
    ssoConfigurationPage.renderSamlSaveStatus(page, "");
    ssoConfigurationPage.renderPageStatus(page, "");
    ssoConfigurationPage.setSamlEditorTitle(page, provider_name);
    ssoConfigurationPage.showSamlEditor(page);
    ssoConfigurationPage.loadSamlProvider(page, provider_name);
    // The same reason openProvider states: opening an editor is a read, and loadSamlProvider says so
    // again once its own fill lands (#1572).
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
    // A blank editor holds nothing anybody typed (#1572); its Save stays closed until the four required
    // fields carry a value.
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
      ? tr("config.insecure_hide", "Hide insecure options")
      : tr("config.insecure_show", "Show insecure options");
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
        // The same reading the OpenID loader makes (#1694). The `|| {}` below no longer
        // stands in for it: a missing member used to present a blank provider as read.
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
        // The editor now holds the stored provider, so the page is clean and the Save gate is re-run
        // against what was filled in rather than against what stood here before (#1572).
        ssoConfigurationPage.markPageClean(page);
      },
      // The same arm the OpenID loader carries, for the same reason and written the same way (#1681).
      // Both protocols reach this through one read of one configuration document, so a failure here is
      // never about one of them: whichever editor was being filled is closed and the page says why.
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
        ? label + " copied to the clipboard."
        : tr(
            "config.copy_failed",
            "Copy failed. Select the field and copy it manually.",
          ),
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
          ? tr("config.metadata_needs_url", "Enter a metadata URL first.")
          : tr("config.metadata_needs_xml", "Paste the metadata XML first."),
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
            "Could not import the metadata. Check the URL or XML, make sure you are signed in as an administrator, and that the address is reachable and not a private/loopback host.",
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
  // Mirror the server's fail-closed provider-name checks (#336/#360) before the round-trip, keeping the
  // source ASCII-only (control chars detected by code point, not a regex escape) as validateProviderName does.
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
          "Enter a full origin such as https://jellyfin.example.com (scheme + host only).",
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
    if ((url.pathname && url.pathname !== "/") || url.search || url.hash) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-BaseUrlOverride",
        tr(
          "config.validation_base_no_path_saml",
          "Enter the base URL only (no path), e.g. https://jellyfin.example.com, not the /sso/... ACS URL.",
        ),
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
            // The page region, for the reason the OpenID delete states: the editor this outcome belongs
            // to has just been closed (#1572).
            ssoConfigurationPage.renderPageStatus(
              page,
              tr("config.provider_removed", "Provider removed."),
              true,
            );
          },
          // The editor is still open on this arm; the outcome belongs beside the button. Same reason as the
          // OpenID delete above.
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
      // The same reason the OpenID delete states (#1577): the read can fail on its own and the editor is
      // still open, so the message goes where that editor's other outcomes go.
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
              ssoConfigurationPage.loadConfiguration(page);
              ssoConfigurationPage.loadSamlProvider(page, provider_name);

              page.querySelector("#saml-selectProvider").value = provider_name;
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
        // The same reason saveProvider states above (#1577): the arm inside belongs to the write, and a
        // failed READ would otherwise leave this promise unsettled and the pressed Save silent.
        .catch(() =>
          reject(
            new Error(
              tr("config.provider_save_failed", "Provider save failed"),
            ),
          ),
        );
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
        tr(
          "config.test_needs_saved_provider",
          "Enter a provider name and save it first, then test.",
        ),
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
          tr(
            "config.test_failed",
            "Could not run the test. Make sure the provider is saved and that you are signed in as an administrator, then try again.",
          ),
        );
        ssoConfigurationPage.recordTestOutcome(page, "saml", false);
      },
    );
  },
  // ---- The Overview tab (#1527) ----
  //
  // A STATUS VIEW THAT HOLDS NO SETTING. It writes nothing and offers nothing to save: every figure on it
  // is read back from the server, which is why docs/ui/mock/FIELDS.md gives it none of the page's 123
  // controls. Two sources, and each is used only for what it actually answers:
  //
  //   sso/Config/Check - whether a provider's configuration is complete, and whether it is switched on.
  //     It says nothing about whether the identity provider ANSWERS, and its own document says so, so
  //     nothing here reports a provider as reachable or as having passed a connection test. That is what
  //     the per-provider Test Connection is for, and it is on the Providers tab.
  //   sso/Links/Roster - the newest recorded SSO sign-in of any account linked to that provider. A
  //     provider nobody has signed in through carries no timestamp, and the card says exactly that
  //     rather than leaving a blank where a date belongs.
  //
  // Built with createElement/textContent throughout and never innerHTML (#221): a provider name reaches
  // this view from the configuration, so it stays inert here as it does on the provider cards.
  //
  // A FAILED READ AND AN EMPTY SERVER ARE NEVER COLLAPSED. Reporting "nothing configured" to an
  // administrator whose providers are all there is the one wrong answer this view can give, so a report
  // that did not arrive is said in words and no card list is painted at all.
  renderOverview: (page) => {
    const cards = page.querySelector("#sso-overview-providers");
    if (!cards) {
      return Promise.resolve();
    }

    return Promise.all([
      ApiClient.getJSON(ApiClient.getUrl("sso/Config/Check")).catch(() => null),
      ApiClient.getJSON(ApiClient.getUrl("sso/Links/Roster")).catch(() => null),
    ]).then(([report, roster]) =>
      ssoConfigurationPage.paintOverview(page, report, roster),
    );
  },

  // One status line of an Overview card. Its own helper rather than renderCheckRow, because that one
  // prefixes a readiness VERDICT ("Ready" / "Needs attention") and these lines are states rather than
  // verdicts - a disabled provider is not a provider needing attention, which is the distinction
  // ProviderCheckDocument itself insists on.
  appendOverviewRow: (list, ok, label) => {
    const item = document.createElement("li");
    item.classList.add("fieldDescription");
    item.dataset.state = ok ? "ok" : "bad";
    item.textContent = label;
    list.appendChild(item);
  },

  // The newest recorded SSO sign-in per "protocol/provider", from the link roster. A provider with links
  // but no recorded sign-in yields nothing rather than a zero date, so a card can tell "nobody has signed
  // in" from "the roster did not load" - the second is the case the caller passes null for.
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

  paintOverview: (page, report, roster) => {
    const cards = page.querySelector("#sso-overview-providers");
    const empty = page.querySelector("#sso-overview-providers-empty");
    const next = page.querySelector("#sso-overview-next");
    const state = page.querySelector("#sso-overview-state");

    // ALL FOUR OR NONE. The caller gates on the card list alone, and three of these were dereferenced
    // straight after it - so a page carrying one of the four and not the others threw here, on a render
    // that runs on every visit. They are one region and there is no arrangement in which a subset of
    // them is the right answer, so this asks for the region rather than for its first member.
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
    // Concatenated rather than substituted into a catalog string. tr() only substitutes placeholders
    // once the catalog has loaded, and loading it is deliberately best-effort, so a "{0} of {1}" default
    // would be shown with its braces intact on exactly the run where that fetch failed.
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
      card.appendChild(list);
      cards.appendChild(card);
    });

    ssoConfigurationPage.paintOverviewNextSteps(next, report, rows);
  },

  // What to do next. Every entry names a condition read out of the report above, so an entry disappears
  // exactly when the condition does and nothing here is advice nobody measured. An empty list is a
  // sentence rather than a blank region, so it cannot be read as a panel that failed to load.
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

  // The SSO-only line rides the configuration load every page already makes rather than a second fetch,
  // so what it says and what the Server tab's own control holds cannot come apart. A no-op on the four
  // tabs that carry no overview.
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

// ---- The five page controllers (#1527) ----
//
// One function per registered configuration page. The object above is the shared core - the API client
// calls, the validation, the provisioning-template controls, the presets and the renderers - and every
// function below only WIRES the controls of the page it is named for. The partition is not a style
// choice: a handler registered against a control that lives on another page would throw on a null and
// take the rest of that page's wiring down with it, because none of these registrations is guarded
// individually. What keeps them safe is that each one is reached only from the page whose markup holds
// its control, and `docs/ui/mock/FIELDS.md` plus `tools/ui-mock-fields.js` are what hold that partition
// to the markup: the tool refuses a control that is on no page, on two pages, or on a page the table
// does not name.
//
// The three calls every page makes are the prelude below. loadConfiguration fills whatever sections the
// page in front of it actually has and skips the rest, so one load path serves five pages.

/**
 * The calls every page with controls makes: the stylesheet, the configuration, the localized labels, the
 * unsaved-changes tracking, and the re-read on return to the tab.
 *
 * THE RE-READ ON `viewshow` IS HERE NOW (#1576), AND IT IS THE LOAD PATH THAT CHANGED RATHER THAN THE
 * DIRTY STATE. #1572 built the state for exactly this and the review refused the re-read, because
 * `loadConfiguration` was written to run once at construction, while the editors are still hidden, and
 * running it again emptied both library checklists, rendered a removed row back out of storage, and
 * decided on a dirty test that ran before an asynchronous fill. Each of those three now has its own
 * guard, and all three live at `refreshOnShow` and in `loadConfiguration`'s `refreshing` arm rather than
 * being restated here.
 *
 * THE LISTENER IS REGISTERED AFTER THE FIRST LOAD AND NOT INSTEAD OF IT, for the reason `initOverviewPage`
 * measured: jellyfin-web constructs the controller inside `loadView`'s own chain and dispatches
 * `viewshow` one microtask after that chain resolves, and this controller is reached through a dynamic
 * import, so the first `viewshow` is always missed. The init call covers the show that has already
 * happened; the listener covers every later show of the same cached view, when the controller does not
 * run at all.
 *
 * @param {Element} view The page element Jellyfin hands the controller.
 */
function initSharedPage(view) {
  ssoConfigurationPage.addTextAreaStyle(view);
  ssoConfigurationPage.loadConfiguration(view);
  ssoConfigurationPage.localize(view);
  ssoConfigurationPage.bindUnsavedChangeTracking(view);
  ssoConfigurationPage.markPageClean(view);
  view.addEventListener("viewshow", () =>
    ssoConfigurationPage.refreshOnShow(view),
  );
}

// One registration per template-control prefix that this page actually carries, derived from the
// prefix->form map rather than written out per form. Two of the three were once listed by hand and the
// third - the profile editor's - was missed, which left the button rendered, styled and disabled-managed
// while doing nothing, so a named profile could never be given a permission from the page at all. The
// presence test is what makes the same loop correct on two different pages since #1527: the OpenID and
// SAML forms are on Providers and the profile form is on Policies, so each page registers its own and
// silently skips a prefix whose form is not in front of it.
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
 *
 * THE ONLY PAGE THAT RE-READS ON EVERY SHOW, and the asymmetry is deliberate. The dashboard keeps three
 * views alive and hands a cached one back rather than building it again - viewContainer caches by
 * pathname+search, and viewManager's onBeforeChange constructs the controller only where `initComplete`
 * is unset - so a tab returned to has NOT re-run its controller and still shows whatever it last loaded.
 * That was read out of jellyfin-web rather than assumed, and the consequence is worst exactly here: add a
 * provider on Providers, come back, and Overview goes on saying no provider is configured.
 *
 * IT LOADS TWICE OVER, AT INIT AND ON `viewshow`, AND THE BELT IS NOT THE BRACES. A first draft moved the
 * load into the listener alone, on the reading that `viewshow` fires on every show including the first.
 * The EVENT does; the LISTENER is not there to hear it. jellyfin-web constructs the controller inside
 * `loadView`'s own chain and dispatches `viewshow` in the `.then` after that chain resolves - one
 * microtask later - and this controller registers its listener only once a dynamic import of the core has
 * resolved, which is a fetch. So the first `viewshow` is always missed, and what that shipped was an
 * Overview blank on every fresh load, with the markup's own default line asserting that SSO-only was off
 * on a server where it was on. The init call covers the show that has already happened by the time the
 * core arrives; the listener covers every later show of the same cached view, when the controller does
 * not run at all. In the ordering where both fire, the page loads twice, which costs one read of a
 * read-only report and paints the same thing.
 *
 * WHY THIS ONE READS UNCONDITIONALLY AND THE OTHER FOUR ASK FIRST. Re-reading the configuration re-fills
 * form controls, and those four pages hold controls an administrator may have typed into and not yet
 * saved. Overview has no control at all - none of the page's 123 - so re-reading it can lose nothing and
 * it needs no guard. The other four go through `refreshOnShow`, which refuses while an editor is open or
 * while the page holds anything the last read did not put there (#1576).
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

  // The aggregate configuration check (#1084). Read-only: it fetches a report and paints its own list.
  //
  // ON THIS TAB AND NOT ON OVERVIEW, because of what its detail lines are made of. Each row names the
  // settings a provider is still missing and resolves each one to the form's own localized label, read
  // off the page's `<label for>` rather than from a second copy of every label kept beside it. Overview
  // holds no form and therefore no label, so the same report rendered there fell back to bare property
  // ids - "Still empty: OidEndpoint, saml-SamlCertificate" where the page had said "OpenID Endpoint, IdP
  // Signing Certificate" - putting an internal prefix in front of an administrator and losing the
  // localization outright. The check belongs beside the labels it reads. Overview says the same thing in
  // whole sentences that need no label, derived from the same report by paintOverviewNextSteps.
  view.querySelector("#CheckAllProviders").addEventListener("click", (e) => {
    ssoConfigurationPage.checkAllProviders(view);
    e.preventDefault();
    return false;
  });

  view.querySelector("#SaveProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#OidProviderName").value;

    // The outcome is rendered in the editor's own status region and nowhere else (#1572). It used to be
    // said twice, inline and in a modal alert, and the inline half then had to point at the modal for the
    // reason - so a reader who dismissed the alert was left with a failure and no cause. The whole
    // sentence is here now. Handling the rejection keeps a failed save from becoming an unhandled promise
    // rejection (the rejection still exists so callers can distinguish failure from success).
    ssoConfigurationPage.saveProvider(view, target_provider).then(
      () => {
        ssoConfigurationPage.renderSaveStatus(view, "Settings saved.", true);
        ssoConfigurationPage.setEditorTitle(view, target_provider);
      },
      () =>
        ssoConfigurationPage.renderSaveStatus(
          view,
          tr(
            "config.provider_save_refused",
            "Could not save the provider. Check that the provider name has no control characters (such as a tab or newline, often introduced by copy-paste), no backslash, and none of the URI-reserved characters such as / ? # %, and that the Base URL Override is a full URL such as https://jellyfin.example.com (or blank).",
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
      // The whole reason, inline, rather than a pointer at a modal the reader has already dismissed
      // (#1572). The server refuses a save for more than one reason, so the sentence names both checks
      // instead of blaming one.
      () =>
        ssoConfigurationPage.renderSamlSaveStatus(
          view,
          tr(
            "config.provider_save_refused",
            "Could not save the provider. Check that the provider name has no control characters (such as a tab or newline, often introduced by copy-paste), no backslash, and none of the URI-reserved characters such as / ? # %, and that the Base URL Override is a full URL such as https://jellyfin.example.com (or blank).",
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

  // ---- Readiness panel (#1083), in the rail (#1664) ----
  // Advisory and read-only: these handlers re-read the form and rebuild the panel. They set no value,
  // check no box, and issue no request, so nothing here can change what a Save would send.
  //
  // NO PRIMING CALL HERE, AND THE ONE THAT STOOD HERE WAS DEAD. It rebuilt both panels at init, from a
  // time when each editor held its own; the rail answers only for an open editor and neither is open at
  // init, so the call returned at the gate every time. The card's starting state is the invitation the
  // markup ships, which a conformance rule pins. Removed rather than left as a line that reads like it
  // does something.
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
  // The per-provider selectors, on both forms. The handler asks before the inline policy is discarded and
  // then syncs the note and the disabled state, so the page reflects the choice immediately rather than
  // only after the next load.
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

/** The Accounts tab: who is linked, and the account-link transfer pair. */
function initAccountsPage(view) {
  initSharedPage(view);

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

  // The filter re-renders from the roster already held and asks the server for nothing (#1529). Bound on
  // `input` rather than on `change` so the table narrows while the reader types: `change` on a search box
  // waits for a blur or an Enter, which reads as a filter that does not work.
  //
  // `container` is looked up per event rather than captured, because the region is replaced on every load
  // and a captured node would be one that is no longer in the page.
  view.querySelector("#LinkedAccountsFilter").addEventListener("input", () => {
    ssoConfigurationPage.renderLinkedAccounts(
      view,
      view.querySelector("#LinkedAccountsResult"),
    );
  });

  ssoConfigurationPage.loadLinkedAccounts(view);

  // The roster is the one thing on this tab that a change made elsewhere - a revoke, a link import, a
  // first sign-in - moves, and `loadConfiguration` does not fetch it (#1576). Unconditional, like
  // Overview's read and for the same reason: it renders a read-only list and writes no control, so a
  // re-read here can discard nothing. `refreshOnShow` still runs beside it from initSharedPage.
  view.addEventListener("viewshow", () =>
    ssoConfigurationPage.loadLinkedAccounts(view),
  );
}

/** The Policies tab: the named provisioning-profile editor. */
function initPoliciesPage(view) {
  initSharedPage(view);
  bindTemplatePermissionAdders(view);

  // ---- Provisioning profiles (#1105) ----
  // The editor is filled by loadConfiguration, so nothing is populated here; these are the four acts and
  // the selection. Each is its own handler against the live configuration, and every one of the four
  // buttons is type="button" in the markup: the section sits in its own form, so a submit that reached the
  // browser would reload the dashboard, and preventDefault runs only AFTER the act - a synchronous throw
  // inside one would let the navigation happen.
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

  // One Save for both switches (#1572). Two buttons became one because the two flags are members of one
  // document and are written by one PUT; what that removes is written at saveServerSettings.
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
 * The controller for each registered page, keyed by the name its markup asks for. A page's own module
 * looks itself up here rather than importing a named function, so adding a tab is one entry and one
 * thin module rather than an edit spread over both.
 */
export const pageControllers = {
  overview: initOverviewPage,
  providers: initProvidersPage,
  accounts: initAccountsPage,
  policies: initPoliciesPage,
  server: initServerPage,
};
