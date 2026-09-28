import { loadCatalog, applyTo, t } from "./i18n.js";

// The self-service linking page: the holder's SSO links per provider, their removal and the sign-out control.
const ssoConfigLinking = {
  pluginUniqueId: "505ce9d1-d916-42fa-86ca-673ef241d7df",

  // Shows the generic failure banner, which never carries a status code or server message (#536, #564).
  showError: () => {
    const banner = document.querySelector("#sso-linking-error");
    if (banner) {
      banner.hidden = false;
    }
  },

  // Hides the generic banner once a rejected unlink turns out to be a refusal with its own sentence (#1731).
  hideError: () => {
    const banner = document.querySelector("#sso-linking-error");
    if (banner) {
      banner.hidden = true;
    }
  },

  // Shows the refusal banner with a catalogue sentence, a separate element because the generic one is
  // rewritten by every catalogue pass; never filled from a server value (#1731, #536).
  showRefusal: (message) => {
    const banner = document.querySelector("#sso-linking-refused");
    if (banner) {
      banner.textContent = message;
      banner.hidden = false;
    }
  },

  // Shows the signed-out notice after the last SSO link is removed, hiding the other banners and every
  // control that would send a request on the now ended session (#1882).
  showSignedOut: (view) => {
    ssoConfigLinking.hideError();
    const refused = document.querySelector("#sso-linking-refused");
    if (refused) {
      refused.hidden = true;
    }
    const banner = document.querySelector("#sso-linking-signed-out");
    if (banner) {
      banner.hidden = false;
    }
    ssoConfigLinking.stopOffering(view);
    ssoConfigLinking.stopOfferingSignOut();
  },

  // Every "Sign out everywhere" control on the page (#1768), so a global refusal can disable them all.
  signOutButtons: [],

  // Draws the sign-out control beside an OpenID provider the holder holds a link on (#1768).
  offerSignOut: (container, provider_name) => {
    const row = container.querySelector(
      `.sso-provider-links-container[data-id="${CSS.escape(provider_name)}"]`,
    );
    if (!row) {
      return;
    }

    const button = document.createElement("button");
    button.type = "button";
    button.classList.add("raised", "emby-button", "sso-provider-sign-out");
    button.dataset.provider = provider_name;
    const icon = document.createElement("span");
    icon.classList.add("material-icons", "logout");
    icon.setAttribute("aria-hidden", "true");
    const label = document.createElement("span");
    label.textContent = t(
      "link.sign_out_everywhere",
      undefined,
      "Sign out everywhere",
    );
    button.append(icon, label);
    // Bound in the closure because a click often lands on the label span, not the button.
    button.addEventListener("click", () =>
      ssoConfigLinking.handleSignOutPressed(button, provider_name),
    );
    row.appendChild(button);
    ssoConfigLinking.signOutButtons.push(button);
  },

  // Disables every sign-out control on the page.
  stopOfferingSignOut: () => {
    ssoConfigLinking.signOutButtons.forEach((button) => {
      button.disabled = true;
    });
  },

  // Mints a one-time logout ticket over the API client, then navigates with it, so no access token goes
  // into the URL (#1768). The control stays disabled while a press is in flight.
  // A 404 means Single Logout is off and removes every control; 503 and 429 keep it; anything else is a failed press.
  handleSignOutPressed: (button, provider_name) => {
    if (button.disabled) {
      return Promise.resolve();
    }
    button.disabled = true;

    return ApiClient.fetch({
      type: "POST",
      url: ApiClient.getUrl(
        `sso/OID/logout-ticket/${encodeURIComponent(provider_name)}`,
      ),
    })
      .then((resp) => resp.json())
      .then((body) => {
        const ticket =
          body && typeof body.ticket === "string" ? body.ticket : "";
        if (ticket === "") {
          return Promise.reject({ status: 0 });
        }
        window.location.assign(
          ApiClient.getUrl(
            `sso/OID/logout/${encodeURIComponent(provider_name)}`,
            { ticket },
          ),
        );
        return undefined;
      })
      .catch((rejection) => {
        const status =
          rejection && typeof rejection.status === "number"
            ? rejection.status
            : 0;
        if (status === 404) {
          ssoConfigLinking.stopOfferingSignOut();
          ssoConfigLinking.showRefusal(
            t(
              "link.sign_out_unavailable",
              undefined,
              "Single Logout is not turned on for this server, so the identity provider cannot be asked to end its session from here. Use Jellyfin's own Sign out to end this session.",
            ),
          );
          return;
        }

        button.disabled = false;
        ssoConfigLinking.showRefusal(
          status === 503 || status === 429
            ? t(
                "link.sign_out_busy",
                undefined,
                "The server is not issuing sign-out tickets right now. Try again in a minute. Jellyfin's own Sign out still ends this session.",
              )
            : t(
                "link.sign_out_failed",
                undefined,
                "Signing out everywhere did not start: the server issued no sign-out ticket. Reload the page and try again, or use Jellyfin's own Sign out.",
              ),
        );
      });
  },
  // Loads the enabled provider names of each protocol and renders their rows.
  loadProviders: (view) => {
    ssoConfigLinking.signOutButtons = [];
    ["oid", "saml"].forEach((provider_mode) => {
      const container = view.querySelector(
        `#sso-provider-list-${provider_mode}`,
      );
      container.innerHTML = "";

      ApiClient.fetch(
        {
          type: "GET",
          url: ApiClient.getUrl(`sso/${provider_mode.toUpperCase()}/GetNames`),
        },
        true,
      )
        .then((resp) => resp.json())
        .then((config_names) => {
          ssoConfigLinking.loadProviderList(
            container,
            config_names,
            provider_mode,
          );
        })
        // A non-2xx status rejects, so a failed load shows the banner rather than an empty list (#564).
        .catch(() => ssoConfigLinking.showError());
    });
  },
  // Shows a placeholder in a protocol section with no rows, once both feeds have resolved (#669).
  maybeShowSectionEmptyState: (container, provider_mode) => {
    if (container.children.length > 0) {
      return;
    }
    const placeholder = document.createElement("p");
    placeholder.classList.add("sso-provider-empty");
    placeholder.textContent = t(
      "link.no_providers",
      { mode: provider_mode.toUpperCase() },
      "No {mode} providers are available.",
    );
    container.appendChild(placeholder);
  },
  // Renders the enabled providers, then the holder's existing links, including those on disabled providers.
  loadProviderList: (container, providers, provider_mode) => {
    // The server offers only enabled providers here (#344), so every name gets an add button.
    providers.forEach((provider_name) => {
      ssoConfigLinking.appendProviderContainer(
        container,
        provider_name,
        provider_mode,
        true,
      );
    });

    const currentUserId = ApiClient.getCurrentUserId();

    if (currentUserId) {
      ApiClient.fetch(
        {
          type: "GET",
          url: ApiClient.getUrl(`sso/${provider_mode}/links/${currentUserId}`),
        },
        true,
      )
        .then((resp) => resp.json())
        .then((provider_map) => {
          Object.keys(provider_map).forEach((provider_name) => {
            let existing_links = container.querySelector(
              `.sso-provider-existing-links-container[data-provider="${CSS.escape(provider_name)}"]`,
            );

            // No container means the provider is disabled (#344); its links are still listed and removable,
            // unless there are none.
            if (!existing_links) {
              if (provider_map[provider_name].length === 0) {
                return;
              }
              existing_links = ssoConfigLinking.appendProviderContainer(
                container,
                provider_name,
                provider_mode,
                false,
              );
            }

            ssoConfigLinking.populateExistingLinks(
              existing_links,
              provider_mode,
              provider_name,
              provider_map[provider_name],
            );

            if (
              provider_mode === "oid" &&
              provider_map[provider_name].length > 0
            ) {
              ssoConfigLinking.offerSignOut(container, provider_name);
            }
          });
          ssoConfigLinking.maybeShowSectionEmptyState(container, provider_mode);
        })
        // A non-2xx status rejects, so a failed load shows the banner rather than an empty list (#536).
        .catch(() => ssoConfigLinking.showError());
    } else {
      // No signed-in user, so the section is complete once the enabled providers are rendered.
      ssoConfigLinking.maybeShowSectionEmptyState(container, provider_mode);
    }
  },

  // Builds and appends one provider row and returns its existing-links container.
  // A disabled provider (offerLink false) gets no add button, but its held links stay listed.
  appendProviderContainer: (
    container,
    provider_name,
    provider_mode,
    offerLink,
  ) => {
    // Names are identity-provider or admin controlled: DOM via textContent, selectors and URLs only escaped.
    const provider_config = document.createElement("div");
    provider_config.classList.add("sso-provider-links-container");
    provider_config.dataset.id = provider_name;

    const title = document.createElement("label");
    title.classList.add(
      "inputLabel",
      "inputLabelUnfocused",
      "sso-provider-link-title",
    );
    title.textContent = provider_name;

    const existing_links = document.createElement("div");
    existing_links.classList.add("sso-provider-existing-links-container");
    existing_links.dataset.provider = provider_name;
    // Whether a link here can sign the holder in; the server reads a disabled provider the same way (#1731, #1720).
    existing_links.dataset.enabled = offerLink ? "true" : "false";

    if (offerLink) {
      const add_provider = document.createElement("a");
      add_provider.classList.add(
        "fab",
        "emby-button",
        "sso-provider-add-link",
        "sso-provider",
      );
      const add_icon = document.createElement("span");
      add_icon.classList.add("material-icons", "add");
      add_icon.setAttribute("aria-hidden", "true");
      add_provider.appendChild(add_icon);
      add_provider.href = ApiClient.getUrl(
        `/SSO/${provider_mode}/p/${encodeURIComponent(provider_name)}?isLinking=true`,
      );
      provider_config.append(title, add_provider, existing_links);
    } else {
      const disabled_note = document.createElement("span");
      disabled_note.classList.add("sso-provider-disabled-note");
      disabled_note.textContent = t(
        "link.disabled_note",
        undefined,
        " (disabled)",
      );
      title.appendChild(disabled_note);
      provider_config.append(title, existing_links);
    }

    container.appendChild(provider_config);
    return existing_links;
  },

  // Renders one checkbox row per canonical name the holder has linked on a provider.
  populateExistingLinks: (
    container,
    provider_mode,
    provider_name,
    canonical_names,
  ) => {
    container
      .querySelectorAll(".sso-provider-link-checkbox-wrapper")
      .forEach((e) => e.remove());

    const checkboxes = canonical_names.map((canonical_name) => {
      const out = document.createElement("label");
      out.classList.add(
        "sso-provider-link-checkbox-wrapper",
        "checkbox-wrapper",
      );

      // The name is set through dataset and textContent so a hostile linked-account name stays inert.
      // The `is` option throws on the Jellyfin 12 client (#1607), so construction falls back to the attribute alone.
      let checkbox;
      try {
        checkbox = document.createElement("input", { is: "emby-checkbox" });
      } catch {
        checkbox = document.createElement("input");
      }
      checkbox.setAttribute("is", "emby-checkbox");
      checkbox.classList.add("sso-link-checkbox");
      checkbox.type = "checkbox";
      checkbox.dataset.id = canonical_name;
      checkbox.dataset.mode = provider_mode;
      checkbox.dataset.provider = provider_name;
      // Copied onto the row because the delete button reads a flat list (#1731); an undeclared container counts as a way in.
      checkbox.dataset.enabled =
        container.dataset.enabled === "false" ? "false" : "true";

      const checkbox_label = document.createElement("span");
      checkbox_label.classList.add("checkbox-label");
      checkbox_label.textContent = canonical_name;

      out.append(checkbox, checkbox_label);
      return out;
    });

    checkboxes.forEach((e) => {
      container.appendChild(e);
    });
  },

  // Disables the delete checkbox and button on a page whose rows may no longer be true (#1731).
  stopOffering: (view) => {
    const enable = view.querySelector("#enable-delete");
    if (enable) {
      enable.checked = false;
      enable.disabled = true;
    }

    const button = view.querySelector("#btn-delete-selected-links");
    if (button) {
      button.disabled = true;
    }
  },

  // Whether the rows being sent remove every rendered link that could sign the holder in (#1720).
  // A link on a disabled provider is not a way in.
  removesEveryWayIn: (rendered, sending) => {
    const isWayIn = (box) => box.dataset.enabled !== "false";
    const waysIn = rendered.filter(isWayIn);
    const removed = sending.filter(isWayIn);
    return removed.length > 0 && removed.length === waysIn.length;
  },

  // Removes the ticked links after confirming a last-link removal, then reports the outcome.
  handleDeleteButtonPressed: (evt, view) => {
    if (evt.target.disabled) return Promise.resolve();

    const currentUserId = ApiClient.getCurrentUserId();
    if (!currentUserId) return Promise.resolve();

    const rendered = [...view.querySelectorAll(".sso-link-checkbox")];
    const selected = rendered.filter((checkbox_link) => {
      const canonical_name = checkbox_link.dataset.id;
      const provider_name = checkbox_link.dataset.provider;
      const provider_mode = checkbox_link.dataset.mode;

      if (![canonical_name, provider_name, provider_mode].every(Boolean)) {
        return false;
      }

      if (!checkbox_link.checked) {
        return false;
      }

      return true;
    });

    // A courtesy before the press; the server's refusal is the rule (#1731). The question names the
    // consequence and never promises a refusal, because administrators (#1732) and some accounts (#1733) are not covered.
    const removesEveryWayIn = ssoConfigLinking.removesEveryWayIn(
      rendered,
      selected,
    );
    if (
      removesEveryWayIn &&
      !window.confirm(
        t(
          "link.delete_last_confirm",
          undefined,
          "Remove the last SSO link that can sign you in? You are signed out on every device the moment it is gone, and nothing on this page will sign you back in: a Jellyfin password for this account would be the only way left in, and on a server that allows only SSO there is usually none. If there is none, you will not be able to sign in at all and only an administrator can restore your access.",
        ),
      )
    ) {
      return Promise.resolve();
    }

    const delete_requests = selected.map((checked_link) => {
      const canonical_name = checked_link.dataset.id;
      const provider_name = checked_link.dataset.provider;
      const provider_mode = checked_link.dataset.mode;

      // Encoded segments stop a name from injecting path segments; "." stays unencoded for dotted names.
      return ApiClient.fetch({
        type: "DELETE",
        url: ApiClient.getUrl(
          `sso/${provider_mode}/link/${encodeURIComponent(provider_name)}/${currentUserId}/${encodeURIComponent(canonical_name)}`,
        ),
      });
    });

    return (
      Promise.all(delete_requests)
        // After a removal the links feed is asked once more: a 401 means the server ended the session with the
        // last link, so the page says so instead of reloading into the banner (#1882).
        .then(() =>
          ApiClient.fetch(
            {
              type: "GET",
              url: ApiClient.getUrl(`sso/oid/links/${currentUserId}`),
            },
            true,
          ).then(
            () => window.location.reload(),
            (rejection) => {
              if (rejection && rejection.status === 401) {
                ssoConfigLinking.showSignedOut(view);
                return;
              }
              window.location.reload();
            },
          ),
        )
        // A rejected DELETE shows the banner instead of reloading (#536). The stranding refusal gets its
        // own sentence (#1731), matched on the endpoint's words; a reword falls back to the generic banner.
        .catch((rejection) => {
          // The banner goes up before the body is read, since the body can stall behind a proxy.
          ssoConfigLinking.showError();

          const status =
            rejection && typeof rejection.status === "number"
              ? rejection.status
              : 0;
          const body =
            rejection && typeof rejection.text === "function"
              ? Promise.resolve(rejection.text()).catch(() => "")
              : Promise.resolve("");

          return body.then((text) => {
            const declined =
              status === 403 &&
              /last SSO link that can sign you in/i.test(String(text || ""));

            // After a partial batch the rows may be wrong, so the delete control stops; a single declined
            // request leaves them true and keeps it.
            if (!declined || delete_requests.length !== 1) {
              ssoConfigLinking.stopOffering(view);
            }

            // Names only the refused removal. The second clause of the server's sentence tells the last
            // administrator apart from a user (#1732).
            if (declined) {
              const serverLeftUnreachable =
                /no other administrator on this server/i.test(
                  String(text || ""),
                );
              ssoConfigLinking.hideError();
              ssoConfigLinking.showRefusal(
                serverLeftUnreachable
                  ? t(
                      "link.delete_refused_would_strand_server",
                      undefined,
                      "The server refused to remove the last SSO link that can sign you in: no other administrator on this server holds an SSO link that can sign them in either, so removing that link could have left this server with no administrator able to reach it. Ask another administrator to remove it for you, or link another provider to your account first and then remove this one. Reload the page to see the links it holds now.",
                    )
                  : t(
                      "link.delete_refused_would_strand",
                      undefined,
                      "The server refused to remove the last SSO link that can sign you in: this account has no password anybody can sign in with, so removing that link would have left you unable to sign in at all. Link another provider first and then remove this one, or ask an administrator to set a password on this account and switch it back to password sign-in. Reload the page to see the links it holds now.",
                    ),
              );
            }
          });
        })
    );
  },
};

// Wires the delete controls, then loads the catalogue and the providers.
export default function initLinkingView(view) {
  view.querySelector("#enable-delete").addEventListener("change", (e) => {
    view.querySelector("#btn-delete-selected-links").disabled =
      !e.target.checked;
  });

  view
    .querySelector("#btn-delete-selected-links")
    .addEventListener("click", (e) =>
      ssoConfigLinking.handleDeleteButtonPressed(e, view),
    );

  // The catalogue loads first so static markup and built rows are localized; it always resolves.
  loadCatalog().then(() => {
    applyTo(document);
    ssoConfigLinking.loadProviders(view);
  });
}
