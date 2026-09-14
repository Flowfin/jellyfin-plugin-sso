import { loadCatalog, applyTo, t } from "./i18n.js";

const ssoConfigLinking = {
  pluginUniqueId: "505ce9d1-d916-42fa-86ca-673ef241d7df",

  // A single generic banner for a failed request on this page (GetNames load, existing-links load,
  // or unlink, #536/#564). It never carries a status code or server message, so a rejection cannot
  // leak an internal detail into the admin UI; it just tells the user the page is no longer
  // trustworthy as shown.
  showError: () => {
    const banner = document.querySelector("#sso-linking-error");
    if (banner) {
      banner.hidden = false;
    }
  },

  // Takes the generic banner back down, and it exists for ONE caller: the unlink shows the generic
  // banner the moment a request is rejected and only then reads the body to find out whether the
  // server declined for a reason worth its own sentence (#1731). Saying nothing until the body has
  // been read would leave a page that took the delete control away and said nothing at all if that
  // read never settles, which is what a stalled body behind a proxy looks like.
  hideError: () => {
    const banner = document.querySelector("#sso-linking-error");
    if (banner) {
      banner.hidden = true;
    }
  },

  // The refusal banner, which is a SECOND element rather than the one above with different words
  // (#1731). The generic banner is authored in the markup and carries `data-i18n="link.load_error"`,
  // so a catalogue pass would write its own row back over anything put into it; and the two say
  // opposite things about the page - one says the page can no longer be trusted as shown, the other
  // says the server understood the request and declined it, with the link still there and still
  // correct on screen. Only ever filled with a catalogue row through `t()`, never with a server
  // value, so nothing the server writes reaches the page (#536).
  showRefusal: (message) => {
    const banner = document.querySelector("#sso-linking-refused");
    if (banner) {
      banner.textContent = message;
      banner.hidden = false;
    }
  },
  loadProviders: (view) => {
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
        // ApiClient.fetch rejects on a non-2xx status (auth expiry, a server error, ...), the same as
        // the existing-links load below, so a failed GetNames load surfaces the banner instead of
        // silently rendering an empty provider list (#564).
        .catch(() => ssoConfigLinking.showError());
    });
  },
  // When a protocol section ends up with no rows (no enabled providers to offer and no existing
  // link the user still holds), show a placeholder instead of a bare heading over blank space
  // (#669), so a single-protocol or fresh install does not look broken. Called only after both the
  // enabled-provider list and the existing-links feed have resolved, since a disabled provider the
  // user still holds a link to is rendered from the links feed and keeps the section non-empty.
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
  loadProviderList: (container, providers, provider_mode) => {
    // The server only offers enabled providers for new links (#344), so every name here gets an
    // add button. A link the user still holds to a since-disabled provider is rendered separately
    // below, from the links feed, so it stays visible and removable.
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

            // No container means the provider is not offered for new links because it is disabled
            // (it is absent from the enabled-only GetNames list, #344). The server still returns
            // such links and still lets the user delete them (LinksByUser / TryRemoveLink pass
            // requireEnabled:false; disabling then cleaning up is the intended workflow), so render
            // a container without an add button, marked disabled, rather than dropping it and
            // throwing on a null container. A disabled provider the user holds no link to (empty
            // list, nothing to remove) is skipped.
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
          });
          ssoConfigLinking.maybeShowSectionEmptyState(container, provider_mode);
        })
        // ApiClient.fetch rejects on a non-2xx status (auth expiry, a server error, ...), so a failed
        // existing-links load surfaces the banner instead of silently leaving the list empty (#536).
        .catch(() => ssoConfigLinking.showError());
    } else {
      // No signed-in user to fetch existing links for: the section is complete once the enabled
      // providers are rendered, so decide the empty state now.
      ssoConfigLinking.maybeShowSectionEmptyState(container, provider_mode);
    }
  },

  // Builds one provider row (title, optional add button, existing-links container) and appends it,
  // returning the existing-links container so the caller can populate it. When offerLink is false the
  // provider is disabled: no add button is drawn (it cannot accept a new link) and the title is marked,
  // but any link the user already holds stays listed and removable.
  appendProviderContainer: (
    container,
    provider_name,
    provider_mode,
    offerLink,
  ) => {
    // Provider and canonical names are identity-provider/admin-controlled: build the DOM with
    // createElement/textContent (never innerHTML), and feed them into selectors and URLs only
    // through CSS.escape / encodeURIComponent, never raw.
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
    // WHETHER A LINK IN THIS CONTAINER IS A WAY IN (#1731), carried here because this is the only
    // place that knows: `offerLink` is false exactly for a provider absent from the enabled-only
    // GetNames list. The server decides stranding by the same reading - a link on a switched-off
    // provider cannot sign anybody in (#1720) - so the sentence before the press and the refusal
    // after it are counting the same population, rather than the page counting rows and the server
    // counting doors.
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

      // The canonical name is identity-provider-controlled - assigning it via dataset/textContent
      // (never innerHTML) keeps a hostile linked-account name inert on this page.
      // The `is` option upgrades the customized built-in where the client accepts it. The Jellyfin 12
      // client refuses that argument outright and throws for any value (#1607), which would take this
      // list the way it took the provider page's library checklists, so the construction falls back to
      // the attribute alone. The attribute is set either way, so CSS attribute selectors and the
      // web-components polyfill see it.
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
      // Copied onto the row rather than looked up from the container at press time (#1731). The
      // delete button reads a flat list of checkboxes across both protocol sections, and a lookup
      // back up the tree would have to work on the container the row happens to sit in - which is a
      // different element on the disabled path, built by the branch below the enabled one. A row
      // whose container never declared it counts as a way in, which is the reading that ASKS before
      // acting rather than the one that stays silent.
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

  // Takes the delete control off a page whose rows may no longer be true (#1731). Both halves, because
  // the button is re-enabled by the checkbox beside it and disabling only the button would be undone by
  // the next tick of it. Nothing turns either back on: the banner beside them asks for a reload, and a
  // reload is what rebuilds the rows from the server.
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

  // Whether the rows about to be sent take away every link that could sign this holder in again.
  //
  // A LINK ON A SWITCHED-OFF PROVIDER IS NOT A WAY IN, in either direction, which is the reading the
  // server's refusal takes (#1720): a leftover link on a provider somebody disabled does not keep the
  // page quiet, and removing such a link on its own never raises the question at all. The counting is
  // over the rows the page has RENDERED, so a link the holder cannot see - one this feed did not
  // return - is not counted as a way in either; that is the same population the delete button acts on.
  removesEveryWayIn: (rendered, sending) => {
    const isWayIn = (box) => box.dataset.enabled !== "false";
    const waysIn = rendered.filter(isWayIn);
    const removed = sending.filter(isWayIn);
    return removed.length > 0 && removed.length === waysIn.length;
  },

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

    // THE SENTENCE BEFORE THE PRESS, and it is the courtesy rather than the rule (#1731). The rule is
    // the server's refusal, and this page cannot reproduce it: whether the account has a password to
    // fall back on is a fact about a Jellyfin user record that nothing here reads. A page can be
    // reloaded, scripted around or out of date against the server, which is why the guard was built
    // there and why declining here only stops the request rather than standing for a decision.
    //
    // SO THE QUESTION NAMES THE CONSEQUENCE AND NEVER PROMISES THE REFUSAL, which is the correction the
    // review of this change made. A sentence saying "the server refuses this and nothing changes" is
    // false in exactly the two populations the server's guard is documented not to cover: an
    // administrator, who is exempt from it (#1732), and an account carrying a password this plugin
    // minted and never recorded, which reads as a door nobody can open (#1733). For both of them the
    // removal goes through, and a dialog naming only benign outcomes would have turned a hesitant press
    // into a confident one on the press that costs the account. Warning of a lockout the server then
    // refuses costs a moment of caution; the other direction costs the account.
    if (
      ssoConfigLinking.removesEveryWayIn(rendered, selected) &&
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

      // Encode the provider/canonical segments so an identity-provider-controlled name with a
      // slash or other reserved character cannot inject extra path segments. A name that is
      // exactly "." or ".." can still be collapsed by a path normalizer, but that only 404s
      // (the route targets the caller's own links); "." is left unencoded because encoding it
      // would break the common dotted username/email behind a strict reverse proxy.
      return ApiClient.fetch({
        type: "DELETE",
        url: ApiClient.getUrl(
          `sso/${provider_mode}/link/${encodeURIComponent(provider_name)}/${currentUserId}/${encodeURIComponent(canonical_name)}`,
        ),
      });
    });

    return (
      Promise.all(delete_requests)
        .then(() => {
          window.location.reload();
        })
        // ApiClient.fetch rejects on a non-2xx status, so a rejected DELETE must not fall through to
        // the unconditional reload below it: that would show the exact same page a successful removal
        // shows, with no indication that the link the user asked to remove is still present (#536).
        //
        // ONE REFUSAL MEANS SOMETHING TO THE READER AND GETS ITS OWN SENTENCE (#1731); everything else
        // is the generic banner, which never reflects a server value. The stranding refusal carries the
        // three facts a user can act on - that this was their last way in, that the account takes no
        // password, and that an administrator can undo it - and a bare banner tells them only that
        // something went wrong, which reads as a broken page and is pressed again.
        //
        // TOLD APART BY THE SENTENCE THE ENDPOINT WRITES rather than by the bare status, the same way
        // the pending-approvals panel tells its two 403s apart. This route already answers 403 for an
        // elevation refusal and for a time-limited link, and a reverse proxy can write a 403 page of
        // its own about something else entirely. The bound is that the match is on the server's own
        // words: a reword there silently falls back to the generic banner, which is the harmless
        // direction, and the gate reads both arms so a reword is caught rather than discovered.
        .catch((rejection) => {
          // SOMETHING IS SAID NOW, before the body is read. Telling one 403 from another needs the
          // body, and a body can stall behind a proxy after its headers arrived, which would leave a
          // page that took the delete control away and said nothing at all. So the generic banner goes
          // up first and the refusal below takes it down again once the body has been read.
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

            // AND THE BUTTON STOPS OFFERING ITSELF WHERE THE ROWS MAY BE WRONG, which the review of
            // this change asked for, and only there. A batch is several requests and Promise.all
            // reports the first rejection, so the page no longer knows which links the holder still
            // holds - and until this change nothing depended on the rows being true; now the question
            // above counts them. The measured sequence was two ticked links, one removed and one
            // failed: no reload, both rows still on screen, and the retry of the failed one asked
            // NOTHING because the page still believed there were two ways in.
            //
            // ONE SHAPE IS EXEMPT AND IT IS THE COMMON ONE: a SINGLE request that the server answered
            // by declining it. There the removal did not happen, the rows are still exactly true, and
            // taking the control away would refuse the largest refusal population the tidy-up the
            // refusal itself sends them to - removing a leftover link on a switched-off provider is
            // never refused, and is how somebody clears the state this page shows. Every other shape,
            // a 500 among them, may have been written before it failed.
            if (!declined || delete_requests.length !== 1) {
              ssoConfigLinking.stopOffering(view);
            }

            // WHAT WAS REFUSED IS NAMED, NOT WHAT THE WHOLE PRESS DID. An earlier wording said "it was
            // not removed", which is a claim about the batch: where several links were ticked, one of
            // them may already be gone when this refusal arrives. The sentence speaks for the one
            // removal the server declined and sends the reader to a reload for the rest.
            //
            // TWO REFUSALS SHARE THAT OPENING AND SEND THE READER TO DIFFERENT PLACES (#1732). The first
            // tells a user to ask an administrator; where the reader IS the last administrator who can
            // sign in, that is advice to ask themselves. The second clause of the server's sentence is
            // what separates them, and the fall-through is the harmless direction: a server whose
            // wording moved shows the user sentence, which is wrong about who to ask and right about
            // what happened, rather than no sentence at all.
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
                      "The server refused to remove the last SSO link that can sign you in: it accepts no password for your account, so removing that link would have left you unable to sign in at all. Link another provider first and then remove this one, or ask an administrator to switch your account back to password sign-in. Reload the page to see the links it holds now.",
                    ),
              );
            }
          });
        })
    );
  },
};

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

  // Load the UI strings before rendering: the static markup is localized in place and the dynamically
  // built rows (provider empty-state, disabled note) read their text through t(). loadCatalog always
  // resolves, so a fetch failure just leaves the built-in English.
  loadCatalog().then(() => {
    applyTo(document);
    ssoConfigLinking.loadProviders(view);
  });
}
