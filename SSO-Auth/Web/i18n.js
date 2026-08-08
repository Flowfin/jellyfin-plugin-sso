// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

// Client-side application of the plugin's UI string catalog (#913). The server owns the culture fallback:
// it resolves the caller's Accept-Language and returns a complete key->value map from SSOViews/i18n. This
// module fetches that map once and applies it to elements marked `data-i18n="<key>"`, and exposes `t()` for
// strings built in JavaScript. It degrades to the markup's built-in English if the fetch fails, so a
// network error never blanks the page.

let catalog = {};

// Substitute {name} placeholders from params; an absent param is left verbatim so a mismatched catalog
// entry never drops text.
function format(text, params) {
  if (!params) {
    return text;
  }

  return text.replace(/\{(\w+)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(params, name) ? params[name] : match,
  );
}

// Look up a key. When it is not in the loaded catalog, most importantly when the fetch failed and the
// catalog is empty, fall back to the caller's built-in English default (the same role the hard-coded text
// on data-i18n markup plays), and only to the key itself if no default was given, so a missing string is
// never blank. Placeholders are substituted in either case.
export function t(key, params, fallback) {
  const value = Object.prototype.hasOwnProperty.call(catalog, key)
    ? catalog[key]
    : (fallback ?? key);
  return format(value, params);
}

// The attributes a data-i18n-<attr> marker may localize. Deliberately an allowlist of inert,
// user-visible attributes rather than a generic setter: a generic one would let a markup typo (or a
// future edit) drive href, src, or an event handler through the same path.
const LOCALIZABLE_ATTRIBUTES = ["title", "placeholder", "aria-label"];

// Apply the loaded catalog under `root` (default: the whole document): `data-i18n="key"` replaces an
// element's text content, and `data-i18n-<attr>="key"` replaces one of the allowlisted attributes above
// (e.g. data-i18n-title). A key that is not in the catalog leaves the built-in English in place.
export function applyTo(root) {
  const scope = root || document;

  scope.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (Object.prototype.hasOwnProperty.call(catalog, key)) {
      el.textContent = catalog[key];
    }
  });

  LOCALIZABLE_ATTRIBUTES.forEach((attribute) => {
    const marker = "data-i18n-" + attribute;
    scope.querySelectorAll("[" + marker + "]").forEach((el) => {
      const key = el.getAttribute(marker);
      if (Object.prototype.hasOwnProperty.call(catalog, key)) {
        el.setAttribute(attribute, catalog[key]);
      }
    });
  });
}

// Fetch the culture-resolved catalog from the server. The returned promise always resolves; on any failure
// the catalog stays empty and callers fall back to the built-in English. ApiClient.getUrl builds the
// server-rooted URL the linking/config pages already use; the endpoint is anonymous, so a plain fetch.
export function loadCatalog() {
  return fetch(ApiClient.getUrl("SSOViews/i18n"), {
    headers: { Accept: "application/json" },
  })
    .then((resp) => (resp.ok ? resp.json() : {}))
    .then((data) => {
      catalog = data || {};
    })
    .catch(() => {
      catalog = {};
    });
}
