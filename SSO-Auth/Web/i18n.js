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

// Look up a key, falling back to the key itself so a missing translation is visible, never blank.
export function t(key, params) {
  const value = Object.prototype.hasOwnProperty.call(catalog, key)
    ? catalog[key]
    : key;
  return format(value, params);
}

// Apply the loaded catalog to every [data-i18n] element under `root` (default: the whole document),
// replacing its text content. Elements whose key is not in the catalog keep their built-in text.
export function applyTo(root) {
  (root || document).querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (Object.prototype.hasOwnProperty.call(catalog, key)) {
      el.textContent = catalog[key];
    }
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
