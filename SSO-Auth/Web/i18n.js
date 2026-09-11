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

// The marker for a SENTENCE THAT HOLDS MARKUP (#1529), and it is deliberately not spelled
// `data-i18n-<something>`: that shape means "localize the attribute of this name", the allowlist above
// is what keeps it safe, and a marker that borrowed the shape without being an attribute would make
// that rule ask a question it no longer means.
const PARTS_MARKER = "data-i18n-parts";

// A slot in a parts value. `{0}` stands for this element's FIRST child element, `{1}` for its second,
// and so on in document order.
const SLOT = /\{(\d+)\}/g;

/*
 * Splits a parts value into the pieces to write and the children to keep, or returns null if the value
 * does not describe this element.
 *
 * WHY THIS REFUSES RATHER THAN DOING ITS BEST. A value that names four slots applied to an element with
 * three children would silently drop a `<code>` sample out of a sentence about recovering from a
 * lockout. Leaving the English standing is a visible, correct fallback; a half-assembled sentence is
 * neither. So every index must be in range and each one must appear exactly once - which also refuses a
 * value that names the same child twice, where one copy would have to be a clone and this never clones.
 */
function plan(value, childCount) {
  const tokens = [];
  const used = new Set();
  let at = 0;
  let match;
  SLOT.lastIndex = 0;
  while ((match = SLOT.exec(value)) !== null) {
    const index = Number(match[1]);
    if (index >= childCount || used.has(index)) {
      return null;
    }
    used.add(index);
    tokens.push({ text: value.slice(at, match.index) });
    tokens.push({ child: index });
    at = match.index + match[0].length;
  }
  tokens.push({ text: value.slice(at) });
  return used.size === childCount ? tokens : null;
}

/*
 * Writes a parts value into one element.
 *
 * NOTHING HERE IS PARSED AS MARKUP AND NOTHING IS CLONED. The children are the element's own nodes,
 * held in an array while the element is emptied and then put back - so they keep their identity, their
 * own content, and any listener on them, and the catalog can reorder them without being able to create
 * one. The only thing built from the catalog is a text node, through createTextNode, which cannot carry
 * markup by construction. That is the same posture as the attribute allowlist above and for the same
 * reason: a localization file is data, and data never becomes structure here.
 */
function applyParts(el, value) {
  const children = [...el.children];
  const tokens = plan(value, children.length);
  if (tokens === null) {
    return;
  }

  const built = tokens.map((token) =>
    token.child === undefined
      ? document.createTextNode(token.text)
      : children[token.child],
  );
  el.replaceChildren(...built);
}

// Apply the loaded catalog under `root` (default: the whole document): `data-i18n="key"` replaces an
// element's text content, `data-i18n-parts="key"` rewrites a sentence AROUND the child elements it
// holds, and `data-i18n-<attr>="key"` replaces one of the allowlisted attributes above (e.g.
// data-i18n-title). A key that is not in the catalog leaves the built-in English in place.
export function applyTo(root) {
  const scope = root || document;

  scope.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (Object.prototype.hasOwnProperty.call(catalog, key)) {
      el.textContent = catalog[key];
    }
  });

  scope.querySelectorAll("[" + PARTS_MARKER + "]").forEach((el) => {
    const key = el.getAttribute(PARTS_MARKER);
    if (Object.prototype.hasOwnProperty.call(catalog, key)) {
      applyParts(el, catalog[key]);
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
