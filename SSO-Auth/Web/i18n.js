// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

// Applies the server-resolved UI string catalog to `data-i18n` markup and exposes `t()` for strings built
// in JavaScript (#913). A failed fetch leaves the markup's built-in English standing.

let catalog = {};

// Substitutes {name} placeholders from params, leaving an absent one verbatim so no text is dropped.
function format(text, params) {
  if (!params) {
    return text;
  }

  return text.replace(/\{(\w+)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(params, name) ? params[name] : match,
  );
}

// Looks up a key, falling back to the given English default and then to the key, so a string is never blank.
export function t(key, params, fallback) {
  const value = Object.prototype.hasOwnProperty.call(catalog, key)
    ? catalog[key]
    : (fallback ?? key);
  return format(value, params);
}

// The attributes a data-i18n-<attr> marker may localize: an allowlist of inert attributes, so no markup
// typo can drive href, src or an event handler.
const LOCALIZABLE_ATTRIBUTES = ["title", "placeholder", "aria-label"];

// The marker for a sentence that holds markup (#1529); not spelled data-i18n-<attr>, which names an attribute.
const PARTS_MARKER = "data-i18n-parts";

// A slot in a parts value: `{0}` is the element's first child element, `{1}` its second, in document order.
const SLOT = /\{(\d+)\}/g;

/*
 * Splits a parts value into text pieces and kept children, or returns null if it does not fit the element.
 * Every index must be in range and used exactly once, so the English stays rather than a half-built sentence.
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
 * Writes a parts value into one element by reordering its own children around text nodes.
 * Nothing is parsed as markup or cloned, so catalog data never becomes structure.
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

// Condensed help (#1662, #1528).

// The attribute a page sets on the container the condensed-help rule applies inside; an opt-in per page.
const CONDENSE_ROOT = "data-sso-condensed-help";

// Set on a container once its focus listener is attached, so a second applyTo() adds no second listener.
const CONDENSE_WIRED = "data-sso-condensed-help-wired";

// A sentence terminator with something after it; one at the very end of a text is not a split.
const SENTENCE_END = /[.!?](?=\s)/g;

// An abbreviation: single letters joined by dots (`z`, `e.g`, `u.a`), so dotted identifiers still split.
// `\p{L}` rather than `\w` so non-ASCII words in the German catalogue are not read as initials.
const INITIALS = /^(?:\p{L}\.)*\p{L}$/u;

// The letters-and-dots tail before a terminator, the only part the abbreviation rule looks at.
const WORD_TAIL = /([\p{L}.]*)$/u;

/*
 * Returns the first sentence of a text, or null when the text holds only one.
 * Null lets the caller hide a fold that would only repeat the line above it.
 */
function firstSentence(text) {
  SENTENCE_END.lastIndex = 0;
  let match;
  while ((match = SENTENCE_END.exec(text)) !== null) {
    const token = WORD_TAIL.exec(text.slice(0, match.index))[1];
    if (INITIALS.test(token)) {
      continue;
    }
    if (text.slice(match.index + 1).trim() === "") {
      return null;
    }
    return text.slice(0, match.index + 1);
  }
  return null;
}

// Returns every element under `root` matching `selector`, as an array.
function all(root, selector) {
  return [...root.querySelectorAll(selector)];
}

// Returns the nearest ancestor, `el` included, for which `test` holds, or null.
// A parent walk rather than Element.closest keeps the DOM surface small enough for tools/ui-condensed-help.js to stub.
function nearest(el, test) {
  for (let at = el; at && at !== document; at = at.parentNode) {
    if (test(at)) {
      return at;
    }
  }
  return null;
}

// Whether `el` carries the class `name`.
function hasClass(el, name) {
  return el.classList !== undefined && el.classList.contains(name);
}

/*
 * Returns the field a help block belongs to: the nearest input or checkbox container, else the block's parent.
 * It is the same rule tools/ui-help-census.js measures with, so both agree on which field a text belongs to.
 */
function fieldOf(help) {
  return (
    nearest(
      help.parentNode,
      (el) =>
        hasClass(el, "inputContainer") || hasClass(el, "checkboxContainer"),
    ) || help.parentNode
  );
}

/*
 * Writes the sentence under one field from the text behind its fold, hiding the fold when there is only one.
 * The lead is derived at runtime from the body so it follows whichever language was just applied (#1528).
 * A one-sentence body is moved rather than copied so its child elements survive (#1669).
 */
function refresh(help) {
  const lead = help.querySelector(".sso-help-lead");
  const details = help.querySelector(".sso-help-full");
  const body = help.querySelector(".sso-help-body");
  if (!lead || !details || !body) {
    return;
  }

  const sentence = firstSentence(body.textContent);
  lead.textContent = sentence === null ? "" : sentence;
  details.hidden = sentence === null;

  // Each move is guarded so a focused link inside the body is not blurred on every catalogue pass.
  // A fold that is not a direct child falls back to appending; the markup gate refuses that shape (#1684).
  if (sentence === null) {
    if (body.parentNode !== help) {
      help.insertBefore(body, details.parentNode === help ? details : null);
    }
  } else if (body.parentNode !== details) {
    details.appendChild(body);
  }

  nameFold(help, details);
  speak(help, body);
}

/*
 * Names the fold after the field it belongs to (#1672), so a screen reader does not hear many identical "Full text" rows.
 * `aria-labelledby` references the label and the summary, so the name follows both through later catalogue passes.
 * Blocks outside an input or checkbox container keep the bare word, since the nearby label belongs to another field.
 */
function nameFold(help, details) {
  const summary = details.querySelector("summary");
  const field = fieldOf(help);
  const label =
    field &&
    (hasClass(field, "inputContainer") || hasClass(field, "checkboxContainer"))
      ? labelBefore(field, help)
      : null;
  if (!summary || !label) {
    return;
  }

  // A label for its control, or one wrapped around it as the checkbox rows are authored.
  const wrapped = label.querySelector("input");
  const control =
    label.getAttribute("for") || (wrapped && wrapped.getAttribute("id"));
  if (!control) {
    return;
  }
  if (!label.hasAttribute("id")) {
    label.setAttribute("id", control + "-label");
  }
  if (!summary.hasAttribute("id")) {
    summary.setAttribute("id", control + "-full-text");
  }
  summary.setAttribute(
    "aria-labelledby",
    label.getAttribute("id") + " " + summary.getAttribute("id"),
  );
}

/*
 * Returns the last label with text before the block in its field.
 * The last, because one container can hold two labelled controls; with text, because jellyfin-web inserts empty labels.
 */
function labelBefore(field, help) {
  const labels = new Set(all(field, "label"));
  let found = null;
  const walk = (el) => {
    for (const child of el.children) {
      if (child === help) {
        return true;
      }
      if (labels.has(child) && child.textContent.trim() !== "") {
        found = child;
      }
      if (walk(child)) {
        return true;
      }
    }
    return false;
  };
  walk(field);
  return found;
}

/*
 * Writes the whole text into the block's hidden spoken copy, where a page authors one (#1672).
 * `aria-describedby` on a closed fold reads only its summary, so the field references this copy instead.
 */
function speak(help, body) {
  const spoken = help.querySelector(".sso-help-spoken");
  if (spoken) {
    spoken.textContent = body.textContent;
  }
}

/*
 * Condenses every help block under one marked container and shows the focused field's whole text in its rail card.
 * The card is filled with textContent from the fold body, never markup (#221), so rail and fold agree.
 * One listener on the container covers fields added later; the wired mark is set only after it is attached.
 */
function condenseHelp(root) {
  const helps = all(root, ".sso-help");
  helps.forEach(refresh);
  if (helps.length === 0 || root.hasAttribute(CONDENSE_WIRED)) {
    return;
  }

  const card = root.querySelector(".sso-help-card");
  const text = card && card.querySelector(".sso-help-card-text");
  if (!text) {
    return;
  }

  // Where two blocks share one field the first wins; tools/ui-condensed-help.js refuses that shape (#1663).
  const fields = new Map();
  helps.forEach((help) => {
    const field = fieldOf(help);
    if (!fields.has(field)) {
      fields.set(field, help);
    }
  });

  const show = (target) => {
    const field = target && nearest(target, (el) => fields.has(el));
    const help = field ? fields.get(field) : null;
    text.textContent =
      help === null ? "" : help.querySelector(".sso-help-body").textContent;
    card.hidden = help === null;
  };

  root.addEventListener("focusin", (event) => show(event.target));

  // Focus moving outside the container clears the card; an unknown destination keeps it, so clicking the card does not hide it.
  root.addEventListener("focusout", (event) => {
    const to = event.relatedTarget;
    if (to && !nearest(to, (el) => el === root)) {
      show(null);
    }
  });
  root.setAttribute(CONDENSE_WIRED, "");
}

// Applies the loaded catalog under `root` (default: the document) to text, parts and allowlisted attribute markers.
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

  // Last, because it reads the text the passes above just wrote.
  scope.querySelectorAll("[" + CONDENSE_ROOT + "]").forEach(condenseHelp);
}

// Fetches the culture-resolved catalog; the promise always resolves and leaves the catalog empty on failure.
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
