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

// ---- Condensed help (#1662, stage 2 of the 4.4 surface planned on #1528) ----

// A page opts INTO the rule by marking the container it applies inside, which is also the container the
// focus is watched on and the one the rail card is looked for under. An opt-in rather than "every help
// text on every page" because the stage moves the pages one slice at a time: the Providers page carries
// 112 of the help sites this tree holds and is the slice after this one, so a rule reaching it early
// would move those texts in a change whose reviewer was handed the other twenty.
const CONDENSE_ROOT = "data-sso-condensed-help";

// Set on a container whose focus listener is attached, so a second applyTo() rewrites the sentences
// without adding a second listener that would answer one focus twice.
const CONDENSE_WIRED = "data-sso-condensed-help-wired";

// A terminator with something after it. A terminator at the very end of a value is not a split - it is
// the end of a text holding one sentence, and such a text has nothing to hide.
const SENTENCE_END = /[.!?](?=\s)/g;

// An abbreviation, and nothing else: single LETTERS joined by dots. `z`, `B`, `e.g`, `i.e`, `u.a`. This
// is what separates an abbreviation's dot from a sentence's, and it is deliberately NOT "the token holds
// a dot": these help texts end sentences with dotted identifiers like
// Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider, whose segments are words, and a
// rule refusing every dotted token would leave those texts unsplit with no visible sign of it.
//
// `\p{L}` RATHER THAN `\w`, because `\w` is ASCII and the German catalogue is not. With `\w` the tail of
// "Das heißt" is "t" - one word character, an abbreviation by this rule - so the sentence was not split
// at all and the whole text stood under the field, which is the exact state this stage removes. Found by
// the review of 2026-09-12 on constructed German; nothing in de.json trips it today, and "heißt" and
// "Größe" are ordinary enough words that nothing keeps it that way.
const INITIALS = /^(?:\p{L}\.)*\p{L}$/u;

// The LETTERS-AND-DOTS tail of what precedes a terminator, which is the only thing the rule above is
// about. NOT the whole non-space run: `config.acr_values_help` writes `(e.g.` with the bracket glued on,
// `(e.g` is not a chain of initials, and the lead came out as "...authentication-context references
// (e.g." - a fragment ending mid-abbreviation that every later check accepts, because it is still a
// prefix of the text. Stopping at the first non-letter also settles the two cases a wider tail gets
// wrong in the other direction: "Sende acr-1." and "Nutze SAML 2.0." leave an EMPTY tail, which is no
// abbreviation, so both split where a reader expects them to.
const WORD_TAIL = /([\p{L}.]*)$/u;

/*
 * The first sentence of a text, or null when the text holds only one.
 *
 * NULL RATHER THAN THE WHOLE TEXT, and the difference is what the caller does with it. A fold whose
 * summary promises the full text and whose body repeats the line above it costs a click and gives
 * nothing back, so a block whose text has come to hold one sentence shows that sentence and hides the
 * fold. A caller handed the whole text back would have to compare lengths to find that case, which is
 * the same test written where it is easier to get wrong.
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

// Every element under `root` matching `selector`, as an array.
function all(root, selector) {
  return [...root.querySelectorAll(selector)];
}

// The nearest ancestor, `el` itself included, for which `test` holds - or null. A parent walk rather
// than Element.closest: what it is given is a map lookup rather than a selector, and keeping the DOM
// surface this module needs small is what lets the whole rule be driven from a stub by
// tools/ui-condensed-help.js instead of being believed.
function nearest(el, test) {
  for (let at = el; at && at !== document; at = at.parentNode) {
    if (test(at)) {
      return at;
    }
  }
  return null;
}

function hasClass(el, name) {
  return el.classList !== undefined && el.classList.contains(name);
}

/*
 * The field a help block belongs to: the nearest container the page draws around one control, and the
 * block's own parent where the page draws neither.
 *
 * THE SAME RULE tools/ui-help-census.js MEASURES "elsewhere" WITH, and writing it the same way is the
 * point. The census refuses a help text that moved outside the field naming it; this decides which
 * field a focus belongs to. Two different answers to "which field is this" would let the rail show a
 * text for a field the census says it does not belong to.
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
 * Writes the sentence under one field from the text behind its fold.
 *
 * THE ONE THING THAT IS NOT IN THE MARKUP, and that is the whole of decision D1 on #1528. The fold, its
 * summary and the whole text are authored on the page, so a reader whose script never arrived still
 * gets every word - closed, one click away, named by a catalogue row. What needs a runtime is the
 * SPLIT: the alternative was 109 short sentences hand-written in two languages, a German wall in front
 * of the reader before anything was visible. So the lead is derived here, from the body's own text,
 * which means it is derived from whatever language the pass above just wrote and never from a copy
 * somebody has to keep in step.
 *
 * The fold is hidden where the body holds one sentence, so the promise its summary makes - that there
 * is more behind it - is never made falsely.
 */
function refresh(help) {
  const lead = help.querySelector(".sso-help-lead");
  const details = help.querySelector(".sso-help-full");
  const body = help.querySelector(".sso-help-body");
  if (!lead || !details || !body) {
    return;
  }

  const whole = body.textContent;
  const sentence = firstSentence(whole);
  lead.textContent = sentence === null ? whole : sentence;
  details.hidden = sentence === null;
}

/*
 * Condenses every help block under one marked container and, where that container has a rail card,
 * shows the whole text of the focused field in it.
 *
 * THE CARD IS FILLED WITH textContent AND NEVER WITH MARKUP (#221), and what it is filled FROM is the
 * body of the fold rather than the catalogue - so the rail and the fold cannot say different things,
 * and a field whose text the catalogue does not carry shows its built-in English in both places.
 *
 * ONE LISTENER ON THE CONTAINER rather than one per field: the field is found by walking up from what
 * the focus landed on, so a control added to a page later is covered without being registered. Focus
 * landing on the container itself, or leaving it altogether, CLEARS the card rather than leaving the
 * last field's text standing beside a control it does not describe - the second half is `focusout`,
 * because `focusin` never fires for a target outside the container and the card would otherwise survive
 * every way of leaving it.
 *
 * THE MARK IS SET LAST, AFTER THE LISTENER EXISTS. It said "this container is wired", and the review of
 * 2026-09-12 found it set on the line before the card lookup that can return early - so one pass over a
 * container whose card had not been authored yet marked it wired with nothing attached, and every later
 * pass returned at the guard. The attribute now means what it says.
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

  // FIRST BLOCK WINS WHERE TWO SHARE ONE FIELD, rather than the last, and neither is good: one of the
  // two is unreachable from the rail either way. A Map built from pairs silently kept the LAST, which is
  // the harder of the two to notice on a page, so this at least fails in document order.
  //
  // THE SHAPE IS NOT REFUSED ANYWHERE, and saying so is the point of this note. No page carries it
  // today - all twenty blocks on the three condensed pages resolve to distinct elements, counted - and
  // the Providers page, which the next slice feeds this code, carries 112 sites in 98 keys and is where
  // it would first arise. The fold and the sentence under the field are unaffected; only the rail is.
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

  // A `relatedTarget` OUTSIDE the container clears the card. An ABSENT one does not, and that asymmetry
  // is the whole of this handler's care: a mousedown on something unfocusable - the card itself, which
  // is a plain div with a scrollbar for exactly these long texts - blurs the input with no related
  // target at all, and clearing there makes the card vanish under the click that was about to scroll it.
  // A window losing focus delivers the same shape. So an unknown destination leaves the card standing,
  // which is the harmless half of being wrong.
  root.addEventListener("focusout", (event) => {
    const to = event.relatedTarget;
    if (to && !nearest(to, (el) => el === root)) {
      show(null);
    }
  });
  root.setAttribute(CONDENSE_WIRED, "");
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

  // LAST, because it reads the text the passes above have just written. Descendants only: the marker
  // sits on the two-column container inside a page, and a page whose container carries no marker keeps
  // the flat help text it shows today, which is how this stage moves one slice at a time.
  scope.querySelectorAll("[" + CONDENSE_ROOT + "]").forEach(condenseHelp);
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
