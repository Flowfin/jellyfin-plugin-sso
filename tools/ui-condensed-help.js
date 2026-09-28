#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Reads the condensed help of the pages that opt into it in both halves
 * (#1662, #1663, #1669, #1672, #1677): a string reader over the shipped markup
 * refuses a help text not authored as a well-formed fold, and a second reader
 * drives the shipped SSO-Auth/Web/i18n.js over a page built from the shipped
 * catalogues and refuses a wrong lead, fold or rail card. The DOM stub has no
 * event propagation or layout, and the string reader does not see implied end
 * tags beyond the `<p>` case; calibration fixtures run first.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..");
const WEB = path.join(ROOT, "SSO-Auth", "Web");
const LOCALIZATION = path.join(ROOT, "SSO-Auth", "Localization");

const CONDENSE_ROOT = "data-sso-condensed-help";
const SUMMARY_KEY = "config.help_full_text";

// The lead line as the markup authors it: present, empty and named, for the applier to fill.
const EMPTY_LEAD = '<span class="sso-help-lead"></span>';

// The stub DOM

// Compiles a selector of an optional tag and `.class` or `[attr]` terms, and
// throws on anything else so an unknown selector cannot match nothing silently.
function selector(text) {
  const parts = /^([a-z0-9-]*)((?:\.[a-zA-Z0-9_-]+|\[[a-zA-Z0-9_-]+\])*)$/.exec(
    text.trim(),
  );
  if (!parts) {
    throw new Error(`the stub does not understand the selector ${text}`);
  }

  const tag = parts[1];
  const classes = [...parts[2].matchAll(/\.([a-zA-Z0-9_-]+)/g)].map(
    (m) => m[1],
  );
  const attributes = [...parts[2].matchAll(/\[([a-zA-Z0-9_-]+)\]/g)].map(
    (m) => m[1],
  );
  return (el) =>
    (tag === "" || el.tag === tag) &&
    classes.every((name) => el.classList.contains(name)) &&
    attributes.every((name) => el.hasAttribute(name));
}

/** The stub text node. */
class Text {
  constructor(data) {
    this.data = data;
    this.parentNode = null;
  }

  get textContent() {
    return this.data;
  }
}

/** The stub element; its members mirror the DOM members of the same name. */
class El {
  constructor(tag) {
    this.tag = tag;
    this.parentNode = null;
    this.nodes = [];
    this.attributes = new Map();
    this.listeners = new Map();
    this.hidden = false;
    const owner = this;
    this.classList = {
      contains: (name) => owner.classes().includes(name),
      add: (name) => {
        if (!owner.classes().includes(name)) {
          owner.attributes.set(
            "class",
            [...owner.classes(), name].join(" ").trim(),
          );
        }
      },
    };
  }

  classes() {
    return (this.attributes.get("class") || "").split(/\s+/).filter(Boolean);
  }

  set className(value) {
    this.attributes.set("class", value);
  }

  get children() {
    return this.nodes.filter((node) => node instanceof El);
  }

  get childNodes() {
    return [...this.nodes];
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  hasAttribute(name) {
    return this.attributes.has(name);
  }

  get textContent() {
    return this.nodes.map((node) => node.textContent).join("");
  }

  set textContent(value) {
    this.nodes = [];
    this.appendChild(new Text(String(value)));
  }

  appendChild(node) {
    this.detach(node);
    node.parentNode = this;
    this.nodes.push(node);
    return node;
  }

  // Takes the node out of its current parent, since a DOM move is a removal and an insertion (#1669).
  detach(node) {
    const from = node.parentNode;
    if (from) {
      from.nodes = from.nodes.filter((other) => other !== node);
    }
    node.parentNode = null;
  }

  // Throws on a reference node that is not a child, as the DOM does; `null` means the end.
  insertBefore(node, before) {
    if (before !== null && !this.nodes.includes(before)) {
      throw new Error(
        "insertBefore was given a reference node that is not a child",
      );
    }
    this.detach(node);
    const at = before === null ? this.nodes.length : this.nodes.indexOf(before);
    node.parentNode = this;
    this.nodes.splice(at, 0, node);
    return node;
  }

  replaceChildren(...nodes) {
    // The dropped nodes lose their parent, as in a browser.
    this.nodes.forEach((node) => {
      node.parentNode = null;
    });
    this.nodes = [];
    nodes.forEach((node) => this.appendChild(node));
  }

  // Returns the descendants depth-first in document order, `this` excluded.
  descendants() {
    const out = [];
    const walk = (el) =>
      el.children.forEach((child) => {
        out.push(child);
        walk(child);
      });
    walk(this);
    return out;
  }

  querySelectorAll(text) {
    const match = selector(text);
    return this.descendants().filter(match);
  }

  querySelector(text) {
    return this.querySelectorAll(text)[0] || null;
  }

  addEventListener(name, handler) {
    if (!this.listeners.has(name)) {
      this.listeners.set(name, []);
    }
    this.listeners.get(name).push(handler);
  }

  // Calls the handlers with the focus target directly; the stub has no propagation.
  fire(name, target, relatedTarget) {
    (this.listeners.get(name) || []).forEach((handler) =>
      handler({ target, relatedTarget: relatedTarget || null }),
    );
  }
}

globalThis.document = {
  createElement: (tag) => new El(tag),
  createTextNode: (data) => new Text(data),
};
globalThis.ApiClient = { getUrl: (route) => `https://stub.invalid/${route}` };

// The first reader: the fold the markup authors

// One `*_help` field description on any tag, walked to its own close by elementBody
// because the block nests a `<details>` and a `<div>`.
const HELP_BLOCK =
  /<(?<tag>[a-z][a-z0-9]*)\b(?<attrs>[^>]*\bclass="[^"]*\bfieldDescription\b[^"]*"[^>]*)>/g;

/** Returns whether an opening tag carries a class as a whitespace-separated token. */
function hasClassToken(opening, name) {
  const attribute = /class="([^"]*)"/.exec(opening);
  return attribute !== null && attribute[1].split(/\s+/).includes(name);
}

// Returns the body of the element whose opening tag ends at `from`, counting
// tags of the same name, or null when it never closes.
function elementBody(markup, from, tag) {
  const tags = new RegExp(`<(/?)${tag}\\b[^>]*?(/?)>`, "g");
  tags.lastIndex = from;
  let depth = 0;
  let match;
  while ((match = tags.exec(markup)) !== null) {
    if (match[2] === "/") {
      continue;
    }
    if (match[1] === "/") {
      if (depth === 0) {
        return markup.slice(from, match.index);
      }
      depth -= 1;
      continue;
    }
    depth += 1;
  }
  return null;
}

/*
 * Returns how many elements are still open at `at` inside `inner`, zero for a
 * direct child. A self-closing tag is depth-neutral, which holds because
 * Prettier writes every void element on these pages with its slash.
 */
function depthAt(inner, at) {
  let depth = 0;
  for (const m of inner.matchAll(/<(\/?)([a-z][a-z0-9]*)\b[^>]*?(\/?)>/g)) {
    if (m.index >= at) {
      break;
    }
    if (m[3] === "/") {
      continue;
    }
    depth += m[1] === "/" ? -1 : 1;
  }
  return depth;
}

/** Refuses the markup half of one page: what a reader is left with if the script never runs. */
function inspectMarkup(page, source) {
  let flat = 0;
  // Comments go first, since the depth counter would read a `</div>` in one as real, and
  // whitespace is collapsed so where Prettier wraps a tag does not matter.
  const markup = source.replace(/<!--[\s\S]*?-->/g, " ").replace(/\s+/g, " ");
  const refusals = [];
  const at = [];
  let blocks = 0;
  let named = 0;
  HELP_BLOCK.lastIndex = 0;
  let match;
  while ((match = HELP_BLOCK.exec(markup)) !== null) {
    const opening = match[0];
    const body = elementBody(
      markup,
      match.index + opening.length,
      match.groups.tag,
    );
    if (body === null) {
      refusals.push(`a field description on ${page} is never closed`);
      continue;
    }

    const keys = [
      ...body.matchAll(/data-i18n(?:-parts)?="([a-z0-9_.]+_help)"/g),
    ].map((m) => m[1]);
    const own = /data-i18n(?:-parts)?="([a-z0-9_.]+_help)"/.exec(opening);
    if (own) {
      refusals.push(
        `${page} still writes ${own[1]} flat: the field shows the whole text under it rather than a sentence and a fold`,
      );
      continue;
    }
    // A marked block naming no key is broken markup or an unreadable one, never a pass.
    if (keys.length === 0) {
      if (hasClassToken(opening, "sso-help")) {
        refusals.push(
          `a condensed block on ${page} names no help key, so either its markup is broken or this reader cannot walk it`,
        );
      }
      continue;
    }
    blocks += 1;
    at.push({ index: match.index, key: keys[0] });

    const key = keys[0];

    // `<details>` closes an open `<p>`, so a browser lifts the fold out of the block
    // and the lead stays empty (#1663); only `p` has that implied end tag.
    if (match.groups.tag === "p") {
      refusals.push(
        `${key} on ${page} is authored in a <p>, which <details> closes: the browser lifts the fold out of the block, the lead line can never be filled, and the rail card throws on a focus inside that field`,
      );
    }

    if (!hasClassToken(opening, "sso-help")) {
      refusals.push(
        `${key} on ${page} is a fold the applier will never find: its block is not marked sso-help, so its lead line stays empty`,
      );
    }
    if (!body.includes(EMPTY_LEAD)) {
      refusals.push(
        `${key} on ${page} has no empty lead line for the first sentence to be written into`,
      );
    }
    const fold = /<details\b[^>]*class="sso-help-full"/.exec(body);
    if (fold === null) {
      refusals.push(
        `${key} on ${page} has no fold to put the whole text behind`,
      );
    } else if (depthAt(body, fold.index) > 0) {
      // The applier promotes a one-sentence body in front of the fold, which needs the
      // fold to be the block's own child (#1684).
      refusals.push(
        `the fold of ${key} on ${page} is not a direct child of its block: the applier finds it at any depth and then appends the one-sentence body after it instead of in front of it, where the stylesheet gives it the fold's spacing rather than the lead's`,
      );
    }
    if (!new RegExp(`<summary data-i18n="${SUMMARY_KEY}">`).test(body)) {
      refusals.push(
        `the fold of ${key} on ${page} is named by something other than ${SUMMARY_KEY}, so one page's folds can be renamed without the others`,
      );
    }
    if (
      !new RegExp(`class="sso-help-body" data-i18n(?:-parts)?="${key}"`).test(
        body,
      )
    ) {
      refusals.push(
        `${key} on ${page} does not sit on the body of its own fold, so the catalogue writes it somewhere the applier does not read it from`,
      );
    }
  }

  // A field's aria-describedby must name the block's hidden spoken copy, not the block or
  // anything inside its closed fold, which a screen reader reads as a word or nothing (#1672).
  const described = new Set(
    [...markup.matchAll(/aria-describedby="([^"]*)"/g)].flatMap((m) =>
      m[1].split(/\s+/).filter(Boolean),
    ),
  );
  // The block's whole extent, so references into the fold and copies outside it are caught.
  const blockSpans = elementSpans(markup).filter((span) =>
    hasClassToken(
      markup.slice(markup.lastIndexOf("<", span.from - 1), span.from),
      "sso-help",
    ),
  );
  const insideBlock = (index) =>
    blockSpans.some((span) => index >= span.from && index < span.to);
  described.forEach((id) => {
    const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // `\sid=` and not `\bid=`: a hyphen is a word boundary, so `data-id="x"` read as an id.
    const target = new RegExp(
      `<[a-z][a-z0-9]*\\b[^>]*\\sid="${escaped}"[^>]*>`,
    ).exec(markup);
    if (!target) {
      return;
    }
    if (hasClassToken(target[0], "sso-help")) {
      refusals.push(
        `${id} on ${page} is a condensed block and a field's aria-describedby names it: with the fold closed the description a screen reader is handed is the lead line and the word "Full text", so name the block's spoken copy instead`,
      );
    } else if (
      insideBlock(target.index) &&
      !hasClassToken(target[0], "sso-help-spoken")
    ) {
      refusals.push(
        `${id} on ${page} sits inside a condensed block and a field's aria-describedby names it: the lead line, the fold and the body inside it describe the field with a sentence, a word or nothing, so name the block's spoken copy instead`,
      );
    }
  });
  for (const tag of markup.matchAll(/<[a-z][a-z0-9]*\b[^>]*>/g)) {
    if (!hasClassToken(tag[0], "sso-help-spoken")) {
      continue;
    }
    const id = /\sid="([^"]*)"/.exec(tag[0]);
    if (!id || !described.has(id[1])) {
      refusals.push(
        `a spoken copy on ${page}${id ? ` (${id[1]})` : ""} is named by no aria-describedby, so the applier fills a text nothing reads`,
      );
    }
    // The attribute, read with quoted values blanked, so a class named `hidden` does not pass.
    if (!/\shidden(?=[\s>/=])/.test(tag[0].replace(/="[^"]*"/g, '=""'))) {
      refusals.push(
        `the spoken copy${id ? ` ${id[1]}` : ""} on ${page} is not hidden, so the whole text stands on the page twice`,
      );
    }
    if (!insideBlock(tag.index)) {
      refusals.push(
        `the spoken copy${id ? ` ${id[1]}` : ""} on ${page} is authored outside any condensed block, where the applier never fills it, so the field it describes is described by nothing`,
      );
    }
  }

  // The card must sit under the marked container, where the applier looks for it.
  if (blocks > 0) {
    const scope = markedScope(markup);
    if (scope === null) {
      refusals.push(
        `${page} condenses ${blocks} help text(s) and carries no readable ${CONDENSE_ROOT} container, so the applier is handed nothing to walk`,
      );
      return { refusals, blocks, declared: flat, markup, named };
    }

    const card = markup.indexOf('class="verticalSection sso-help-card"');
    if (card < 0) {
      refusals.push(
        `${page} condenses ${blocks} help text(s) and has no rail card, so a focused field has nowhere to be read in full`,
      );
    } else if (card < scope.from || card > scope.to) {
      refusals.push(
        `the rail card on ${page} sits outside the ${CONDENSE_ROOT} container, where the applier does not look for it: no focus listener is attached and the card never opens`,
      );
    }
    // The heading must be inside the card.
    const inCard =
      card < 0
        ? ""
        : elementBody(markup, markup.indexOf(">", card) + 1, "div") || "";
    // Any heading level; the card only has to be headed by the row the folds share.
    if (
      card >= 0 &&
      !new RegExp(`<h[1-6][^>]*data-i18n="${SUMMARY_KEY}"`).test(inCard)
    ) {
      refusals.push(`the rail card on ${page} is not headed by ${SUMMARY_KEY}`);
    }

    const outside = at.filter(
      (block) => block.index < scope.from || block.index > scope.to,
    ).length;
    if (outside > 0) {
      refusals.push(
        `${outside} condensed help text(s) on ${page} sit outside the ${CONDENSE_ROOT} container, so no sentence is ever written under those fields`,
      );
    }

    // Two help blocks in one field (#1663): the rail card keeps the first in document
    // order, so the second is unreachable from it.
    forEachSharedField(markup, at, (first, second) =>
      refusals.push(
        `${first} and ${second} on ${page} are two help blocks in one field: the rail card answers for ${first} wherever the focus lands in it, and ${second} is unreachable from it`,
      ),
    );

    // How many folds a browser names after their field (#1672), as the applier decides it.
    named = resolveFields(markup, at).filter((each) => each.labelled).length;

    // Every `*_help` marker must be a condensed block or declare itself flat with a reason
    // (#1677), so a help text on a class neither reader enters is refused.
    const markers = [
      ...markup.matchAll(/data-i18n(?:-parts)?="[a-z0-9_.]+_help"/g),
    ].length;
    flat = [...markup.matchAll(/<[a-z][a-z0-9]*\b[^>]*>/g)].filter(
      (tag) =>
        /data-sso-flat-help="[^"]+"/.test(tag[0]) &&
        /data-i18n(?:-parts)?="[a-z0-9_.]+_help"/.test(tag[0]),
    ).length;
    if (markers !== blocks + flat) {
      refusals.push(
        `${page} carries ${markers} help marker(s) and accounts for ${blocks + flat} of them - ${blocks} condensed and ${flat} declared flat - so a help text sits on an element neither reader enters`,
      );
    }
  }

  return { refusals, blocks, declared: flat, markup, named };
}

// Elements a browser closes without a closing tag, kept off the stack below.
const VOID_TAGS = new Set([
  "area",
  "base",
  "br",
  "col",
  "embed",
  "hr",
  "img",
  "input",
  "link",
  "meta",
  "param",
  "source",
  "track",
  "wbr",
]);

/** Returns every element on the page as a span, from one stack pass. */
function elementSpans(markup) {
  const spans = [];
  const stack = [];
  const tags = /<(\/?)([a-z][a-z0-9]*)([^>]*)>/g;
  let match;
  while ((match = tags.exec(markup)) !== null) {
    const [whole, slash, tag, attrs] = match;
    if (VOID_TAGS.has(tag) || /\/\s*$/.test(attrs)) {
      continue;
    }
    if (slash === "/") {
      // An unbalanced close is dropped rather than unwinding the stack past its element.
      const open = stack.pop();
      if (open === undefined) {
        continue;
      }
      spans.push({ from: open.from, to: match.index, tag: open.tag });
      continue;
    }
    stack.push({ from: match.index + whole.length, tag });
  }
  return spans;
}

/*
 * Calls back once per pair of condensed blocks the applier resolves to one field,
 * naming the key it keeps and the key it drops. The field is the nearest field
 * container, or the block's parent where there is none, as `fieldOf` in
 * SSO-Auth/Web/i18n.js decides it.
 */
function forEachSharedField(markup, blocks, say) {
  const held = new Map();
  resolveFields(markup, blocks).forEach(({ block, field, parent }) => {
    const at = field || parent;
    if (at === null) {
      return;
    }
    if (held.has(at.from)) {
      say(held.get(at.from), block.key);
      return;
    }
    held.set(at.from, block.key);
  });
}

/*
 * Returns where each block sits: the innermost field container and the innermost
 * element holding it, and whether that container carries the label `nameFold` names
 * the fold after (#1672).
 */
function resolveFields(markup, blocks) {
  const spans = elementSpans(markup);
  const isField = (span) => {
    const opening = markup.slice(
      markup.lastIndexOf("<", span.from - 1),
      span.from,
    );
    return (
      hasClassToken(opening, "inputContainer") ||
      hasClassToken(opening, "checkboxContainer")
    );
  };

  return blocks.map((block) => {
    // The innermost element wins in both halves, as the applier stops at the first on its way up.
    let field = null;
    let parent = null;
    spans.forEach((span) => {
      if (block.index < span.from || block.index >= span.to) {
        return;
      }
      if (parent === null || span.from > parent.from) {
        parent = span;
      }
      if (isField(span) && (field === null || span.from > field.from)) {
        field = span;
      }
    });
    return {
      block,
      field,
      parent,
      // A label for a control, or one wrapped around an input with an id, as `nameFold` reads it.
      labelled:
        field !== null &&
        /<label\b[^>]*\sfor="[^"]+"|<label\b(?:(?!<\/label>)[\s\S])*<input\b[^>]*\sid="/.test(
          markup.slice(field.from, field.to),
        ),
    };
  });
}

// Returns the span of the container a page marks for condensing, or null when it
// marks none or the element never closes.
function markedScope(markup) {
  // Any tag, as the applier's selector is; only the first marked container is returned,
  // and no page marks two.
  const opening = new RegExp(
    `<([a-z][a-z0-9]*)\\b[^>]*\\b${CONDENSE_ROOT}\\b[^>]*>`,
  );
  const match = opening.exec(markup);
  if (!match) {
    return null;
  }

  const from = match.index + match[0].length;
  const body = elementBody(markup, from, match[1]);
  return body === null ? null : { from, to: from + body.length };
}

// The second reader: the sentence the applier derives

/*
 * Returns the first sentence of a text, or null for a single sentence. It is the
 * applier's rule written a second time, so it catches the rule not being applied;
 * the hand-written lead table catches the rule itself being wrong.
 */
function expectedLead(text) {
  const terminator = /[.!?](?=\s)/g;
  let match;
  while ((match = terminator.exec(text)) !== null) {
    const token = /([\p{L}.]*)$/u.exec(text.slice(0, match.index))[1];
    if (/^(?:\p{L}\.)*\p{L}$/u.test(token)) {
      continue;
    }
    return text.slice(match.index + 1).trim() === ""
      ? null
      : text.slice(0, match.index + 1);
  }
  return null;
}

/*
 * Returns the direct child elements of a body as `{ tag, attrs, inner }`, or null
 * where it cannot walk them, so an unreadable body stays out of the driven set.
 * It is built on `elementBody` so the two walkers cannot disagree.
 */
function directChildren(inner) {
  const tags = /<([a-z][a-z0-9]*)\b([^>]*?)(\/?)>/g;
  const out = [];
  let match;
  while ((match = tags.exec(inner)) !== null) {
    const [whole, tag, attrs, selfClosing] = match;
    if (selfClosing === "/" || VOID_TAGS.has(tag)) {
      out.push({ tag, attrs, inner: "" });
      continue;
    }
    const from = match.index + whole.length;
    const body = elementBody(inner, from, tag);
    if (body === null) {
      return null;
    }
    out.push({ tag, attrs, inner: body });
    tags.lastIndex = from + body.length;
  }
  return out;
}

/*
 * Returns what one child's text will be when the pass reaches the parts body, or
 * null where this reader cannot say. `applyTo` writes `data-i18n` elements first,
 * so a marked child is read from the catalogue; nested tags are refused.
 */
function childText(child, values, fallback) {
  const key = /\bdata-i18n="([a-z0-9_.]+)"/.exec(child.attrs);
  if (key) {
    const value =
      values[key[1]] !== undefined ? values[key[1]] : fallback[key[1]];
    return value === undefined ? null : value;
  }
  return /</.test(child.inner) ? null : decodeText(child.inner);
}

// The named references a help body may hold; any other reference takes the body out
// of the driven set. `&amp;` is decoded last so `&amp;lt;` stays as written.
const NAMED = {
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&apos;": "'",
  "&#39;": "'",
};

/** Decodes the named references, or returns null for one outside the set. */
function decodeText(text) {
  const out = text.replace(
    /&(?:lt|gt|quot|apos|#39);/g,
    (found) => NAMED[found],
  );
  return /&(?!amp;)/.test(out) ? null : out.replace(/&amp;/g, "&");
}

/*
 * Returns a parts value with each `{n}` slot replaced by the nth child's text, or
 * null where the value does not describe the body, which the pass refuses too.
 * The same rule written a second time, like `expectedLead`.
 */
function assemble(value, children) {
  // A child nobody could resolve is null and must not be concatenated as "null".
  if (children.some((text) => typeof text !== "string")) {
    return null;
  }

  const used = new Set();
  const slot = /\{(\d+)\}/g;
  let out = "";
  let at = 0;
  let match;
  while ((match = slot.exec(value)) !== null) {
    const index = Number(match[1]);
    if (index >= children.length || used.has(index)) {
      return null;
    }
    used.add(index);
    out += value.slice(at, match.index) + children[index];
    at = match.index + match[0].length;
  }
  return used.size === children.length ? out + value.slice(at) : null;
}

/*
 * Builds one page as a tree: a marked container with one folded field per help
 * key, and a rail card beside them. It judges what the applier does with a block
 * of this shape, not how a real page nests its fields.
 */
function buildPage(keys, texts, summary, options) {
  const wrapper = new El("div");
  const root = new El("div");
  root.className = "sso-columns";
  if (!options || options.marked !== false) {
    root.setAttribute(CONDENSE_ROOT, "");
  }

  const main = new El("div");
  main.className = "sso-column-main";
  const fields = keys.map((key, index) => {
    const container = new El("div");
    container.className = "inputContainer";
    // A label for the control, which the fold is named after (#1672).
    const label = new El("label");
    label.setAttribute("for", `fixture_${index}`);
    label.textContent = `Field ${index}`;
    const input = new El("input");
    input.setAttribute("id", `fixture_${index}`);

    const lead = new El("span");
    lead.className = "sso-help-lead";
    const summaryEl = new El("summary");
    summaryEl.setAttribute("data-i18n", SUMMARY_KEY);
    summaryEl.textContent = summary;
    const body = new El("div");
    body.className = "sso-help-body";
    // A parts body holds child elements and a value with `{n}` slots (#1669).
    const assembled = options && options.parts && options.parts[key];
    if (assembled) {
      body.setAttribute("data-i18n-parts", key);
      body.replaceChildren(
        ...assembled.map((child) => {
          const el = new El(child.tag);
          el.textContent = child.text;
          return el;
        }),
      );
    } else {
      body.setAttribute("data-i18n", key);
      body.textContent = texts[key];
    }
    const details = new El("details");
    details.className = "sso-help-full";
    details.replaceChildren(summaryEl, body);
    const help = new El("div");
    help.className = "fieldDescription sso-help";
    help.replaceChildren(lead, details);

    // A hidden spoken copy named by the field's aria-describedby, where the arm asks for one (#1672).
    let spoken = null;
    if (options && options.spoken) {
      spoken = new El("span");
      spoken.className = "sso-help-spoken";
      spoken.hidden = true;
      spoken.setAttribute("hidden", "");
      spoken.setAttribute("id", `fixture_${index}-help-spoken`);
      input.setAttribute("aria-describedby", `fixture_${index}-help-spoken`);
      help.appendChild(spoken);
    }

    container.replaceChildren(label, input, help);
    main.appendChild(container);
    return {
      key,
      container,
      label,
      input,
      help,
      lead,
      details,
      body,
      spoken,
      parts: assembled ? assembled.length : undefined,
    };
  });

  root.appendChild(main);
  if (!options || options.card !== false) {
    const rail = new El("aside");
    rail.className = "sso-column-rail";
    const heading = new El("h2");
    heading.className = "sectionTitle";
    heading.setAttribute("data-i18n", SUMMARY_KEY);
    heading.textContent = summary;
    const text = new El("div");
    text.className = "fieldDescription sso-help-card-text";
    const card = new El("div");
    card.className = "verticalSection sso-help-card";
    card.hidden = true;
    card.replaceChildren(heading, text);
    rail.appendChild(card);
    root.appendChild(rail);
  }

  wrapper.appendChild(root);
  return { wrapper, root, fields };
}

/*
 * Refuses the runtime half. `texts` is what each key's text ought to be after the
 * pass, so a lost sentence and a wrong language are both refused.
 */
function inspect(page, texts, summary) {
  const refusals = [];
  const say = (message) => refusals.push(message);
  const counts = { folded: 0, flat: 0, flatParts: 0, named: 0 };

  page.fields.forEach((field) => {
    const whole = texts[field.key];
    // A key no catalogue carries; the census step refuses it first, and this keeps it from crashing.
    if (typeof whole !== "string") {
      say(
        `${field.key} is named by a page and carried by no catalogue, so there is no text for the fold to hold`,
      );
      return;
    }
    const lead = expectedLead(whole);

    if (field.body.textContent !== whole) {
      say(
        `${field.key} holds ${field.body.textContent.length} character(s) in its help body and its text has ${whole.length}: a help text was cut rather than moved`,
      );
    }

    // The tree and not only the text for a parts body (#1669), so flattened or moved
    // children are refused.
    if (
      field.parts !== undefined &&
      field.body.children.length !== field.parts
    ) {
      say(
        `${field.key} is assembled around ${field.parts} child element(s) and its body now holds ${field.body.children.length}: the sentence kept its words and lost its markup`,
      );
    }

    const summaryEl = field.details.querySelector("summary");
    if (!summaryEl || summaryEl.textContent !== summary) {
      say(
        `${field.key} names its fold ${JSON.stringify(summaryEl ? summaryEl.textContent : null)} and the catalogue says ${JSON.stringify(summary)}`,
      );
    }

    // The summary's aria-labelledby names the field's label and then itself (#1672).
    const labelId = field.label.getAttribute("id");
    const summaryId = summaryEl ? summaryEl.getAttribute("id") : null;
    const namedBy = summaryEl
      ? summaryEl.getAttribute("aria-labelledby")
      : null;
    if (!labelId || !summaryId || namedBy !== `${labelId} ${summaryId}`) {
      say(
        `${field.key} folds under a summary named by ${JSON.stringify(namedBy)} rather than by its field's label and its own word, so a list of the page's folds reads as one row repeated`,
      );
    } else {
      counts.named += 1;
    }

    // A spoken copy holds the whole text and stays hidden.
    if (field.spoken) {
      if (field.spoken.textContent !== whole) {
        say(
          `${field.key} has a spoken copy holding ${field.spoken.textContent.length} character(s) and its text has ${whole.length}: what aria-describedby hands a screen reader is not the whole text`,
        );
      }
      if (!field.spoken.hidden && !field.spoken.hasAttribute("hidden")) {
        say(
          `${field.key} shows its spoken copy on the page, so the whole text stands twice`,
        );
      }
    }

    // A one-sentence body moves in front of the fold rather than being copied into the
    // lead (#1669), so its parent, the empty lead and the hidden fold are each checked.
    if (lead === null) {
      counts.flat += 1;
      // The parts bodies holding one sentence, the population #1669 is about, derived from the lead rule.
      counts.flatParts += field.parts === undefined ? 0 : 1;
      if (field.body.parentNode !== field.help) {
        say(
          `${field.key} holds one sentence and its text is still inside the hidden fold, so the field shows no description at all`,
        );
      }
      if (field.lead.textContent !== "") {
        say(
          `${field.key} holds one sentence and its text was copied into the lead as ${JSON.stringify(field.lead.textContent)} as well, so the field says it twice`,
        );
      }
      if (!field.details.hidden) {
        say(
          `${field.key} holds one sentence and its fold is shown anyway, promising a text behind it that is the line above it`,
        );
      }
      return;
    }

    counts.folded += 1;
    if (field.body.parentNode !== field.details) {
      say(
        `${field.key} holds more than one sentence and its text stands under the field rather than behind the fold, so the condensing did nothing for it`,
      );
    }
    if (field.lead.textContent !== lead) {
      say(
        `${field.key} shows ${JSON.stringify(field.lead.textContent)} under the field and its first sentence is ${JSON.stringify(lead)}`,
      );
    }
    if (!whole.startsWith(field.lead.textContent)) {
      say(
        `${field.key} shows a sentence under the field that the text behind the fold does not begin with, so the two can drift`,
      );
    }
    if (field.details.hidden) {
      say(`${field.key} hid a fold that holds more than the line above it`);
    }
  });

  return { refusals, counts };
}

// Reads the rail: the card answers the field that has focus, and nothing else.
function inspectRail(page, texts, summary, expectCard) {
  const refusals = [];
  const card = page.root.querySelector(".sso-help-card");
  if (!expectCard) {
    if (card && !card.hidden) {
      refusals.push(
        "a page with no card to fill showed one anyway, in a column that does not hold it",
      );
    }
    return refusals;
  }

  if (!card) {
    refusals.push(
      "the rail holds no card, so a focused field has nowhere to be read in full",
    );
    return refusals;
  }

  const text = card.querySelector(".sso-help-card-text");
  const heading = card.querySelector(".sectionTitle");
  if (!card.hidden) {
    refusals.push(
      "the card is shown before anything has focus, naming a field nobody chose",
    );
  }
  // Guarded in the message as well as the condition, so a missing element is a refusal, not a crash.
  if (!text) {
    refusals.push(
      "the card holds no element for a field's text, so a focus has nowhere to write",
    );
    return refusals;
  }
  if (!heading || heading.textContent !== summary) {
    refusals.push(
      `the card is headed ${JSON.stringify(heading ? heading.textContent : null)} and the catalogue says ${JSON.stringify(summary)}`,
    );
  }

  page.fields.forEach((field) => {
    page.root.fire("focusin", field.input);
    if (text.textContent !== texts[field.key]) {
      refusals.push(
        `focus in the field of ${field.key} put ${JSON.stringify(text.textContent.slice(0, 40))} in the rail rather than that field's own text`,
      );
    }
    if (card.hidden) {
      refusals.push(`focus in the field of ${field.key} left the card hidden`);
    }
  });

  if (page.fields.length > 0) {
    page.root.fire("focusin", page.root);
    if (!card.hidden) {
      refusals.push(
        "focus moving to the container itself left the previous field's text standing in the rail, beside a control it does not describe",
      );
    }

    // Focus leaving the container, which `focusin` never sees, must clear the card.
    page.root.fire("focusin", page.fields[0].input);
    page.root.fire("focusout", page.fields[0].input, page.wrapper);
    if (!card.hidden) {
      refusals.push(
        "focus leaving the container left the last field's text standing in the rail with nothing focused at all",
      );
    }

    // A blur with no destination, such as a click on the card itself, must not clear it.
    page.root.fire("focusin", page.fields[0].input);
    page.root.fire("focusout", page.fields[0].input, null);
    if (card.hidden) {
      refusals.push(
        "a blur with no destination cleared the card, so it disappears under a click on itself",
      );
    }
  }

  return refusals;
}

// The run

/** Reads a file as UTF-8. */
function read(file) {
  return fs.readFileSync(file, "utf8");
}

/** Parses one catalogue from the Localization folder. */
function catalogue(name) {
  return JSON.parse(read(path.join(LOCALIZATION, `${name}.json`)));
}

// Returns the pages carrying the opt-in attribute, which is what puts a page in scope.
function markedPages() {
  return fs
    .readdirSync(WEB)
    .filter((name) => name.endsWith(".html"))
    .filter((name) => read(path.join(WEB, name)).includes(CONDENSE_ROOT))
    .sort();
}

/** Imports the shipped i18n.js as a module. */
async function loadApplier() {
  const source = read(path.join(WEB, "i18n.js"));
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64");
  return import(url);
}

// Applies one catalogue to one built page. `loadCatalog` always resolves, so a failed
// fetch leaves the built-in English and `applyTo` runs either way.
async function render(i18n, page, values) {
  globalThis.fetch = () =>
    values === null
      ? Promise.reject(new Error("no network in this gate"))
      : Promise.resolve({ ok: true, json: () => Promise.resolve(values) });
  await i18n.loadCatalog();
  i18n.applyTo(page.wrapper);
}

/** Maps each fixture text to a `config.fixture_N_help` key. */
function fixtureTexts(values) {
  return values.reduce((all, value, index) => {
    all[`config.fixture_${index}_help`] = value;
    return all;
  }, {});
}

/*
 * Leads written by hand, one row per way the sentence rule is known to break, so
 * this arm is the one not derived from the rule. `null` means one sentence.
 */
const HAND_WRITTEN_LEADS = [
  [
    "Off by default. When on, two logout surfaces become active.",
    "Off by default.",
  ],
  [
    "The language code Jellyfin itself stores, for example eng. Leave blank to keep the default.",
    "The language code Jellyfin itself stores, for example eng.",
  ],
  // An abbreviation with a bracket glued to its front.
  [
    "Space-separated values (e.g. acr-1) may be sent. The rest follows.",
    "Space-separated values (e.g. acr-1) may be sent.",
  ],
  // A dotted identifier is not an abbreviation and must still split.
  [
    "Name Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider here. It is what a save accepts.",
    "Name Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider here.",
  ],
  [
    "Standardmäßig aus. Eingeschaltet speichert jede Anmeldung ihren Zustand.",
    "Standardmäßig aus.",
  ],
  [
    "Ein Code wie z. B. eng gehört hierhin. Mehr steht dahinter.",
    "Ein Code wie z. B. eng gehört hierhin.",
  ],
  ["Welche Untertitel? Diese hier.", "Welche Untertitel?"],
  // Non-ASCII letters, which `\w` would miss.
  ["Das heißt. Mehr steht dahinter.", "Das heißt."],
  ["Es zählt die Größe. Mehr steht dahinter.", "Es zählt die Größe."],
  // An empty tail is no abbreviation, so values ending on a digit split.
  ["Sende acr-1. Der Rest folgt.", "Sende acr-1."],
  ["Nutze SAML 2.0. Der Rest folgt.", "Nutze SAML 2.0."],
  // A sentence ending on a bracket pins the empty tail from the other side.
  [
    "Nie enthalten (auch keine Geheimnisse). Der Rest folgt.",
    "Nie enthalten (auch keine Geheimnisse).",
  ],
  // A lone non-ASCII capital before a dot is an initial, which pins the character class.
  ["Siehe Anlage Ö. Mehr steht dahinter.", null],
  ["Nur ein Satz, und nicht mehr.", null],
  ["Ein Satz ganz ohne Satzzeichen am Ende", null],
];

const TWO = "The first sentence. And a second one that the fold holds.";
const ONE = "A text that holds exactly one sentence.";
const ABBREVIATION =
  "Use a code such as e.g. eng here. The fold holds the rest of it.";
const GERMAN =
  "Standardmäßig aus. Eingeschaltet speichert jede Anmeldung den Zustand, den eine Abmeldung braucht.";

// Builds markup in the shape the applier expects, for the markup reader's own arms,
// so a negative can break one part of it at a time.
function fixtureMarkup(key, parts) {
  const p = {
    lead: true,
    details: true,
    summary: true,
    body: true,
    marked: true,
    card: true,
    flat: false,
    ...parts,
  };
  if (p.flat) {
    return [
      `<div ${CONDENSE_ROOT}>`,
      `<div class="fieldDescription" data-i18n${p.assembled ? "-parts" : ""}="${key}">whatever</div>`,
      `</div>`,
    ].join("\n");
  }

  // `heading: false` leaves the card headless.
  const heading =
    p.heading === false
      ? ""
      : `<h2 class="sectionTitle" data-i18n="${SUMMARY_KEY}">Full text</h2>`;
  const card = `<div class="verticalSection sso-help-card" hidden>${heading}<div class="sso-help-card-text"></div></div>`;
  // The element the block is authored in; `p` is the negative a browser re-parents.
  const tag = p.tag || "div";
  const block = [
    `<${tag} class="fieldDescription${p.marked ? " sso-help" : ""}"${p.described ? ' id="fixture-help"' : ""}>`,
    p.comment ? `<!-- a note that mentions a closing </div> tag -->` : "",
    p.lead ? `<span class="sso-help-lead"></span>` : "",
    // `selfClosed` puts a void element with its slash before the fold, which must not move the depth.
    p.selfClosed ? `<br />` : "",
    // `wrapped` puts the fold inside a layout element (#1684).
    p.wrapped ? `<div class="sso-help-layout">` : "",
    p.details ? `<details class="sso-help-full">` : "<div>",
    p.summary
      ? `<summary data-i18n="${SUMMARY_KEY}">Full text</summary>`
      : `<summary data-i18n="config.something_else">More</summary>`,
    p.body
      ? p.assembled
        ? `<div class="sso-help-body" data-i18n-parts="${key}">whatever <strong data-i18n="config.fixture_emphasis">this</strong></div>`
        : `<div${p.describedBody ? ' id="fixture-help-body"' : ""} class="sso-help-body" data-i18n="${key}">whatever</div>`
      : `<div class="sso-help-body"><span data-i18n="${key}">whatever</span></div>`,
    p.details ? `</details>` : "</div>",
    p.wrapped ? `</div>` : "",
    // The spoken copy (#1672): named by the field below, or by nothing, or shown.
    p.spoken || p.spokenUnnamed || p.spokenShown || p.spokenClassHidden
      ? `<span class="sso-help-spoken${p.spokenClassHidden ? " hidden" : ""}" id="fixture-help-spoken"${p.spokenShown || p.spokenClassHidden ? "" : " hidden"}></span>`
      : "",
    `</${tag}>`,
  ].join("\n");

  // `scoped: false` puts the card one element outside the container the applier walks.
  if (p.scoped === false) {
    return [`<div ${CONDENSE_ROOT}>`, block, `</div>`, card].join("\n");
  }

  // A second `*_help` marker on a class neither reader enters (#1677): `stray` leaves it
  // undeclared, `declared` gives it a reason.
  const extra =
    p.stray || p.declared
      ? `<div class="sso-callout"${p.declared ? ' data-sso-flat-help="a warning, not a field description"' : ""} data-i18n-parts="config.fixture_9_help">a warning</div>`
      : "";

  // The field the block describes (#1672): by its block, which is refused, or by the
  // block's spoken copy, which is the shape the Providers page authors.
  const field = p.described
    ? `<input id="fixture-input" aria-describedby="fixture-help" />`
    : p.describedBody
      ? `<input id="fixture-input" aria-describedby="fixture-help-body" />`
      : p.spoken || p.spokenShown || p.spokenClassHidden || p.spokenOutside
        ? `<input id="fixture-input" aria-describedby="fixture-help-spoken" />`
        : "";

  return [
    `<div ${CONDENSE_ROOT}>`,
    field,
    block,
    // `spokenOutside` is the copy one element past its block: named, hidden, and never filled.
    p.spokenOutside
      ? `<span class="sso-help-spoken" id="fixture-help-spoken" hidden></span>`
      : "",
    extra,
    p.card ? card : "",
    `</div>`,
  ].join("\n");
}

/*
 * Builds two condensed blocks in two field containers, in one, or under one
 * plain parent (#1663); the shapes differ by one moved closing tag.
 */
function fixturePair(key, other, shared) {
  const block = (name) =>
    [
      `<div class="fieldDescription sso-help">`,
      `<span class="sso-help-lead"></span>`,
      `<details class="sso-help-full">`,
      `<summary data-i18n="${SUMMARY_KEY}">Full text</summary>`,
      `<div class="sso-help-body" data-i18n="${name}">whatever</div>`,
      `</details>`,
      `</div>`,
    ].join("\n");
  const card = `<div class="verticalSection sso-help-card" hidden><h2 class="sectionTitle" data-i18n="${SUMMARY_KEY}">Full text</h2><div class="sso-help-card-text"></div></div>`;
  // `inputContainer` is the branch `fieldOf` walks up to; anything else is the parent branch.
  const wrapper = shared === "parent" ? "sso-test-block" : "inputContainer";
  const fields =
    shared === false
      ? `<div class="inputContainer">${block(key)}</div><div class="inputContainer">${block(other)}</div>`
      : `<div class="${wrapper}">${block(key)}${block(other)}</div>`;
  return [`<div ${CONDENSE_ROOT}>`, fields, card, `</div>`].join("\n");
}

/** Runs every calibration arm of both readers and returns the results. */
async function calibrate(i18n) {
  const results = [];
  const record = (name, mustRefuse, refusals) =>
    results.push({ name, mustRefuse, refusals });

  // --- the markup reader ---
  record(
    "authored markup passes",
    false,
    inspectMarkup("fixture", fixtureMarkup("config.fixture_0_help", {}))
      .refusals,
  );
  record(
    "a page with no help text at all",
    false,
    inspectMarkup("fixture", "<div>nothing here</div>").refusals,
  );
  record(
    "a comment mentioning a closing tag inside a block",
    false,
    inspectMarkup(
      "fixture",
      fixtureMarkup("config.fixture_0_help", { comment: true }),
    ).refusals,
  );
  record(
    "a help marker declared flat, with its reason",
    false,
    inspectMarkup(
      "fixture",
      fixtureMarkup("config.fixture_0_help", { declared: true }),
    ).refusals,
  );
  record(
    "a fold whose text is assembled from parts",
    false,
    inspectMarkup(
      "fixture",
      fixtureMarkup("config.fixture_0_help", { assembled: true }),
    ).refusals,
  );
  record(
    "a block carrying a self-closed tag before its fold",
    false,
    inspectMarkup(
      "fixture",
      fixtureMarkup("config.fixture_0_help", { selfClosed: true }),
    ).refusals,
  );
  record(
    "a field described by its block's spoken copy",
    false,
    inspectMarkup(
      "fixture",
      fixtureMarkup("config.fixture_0_help", { spoken: true }),
    ).refusals,
  );
  record(
    "two help blocks in two fields",
    false,
    inspectMarkup(
      "fixture",
      fixturePair("config.fixture_0_help", "config.fixture_1_help", false),
    ).refusals,
  );
  const markupNegatives = [
    ["a help text still written flat", { flat: true }],
    [
      "a parts-marked help text still written flat",
      { flat: true, assembled: true },
    ],
    ["a fold authored inside a <p>", { tag: "p" }],
    ["a fold wrapped in a layout element", { wrapped: true }],
    ["a help marker on a class neither reader enters", { stray: true }],
    ["a rail card with no heading", { heading: false }],
    ["a block the applier will not find", { marked: false }],
    ["a fold with no lead line to fill", { lead: false }],
    ["a whole text behind no fold", { details: false }],
    ["a fold named by another key", { summary: false }],
    ["a key that is not on the body of its own fold", { body: false }],
    ["a condensed page with no rail card", { card: false }],
    ["a rail card outside the container the applier walks", { scoped: false }],
    ["a field described by its whole block", { described: true }],
    ["a spoken copy nothing names", { spokenUnnamed: true }],
    ["a spoken copy authored shown", { spokenShown: true }],
    ["a field described by the body inside its fold", { describedBody: true }],
    ["a spoken copy authored outside its block", { spokenOutside: true }],
    [
      "a spoken copy hidden by a class token rather than the attribute",
      { spokenClassHidden: true },
    ],
  ];
  markupNegatives.forEach(([name, parts]) =>
    record(
      name,
      true,
      inspectMarkup("fixture", fixtureMarkup("config.fixture_0_help", parts))
        .refusals,
    ),
  );
  record(
    "two help blocks in one field",
    true,
    inspectMarkup(
      "fixture",
      fixturePair("config.fixture_0_help", "config.fixture_1_help", true),
    ).refusals,
  );
  record(
    "two help blocks sharing a parent that is not a field container",
    true,
    inspectMarkup(
      "fixture",
      fixturePair("config.fixture_0_help", "config.fixture_1_help", "parent"),
    ).refusals,
  );

  /*
   * --- the child reader, against hand-written answers (#1669) ---
   * The same reading builds a fixture's children and the text it is judged against,
   * so these hand-written answers are what keep it from agreeing with itself.
   */
  const CHILD_CATALOGUE = { "config.fixture_child": "the setting's name" };
  const CHILD_ROWS = [
    // A plain sample, an entity inside one, and a void element with no text at all.
    [
      "<code>/sso/OID/p/&lt;name&gt;</code> then <br /> then <code>a &amp; b</code>",
      ["/sso/OID/p/<name>", "", "a & b"],
    ],
    // A marked child holds the catalogue's text by the time the sentence is assembled.
    [
      '<strong data-i18n="config.fixture_child">Whatever the page says</strong>',
      ["the setting's name"],
    ],
    // A child of a child, which this reader does not resolve.
    ["<span>a <code>nested</code> sample</span>", null],
    // A marked child whose key no catalogue carries, so its text is unknown here.
    ['<strong data-i18n="config.no_such_key">Whatever</strong>', null],
    // A reference it does not know.
    ["<code>&hellip;</code>", null],
    // Markup it cannot walk at all.
    ["<code>unclosed", null],
  ];
  for (const [inner, expected] of CHILD_ROWS) {
    const children = directChildren(inner.replace(/\s+/g, " "));
    const read =
      children === null
        ? null
        : children.map((child) => childText(child, CHILD_CATALOGUE, {}));
    const got = read === null || read.includes(null) ? null : read;
    record(
      `the hand-written children of ${JSON.stringify(inner.slice(0, 34))}`,
      false,
      JSON.stringify(got) === JSON.stringify(expected)
        ? []
        : [
            `the child reader read ${JSON.stringify(got)} and the hand-written answer is ${JSON.stringify(expected)}`,
          ],
    );
  }

  // The assembly, hand-written the same way: a value must name each child exactly once.
  const ASSEMBLY_ROWS = [
    ["Set {0} first.", ["A"], "Set A first."],
    ["Set {1} before {0}.", ["A", "B"], "Set B before A."],
    ["No slot at all.", ["A"], null],
    ["Set {0} and {0}.", ["A", "B"], null],
    ["Set {2}.", ["A"], null],
  ];
  for (const [value, children, expected] of ASSEMBLY_ROWS) {
    const got = assemble(value, children);
    record(
      `the hand-written assembly of ${JSON.stringify(value)}`,
      false,
      got === expected
        ? []
        : [
            `the assembly read ${JSON.stringify(got)} and the hand-written answer is ${JSON.stringify(expected)}`,
          ],
    );
  }

  // --- the hand-written answers, which is the only arm not derived from the rule ---
  for (const [text, expected] of HAND_WRITTEN_LEADS) {
    const texts = fixtureTexts([text]);
    const key = Object.keys(texts)[0];
    const page = buildPage([key], texts, "Full text", {});
    await render(i18n, page, { ...texts, [SUMMARY_KEY]: "Full text" });
    const field = page.fields[0];
    // A one-sentence answer is read off the body and a split one off the lead (#1669),
    // and the row also checks where the body now sits.
    const shown = expected === null ? field.body : field.lead;
    const want = expected === null ? text : expected;
    const placed =
      expected === null
        ? field.body.parentNode === field.help
        : field.body.parentNode === field.details;
    record(
      `the hand-written lead of ${JSON.stringify(text.slice(0, 34))}`,
      false,
      shown.textContent === want &&
        placed &&
        field.details.hidden === (expected === null)
        ? []
        : [
            `the applier shows ${JSON.stringify(shown.textContent)} under the field and the hand-written answer is ${JSON.stringify(want)}, with the fold ${field.details.hidden ? "hidden" : "shown"} and the text ${placed ? "where it belongs" : "in the wrong place"}`,
          ],
    );
  }

  // --- the runtime reader, positives ---
  const positives = [
    ["a two-sentence text is split", [TWO]],
    ["a one-sentence text shows its sentence and hides the fold", [ONE]],
    ["an abbreviation is not a sentence end", [ABBREVIATION]],
    ["a German text is split on its own terminator", [GERMAN]],
    ["several fields on one page", [TWO, ONE, ABBREVIATION, GERMAN]],
  ];
  for (const [name, values] of positives) {
    const texts = fixtureTexts(values);
    const page = buildPage(Object.keys(texts), texts, "Full text", {});
    await render(i18n, page, { ...texts, [SUMMARY_KEY]: "Full text" });
    record(name, false, [
      ...inspect(page, texts, "Full text").refusals,
      ...inspectRail(page, texts, "Full text", true),
    ]);
  }

  /*
   * --- the fold's name and the spoken copy (#1672) ---
   * The stub computes no accessible name, so the arms hold the attributes it is computed from.
   */
  {
    const texts = fixtureTexts([TWO, ONE]);
    const page = buildPage(Object.keys(texts), texts, "Full text", {
      spoken: true,
    });
    await render(i18n, page, { ...texts, [SUMMARY_KEY]: "Full text" });
    // Twice, so a second pass must find the ids rather than mint a second set.
    await render(i18n, page, { ...texts, [SUMMARY_KEY]: "Full text" });
    const summaryEl = page.fields[0].details.querySelector("summary");
    record(
      "a fold is named by its field's label and its own word, and a spoken copy holds the whole text",
      false,
      [
        ...inspect(page, texts, "Full text").refusals,
        ...inspectRail(page, texts, "Full text", true),
        ...(summaryEl.getAttribute("aria-labelledby") ===
          "fixture_0-label fixture_0-full-text" &&
        page.fields[0].label.getAttribute("id") === "fixture_0-label"
          ? []
          : [
              `the summary is named by ${JSON.stringify(summaryEl.getAttribute("aria-labelledby"))} and the ids the applier derives from the control are fixture_0-label and fixture_0-full-text`,
            ]),
        ...(page.fields[0].spoken.textContent === TWO
          ? []
          : ["the spoken copy does not hold the whole text"]),
      ],
    );
  }

  // A label wrapped around its control, as every checkbox row is authored.
  {
    const texts = fixtureTexts([TWO]);
    const page = buildPage(Object.keys(texts), texts, "Full text", {});
    const field = page.fields[0];
    field.container.className = "checkboxContainer";
    field.label.removeAttribute("for");
    field.label.appendChild(field.input);
    await render(i18n, page, { ...texts, [SUMMARY_KEY]: "Full text" });
    const summaryEl = field.details.querySelector("summary");
    record(
      "a fold under a label wrapped around its checkbox is named by that label",
      false,
      summaryEl.getAttribute("aria-labelledby") ===
        "fixture_0-label fixture_0-full-text"
        ? []
        : [
            `the summary under a wrapping label is named by ${JSON.stringify(summaryEl.getAttribute("aria-labelledby"))}`,
          ],
    );
  }

  // A block in no field container keeps the bare word rather than another field's label.
  {
    const texts = fixtureTexts([TWO]);
    const page = buildPage(Object.keys(texts), texts, "Full text", {});
    const field = page.fields[0];
    field.container.className = "sso-test-block";
    await render(i18n, page, { ...texts, [SUMMARY_KEY]: "Full text" });
    const summaryEl = field.details.querySelector("summary");
    record(
      "a fold in no field container is not named after somebody else's label",
      false,
      summaryEl.hasAttribute("aria-labelledby")
        ? [
            `a fold under a plain parent was named by ${JSON.stringify(summaryEl.getAttribute("aria-labelledby"))}, the label of a field it does not open`,
          ]
        : [],
    );
  }

  // Two labelled controls in one container: the last label before the block names the fold.
  {
    const texts = fixtureTexts([TWO]);
    const page = buildPage(Object.keys(texts), texts, "Full text", {});
    const field = page.fields[0];
    const second = new El("label");
    second.setAttribute("for", "fixture_0b");
    second.textContent = "Second field";
    const control = new El("input");
    control.setAttribute("id", "fixture_0b");
    field.container.insertBefore(second, field.help);
    field.container.insertBefore(control, field.help);
    await render(i18n, page, { ...texts, [SUMMARY_KEY]: "Full text" });
    const summaryEl = field.details.querySelector("summary");
    record(
      "a fold under the second of two labelled controls is named by the second label",
      false,
      summaryEl.getAttribute("aria-labelledby") ===
        "fixture_0b-label fixture_0b-full-text"
        ? []
        : [
            `the fold under the second control is named by ${JSON.stringify(summaryEl.getAttribute("aria-labelledby"))}`,
          ],
    );
  }

  // The empty label jellyfin-web inserts before an upgraded control must not name the fold
  // or be given an id.
  {
    const texts = fixtureTexts([TWO]);
    const page = buildPage(Object.keys(texts), texts, "Full text", {});
    const field = page.fields[0];
    const host = new El("label");
    host.setAttribute("for", "fixture_0");
    field.container.insertBefore(host, field.input);
    await render(i18n, page, { ...texts, [SUMMARY_KEY]: "Full text" });
    const summaryEl = field.details.querySelector("summary");
    record(
      "the empty label the host inserts before a control does not name the fold",
      false,
      summaryEl.getAttribute("aria-labelledby") ===
        "fixture_0-label fixture_0-full-text" &&
        host.getAttribute("id") === null
        ? []
        : [
            `with the host's empty label in front of the control the fold is named by ${JSON.stringify(summaryEl.getAttribute("aria-labelledby"))}${host.getAttribute("id") === null ? "" : " and the empty label was given the id"}`,
          ],
    );
  }

  /*
   * --- the applier driven over a body assembled from parts (#1669) ---
   * Each arm asks where the child elements ended up, not only where the words did.
   */
  const AVATAR = "https://example.com/@{user_id}.png";
  const partsArm = async (name, values, children, extra) => {
    const key = "config.fixture_0_help";
    const kids = children.map((text) => ({ tag: "code", text }));
    const page = buildPage([key], {}, "Full text", { parts: { [key]: kids } });
    let texts = {};
    for (const value of values) {
      texts = { [key]: assemble(value, children) };
      await render(i18n, page, { [key]: value, [SUMMARY_KEY]: "Full text" });
    }
    record(name, false, [
      ...inspect(page, texts, "Full text").refusals,
      ...inspectRail(page, texts, "Full text", true),
      ...(extra ? extra(page.fields[0], texts[key]) : []),
    ]);
  };

  // More than one sentence: the markup stays behind the fold.
  await partsArm(
    "a parts body holding two sentences is split like any other",
    ["The avatar url takes the form {0}. Leave it blank to keep the default."],
    [AVATAR],
  );

  // One sentence: the child is still an element and sits outside the hidden fold.
  await partsArm(
    "a parts body holding one sentence keeps its child where a reader can see it",
    ["The avatar url takes the form {0}"],
    [AVATAR],
    (field) =>
      field.body.children.length === 1 &&
      field.body.children[0].tag === "code" &&
      field.body.parentNode === field.help &&
      field.details.hidden
        ? []
        : [
            "a one-sentence parts body did not end up outside its hidden fold with its child element intact",
          ],
  );

  // A second catalogue must reassemble the body, so moving the children into the lead fails.
  await partsArm(
    "a second catalogue reassembles a one-sentence parts body",
    [
      "The avatar url takes the form {0}",
      "Die Adresse des Avatars hat die Form {0}",
    ],
    [AVATAR],
  );

  // One sentence in English and two in German, so the body goes back behind the fold.
  await partsArm(
    "a parts body that gains a sentence in the other language folds again",
    [
      "The avatar url takes the form {0}",
      "Die Adresse hat die Form {0}. Leer lassen behält die Vorgabe.",
    ],
    [AVATAR],
  );

  /*
   * The applier's fallback for a fold that is not the block's own child (#1684):
   * the pass must not throw and the body must end up outside the hidden fold.
   */
  {
    const key = "config.fixture_0_help";
    const page = buildPage([key], {}, "Full text", {
      parts: { [key]: [{ tag: "code", text: AVATAR }] },
    });
    const field = page.fields[0];
    const wrap = new El("div");
    // replaceChildren first drops the fold's parent, as a browser would, before the wrapper adopts it.
    field.help.replaceChildren(field.lead, wrap);
    wrap.appendChild(field.details);
    let threw = null;
    try {
      await render(i18n, page, {
        [key]: "The avatar url takes the form {0}",
        [SUMMARY_KEY]: "Full text",
      });
    } catch (error) {
      threw = error;
    }
    const placed =
      threw === null
        ? field.body.parentNode === field.help && field.details.hidden
        : false;
    record(
      "a fold the page wrapped still gets its one-sentence body onto the page",
      false,
      threw !== null
        ? [
            `condensing a block whose fold is not its own child threw ${threw.message}, which in a browser leaves every block after it on the page unread and attaches no rail listener`,
          ]
        : placed
          ? []
          : [
              `a one-sentence body under a wrapped fold ended up in ${field.body.parentNode === wrap ? "the wrapper, inside the hidden fold" : "neither the block nor the wrapper"}, so the field shows no description at all`,
            ],
    );
  }

  /*
   * A second identical pass must not move the promoted body again, since a DOM move
   * blurs a focused link inside it; the stub has no focus, so the moves are counted.
   */
  {
    const key = "config.fixture_0_help";
    const page = buildPage([key], {}, "Full text", {
      parts: { [key]: [{ tag: "code", text: AVATAR }] },
    });
    const catalogue = {
      [key]: "The avatar url takes the form {0}",
      [SUMMARY_KEY]: "Full text",
    };
    await render(i18n, page, catalogue);
    const field = page.fields[0];
    let moves = 0;
    const insert = field.help.insertBefore.bind(field.help);
    field.help.insertBefore = (node, before) => {
      moves += node === field.body ? 1 : 0;
      return insert(node, before);
    };
    await render(i18n, page, catalogue);
    record(
      "a second identical pass does not move the promoted body again",
      false,
      moves === 0
        ? []
        : [
            `a second pass re-inserted an already promoted body ${moves} time(s), which in a browser drops the focus out of a link inside it`,
          ],
    );
  }

  // The negative: the children flattened into one text node, which only the tree can refuse.
  {
    const key = "config.fixture_0_help";
    const value = "The avatar url takes the form {0}";
    const page = buildPage([key], {}, "Full text", {
      parts: { [key]: [{ tag: "code", text: AVATAR }] },
    });
    await render(i18n, page, { [key]: value, [SUMMARY_KEY]: "Full text" });
    const texts = { [key]: assemble(value, [AVATAR]) };
    page.fields[0].body.textContent = texts[key];
    record("a parts body flattened into plain text", true, [
      ...inspect(page, texts, "Full text").refusals,
    ]);
  }

  // --- the runtime reader, negatives: one per refusal it can make ---
  const negatives = [
    [
      "a fold that cut its text",
      (page) => {
        page.fields[0].body.textContent = "cut short.";
      },
    ],
    [
      "a lead that is not the first sentence",
      (page) => {
        page.fields[0].lead.textContent = "A sentence nobody wrote.";
      },
    ],
    [
      "a lead the applier never wrote",
      (page) => {
        page.fields[0].lead.textContent = "";
      },
    ],
    [
      "a fold hidden although it holds more",
      (page) => {
        page.fields[0].details.hidden = true;
      },
    ],
    [
      "a one-sentence text folded anyway",
      (page) => {
        page.fields[1].details.hidden = false;
      },
    ],
    // The one-sentence state fails by leaving the text in the hidden fold or by
    // copying it into the lead as well (#1669).
    [
      "a one-sentence text left inside its hidden fold",
      (page) => {
        page.fields[1].details.appendChild(page.fields[1].body);
      },
    ],
    [
      "a one-sentence text copied into the lead as well as moved",
      (page) => {
        page.fields[1].lead.textContent = page.fields[1].body.textContent;
      },
    ],
    [
      "a multi-sentence text whose body was left standing under the field",
      (page) => {
        page.fields[0].help.insertBefore(
          page.fields[0].body,
          page.fields[0].details,
        );
      },
    ],
    [
      "a summary naming something the catalogue does not say",
      (page) => {
        page.fields[0].details.querySelector("summary").textContent = "More";
      },
    ],
    [
      "a card the focus never reaches",
      (page) => {
        page.root.listeners.clear();
      },
    ],
    [
      "a card shown before anything has focus",
      (page) => {
        page.root.querySelector(".sso-help-card").hidden = false;
      },
    ],
    [
      "a card that never clears",
      (page) => {
        const card = page.root.querySelector(".sso-help-card");
        const inner = card.querySelector(".sso-help-card-text");
        page.root.listeners.clear();
        page.root.addEventListener("focusin", () => {
          card.hidden = false;
          inner.textContent = "whatever was there last";
        });
      },
    ],
    [
      "a card answering the wrong field",
      (page) => {
        const card = page.root.querySelector(".sso-help-card");
        const inner = card.querySelector(".sso-help-card-text");
        page.root.listeners.clear();
        page.root.addEventListener("focusin", () => {
          card.hidden = false;
          inner.textContent = page.fields[0].body.textContent;
        });
      },
    ],
    [
      "a card heading that is not the catalogue's",
      (page) => {
        page.root.querySelector(".sectionTitle").textContent = "Details";
      },
    ],
  ];
  for (const [name, mutate] of negatives) {
    const texts = fixtureTexts([TWO, ONE]);
    const page = buildPage(Object.keys(texts), texts, "Full text", {});
    await render(i18n, page, { ...texts, [SUMMARY_KEY]: "Full text" });
    mutate(page);
    record(name, true, [
      ...inspect(page, texts, "Full text").refusals,
      ...inspectRail(page, texts, "Full text", true),
    ]);
  }

  // The fold's name and the spoken copy (#1672), one negative per refusal.
  const namedNegatives = [
    [
      "a fold named by nothing but the catalogue word",
      (page) => {
        page.fields[0].details
          .querySelector("summary")
          .removeAttribute("aria-labelledby");
      },
    ],
    [
      "a fold named by an id that is not its field's label",
      (page) => {
        const summaryEl = page.fields[0].details.querySelector("summary");
        summaryEl.setAttribute(
          "aria-labelledby",
          "elsewhere " + summaryEl.getAttribute("id"),
        );
      },
    ],
    [
      "a spoken copy that is not the whole text",
      (page) => {
        page.fields[0].spoken.textContent = "cut short.";
      },
    ],
    [
      "a spoken copy the applier left shown",
      (page) => {
        page.fields[0].spoken.hidden = false;
        page.fields[0].spoken.removeAttribute("hidden");
      },
    ],
  ];
  for (const [name, mutate] of namedNegatives) {
    const texts = fixtureTexts([TWO, ONE]);
    const page = buildPage(Object.keys(texts), texts, "Full text", {
      spoken: true,
    });
    await render(i18n, page, { ...texts, [SUMMARY_KEY]: "Full text" });
    mutate(page);
    record(name, true, inspect(page, texts, "Full text").refusals);
  }

  // Two help blocks in one field container: the applier deterministically lets the
  // first block in document order answer the rail.
  const sharedTexts = fixtureTexts([TWO, GERMAN]);
  const sharedKeys = Object.keys(sharedTexts);
  const shared = buildPage(sharedKeys, sharedTexts, "Full text", {});
  const moved = shared.fields[1].help;
  moved.parentNode.nodes = moved.parentNode.nodes.filter((n) => n !== moved);
  shared.fields[0].container.appendChild(moved);
  await render(i18n, shared, { ...sharedTexts, [SUMMARY_KEY]: "Full text" });
  shared.root.fire("focusin", shared.fields[0].input);
  record("two help blocks in one field: the first answers the rail", false, [
    ...(shared.root.querySelector(".sso-help-card-text").textContent ===
    sharedTexts[sharedKeys[0]]
      ? []
      : [
          `the rail answered with ${JSON.stringify(shared.root.querySelector(".sso-help-card-text").textContent.slice(0, 30))} rather than the first block's text`,
        ]),
    // Both leads are still written: the collision costs the rail, never the fold.
    ...(shared.fields[1].lead.textContent === "Standardmäßig aus."
      ? []
      : [
          "the second block of a shared field lost its sentence as well as its rail",
        ]),
  ]);

  // --- two arms about the scope of the rule rather than one page's shape ---
  const scopeTexts = fixtureTexts([TWO]);
  const unmarked = buildPage(Object.keys(scopeTexts), scopeTexts, "Full text", {
    marked: false,
  });
  await render(i18n, unmarked, { ...scopeTexts, [SUMMARY_KEY]: "Full text" });
  record(
    "a container without the opt-in attribute keeps its lead line empty",
    false,
    unmarked.fields[0].lead.textContent === ""
      ? []
      : [
          "an unmarked container was condensed, so the slice reached a page nobody moved",
        ],
  );

  const cardless = buildPage(Object.keys(scopeTexts), scopeTexts, "Full text", {
    card: false,
  });
  await render(i18n, cardless, { ...scopeTexts, [SUMMARY_KEY]: "Full text" });
  record("a page with no card still condenses its help", false, [
    ...inspect(cardless, scopeTexts, "Full text").refusals,
    ...inspectRail(cardless, scopeTexts, "Full text", false),
  ]);

  // A container with no card must not be marked wired, or a later pass with a card
  // attaches no listener.
  record("a container with no card is not marked as wired", false, [
    ...(cardless.root.hasAttribute("data-sso-condensed-help-wired")
      ? [
          "a container with no card was marked wired, so a later pass with a card attaches no listener",
        ]
      : []),
    ...(cardless.root.listeners.get("focusin")
      ? [
          "a container with no card attached a focus listener with nothing to fill",
        ]
      : []),
  ]);

  // The catalogue arriving twice: the second pass must move the lead, the fold
  // and the summary together, and must not wire a second listener.
  const twice = buildPage(Object.keys(scopeTexts), scopeTexts, "Full text", {});
  await render(i18n, twice, { ...scopeTexts, [SUMMARY_KEY]: "Full text" });
  const key = Object.keys(scopeTexts)[0];
  await render(i18n, twice, {
    [key]: GERMAN,
    [SUMMARY_KEY]: "Vollständiger Text",
  });
  record(
    "a second catalogue moves the lead, the fold and the summary together",
    false,
    [
      ...inspect(twice, { [key]: GERMAN }, "Vollständiger Text").refusals,
      // `|| []`, since a container with no listener is one of the states to name.
      ...((twice.root.listeners.get("focusin") || []).length === 1
        ? []
        : [
            `a second pass left ${(twice.root.listeners.get("focusin") || []).length} focus listener(s) on one container, and one is the only right number`,
          ]),
    ],
  );

  const wrong = results.filter(
    (result) => result.refusals.length > 0 !== result.mustRefuse,
  );
  if (wrong.length > 0) {
    wrong.forEach((result) =>
      console.error(
        `CALIBRATION  ${result.name}: ${result.mustRefuse ? "no refusal" : result.refusals.join("; ")}`,
      ),
    );
    return null;
  }

  const mustPass = results.filter((result) => !result.mustRefuse).length;
  return `calibration:       ${results.length} arms, ${mustPass} that must pass and ${results.length - mustPass} that must be refused, all as expected`;
}

/** Calibrates, then judges every marked page in both catalogues and returns the exit code. */
async function run() {
  const i18n = await loadApplier();
  const calibration = await calibrate(i18n);
  if (calibration === null) {
    console.error("the calibration disagreed, so nothing was counted (#1662)");
    return 1;
  }
  console.log(calibration);

  const en = catalogue("en");
  const de = catalogue("de");
  const pages = markedPages();
  if (pages.length === 0) {
    console.error(
      `REFUSED  no page carries ${CONDENSE_ROOT}, so the condensing rule reaches nothing and every arm above judged fixtures only`,
    );
    return 1;
  }

  let refused = 0;
  let total = 0;
  for (const page of pages) {
    const markup = read(path.join(WEB, page));
    const authored = inspectMarkup(page, markup);
    authored.refusals.forEach((message) => {
      console.error(`REFUSED  ${message}`);
      refused += 1;
    });

    // The collapsed string comes from the markup reader, so the two block counts
    // below are read from the same text.
    const flatMarkup = authored.markup;
    const bodies = [
      ...flatMarkup.matchAll(
        /<(?<tag>[a-z][a-z0-9]*)\b[^>]*class="sso-help-body" data-i18n(?<parts>-parts)?="(?<key>[a-z0-9_.]+_help)"[^>]*>/g,
      ),
    ].map((m) => {
      if (m.groups.parts === undefined) {
        return { key: m.groups.key, parts: false, children: [] };
      }
      // A body that never closes is unreadable, not childless.
      const inner = elementBody(
        flatMarkup,
        m.index + m[0].length,
        m.groups.tag,
      );
      return {
        key: m.groups.key,
        parts: true,
        children: inner === null ? null : directChildren(inner),
      };
    });
    const keys = bodies.map((body) => body.key);

    // Parts bodies are driven with their own children (#1669); a body this reader
    // cannot walk is counted in the printed line rather than dropped. Child text is
    // read from collapsed markup, so a wrapped line break is one space here.
    const either = { ...de, ...en };
    const readable = (body) =>
      !body.parts ||
      (body.children !== null &&
        body.children.every((child) => childText(child, either, {}) !== null));
    const driven = bodies.filter(readable);
    const assembled = driven.filter((body) => body.parts).length;
    const unread = keys.length - driven.length;

    if (keys.length === 0) {
      console.error(
        `REFUSED  ${page} carries ${CONDENSE_ROOT} and no condensed help text, so the applier is driven over nothing on it`,
      );
      refused += 1;
    }

    // The element reader and the marker reader must agree on the block count.
    if (authored.blocks !== keys.length) {
      console.error(
        `REFUSED  ${page}: the element reader finds ${authored.blocks} condensed block(s) and the marker reader finds ${keys.length}, so one of them is not seeing the page`,
      );
      refused += 1;
    }
    total += keys.length;

    for (const [name, values] of [
      ["en", en],
      ["de", de],
    ]) {
      const summary = values[SUMMARY_KEY];
      if (summary === undefined) {
        console.error(
          `REFUSED  ${name}.json carries no ${SUMMARY_KEY}, so every fold on every page falls back to the English in the markup`,
        );
        refused += 1;
        continue;
      }

      // `catalogue` is what the pass is handed and `texts` what each body ought to
      // hold afterwards, which for a parts body has its slots filled.
      const value = (key) =>
        values[key] !== undefined ? values[key] : en[key];
      const catalogue = {};
      const texts = {};
      const parts = {};
      const drivenKeys = [];
      for (const body of driven) {
        catalogue[body.key] = value(body.key);
        if (!body.parts) {
          texts[body.key] = catalogue[body.key];
          drivenKeys.push(body.key);
          continue;
        }
        const childrenText = body.children.map((child) =>
          childText(child, values, en),
        );
        const whole = assemble(catalogue[body.key], childrenText);
        if (whole === null) {
          console.error(
            `REFUSED  ${page} (${name}): ${body.key} is assembled from ${body.children.length} child element(s) and its ${name}.json value does not name each of them exactly once, or one of those children has no text in this catalogue - either way the pass leaves the authored English standing`,
          );
          refused += 1;
          continue;
        }
        texts[body.key] = whole;
        // Each child keeps its own tag. The maps are keyed by key, so for a key on two
        // sites the last site's children stand for both.
        parts[body.key] = body.children.map((child, index) => ({
          tag: child.tag,
          text: childrenText[index],
        }));
        drivenKeys.push(body.key);
      }

      const built = buildPage(drivenKeys, texts, summary, { parts });
      await render(i18n, built, { ...catalogue, [SUMMARY_KEY]: summary });
      const runtime = inspect(built, texts, summary);
      [
        ...runtime.refusals,
        ...inspectRail(built, texts, summary, true),
      ].forEach((message) => {
        console.error(`REFUSED  ${page} (${name}): ${message}`);
        refused += 1;
      });
      if (name === "en") {
        console.log(
          `${page.padEnd(20)}${String(keys.length).padStart(3)} condensed help text(s), ${runtime.counts.folded} with a fold that holds more, ${runtime.counts.flat} whose text is one sentence, ${authored.named} named after their field's label and ${keys.length - authored.named} by the catalogue word alone` +
            (assembled === 0
              ? ""
              : `, ${assembled} assembled from parts and driven with their own children, ${runtime.counts.flatParts} of them holding one sentence`) +
            (unread === 0
              ? ""
              : `, ${unread} whose children this reader cannot walk and judged by the markup reader only`) +
            (authored.declared === 0
              ? ""
              : `, ${authored.declared} declared flat with a reason`),
        );
      }
    }
  }

  console.log(
    `the marked pages:   ${total} condensed help text(s) over ${pages.length} page(s), read in en and de`,
  );
  if (refused > 0) {
    console.error(`${refused} refusal(s) in the condensed help (#1662)`);
    return 1;
  }

  console.log(
    "every condensed help text is authored as a fold and shows its own first sentence under the field, in both catalogues",
  );
  return 0;
}

run().then(
  (code) => process.exit(code),
  (error) => {
    console.error(`the condensed-help gate could not run: ${error.stack}`);
    process.exit(1);
  },
);
