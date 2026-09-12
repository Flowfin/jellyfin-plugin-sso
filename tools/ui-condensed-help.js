#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Reads the condensed help of the pages that opt into it, in both halves it has
 * (#1662): the fold the markup authors, and the sentence SSO-Auth/Web/i18n.js
 * derives at runtime.
 *
 * WHY THIS EXISTS BESIDE THE CENSUS AND DOES NOT REPLACE IT. tools/ui-help-census.js
 * reads bytes, and it holds the promise "nothing is deleted, only moved": every
 * help text is still on the page its row names, inside the field that names it,
 * exactly once. It says nothing about what the move PRODUCED. A help text sealed
 * inside a `<details>` whose summary is never named, above a lead line that stays
 * empty because no applier ran, satisfies the census exactly as well as a
 * working page does - the text is there, once, in the right field, and no reader
 * can see it. That gap is this tool's subject.
 *
 * TWO READERS, BECAUSE THE SLICE HAS TWO HALVES AND THEY FAIL DIFFERENTLY. The
 * first reads the shipped markup and refuses a help text that is not authored as
 * a fold, a fold with no lead line to fill, a summary naming something other than
 * the catalogue row the folds share, and a marked page with no rail card. The
 * second LOADS the shipped applier and drives it over the shipped catalogues,
 * refusing a lead that is not the first sentence of the text behind it, a fold
 * hiding nothing, a fold hidden while it holds more, and a rail card answering a
 * field that does not have focus.
 *
 * WHY IT IS NODE AND NOT A BROWSER OR A DOM LIBRARY. The means check, per the
 * standpoint: node is already carried by this tree - tools/ui-mock-fields.js and
 * tools/ui-unsaved-state.js are run by the .NET workflow with no install - and a
 * DOM library would add a dependency and a lockfile to a repository that has
 * neither. tools/ui-unsaved-state.js took the same decision for the same reason
 * and carries the same class of bound, stated below rather than hidden.
 *
 * WHAT THE STUB CAN AND CANNOT SAY, AND THIS BOUND IS THE PART TO READ. The DOM
 * below is a stub with a real TREE - parents, children, text, and a selector
 * reader over tag, class and attribute - because the rule under test walks upward
 * from a focus, and that is not decidable without one. It is still NOT a browser.
 * It has NO EVENT PROPAGATION: the listener is registered on the container and
 * the stub CALLS it with the element the focus landed on, which is the shape a
 * browser delivers `focusin` in, but the stub cannot say that `focusin` bubbles,
 * and a mutation spelling it `focus` - which does not bubble - passes every arm
 * below. That property is the event's, not this code's, and it is named here
 * rather than claimed.
 *
 * It also says nothing about layout, about whether `<details>` draws a disclosure
 * triangle, or about what a screen reader announces when one opens. Those are
 * exactly the reasons the element is native rather than rebuilt, and they are a
 * walk's to confirm rather than this tool's.
 *
 * WHAT KEEPS IT FROM BEING A PROOF ABOUT ITSELF. The code under test is the
 * shipped i18n.js, loaded whole, not a copy and not an extract. The pages read
 * are the ones carrying the opt-in attribute, so a page joining the slice is
 * picked up without being named here, and a field removed from a page is removed
 * from what is read. The texts are the shipped en.json and de.json values rather
 * than prose written for a test.
 *
 * AND WHAT THE SECOND READER DOES NOT TOUCH, which is the bound to read before
 * trusting its green line. It drives the applier over a page this file BUILDS from
 * the real keys, not over the real page's tree - this tree carries no HTML parser
 * and adding one is a dependency the standpoint has not been asked for. So every
 * question about WHERE something sits on a real page belongs to the first reader,
 * and the first reader is a string reader. The review of 2026-09-12 measured what
 * that costs: moving the opt-in attribute onto an inner element left the rail card
 * outside the container the applier walks, killed the card on the whole page, and
 * the runtime arms - judging a fixture whose card is in the right place - printed a
 * pass. The markup reader now refuses that placement by name, which closes the one
 * instance and not the class. A real-page shape the string reader cannot see is
 * still a shape nothing here judges.
 *
 * THE CALIBRATION RUNS FIRST AND THE REAL PAGES SECOND. A reader that accepts
 * everything passes its own arithmetic, so the arms below drive both readers over
 * fixtures whose answers are known - a positive for each shape that must pass and
 * one negative per refusal each reader can make - and the run stops before the
 * pages are opened if any of them disagrees. The pass is printed, because a
 * calibration nobody sees the result of reads exactly like one that was never run.
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

// The lead line as the markup authors it: present, empty, and named, so the applier has
// somewhere to write the first sentence and a page whose script never ran shows no blank prose.
const EMPTY_LEAD = '<span class="sso-help-lead"></span>';

// A help key a marker names, under EITHER marker. `data-i18n-parts` is a sentence
// that holds markup (#1529), and 36 of the Providers page's help texts are written
// that way; a reader that knew only the plain marker read every one of them as a
// condensed block naming no key at all.
const HELP_KEY = 'data-i18n(?:-parts)?="([a-z0-9_.]+_help)"';

// The same pattern pinned to one key. Both forms allow OTHER ATTRIBUTES between the
// body's class and its marker, because one body carries an id: the input it describes
// points at it through aria-describedby, and that reference has to resolve to the
// element holding the text rather than to the wrapper whose first readable child is
// the word the summary is named with.
const HELP_KEY_FOR = (key) => `data-i18n(?:-parts)?="${key}"`;

// A field description DECLARING that it stays flat, which is the only way one may.
// The Providers page leaves thirteen that way - the twelve inside the two security
// regions that slice 5 (#1666) turns into folds of their own, where a second fold
// over a warning would be the wrong change to make early, and the one callout,
// which is a note rather than a field. The declaration is an attribute at the site
// rather than a class list inside this tool: a reader of the page sees why it is
// flat where the page is flat, and a help text nobody declared is still refused.
const FLAT_MARK = "data-sso-help-flat";

// The elements that never close, so a stack of open tags does not keep one and a
// later closing tag does not unwind the wrong element. The `<input>` inside every
// field container is exactly where that bites.
const VOID_ELEMENTS = new Set([
  "br",
  "hr",
  "img",
  "input",
  "link",
  "meta",
  "wbr",
  "source",
  "area",
  "base",
  "col",
  "embed",
  "param",
  "track",
]);

// ---------------------------------------------------------------------------
// The stub DOM
// ---------------------------------------------------------------------------

// A selector this stub understands: an optional tag name followed by any number
// of `.class` and `[attr]` terms. That is the whole vocabulary i18n.js uses, and
// a selector outside it THROWS rather than matching nothing - a stub silently
// returning an empty list for a selector it did not understand would turn every
// arm below green for the wrong reason.
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

class Text {
  constructor(data) {
    this.data = data;
    this.parentNode = null;
  }

  get textContent() {
    return this.data;
  }
}

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
    node.parentNode = this;
    this.nodes.push(node);
    return node;
  }

  replaceChildren(...nodes) {
    this.nodes = [];
    nodes.forEach((node) => this.appendChild(node));
  }

  // Depth-first, document order, `this` excluded - the contract querySelectorAll
  // has, and the exclusion matters: the rule asks a container for the help blocks
  // INSIDE it and would otherwise be handed the container.
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

  // No propagation: the stub hands the registered handler the element the focus
  // landed on, which is what a browser delivers for a bubbling event, and the
  // header says what that cannot prove.
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

// ---------------------------------------------------------------------------
// The first reader: the fold the markup authors
// ---------------------------------------------------------------------------

// One `*_help` field description, as the markup writes it. The opening tag is
// matched first and its element walked to its own close with a depth counter,
// because the block nests a `<details>` and a `<div>` inside itself and the
// lazy-to-first-`</div>` reading that suffices for a flat description would stop
// in the middle of one.
// ANY TAG, NOT `<div>`, and the review of 2026-09-12 is why. A div-only reader was
// handed `<p class="fieldDescription" data-i18n="config.server_slo_help">` on the
// real Server page - one field un-condensed by hand, which is what a later edit
// undoing this stage looks like - and printed its pass line over nineteen blocks
// where there had been twenty. The census next door drops its `<details>` figure
// from 20 to 19 for the same edit and refuses nothing, because the text is still
// present once in its own field. Neither reader owned it.
// A CALLOUT IS IN THE POPULATION TOO, and it is in it so that its declaration is
// READ rather than merely written. One `*_help` key on the Providers page sits on a
// `sso-callout sso-callout-warning` with `role="note"` - a warning about a reverse
// proxy, which is a statement about the server rather than a description of the
// field beside it, and folding a warning is the wrong move. It stays flat and says
// so; a reader that did not know the class would have accepted the attribute while
// reading nothing, which is the shape of a declaration nobody checks.
const HELP_BLOCK =
  /<(?<tag>[a-z][a-z0-9]*)\b(?<attrs>[^>]*\bclass="[^"]*\b(?:fieldDescription|sso-callout)\b[^"]*"[^>]*)>/g;

/*
 * Whether an opening tag carries a class, as a CLASS rather than as a substring.
 *
 * `\bsso-help\b` was the first spelling and it is wrong in the direction that
 * matters: a hyphen is a non-word character, so the boundary matches inside
 * `sso-help-card-text` - the card's own text holder, which is a `fieldDescription`
 * with no help key - and the reader named it as a broken block on all three pages.
 * A class is a whitespace-separated token, so it is compared as one.
 */
function hasClassToken(opening, name) {
  const attribute = /class="([^"]*)"/.exec(opening);
  return attribute !== null && attribute[1].split(/\s+/).includes(name);
}

// The body of the element whose opening tag ends at `from`, walked to its own close
// with a depth counter over tags of the SAME NAME. Returns null when the element
// never closes.
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
 * Refuses the markup half, page by page: what a reader of a page whose script
 * never arrived is left with.
 */
function inspectMarkup(page, source) {
  // Whitespace-collapsed first, because Prettier decides where the lines in these
  // files break: it puts every attribute of a long tag on its own line and the
  // closing angle bracket on a line after them. A reader matching
  // `class="x" data-i18n="y"` against the file as written would start refusing the
  // moment a class name grew long enough to wrap, which is a refusal about a
  // formatter rather than about a page. The C# markup rules collapse for the same
  // reason and say so where they do it.
  //
  // COMMENTS ARE REMOVED BEFORE ANYTHING IS COUNTED, and the review of 2026-09-12
  // is why. These pages are heavily commented - the three carry twenty-one comments
  // between them - and the depth counter below reads `</div>` inside one as a real
  // closing tag. A comment mentioning a closing tag inside a help block truncated the
  // block, left it with no key, and dropped it from the population with NO refusal:
  // the tool printed its success line over a page it had stopped reading. That is the
  // "green for the wrong reason" this file's header says it exists to refuse,
  // arriving in the file itself.
  const markup = source.replace(/<!--[\s\S]*?-->/g, " ").replace(/\s+/g, " ");
  const refusals = [];
  const at = [];
  let blocks = 0;
  let flat = 0;
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

    const keys = [...body.matchAll(new RegExp(HELP_KEY, "g"))].map((m) => m[1]);
    const own = new RegExp(HELP_KEY).exec(opening);
    if (own) {
      // A DECLARED flat field passes and an undeclared one does not, which is the
      // whole difference between a boundary between two issues and a hole. The
      // attribute is at the site, so the page says where it is flat and this tool
      // does not carry a list of exceptions somebody has to keep in step.
      if (!opening.includes(FLAT_MARK)) {
        refusals.push(
          `${page} still writes ${own[1]} flat and does not declare it: the field shows the whole text under it rather than a sentence and a fold`,
        );
        continue;
      }
      // Counted only once the declaration is there, so a refused page does not
      // report its offender among the sites that declared themselves.
      flat += 1;
      continue;
    }
    // A BLOCK THE READER COULD NOT READ IS REFUSED, never skipped. This was a plain
    // `continue`, and the review of 2026-09-12 showed what that bought: a block whose
    // body the walker had truncated yielded no key, left the population with no
    // refusal, and the run printed its success line over a page it had stopped
    // reading. A marked block naming no key is either broken markup or a reader that
    // cannot walk it, and neither of those is a pass.
    if (keys.length === 0) {
      if (hasClassToken(opening, "sso-help")) {
        refusals.push(
          `a condensed block on ${page} names no help key, so either its markup is broken or this reader cannot walk it`,
        );
      }
      continue;
    }
    // AFTER the key read, because before it this fired on any keyless field
    // description somebody had left a stray attribute on - an element that is
    // neither condensed nor a help site, refused for being both.
    if (opening.includes(FLAT_MARK)) {
      refusals.push(
        `a condensed block on ${page} declares itself flat, so one of the two statements about it is wrong`,
      );
    }
    blocks += 1;
    at.push(match.index);

    const key = keys[0];
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
    if (!/<details\b[^>]*class="sso-help-full"/.test(body)) {
      refusals.push(
        `${key} on ${page} has no fold to put the whole text behind`,
      );
    }
    if (!new RegExp(`<summary data-i18n="${SUMMARY_KEY}">`).test(body)) {
      refusals.push(
        `the fold of ${key} on ${page} is named by something other than ${SUMMARY_KEY}, so one page's folds can be renamed without the others`,
      );
    }
    if (
      !new RegExp(`class="sso-help-body"[^>]*${HELP_KEY_FOR(key)}`).test(body)
    ) {
      refusals.push(
        `${key} on ${page} does not sit on the body of its own fold, so the catalogue writes it somewhere the applier does not read it from`,
      );
    }
  }

  // WHERE THE CARD SITS, not merely whether the page holds one, and the review of
  // 2026-09-12 is why this is not a page-wide grep. The applier looks for the card
  // UNDER the marked container and attaches no focus listener when it does not find
  // one there. Moving the marker onto an inner element - one attribute, the kind of
  // authoring slip a page grows while it is being rearranged - left the card outside
  // it, killed the rail on the whole page, and a reader grepping the page string
  // found the card exactly where it had always been and passed.
  if (blocks > 0) {
    const scope = markedScope(markup);
    if (scope === null) {
      refusals.push(
        `${page} condenses ${blocks} help text(s) and carries no readable ${CONDENSE_ROOT} container, so the applier is handed nothing to walk`,
      );
      return { refusals, blocks, flat };
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
    // INSIDE THE CARD, not anywhere on the page. This was a page-wide test, which is
    // the reading the placement refusal above exists against: moving the heading out
    // of the card and leaving it standing elsewhere on the page passed, and the card
    // shipped headless in the rail.
    const inCard =
      card < 0
        ? ""
        : elementBody(markup, markup.indexOf(">", card) + 1, "div") || "";
    if (
      card >= 0 &&
      !new RegExp(`<h2[^>]*data-i18n="${SUMMARY_KEY}"`).test(inCard)
    ) {
      refusals.push(`the rail card on ${page} is not headed by ${SUMMARY_KEY}`);
    }

    const outside = at.filter((i) => i < scope.from || i > scope.to).length;
    if (outside > 0) {
      refusals.push(
        `${outside} condensed help text(s) on ${page} sit outside the ${CONDENSE_ROOT} container, so no sentence is ever written under those fields`,
      );
    }
  }

  return { refusals, blocks, flat };
}

/*
 * Every tag on a page, with quoted attribute values and comments respected.
 *
 * A SECOND READER OF THE SAME BYTES, and what it adds is the STACK: which elements a
 * block sits inside, which a match-and-count walk cannot say. Quoted attribute values
 * are respected as well, and THAT HALF IS INSURANCE RATHER THAN A REPAIR - measured
 * across all six HTML assets in this tree, no attribute value holds a `<` or a `>`.
 * The comment half is real: a comment on the Providers page carries a closing tag,
 * and a depth counter reading it as a real one truncates the element it is in. Said
 * this way round because the first version of this paragraph claimed both as failures
 * this page had produced, and only one of them had.
 */
function tags(str) {
  const out = [];
  let i = 0;
  while (i < str.length) {
    const lt = str.indexOf("<", i);
    if (lt < 0) break;
    if (str.startsWith("<!--", lt)) {
      const e = str.indexOf("-->", lt);
      i = e < 0 ? str.length : e + 3;
      continue;
    }
    let j = lt + 1;
    let closing = false;
    if (str[j] === "/") {
      closing = true;
      j++;
    }
    let name = "";
    while (j < str.length && /[a-zA-Z0-9-]/.test(str[j])) {
      name += str[j];
      j++;
    }
    if (name === "") {
      i = lt + 1;
      continue;
    }
    let quote = null;
    let self = false;
    while (j < str.length) {
      const c = str[j];
      if (quote) {
        if (c === quote) quote = null;
        j++;
        continue;
      }
      if (c === '"' || c === "'") {
        quote = c;
        j++;
        continue;
      }
      if (c === ">") {
        self = str[j - 1] === "/";
        j++;
        break;
      }
      j++;
    }
    out.push({
      name: name.toLowerCase(),
      closing,
      self,
      attrs: str.slice(lt + 1 + name.length + (closing ? 1 : 0), j - 1),
      start: lt,
      end: j,
    });
    i = j;
  }
  return out;
}

/*
 * Refuses two condensed help blocks resolving to ONE field.
 *
 * WHAT IT COSTS IS THE RAIL AND NOT THE FOLD. The applier keys the focused field to
 * one help block by walking up to the nearest `inputContainer` or `checkboxContainer`
 * - the census's own rule for which field a text belongs to - so two blocks under one
 * container leave the second unreachable from the card, in silence. Both still show
 * their own sentence and their own fold.
 *
 * IT WAS UNREFUSED WHEN SLICE 1 LANDED and #1662 says so of itself. No page had the
 * shape then, counted over its twenty blocks; the Providers page brings ninety-nine
 * and is where it would first arise, which is why the refusal lands with it.
 */
function inspectFields(page, source) {
  const refusals = [];
  const toks = tags(source);
  const open = [];
  const owners = new Map();
  let blocks = 0;

  toks.forEach((t) => {
    if (t.self) return;
    if (t.closing) {
      while (open.length && open[open.length - 1].name !== t.name) open.pop();
      open.pop();
      return;
    }

    // hasClassToken, not a word-boundary match: `sso-help-lead`, `-full`, `-body`
    // and `-card-text` all satisfy a boundary after "help", and the first spelling
    // of this counted fourteen blocks on a page holding three.
    const isBlock = hasClassToken(t.attrs, "sso-help");
    if (!VOID_ELEMENTS.has(t.name)) {
      open.push(t);
    }
    if (!isBlock) return;

    blocks += 1;
    // The block itself is on the stack, so the field is looked for beneath it.
    const above = open.slice(0, -1);
    // THE SAME CLASS TEST THE APPLIER MAKES, which is a token test and not a
    // boundary match. `checkboxContainer-withDescription` satisfies a boundary after
    // "checkboxContainer" and does NOT satisfy classList.contains, so the first
    // spelling of this computed a different field from the one the rail actually
    // keys on - and then passed a page where the second block of a shared field was
    // unreachable, which is the whole loss this reader exists for.
    const field =
      [...above]
        .reverse()
        .find(
          (el) =>
            hasClassToken(el.attrs, "inputContainer") ||
            hasClassToken(el.attrs, "checkboxContainer"),
        ) || above[above.length - 1];
    const at = field ? field.start : -1;
    if (owners.has(at)) {
      refusals.push(
        `two condensed help texts on ${page} share one field, so the second is unreachable from the rail card: the blocks at offsets ${owners.get(at)} and ${t.start}`,
      );
      return;
    }
    owners.set(at, t.start);
  });

  return { refusals, blocks };
}

// The span of the container a page marks for condensing, or null when it marks
// none or the element cannot be walked to its close.
function markedScope(markup) {
  // Tag-agnostic, because the applier's selector is: it asks for the attribute and
  // does not care what element carries it. A div-only reader refused a `<section>`
  // container with a message saying the applier had been handed nothing to walk,
  // which was false of the applier.
  //
  // THE FIRST MARKED CONTAINER AND ONLY THE FIRST. The applier condenses under EVERY
  // container carrying the attribute; this returns one span, so a page marking two
  // would have the second's blocks reported as sitting outside "the" container. No
  // page marks two and nothing refuses one that does - said here rather than left for
  // the reader of a confusing refusal to work out.
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

// ---------------------------------------------------------------------------
// The second reader: the sentence the applier derives
// ---------------------------------------------------------------------------

/*
 * The first sentence, re-expressed here rather than imported from the module under
 * test - and THIS IS NOT AN INDEPENDENT DERIVATION, which an earlier version of
 * this comment claimed it was. It is the same rule written a second time: same
 * terminator, same abbreviation guard, same order. It therefore catches the applier
 * failing to APPLY the rule - a lead never written, written from the wrong text,
 * written once and left behind by a second catalogue - and it cannot catch the RULE
 * being wrong, because it is wrong in the same place.
 *
 * WHAT HOLDS THAT HALF is the table below: leads written out by hand, against inputs
 * chosen for the ways this rule breaks. The review of 2026-09-12 found the rule
 * cutting `config.acr_values_help` mid-abbreviation at `(e.g.` while every arm here
 * passed, precisely because both copies agreed. A hand-written answer cannot agree
 * with a mistake it was not told about.
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
 * One page as a tree: a marked container holding one folded field per help key,
 * and a rail card beside them.
 *
 * BUILT RATHER THAN PARSED, and that is a bound as well as a convenience. The
 * markup reader above judges the shipped pages; this one judges what the applier
 * DOES with a block of that shape. What it cannot see is a page that nests a
 * field differently from this fixture - a help block outside any
 * `inputContainer`, say, whose field would then be its own parent.
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
  const fields = keys.map((key) => {
    const container = new El("div");
    container.className = "inputContainer";
    const input = new El("input");

    const lead = new El("span");
    lead.className = "sso-help-lead";
    const summaryEl = new El("summary");
    summaryEl.setAttribute("data-i18n", SUMMARY_KEY);
    summaryEl.textContent = summary;
    const body = new El("div");
    body.className = "sso-help-body";
    body.setAttribute("data-i18n", key);
    body.textContent = texts[key];
    const details = new El("details");
    details.className = "sso-help-full";
    details.replaceChildren(summaryEl, body);
    const help = new El("div");
    help.className = "fieldDescription sso-help";
    help.replaceChildren(lead, details);

    container.replaceChildren(input, help);
    main.appendChild(container);
    return { key, container, input, help, lead, details, body };
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
 * Refuses the runtime half: `texts` is what each key's text OUGHT to be after the
 * pass - the catalogue value where the catalogue carries the key, the built-in
 * English where it does not - so "the fold lost a sentence" and "the fold is
 * showing the wrong language" are both refusable rather than only the first.
 */
function inspect(page, texts, summary) {
  const refusals = [];
  const say = (message) => refusals.push(message);
  const counts = { folded: 0, flat: 0 };

  page.fields.forEach((field) => {
    const whole = texts[field.key];
    // A key neither catalogue carries reaches here as undefined, and every comparison
    // below would then read a property off it. The census step refuses such a key
    // first, so this is a floor rather than the primary guard - and a floor is what
    // keeps the ORDER of two steps from being the only thing holding a crash back.
    if (typeof whole !== "string") {
      say(
        `${field.key} is named by a page and carried by no catalogue, so there is no text for the fold to hold`,
      );
      return;
    }
    const lead = expectedLead(whole);

    if (field.body.textContent !== whole) {
      say(
        `${field.key} shows ${field.body.textContent.length} character(s) behind the fold and its text has ${whole.length}: a help text was cut rather than moved`,
      );
    }

    const summaryEl = field.details.querySelector("summary");
    if (!summaryEl || summaryEl.textContent !== summary) {
      say(
        `${field.key} names its fold ${JSON.stringify(summaryEl ? summaryEl.textContent : null)} and the catalogue says ${JSON.stringify(summary)}`,
      );
    }

    if (lead === null) {
      counts.flat += 1;
      if (field.lead.textContent !== whole) {
        say(
          `${field.key} holds one sentence and the line under the field is ${JSON.stringify(field.lead.textContent)} rather than that sentence`,
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
  // GUARDED IN THE MESSAGE AS WELL AS IN THE CONDITION, which is where the first
  // attempt at this stopped: the condition admitted an absent heading and the message
  // then read a property off it, so the refusal it was meant to produce was still a
  // stack trace. The same applies to the card's text holder, read above.
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

    // AND FOCUS LEAVING THE CONTAINER ALTOGETHER, which is the half `focusin`
    // cannot see: it never fires for a target outside the container, so a card
    // cleared only on focusin keeps the last field's text for as long as the view
    // lives. The review of 2026-09-12 named it; this is the arm that holds it.
    page.root.fire("focusin", page.fields[0].input);
    page.root.fire("focusout", page.fields[0].input, page.wrapper);
    if (!card.hidden) {
      refusals.push(
        "focus leaving the container left the last field's text standing in the rail with nothing focused at all",
      );
    }

    // AND THE OTHER DIRECTION, which the fix for the line above can overshoot into. A
    // blur with NO destination - a mousedown on the card itself, which is a plain div
    // with a scrollbar for exactly these long texts, or a window losing focus - must
    // NOT clear: the card would vanish under the click that was about to scroll it.
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

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

function read(file) {
  return fs.readFileSync(file, "utf8");
}

function catalogue(name) {
  return JSON.parse(read(path.join(LOCALIZATION, `${name}.json`)));
}

// The pages this slice moved, read from the tree: a page is in scope because it
// carries the opt-in attribute, never because it is named here.
function markedPages() {
  return fs
    .readdirSync(WEB)
    .filter((name) => name.endsWith(".html"))
    .filter((name) => read(path.join(WEB, name)).includes(CONDENSE_ROOT))
    .sort();
}

async function loadApplier() {
  const source = read(path.join(WEB, "i18n.js"));
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64");
  return import(url);
}

// Applies one catalogue to one built page. `loadCatalog` always resolves - a
// failed fetch leaves the catalogue empty and the built-in English standing - so
// `applyTo` runs either way, which is the degraded path this drives rather than
// assumes.
async function render(i18n, page, values) {
  globalThis.fetch = () =>
    values === null
      ? Promise.reject(new Error("no network in this gate"))
      : Promise.resolve({ ok: true, json: () => Promise.resolve(values) });
  await i18n.loadCatalog();
  i18n.applyTo(page.wrapper);
}

function fixtureTexts(values) {
  return values.reduce((all, value, index) => {
    all[`config.fixture_${index}_help`] = value;
    return all;
  }, {});
}

/*
 * Leads written out BY HAND, one row per way this rule is known to break, and the
 * only arm in this file whose answer does not come from the rule it judges. `null`
 * means "one sentence": nothing behind the fold, so the whole text is the line
 * under the field.
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
  // The one the review found: an abbreviation with a bracket glued to its front.
  [
    "Space-separated values (e.g. acr-1) may be sent. The rest follows.",
    "Space-separated values (e.g. acr-1) may be sent.",
  ],
  // And the other direction: a dotted IDENTIFIER is not an abbreviation, and a
  // guard wide enough to cover the row above must still split this one.
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
  // `\w` is ASCII and this catalogue is not: with it, the tail of "Das heißt" is
  // "t", one word character, an abbreviation by the rule - and the text went unsplit.
  ["Das heißt. Mehr steht dahinter.", "Das heißt."],
  ["Es zählt die Größe. Mehr steht dahinter.", "Es zählt die Größe."],
  // A tail that stops at the first non-letter is what keeps these two splitting: an
  // empty tail is no abbreviation, and both a hyphenated value and a version number
  // end on a digit.
  ["Sende acr-1. Der Rest folgt.", "Sende acr-1."],
  ["Nutze SAML 2.0. Der Rest folgt.", "Nutze SAML 2.0."],
  // A sentence ending on a bracket rather than on a word, which is what pins the
  // empty tail from the other side: widen INITIALS to accept one and this row breaks.
  [
    "Nie enthalten (auch keine Geheimnisse). Der Rest folgt.",
    "Nie enthalten (auch keine Geheimnisse).",
  ],
  // A single non-ASCII capital as an initial. This row exists to pin the CHARACTER
  // CLASS of the abbreviation test rather than to settle whether an author meant an
  // initial here: the rule says a lone letter before a dot is an abbreviation, and
  // that has to hold for a letter outside ASCII too. Without this row the ASCII
  // spelling of that test survives every other arm, because the letters-and-dots
  // tail already carries the German cases above on its own.
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

// A page of markup in the shape the applier expects, for the markup reader's own
// arms. Written here rather than taken from a page so a negative can break one
// part of it at a time.
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
      `<div class="fieldDescription" data-i18n="${key}"${p.declared ? " " + FLAT_MARK : ""}>whatever</div>`,
      `</div>`,
    ].join("\n");
  }

  const card = `<div class="verticalSection sso-help-card" hidden><h2 class="sectionTitle" data-i18n="${SUMMARY_KEY}">Full text</h2><div class="sso-help-card-text"></div></div>`;
  const block = [
    `<div class="fieldDescription${p.marked ? " sso-help" : ""}"${p.declared ? " " + FLAT_MARK : ""}>`,
    p.comment ? `<!-- a note that mentions a closing </div> tag -->` : "",
    p.lead ? `<span class="sso-help-lead"></span>` : "",
    p.details ? `<details class="sso-help-full">` : "<div>",
    p.summary
      ? `<summary data-i18n="${SUMMARY_KEY}">Full text</summary>`
      : `<summary data-i18n="config.something_else">More</summary>`,
    p.body
      ? `<div class="sso-help-body" data-i18n${p.partsBody ? "-parts" : ""}="${key}">whatever</div>`
      : `<div class="sso-help-body"><span data-i18n="${key}">whatever</span></div>`,
    p.details ? `</details>` : "</div>",
    `</div>`,
  ].join("\n");

  // `scoped: false` is the shape the review of 2026-09-12 killed a whole page's
  // rail with: the card is on the page, one element outside the container the
  // applier walks.
  if (p.scoped === false) {
    return [`<div ${CONDENSE_ROOT}>`, block, `</div>`, card].join("\n");
  }
  return [`<div ${CONDENSE_ROOT}>`, block, p.card ? card : "", `</div>`].join(
    "\n",
  );
}

/*
 * A field container holding `n` condensed help blocks, for the field reader's arms.
 * `voidTag` puts an `<input>` beside them, which is what a real field holds and what
 * unwinds a stack of open tags that does not know which elements never close.
 */
function fieldMarkup(n, opts) {
  const blocks = [];
  for (let i = 0; i < n; i++) {
    blocks.push(
      [
        `<div class="fieldDescription sso-help">`,
        `<span class="sso-help-lead"></span>`,
        `<details class="sso-help-full">`,
        `<summary data-i18n="${SUMMARY_KEY}">Full text</summary>`,
        `<div class="sso-help-body" data-i18n="config.fixture_${i}_help">whatever</div>`,
        `</details>`,
        `</div>`,
      ].join("\n"),
    );
  }
  return [
    `<div ${CONDENSE_ROOT}>`,
    `<div class="inputContainer">`,
    opts && opts.voidTag ? `<input id="x" type="text" />` : "",
    ...blocks,
    `</div>`,
    `</div>`,
  ].join("\n");
}

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
    "a help text written flat and declaring it",
    false,
    inspectMarkup(
      "fixture",
      fixtureMarkup("config.fixture_0_help", { flat: true, declared: true }),
    ).refusals,
  );
  record(
    "a parts-marked body is a key like any other",
    false,
    inspectMarkup(
      "fixture",
      fixtureMarkup("config.fixture_0_help", { partsBody: true }),
    ).refusals,
  );

  // The field reader, which is a different reader over the same bytes.
  record(
    "one condensed block per field container",
    false,
    inspectFields("fixture", fieldMarkup(1)).refusals,
  );
  record(
    "two condensed blocks in one field container",
    true,
    inspectFields("fixture", fieldMarkup(2)).refusals,
  );
  record(
    "an input in the container does not unwind the stack",
    false,
    inspectFields("fixture", fieldMarkup(1, { voidTag: true })).refusals,
  );

  const markupNegatives = [
    ["a help text still written flat", { flat: true }],
    ["a condensed block declaring itself flat", { declared: true }],
    ["a block the applier will not find", { marked: false }],
    ["a fold with no lead line to fill", { lead: false }],
    ["a whole text behind no fold", { details: false }],
    ["a fold named by another key", { summary: false }],
    ["a key that is not on the body of its own fold", { body: false }],
    ["a condensed page with no rail card", { card: false }],
    ["a rail card outside the container the applier walks", { scoped: false }],
  ];
  markupNegatives.forEach(([name, parts]) =>
    record(
      name,
      true,
      inspectMarkup("fixture", fixtureMarkup("config.fixture_0_help", parts))
        .refusals,
    ),
  );

  // --- the hand-written answers, which is the only arm not derived from the rule ---
  for (const [text, expected] of HAND_WRITTEN_LEADS) {
    const texts = fixtureTexts([text]);
    const key = Object.keys(texts)[0];
    const page = buildPage([key], texts, "Full text", {});
    await render(i18n, page, { ...texts, [SUMMARY_KEY]: "Full text" });
    const want = expected === null ? text : expected;
    record(
      `the hand-written lead of ${JSON.stringify(text.slice(0, 34))}`,
      false,
      page.fields[0].lead.textContent === want &&
        page.fields[0].details.hidden === (expected === null)
        ? []
        : [
            `the applier wrote ${JSON.stringify(page.fields[0].lead.textContent)} and the hand-written answer is ${JSON.stringify(want)}, with the fold ${page.fields[0].details.hidden ? "hidden" : "shown"}`,
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
    [
      "a one-sentence text whose line under the field is empty",
      (page) => {
        page.fields[1].lead.textContent = "";
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

  // TWO HELP BLOCKS IN ONE FIELD CONTAINER. No page carries the shape and nothing
  // refuses it, which `i18n.js` says of itself at the map it builds; what this arm
  // holds is that the applier is DETERMINISTIC about it - the first block in
  // document order answers the rail rather than whichever the map happened to keep -
  // so the day the Providers slice produces one, the loss is visible in the order
  // the page is written rather than in the order a Map was built.
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

  // --- two arms about the SCOPE of the rule rather than one page's shape ---
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

  // AND IT IS NOT MARKED AS WIRED, which is a different claim from the one above and
  // the one the applier's guard rests on. The attribute says "this container has a
  // focus listener"; it was set on the line before the card lookup that returns
  // early, so a pass over a container whose card was not there yet marked it wired
  // with nothing attached and every later pass returned at the guard. Nothing held
  // that until this arm: the mutation putting the attribute back above the lookup
  // left the whole calibration green.
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
      // `|| []` rather than a direct read, because a container with NO listener is
      // exactly one of the states this arm has to name. Reading the length off an
      // absent list turned a legible refusal into a stack trace, which is the shape
      // of failure a gate is least useful in.
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
  let declaredFlat = 0;
  for (const page of pages) {
    const markup = read(path.join(WEB, page));
    const authored = inspectMarkup(page, markup);
    const fields = inspectFields(page, markup);
    [...authored.refusals, ...fields.refusals].forEach((message) => {
      console.error(`REFUSED  ${message}`);
      refused += 1;
    });
    if (authored.blocks !== fields.blocks) {
      console.error(
        `REFUSED  ${page}: the string reader finds ${authored.blocks} condensed block(s) and the tag reader finds ${fields.blocks}, so one of them is not seeing the page`,
      );
      refused += 1;
    }

    // Collapsed for the same reason the markup reader collapses, and the floor
    // below is not decoration: reading the file as written yields ZERO keys the
    // moment Prettier wraps the body tag, and a run that counted nothing printed
    // a green line for all three pages. That is the shape this tool exists to
    // refuse, arriving in the tool itself.
    const keys = [
      ...markup
        .replace(/\s+/g, " ")
        .matchAll(new RegExp('class="sso-help-body"[^>]*' + HELP_KEY, "g")),
    ].map((m) => m[1]);
    if (keys.length === 0) {
      console.error(
        `REFUSED  ${page} carries ${CONDENSE_ROOT} and no condensed help text, so the applier is driven over nothing on it`,
      );
      refused += 1;
    }

    // THE TWO READERS ARE MADE TO AGREE ON THE COUNT, which is the arithmetic neither
    // of them does alone. One walks elements and one greps for the body marker, so a
    // block either of them loses - a truncated walk, a body tag spelled differently,
    // a field quietly un-condensed - moves one number and not the other. Without this
    // the run printed a green line over nineteen blocks where there had been twenty.
    // THE WHOLE POPULATION IS TIED TO THE PAGE'S OWN MARKER COUNT, which is the
    // arithmetic the flat half was missing. Both readers above enter a block through
    // its CLASS, so a help text written on a class neither knows is invisible to
    // both: the review of 2026-09-12 renamed one declared-flat field to
    // `sso-field-note`, took its declaration away, and every gate here stayed green
    // because the only trace was a count nothing asserted. This counts every marker
    // on the page, class-agnostic, and requires the two halves to add up to it.
    const markers = [
      ...markup
        .replace(/<!--[sS]*?-->/g, " ")
        .matchAll(new RegExp(HELP_KEY, "g")),
    ].length;
    if (authored.blocks + authored.flat !== markers) {
      console.error(
        `REFUSED  ${page}: ${markers} help marker(s) on the page and ${authored.blocks} condensed plus ${authored.flat} declared flat, so a help text sits on an element neither reader enters`,
      );
      refused += 1;
    }
    if (authored.blocks !== keys.length) {
      console.error(
        `REFUSED  ${page}: the element reader finds ${authored.blocks} condensed block(s) and the marker reader finds ${keys.length}, so one of them is not seeing the page`,
      );
      refused += 1;
    }
    total += keys.length;
    declaredFlat += authored.flat;

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

      const texts = Object.fromEntries(
        keys.map((key) => [
          key,
          values[key] !== undefined ? values[key] : en[key],
        ]),
      );
      const built = buildPage(keys, texts, summary, {});
      await render(i18n, built, { ...texts, [SUMMARY_KEY]: summary });
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
          `${page.padEnd(20)}${String(keys.length).padStart(3)} condensed help text(s), ${runtime.counts.folded} with a fold that holds more, ${runtime.counts.flat} whose text is one sentence, ${authored.flat} left flat by declaration`,
        );
      }
    }
  }

  console.log(
    `the marked pages:   ${total} condensed help text(s) and ${declaredFlat} left flat by declaration, over ${pages.length} page(s), read in en and de`,
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
