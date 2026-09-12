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
 * the catalogue row the folds share, a marked page with no rail card, a fold authored
 * inside a `<p>` - which `<details>` closes, so a browser takes the fold out of the
 * block - and two help blocks resolving to one field, by either branch of the walk the
 * applier makes (#1663). It also closes the COUNT over the page: every `*_help` marker
 * is either a condensed block or a site that DECLARES itself flat with a reason, so a
 * help text on a class neither reader enters is refused rather than dropped from both
 * populations in silence (#1677). The
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
 * WHAT WAS MEASURED WHERE THIS TOOL CANNOT LOOK (#1672): Chromium 152's accessibility
 * tree, read on 2026-09-12 over the shipped Providers page with the shipped applier
 * run on it. A field whose `aria-describedby` names its whole block is described by
 * the lead line and the word "Full text" while the fold is closed, and by nothing at
 * all when the reference names the body inside the closed fold; a hidden element
 * named directly carries the whole text; and every fold's summary is a disclosure
 * triangle named by the one catalogue word, 111 rows alike. The applier answers both
 * with `nameFold` and `speak`, and the arms below hold the ATTRIBUTES that computation
 * reads, because the stub computes no accessible name. What a screen reader then
 * says is still measured by nothing in this tree.
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
 * IT IS A STRING READER AND NOT A PARSER, WHICH IS A SEPARATE BOUND FROM THAT ONE AND
 * COST TWO LIVE BLOCKS (#1663). Both readers here walk the tags as AUTHORED; a browser
 * walks them as PARSED, and the two differ wherever HTML implies an end tag. Two folds
 * authored inside a `<p>` therefore read as whole to every line of this file while a
 * browser lifted them out of their blocks and left the lead line unfillable for good.
 * The `<p>` case is refused by name now, and the class is not closed: any other implied
 * end tag would pass exactly the same way.
 *
 * ONE HALF OF THE PAGE WAS JUDGED BY THE MARKUP READER ALONE UNTIL #1669, AND THIS
 * PARAGRAPH SAID SO. A help text whose body is marked `data-i18n-parts` holds a
 * catalogue value with `{n}` slots the pass fills from the body's own children, so the
 * sentence a reader sees is assembled on the page and the raw value is not it. The
 * built page had no such children, so those keys were kept out of the runtime half
 * rather than judged against a lead holding `{0}` - and the defect that closed that
 * gap lived exactly there: the one-sentence rule wrote the body's TEXT into the lead,
 * which flattens the children of a body that is a sentence built around them, and
 * every arm here passed. The built page carries those children now, read off the
 * shipped markup by `directChildren` and `childText` below, so the applier is DRIVEN
 * over both shapes.
 *
 * WHAT THAT COSTS IS A THIRD READER, AND IT IS CIRCULAR UNLESS SOMETHING PINS IT. The
 * same reading builds the fixture's children and the text the fixture is judged
 * against, so a mis-read child agrees with itself. The hand-written child and assembly
 * tables in the calibration are what break that circle, in the same way and for the
 * same reason as the hand-written leads beside them. A body whose children that reader
 * cannot walk - a child holding its own elements, a character reference it does not
 * know - stays OUT of the driven set and the run prints how many, so a page moving out
 * of its reach is visible rather than silently dropped from the population.
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
    this.detach(node);
    node.parentNode = this;
    this.nodes.push(node);
    return node;
  }

  // The node is taken out of wherever it currently sits FIRST, which is the half a
  // stub is easiest to get wrong: a DOM move is a removal and an insertion, and a
  // stub that only inserts leaves the node in two parent lists at once. The applier
  // moves a one-sentence body between the block and the fold and back (#1669), so a
  // stub without this would show the body in both places and every arm judging
  // "where is it now" would pass whatever the applier did.
  detach(node) {
    const from = node.parentNode;
    if (from) {
      from.nodes = from.nodes.filter((other) => other !== node);
    }
    node.parentNode = null;
  }

  // A REFERENCE NODE THAT IS NOT A CHILD THROWS, which is what the DOM does and is the
  // half a lenient stub hides: appending instead would let a block whose fold is not a
  // direct child pass every arm here while a browser aborted the whole condensing pass
  // on it. `null` means "at the end", which is the DOM's own spelling.
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
    // The nodes being dropped lose their parent, which is what a browser does and what
    // an arm asking "is the body still in the tree" rests on: a stub that only emptied
    // the list would leave a detached body still claiming this element as its parent.
    this.nodes.forEach((node) => {
      node.parentNode = null;
    });
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
const HELP_BLOCK =
  /<(?<tag>[a-z][a-z0-9]*)\b(?<attrs>[^>]*\bclass="[^"]*\bfieldDescription\b[^"]*"[^>]*)>/g;

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
 * How many elements are still open at `at` inside `inner` - zero when whatever starts
 * there is a direct child of the element `inner` is the body of.
 *
 * A SELF-CLOSING TAG IS DEPTH-NEUTRAL AND A VOID NAME IS NOT READ, which is the bound to
 * know rather than a simplification. These pages write every void element with its slash -
 * nineteen `<br />` on the Providers page and every `<input>` closed the same way - because
 * Prettier formats this markup and the `prettier` gate runs on every change, so `<br>` with
 * no slash cannot land. A name list instead would have to be right about every void element
 * these pages use, and the direction it fails in is silent: an `<input>` counted as an
 * element that opens makes every tag after it read as nested inside it, and this reader
 * would then refuse honest markup. One was written here first and deleted, because the
 * proof run showed every branch of it could go with the gate staying green - no block on
 * any of the four pages authors a void element before its fold today, so nothing drove it.
 * The arm below does drive the self-closing branch.
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

/*
 * Refuses the markup half, page by page: what a reader of a page whose script
 * never arrived is left with.
 */
function inspectMarkup(page, source) {
  let flat = 0;
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
    blocks += 1;
    at.push({ index: match.index, key: keys[0] });

    const key = keys[0];

    // A BLOCK AUTHORED IN A `<p>` IS REFUSED, AND THIS READER FOUND IT ONLY AFTER A
    // PARSER DID (#1663). `<details>` is on the HTML spec's list of elements whose
    // start tag closes an open `<p>`, so a browser RE-PARENTS the fold out of the
    // block and leaves the lead span alone inside a `<p>` that ends before it. The
    // applier then finds a `.sso-help` with no `.sso-help-body`, returns at its own
    // guard, and the lead stays empty for good - which the stylesheet hides, so the
    // field shows a bare "Full text" triangle and nothing else. The rail handler is
    // worse: it reads `.sso-help-body` off that block without a guard and throws.
    //
    // NEITHER READER HERE COULD SEE IT AND THAT IS THE POINT. This one walks the
    // SOURCE nesting with a depth counter over the authored tags, so the block reads
    // as whole; the runtime one drives a tree this file BUILDS, where the element is
    // whatever `buildPage` chose. Two green readers over two structurally dead blocks
    // is exactly the "green for the wrong reason" the header says this file exists to
    // refuse, and the repair is a property rather than a fixed page.
    //
    // ONLY `p`, because that is the rule HTML actually has: an implied end tag before
    // `<details>`. A longer list of tags would be a guess, and a guess that refuses
    // honest markup is worse here than one that misses.
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
      // THE FOLD IS A DIRECT CHILD OF ITS BLOCK, WHICH THE APPLIER RELIES ON AND NOTHING
      // REFUSED UNTIL NOW (#1684). `refresh` in SSO-Auth/Web/i18n.js finds the fold with a
      // querySelector over the WHOLE block, so it finds one at any depth, and then promotes
      // a one-sentence body with `help.insertBefore(body, details)` - which needs the fold
      // to be that element's own child. Every one of these blocks authors it that way and
      // the applier carries a fallback for the other shape, so this is not a crash waiting
      // to happen; it is a layout edit that silently changes where a help body ends up,
      // after the fold rather than in front of it, and takes it out of the stylesheet rule
      // that gives a promoted body the lead's spacing.
      //
      // READ FROM THE SAME WALK AS EVERY OTHER REFUSAL HERE, over the authored source with
      // its comments stripped, because the runtime reader next door cannot see it at all:
      // that one drives a tree `buildPage` builds, where the fold is a direct child by
      // construction. Two green readers over a shape neither of them authors is the "green
      // for the wrong reason" this file exists to refuse.
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

  // A FIELD DESCRIBED BY ITS WHOLE BLOCK (#1672). Measured in Chromium's accessibility
  // tree over the shipped Providers page: `aria-describedby` is computed from what the
  // named element RENDERS, and a closed fold renders its summary and nothing behind it,
  // so the description a screen reader is handed is the lead line and the word "Full
  // text" - and empty when the reference names the body inside the closed fold. The
  // shape a description can be computed from is the block's spoken copy, a hidden span
  // the applier fills from the body; so a reference to a block is refused by name and
  // a copy nothing names is refused as dead weight, both here where the page is
  // authored, because the runtime reader drives a fixture whose references are right
  // by construction.
  const described = new Set(
    [...markup.matchAll(/aria-describedby="([^"]*)"/g)].flatMap((m) =>
      m[1].split(/\s+/).filter(Boolean),
    ),
  );
  // THE BLOCK'S EXTENT AND NOT ONLY ITS OPENING TAG, because the review of 2026-09-12
  // drove a reference to the body inside the fold past a reader that knew the block by
  // its class alone - which is the EMPTY case, worse than the one it refused - and a
  // spoken copy authored one element outside its block, which `speak` looks for inside
  // the block and never fills.
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
    // The ATTRIBUTE, read with every quoted value blanked first, so a class token spelled
    // `hidden` does not pass for it.
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
    // INSIDE THE CARD, not anywhere on the page. This was a page-wide test, which is
    // the reading the placement refusal above exists against: moving the heading out
    // of the card and leaving it standing elsewhere on the page passed, and the card
    // shipped headless in the rail.
    const inCard =
      card < 0
        ? ""
        : elementBody(markup, markup.indexOf(">", card) + 1, "div") || "";
    // ANY HEADING LEVEL, AND THE LEVEL IS THE PAGE'S QUESTION RATHER THAN THIS ONE'S.
    // `<h2` was the only spelling until the review of 2026-09-12, which is a constraint
    // nobody argued for: what this refusal is about is that the card is HEADED by the
    // row the folds share, so one page's card cannot be renamed without the others.
    // The level belongs beside the headings the page already has - the Providers rail
    // carries an h3 readiness card, so an h2 help card beside it is a heading-order
    // defect a screen reader meets and the refusal was creating.
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

    // TWO HELP BLOCKS IN ONE FIELD (#1663). The applier keeps the FIRST in document
    // order and the second is then unreachable from the rail card - focus anywhere in
    // that field shows the first block's text, whichever control the reader is in. The
    // fold and the sentence under the field are unaffected, so nothing on the page
    // looks wrong; the card just answers with the wrong text, which is the failure a
    // reader is least able to name.
    //
    // WHY IT IS REFUSED ON THIS PAGE AND NOT ON THE THREE BEFORE IT. No page carried
    // the shape when slice 1 landed, counted over its twenty blocks, and the applier
    // says so at the choice it makes rather than leaving it to be discovered. The
    // Providers page is where it can first arise: 112 sites in 98 keys over two
    // protocol forms, fourteen keys standing twice. It does not carry the shape today
    // either - this refusal is green on the tree it lands with, and its bite is the
    // negative arm below rather than a page it currently catches.
    forEachSharedField(markup, at, (first, second) =>
      refusals.push(
        `${first} and ${second} on ${page} are two help blocks in one field: the rail card answers for ${first} wherever the focus lands in it, and ${second} is unreachable from it`,
      ),
    );

    // HOW MANY FOLDS A BROWSER NAMES AFTER THEIR FIELD (#1672), read the way the applier
    // decides it: a block under a field container that carries a label. The rest keep
    // the catalogue word, on purpose, and the run prints both so the split is a number
    // rather than a sentence.
    named = resolveFields(markup, at).filter((each) => each.labelled).length;

    // THE COUNT IS CLOSED, CLASS-AGNOSTIC (#1677). Everything above enters a help text
    // through its CLASS - `fieldDescription` for a block, `sso-help` for a condensed one
    // - so a `*_help` marker written on a class neither reader knows is in NEITHER
    // population, and the census next door does not care how a site is authored. A field
    // taken out of the condensing by renaming its class would leave no trace anywhere but
    // in a number nothing asserts.
    //
    // So the markers are counted from the attribute alone and the page has to add up:
    // every one is either a condensed block or a site that DECLARES itself flat, with the
    // reason at the site. The tree carries exactly one declaration today and it is a
    // warning rather than a field description - folding a warning hides the thing it
    // exists to put in front of a reader - which is why the answer is a declaration and
    // not an exemption by class name: the next one has to say why too.
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

// Elements a browser closes without a closing tag; they never contain a help block
// and would otherwise be pushed onto the stack below and swallow the rest of a page.
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

/*
 * Every element on the page as a span, innermost last for any given point.
 *
 * ONE STACK PASS rather than a walk per candidate: the reader below needs the field
 * of every block and the fallback field is the block's PARENT, which is a question
 * about every element rather than about a named few.
 */
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
      // An unbalanced close is dropped rather than allowed to unwind the stack past
      // the element it does not belong to: this reader is not a parser, and guessing
      // at broken markup is how it would start refusing pages for the wrong reason.
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
 * Calls back once per pair of condensed blocks that the applier would resolve to ONE
 * field, naming the key it keeps and the key it drops.
 *
 * THE FIELD IS DECIDED THE WAY THE APPLIER DECIDES IT, BOTH HALVES OF IT. `fieldOf`
 * in SSO-Auth/Web/i18n.js walks up from the block to the nearest `inputContainer` or
 * `checkboxContainer`, and where there is none it takes the block's own PARENT. This
 * read only the first half until the review of 2026-09-12, which is worse than a gap
 * because the note in i18n.js claimed the whole of it: ten of the Providers page's
 * blocks sit in neither container - the empty states, the collapse contents, the
 * subgroups, the danger zone, the test block - and two help texts added to any of
 * them would share a field, lose one of the two to the rail, and be refused by
 * nothing while a comment said otherwise. The refuted claim and the missing half are
 * repaired in the same change.
 *
 * A PARENT IS THE INNERMOST SPAN THAT IS NOT THE BLOCK ITSELF, which is why the
 * spans are taken over every element rather than over the two class names.
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
 * Where each block sits, both halves of the applier's walk: the innermost field
 * container holding it, and the innermost element of any kind. `labelled` says whether
 * that container carries a label, which is what `nameFold` in i18n.js names the fold
 * after (#1672); a block under no container is never named, whatever labels its parent
 * happens to hold.
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
    // INNERMOST WINS in both halves: a container nested in another is the one the
    // applier stops at first on its way up, and the parent is the innermost element
    // of any kind. Picking an outer one would collapse a whole section into one field
    // and refuse a page nothing is wrong with.
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
      // A label FOR a control, or one wrapped around an input with an id: the two shapes
      // `nameFold` derives its ids from. A bare `<label>` is not enough to be counted.
      labelled:
        field !== null &&
        /<label\b[^>]*\sfor="[^"]+"|<label\b(?:(?!<\/label>)[\s\S])*<input\b[^>]*\sid="/.test(
          markup.slice(field.from, field.to),
        ),
    };
  });
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
 * The DIRECT child elements of a body, as `{ tag, attrs, inner }`, or null where this
 * reader cannot walk them.
 *
 * NULL RATHER THAN A BEST EFFORT, and the null is what keeps the count honest. A body
 * whose children this cannot read stays outside the driven population and is printed as
 * such; a body it reads WRONG would be judged against a sentence nobody wrote.
 *
 * BUILT ON `elementBody` RATHER THAN ON A SECOND DEPTH COUNTER. The first spelling of
 * this counted every tag name in one counter where `elementBody` counts tags of the
 * same name, so the two walkers disagreed on mismatched nesting while a comment here
 * claimed they were the same reader. One walker cannot disagree with itself, and it
 * carries the bound that walker already has: a page whose nesting relies on an implied
 * end tag reads as something a browser would not build.
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
 * What one such child's text WILL be when the pass reaches the parts body, or null where
 * this reader cannot say.
 *
 * THE ORDER THE APPLIER RUNS IN IS THE WHOLE OF THIS. `applyTo` writes every
 * `data-i18n` element first and assembles the parts sentences afterwards, so a child
 * carrying a key holds the CATALOGUE's text by then and not the page's - which is why a
 * marked child is read out of the catalogue rather than out of the markup. An unmarked
 * child keeps whatever the page authored, so its own tags would have to be resolved the
 * same way, one level further down; that is refused instead, and so is an entity, whose
 * decoding this reader does not do.
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

// The named references a help body may hold. THE SET IS A FLOOR AND NOT AN INVENTORY:
// the parts bodies carry two of these today, `&lt;` and `&gt;`, in the `<code>` samples
// that write a URL template or a JSON snippet, and the others are here because the same
// samples reach for them rather than because anything writes them now. A reference
// OUTSIDE the set - `&mdash;`, which these pages do author elsewhere - takes its body
// out of the driven set and into the count the run prints, which is the fail-closed
// direction. `&amp;` is decoded LAST so `&amp;lt;` comes out as the four characters
// somebody wrote and not as a `<`.
const NAMED = {
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&apos;": "'",
  "&#39;": "'",
};

function decodeText(text) {
  const out = text.replace(
    /&(?:lt|gt|quot|apos|#39);/g,
    (found) => NAMED[found],
  );
  return /&(?!amp;)/.test(out) ? null : out.replace(/&amp;/g, "&");
}

/*
 * The text a parts value comes to after the pass fills its slots: `{n}` stands for the
 * nth child element of the body, so what a reader sees is the value with each slot
 * replaced by that child's own text. Null where the value does not describe the body -
 * a slot out of range, a slot named twice, a child no slot names - which is the case
 * the pass REFUSES, leaving the authored English standing.
 *
 * THE SAME RULE WRITTEN A SECOND TIME, exactly as `expectedLead` above is, and with the
 * same bound: it catches the pass failing to apply the rule and it cannot catch the
 * rule being wrong, because it would be wrong here in the same place. What holds that
 * half for the sentence rule is the hand-written table; what holds it here is that the
 * children the arms below hand in are elements, so a pass that flattened them would
 * produce the same TEXT and a different TREE, and the tree is what is refused.
 */
function assemble(value, children) {
  // A CHILD NOBODY COULD RESOLVE IS NULL, AND IT MUST NOT BE CONCATENATED. `"a " + null`
  // is the string `"a null"`, which would be written into the fixture and into the text
  // the fixture is judged against at once - green over a sentence nobody wrote, which is
  // the one failure this whole reader exists to avoid.
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
  const fields = keys.map((key, index) => {
    const container = new El("div");
    container.className = "inputContainer";
    // A LABEL FOR THE CONTROL, as the pages author one per field (#1672): the fold is
    // named after it, so the fixture carries the thing the name is derived from.
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
    // A BODY ASSEMBLED FROM PARTS IS A DIFFERENT SHAPE AND IS BUILT AS ONE (#1669). Its
    // marker is the parts spelling, its content is child ELEMENTS rather than one text
    // node, and the catalogue value handed to the pass holds `{n}` slots naming them -
    // so the text the reader ends up with is assembled on the page and is not the raw
    // value. Without this the only thing that could be driven was the plain shape, and
    // the rule's behaviour on the other one was asserted in a comment instead.
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

    // A SPOKEN COPY where the arm asks for one (#1672), named by the field's
    // aria-describedby in place of the block: the one shape a description can be
    // computed from with the fold closed.
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
 * Refuses the runtime half: `texts` is what each key's text OUGHT to be after the
 * pass - the catalogue value where the catalogue carries the key, the built-in
 * English where it does not - so "the fold lost a sentence" and "the fold is
 * showing the wrong language" are both refusable rather than only the first.
 */
function inspect(page, texts, summary) {
  const refusals = [];
  const say = (message) => refusals.push(message);
  const counts = { folded: 0, flat: 0, flatParts: 0, named: 0 };

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
        `${field.key} holds ${field.body.textContent.length} character(s) in its help body and its text has ${whole.length}: a help text was cut rather than moved`,
      );
    }

    // THE TREE AND NOT ONLY THE TEXT, for a body whose sentence is assembled around
    // child elements (#1669). Flattening those children into one text node keeps every
    // character and loses every `<code>`, `<strong>` and link in the sentence, so a
    // comparison of text alone passes a defect whose whole content is the markup. It
    // also refuses the other direction, which the repair this issue rejected would have
    // produced: moving the children somewhere else empties the body that the NEXT
    // catalogue pass reassembles from, and the count goes to zero.
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

    // THE FOLD IS NAMED AFTER ITS FIELD (#1672): the summary's aria-labelledby names the
    // field's label and then the summary itself, by ids the applier writes. Measured in
    // Chromium's accessibility tree, a summary without it is a disclosure triangle named
    // by the catalogue word alone, the same as every other fold on the page.
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

    // AND THE SPOKEN COPY, WHERE THE FIELD HAS ONE, HOLDS THE WHOLE TEXT AND STAYS HIDDEN.
    // It is what the field's aria-describedby hands a screen reader, so a copy short of
    // the text describes the field with less than the fold holds, and one that is shown
    // puts the text on the page twice.
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

    // THE ONE-SENTENCE STATE IS A PLACE RATHER THAN A COPY (#1669). The body itself is
    // the line under the field: the applier moves it out of the fold and in front of
    // it, so a sentence assembled around child elements arrives with them instead of
    // being flattened into the lead's text. So what is refused here is the body's
    // PARENT, the empty lead beside it and the hidden fold - three states that fail
    // differently. A body left inside a hidden fold shows the field NOTHING, which is
    // the worst of the three and the one a partial repair produces. The parent and not
    // the index: a body appended after the hidden fold rather than before it draws the
    // same page, so the two orders are not separated here.
    if (lead === null) {
      counts.flat += 1;
      // THE POPULATION #1669 IS ABOUT, COUNTED WHERE THE PAGE IS READ rather than by a
      // walk somebody runs once. It is the parts-marked bodies that come out holding ONE
      // sentence after their own children are substituted, which is the only shape the
      // flattening defect could reach, and it moves with every catalogue edit - a
      // translator adding a second sentence in German takes a row out of it. Derived from
      // the hand-written lead rule above and never from where the applier put the body,
      // so a regression shrinks the figure instead of being counted as a pass.
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
      `<div class="fieldDescription" data-i18n${p.assembled ? "-parts" : ""}="${key}">whatever</div>`,
      `</div>`,
    ].join("\n");
  }

  // `heading: false` leaves the card headless. It is a negative of its own because the
  // heading refusal had none until the review of 2026-09-12 - it was written, never
  // driven, and then widened from `<h2` to any level by that review, which is exactly
  // when an undriven refusal stops being trustworthy.
  const heading =
    p.heading === false
      ? ""
      : `<h2 class="sectionTitle" data-i18n="${SUMMARY_KEY}">Full text</h2>`;
  const card = `<div class="verticalSection sso-help-card" hidden>${heading}<div class="sso-help-card-text"></div></div>`;
  // The element the block is authored in. `div` everywhere but the one negative that
  // asks for `p`, which is the tag a browser will not keep a `<details>` inside.
  const tag = p.tag || "div";
  const block = [
    `<${tag} class="fieldDescription${p.marked ? " sso-help" : ""}"${p.described ? ' id="fixture-help"' : ""}>`,
    p.comment ? `<!-- a note that mentions a closing </div> tag -->` : "",
    p.lead ? `<span class="sso-help-lead"></span>` : "",
    // `selfClosed` puts the one kind of tag that must NOT move the depth count before the
    // fold: a void element with its slash, which is how these pages author all of them.
    // Without this arm the self-closing branch of `depthAt` is driven by nothing, because
    // no block on any of the four pages carries such a tag before its fold today.
    p.selfClosed ? `<br />` : "",
    // `wrapped` puts the fold inside a layout element, which is the edit somebody makes
    // while rearranging a form and the shape #1684 is about. It is a near-miss of one
    // opening tag and one closing tag, and nothing else about the block moves.
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

  // `scoped: false` is the shape the review of 2026-09-12 killed a whole page's
  // rail with: the card is on the page, one element outside the container the
  // applier walks.
  if (p.scoped === false) {
    return [`<div ${CONDENSE_ROOT}>`, block, `</div>`, card].join("\n");
  }

  // A second `*_help` marker on a class neither reader enters (#1677). `stray` leaves it
  // undeclared, which the closure refuses; `flat` declares it with a reason, which it
  // accepts. The two differ by one attribute, which is the whole near-miss: renaming a
  // field's class to take it out of the condensing produces the first, and a warning that
  // was never a field description produces the second.
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
 * Two condensed blocks, in two field containers or in one (#1663).
 *
 * THE NEAR-MISS IS THE POINT AND IT IS ONE CLOSING TAG. `shared: false` is the shape
 * every page already has - a block per field - and `shared: true` is that page with
 * one `</div>` moved, which is exactly the edit somebody makes while rearranging a
 * form. The refusal has to separate those two and nothing else.
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
  // `wrapper` is the class the two blocks share. `inputContainer` is the branch
  // `fieldOf` walks up to; anything else is the PARENT branch, which is the half the
  // review of 2026-09-12 found unread and which ten of the Providers page's blocks
  // sit in.
  const wrapper = shared === "parent" ? "sso-test-block" : "inputContainer";
  const fields =
    shared === false
      ? `<div class="inputContainer">${block(key)}</div><div class="inputContainer">${block(other)}</div>`
      : `<div class="${wrapper}">${block(key)}${block(other)}</div>`;
  return [`<div ${CONDENSE_ROOT}>`, fields, card, `</div>`].join("\n");
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
   *
   * WITHOUT THIS THE REAL-PAGE HALF IS GREEN FOR THE WRONG REASON. The children a
   * parts body on a page carries are read off the markup by `directChildren` and
   * `childText`, and the SAME reading builds both the fixture's children and the text
   * the fixture is judged against - so a reader that mis-reads a child agrees with
   * itself and every arm downstream passes. What breaks that circle is an answer
   * written by hand, which is the same device the lead table below is, for the same
   * reason.
   *
   * The catalogue row is the one a marked child resolves through, because the pass
   * writes those children before it assembles the sentence around them.
   */
  const CHILD_CATALOGUE = { "config.fixture_child": "the setting's name" };
  const CHILD_ROWS = [
    // A plain sample, an entity inside one, and a void element with no text at all.
    [
      "<code>/sso/OID/p/&lt;name&gt;</code> then <br /> then <code>a &amp; b</code>",
      ["/sso/OID/p/<name>", "", "a & b"],
    ],
    // A marked child holds the CATALOGUE's text by the time the sentence is
    // assembled, never the page's.
    [
      '<strong data-i18n="config.fixture_child">Whatever the page says</strong>',
      ["the setting's name"],
    ],
    // A child of a child: one level further down, which this reader does not resolve.
    ["<span>a <code>nested</code> sample</span>", null],
    // A marked child whose key neither catalogue carries: its text is the page's own
    // English, which this reader has no way to know, so the body leaves the driven set.
    ['<strong data-i18n="config.no_such_key">Whatever</strong>', null],
    // A reference it does not know, which a browser would decode and it would not.
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

  // And the assembly around them, hand-written the same way: a value may reorder its
  // slots, and one that does not name each child exactly once describes a different
  // element and is refused rather than half-applied.
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
    // A ONE-SENTENCE ANSWER IS READ OFF THE BODY AND A SPLIT ONE OFF THE LEAD (#1669),
    // and the row pins WHICH element as well as what it says. `null` here means the
    // whole text stands under the field, which since that change means the body itself
    // has been moved out of the fold - so the row asks the body for the text AND asks
    // where it now sits. Reading "whatever is outside the fold" instead would have
    // accepted the behaviour this issue replaced, where the lead held the whole text
    // and the body stayed behind a hidden fold.
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
   *
   * Both were measured in a browser's accessibility tree and neither can be measured
   * here: the stub computes no accessible name. What the arms hold is the ATTRIBUTES
   * that computation reads, which the applier writes and which a mutation removes.
   */
  {
    const texts = fixtureTexts([TWO, ONE]);
    const page = buildPage(Object.keys(texts), texts, "Full text", {
      spoken: true,
    });
    await render(i18n, page, { ...texts, [SUMMARY_KEY]: "Full text" });
    // Twice, because the ids are written where they are missing and a second pass has
    // to find them rather than mint a second set.
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

  // A LABEL WRAPPED AROUND ITS CONTROL, which is how every checkbox row is authored:
  // no `for`, the input inside the label, and the id taken from that input.
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

  // A BLOCK IN NO FIELD CONTAINER KEEPS THE BARE WORD: the first label under its parent
  // belongs to some other field, and a fold named after a field it does not open is
  // worse than one named "Full text". The arm holds that the applier does NOT reach
  // for that label; deleting the container test in `nameFold` is what turns it red.
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

  // TWO LABELLED CONTROLS IN ONE CONTAINER, the help under the second: the SAML form's
  // Live TV rows author this once, and the FIRST label named that fold after the field
  // above it (review of 2026-09-12). The label that names a fold is the last one before
  // its block.
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

  // THE HOST'S OWN EMPTY LABEL. jellyfin-web's emby-input, emby-textarea and emby-select
  // insert `<label for=id></label>` with no text directly in front of every control they
  // upgrade, so on a real page an empty label stands between the authored one and the
  // block on every field. The stub has no custom elements, so the label is authored here;
  // the arm also asks that no id was minted on it, because the id it would get is the
  // authored label's, and the same attribute string would then name an empty element.
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
   *
   * UNTIL THIS BLOCK THESE BODIES WERE JUDGED BY THE MARKUP READER ALONE, and the
   * defect that produced the issue is exactly what that leaves open: the one-sentence
   * rule wrote the body's TEXT into the lead, which is right for a body whose content
   * is a catalogue row and flattens the children of one that is a sentence built
   * around them. Every arm here drives the shipped applier over a body with real child
   * elements and asks where the children ended up, not only where the words did.
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

  // The shape that already worked: more than one sentence, so the lead is a plain text
  // slice and the markup stays behind the fold where it always was.
  await partsArm(
    "a parts body holding two sentences is split like any other",
    ["The avatar url takes the form {0}. Leave it blank to keep the default."],
    [AVATAR],
  );

  // The shape the issue is about, and the two things it has to hold at once: the child
  // element is still an ELEMENT, and it is somewhere the reader can see it - outside
  // the fold that is now hidden.
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

  // THE ARM THAT REFUSES THE REPAIR THIS ISSUE REJECTED. Moving the body's children
  // into the lead shows the markup once and empties the body, so the SECOND catalogue
  // finds no children to assemble around and the field goes blank in the other
  // language. Two passes, both one-sentence, is the cheapest way to say so.
  await partsArm(
    "a second catalogue reassembles a one-sentence parts body",
    [
      "The avatar url takes the form {0}",
      "Die Adresse des Avatars hat die Form {0}",
    ],
    [AVATAR],
  );

  // And the move in the other direction: one sentence in English, two in German, so
  // the body has to go back behind the fold that the first pass hid.
  await partsArm(
    "a parts body that gains a sentence in the other language folds again",
    [
      "The avatar url takes the form {0}",
      "Die Adresse hat die Form {0}. Leer lassen behält die Vorgabe.",
    ],
    [AVATAR],
  );

  /*
   * THE FALLBACK REFERENCE NODE IS DRIVEN RATHER THAN ASSERTED. `refresh` reads the fold
   * with a querySelector over the whole block, so it finds one at any depth, and then
   * inserts the promoted body with `help.insertBefore(body, details)` - which requires the
   * fold to be the block's own CHILD. Every page authors it that way, so the arm the
   * applier carries for the other shape was reachable from nothing:
   * `details.parentNode === help ? details : null`. An arm nothing drives cannot be told
   * apart from one that does not work, and deleting it instead was tried and is worse: a
   * browser aborts the whole condensing pass and the rail listener on the throw.
   *
   * So the shape is authored here. The fold goes inside a wrapper, which is the layout
   * change somebody makes without reading this function, and the arm asks for the two
   * things that separate a degradation from a failure: the pass does not throw, and the
   * body ends up somewhere a reader can see it rather than inside the hidden fold. Where
   * it ends up is AFTER the fold rather than before it, which draws the same field because
   * the fold is hidden, and the stylesheet then gives it the fold's spacing rather than
   * the lead's - the one visible cost, and the reason #1684 asks the markup reader to
   * refuse the shape at authoring time instead of leaving the applier to absorb it.
   */
  {
    const key = "config.fixture_0_help";
    const page = buildPage([key], {}, "Full text", {
      parts: { [key]: [{ tag: "code", text: AVATAR }] },
    });
    const field = page.fields[0];
    const wrap = new El("div");
    // ORDER: replaceChildren drops the fold's parent first, so the wrapper adopts a node
    // that belongs to nobody. Appending to the wrapper first would leave the fold in two
    // child lists at once in a stub that did not detach, and this one does - so the order
    // here is the one a browser also takes rather than a habit.
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
   * THE SECOND PASS MOVES NOTHING, which is what the `body.parentNode !== help`
   * guard in the applier buys and what the arms above cannot see: every one of them
   * compares a FINAL tree, and re-inserting a body that is already in place leaves the
   * same tree behind. A DOM move is a removal and an insertion, so a browser blurs
   * anything focused inside the moved node - three of these bodies carry a link - and
   * `refresh` runs again on every catalogue pass. The stub is not a browser and holds no
   * focus, which this file's header says of itself, so the arm counts the MOVES rather
   * than asserting the blur: one on the pass that promotes the body, none on an
   * identical pass after it.
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

  // The negative: the children flattened into one text node, which is the defect
  // itself. Every character is still there, so only the tree can refuse it.
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
    // The two ways the one-sentence state fails since the body is moved rather than
    // copied (#1669), and they are the two repairs the issue rejected, arriving as
    // mutations: the fold keeps the text, so the field shows nothing at all; or the
    // text is copied into the lead beside the body, so the field says it twice.
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
  for (const page of pages) {
    const markup = read(path.join(WEB, page));
    const authored = inspectMarkup(page, markup);
    authored.refusals.forEach((message) => {
      console.error(`REFUSED  ${message}`);
      refused += 1;
    });

    // THE COLLAPSED STRING COMES FROM THE MARKUP READER RATHER THAN BEING PRODUCED
    // AGAIN HERE. Reading the file as written yields ZERO keys the moment Prettier
    // wraps the body tag, and comments have to go first because these pages are heavily
    // commented and a comment mentioning a closing tag reads as one to a walker - both
    // of which that reader already does. The count below refuses the page when the two
    // readers disagree about how many blocks it holds, so they have to be reading the
    // same string; a second copy of the two replacements made that agreement a property
    // of two edits staying in step instead of a property of the code.
    const flatMarkup = authored.markup;
    const bodies = [
      ...flatMarkup.matchAll(
        /<(?<tag>[a-z][a-z0-9]*)\b[^>]*class="sso-help-body" data-i18n(?<parts>-parts)?="(?<key>[a-z0-9_.]+_help)"[^>]*>/g,
      ),
    ].map((m) => {
      if (m.groups.parts === undefined) {
        return { key: m.groups.key, parts: false, children: [] };
      }
      // A BODY THAT NEVER CLOSES IS UNREADABLE AND NOT CHILDLESS. Defaulting the
      // absent body to an empty string read as "no children", put it in the driven
      // set, and produced a refusal blaming the catalogue for naming slots - for a
      // failure of this reader, with the unread count still at zero.
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

    // A PARTS BODY IS DRIVEN TOO, WITH ITS OWN CHILDREN UNDER IT (#1669), and until
    // that issue it was not. Such a body holds a catalogue value with `{n}` slots the
    // pass fills from the body's own child elements, so the text a reader sees is
    // assembled on the page and the raw value is not it; the page this file builds now
    // carries those children, read off the shipped markup, so the applier is driven
    // over the shape it flattened rather than judged on it by the markup reader alone.
    //
    // WHAT IS STILL NOT DRIVEN IS PRINTED RATHER THAN DROPPED. A body whose children
    // this string reader cannot walk, or one holding a child whose own text it cannot
    // resolve in either catalogue, stays out of the driven set and is counted in the
    // line the run prints - so a page moving out of reach of this half is visible
    // instead of silently shrinking the population. Nothing on the pages carries that
    // shape today.
    //
    // AND ONE BOUND THAT IS DISCLOSED RATHER THAN CLOSED. A child's text is read off
    // the COLLAPSED markup, so a child whose text Prettier wrapped across a source line
    // is read here as one space where a browser's `textContent` holds the line break
    // and its indentation. One shipped body is in that state today - the JSON sample in
    // `config.role_claim_object_help` - and both are whitespace, so the sentence splits
    // in the same place and the fixture and its expected text agree by construction. A
    // future wrap whose break landed just after a terminator would move the split in a
    // browser and not here, and nothing in this file would see it.
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

    // THE TWO READERS ARE MADE TO AGREE ON THE COUNT, which is the arithmetic neither
    // of them does alone. One walks elements and one greps for the body marker, so a
    // block either of them loses - a truncated walk, a body tag spelled differently,
    // a field quietly un-condensed - moves one number and not the other. Without this
    // the run printed a green line over nineteen blocks where there had been twenty.
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

      // THE CATALOGUE VALUE AND THE TEXT A READER ENDS UP WITH ARE THE SAME THING FOR A
      // PLAIN BODY AND ARE NOT FOR A PARTS ONE. `catalogue` is what the pass is handed;
      // `texts` is what each body ought to hold afterwards, which for a parts body is
      // that value with every slot filled by its own child. Keeping the two apart is
      // what lets one `inspect` judge both shapes.
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
        // THE CHILD KEEPS ITS OWN TAG. The page writes `code`, `br`, `strong`, `em` and
        // `a`; building every one as a `span` would have made the fixture a shape no
        // page authors, and a `<br>` in particular is a void element whose text is
        // empty for a reason. The three maps are keyed by KEY while a page may carry
        // one key at two sites - fourteen of the Providers page's do - so the last
        // site's children stand for all of them. No duplicated key has differing
        // children today; the day one does, one of the two sites is driven twice.
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
