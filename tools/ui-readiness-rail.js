#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Runs the REAL readiness rail of sso-core.js against the REAL Providers page and
 * refuses each way it can be wrong (#1678).
 *
 * WHY THIS EXISTS AS A RUNNING PROOF AND NOT AS A CONFORMANCE RULE. The rules this
 * repository already has over the rail read its TEXT:
 * ArchitectureConformanceTests.ProviderCheckSurface asks whether the two ids are
 * still declared, whether the list still ships `hidden`, and whether each spec
 * still names its required ids. None of them can ask what the page DOES, and
 * #1664 moved the panel out of the two editors and into one card in the rail - so
 * the rail is the ONLY place readiness appears now. A fault in the one function
 * that decides what it holds removes the signal from the product rather than
 * duplicating it somewhere else, and a page whose list quietly stops being filled
 * looks exactly like a page where every provider is fine.
 *
 * That is the failure shape this file exists for: the rail is confidently wrong or
 * confidently silent, and every text rule over it stays green.
 *
 * WHY IT IS NODE AND NOT A BROWSER OR A DOM LIBRARY. The means check, per the
 * standpoint: node is already carried by this tree - the .NET workflow runs the other
 * gates beside this one with no install - and a DOM library would add a dependency and a
 * lockfile to a repository that has neither. A browser would answer more and is
 * the walk, which is a person's job and is owed on #1664 either way. What the
 * cheap means cannot say is stated below rather than hidden.
 *
 * WHAT THE STUB CAN AND CANNOT SAY, AND THIS BOUND IS THE PART TO READ. The DOM
 * below is a stub: id lookup, one attribute selector, a class list, text nodes, a
 * parent walk for `closest`, and an ANCESTOR CHAIN read out of the page's own
 * markup so an event can bubble along it.
 *
 * THAT CHAIN IS WHY THE ROUTE FROM A KEYSTROKE TO THE REBUILD IS DRIVEN (#1687) and
 * is the newest thing here. initProvidersPage binds `input` and `change` on the two
 * editor ELEMENTS and relies on a field's event reaching them from inside, so until
 * there was a chain, a listener dropped, bound to a element the field's events never
 * reach, or paired with the wrong protocol key passed every arm. The chain is DERIVED
 * rather than declared: each id-bearing element's span is walked out of the markup and
 * its parent is the smallest span that strictly contains it, so a field moved out of
 * its editor moves in this fixture too.
 *
 * WHAT THE CHAIN STILL DOES NOT SAY. It holds id-bearing elements only, which is
 * enough for every listener this module registers and is not a document tree: an
 * element with no id is not in it, and capture-phase order, `stopPropagation` and
 * default actions are not modelled. A listener on an ANCESTOR of the editor is not
 * refused and should not be - an event from a field inside the editor reaches the page
 * too, so a handler there would rebuild the rail in a browser exactly as one on the
 * editor does. What is refused is a listener somewhere the field's event never reaches.
 *
 * It also cannot say anything about layout, about the order a real browser would
 * run two listeners in, or about what a screen reader announces from the list's
 * `role="status"`. What keeps it from being a proof about ITSELF is that the
 * CONTROLS, THE REGIONS AND THE FIELD LABELS are all read out of the shipped
 * providersPage.html, so a control or a label that leaves the page leaves this
 * fixture with it, and that the code under test is the shipped sso-core.js loaded
 * whole, not a copy and not an extract.
 *
 * WHY THE MODULE IS LOADED THROUGH A DATA URL. sso-core.js is an ES module and
 * this tree carries no package.json, so node would read a `.js` file as CommonJS
 * and fail on its `export`. Importing the bytes as a data: URL loads the same
 * source as a module without writing a temporary file beside the tree.
 *
 * THE CALIBRATION RUNS BEFORE THE REAL PAGE IS OPENED, POSITIVE AND NEGATIVE.
 * The reader below decides what the rail ought to hold, and a reader that cannot
 * fail is not a measurement: it would pass a page it had stopped looking at. So it
 * is first handed a hand-built rail that is right, and then one hand-broken rail
 * per refusal it can make - and the run stops on any disagreement instead of
 * opening the real page. The negative is the half that gets skipped and the half
 * that matters: a reader carrying positives only passes its own calibration by
 * accepting everything.
 *
 * EVERY LEG REFUSES BY NAME AND THE PASS IS PRINTED. A proof whose result nobody
 * sees reads exactly like one that never ran.
 */

"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const CORE = path.join(root, "SSO-Auth", "Web", "sso-core.js");
const PROVIDERS_PAGE = path.join(root, "SSO-Auth", "Web", "providersPage.html");

// The two ids the rail is made of, and the two editors whose `hidden` attributes
// decide which protocol it answers for. Spelled here because an arm has to name
// them; that they are the ids the page and the module agree on is what
// ProviderCheckSurface already refuses, and this file asserts it again below
// rather than trusting it.
const INVITATION = "sso-rail-readiness";
const LIST = "sso-rail-readiness-list";
const EDITORS = { oid: "sso-editor", saml: "saml-editor" };

// ---------------------------------------------------------------------------
// The stub. Small on purpose: every member here is one the code under test
// reaches for, and nothing is added for completeness.
// ---------------------------------------------------------------------------

class Classes {
  constructor() {
    this.set = new Set();
  }
  add(...names) {
    names.forEach((name) => this.set.add(name));
  }
  remove(...names) {
    names.forEach((name) => this.set.delete(name));
  }
  contains(name) {
    return this.set.has(name);
  }
}

class Text {
  constructor(data) {
    this.nodeType = 3;
    this.textContent = String(data);
  }
}

class Element {
  constructor(tag, id, type) {
    this.nodeType = 1;
    this.tag = tag;
    this.id = id;
    this.type = type || tag;
    this.value = "";
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.parentNode = null;
    this.nodes = [];
    this.classList = new Classes();
    // Registered by the page's controller and called by `dispatch` below. A Map per
    // element rather than one on the page, because WHICH element a listener sits on is
    // the property #1687 is about.
    this.listeners = new Map();
    // initProvidersPage sets these on controls it wires; they are here so the fixture
    // does not have to guess which. `dataset` carries the one flag the Save gate reads
    // back - a button a managed provider froze - so the gate cannot hand a Save back that
    // something else disabled.
    this.placeholder = "";
    this.title = "";
    this.dataset = {};
  }

  addEventListener(name, handler) {
    if (!this.listeners.has(name)) {
      this.listeners.set(name, []);
    }
    this.listeners.get(name).push(handler);
  }

  removeChild(node) {
    this.nodes = this.nodes.filter((other) => other !== node);
    node.parentNode = null;
    return node;
  }

  remove() {
    if (this.parentNode) {
      this.parentNode.removeChild(this);
    }
  }

  setAttribute(name, value) {
    this[name] = String(value);
  }

  getAttribute(name) {
    return this[name] === undefined ? null : String(this[name]);
  }

  removeAttribute(name) {
    delete this[name];
  }

  hasAttribute(name) {
    return this[name] !== undefined;
  }

  get children() {
    return this.nodes.filter((node) => node instanceof Element);
  }

  append(...nodes) {
    nodes.forEach((node) => this.appendChild(node));
  }

  insertBefore(node) {
    return this.appendChild(node);
  }

  querySelector(selector) {
    return this.ownerPage.querySelector(selector);
  }

  querySelectorAll(selector) {
    return this.ownerPage.querySelectorAll(selector);
  }

  focus() {}

  scrollIntoView() {}

  get childNodes() {
    return [...this.nodes];
  }

  // Concatenated, like a browser: readinessFieldName falls back to the WHOLE
  // label's text for the wrapped-checkbox idiom, where the direct text nodes are
  // empty and the name lives in a child span. A stub returning only its own text
  // would make that idiom return the id and no arm would notice, because the id is
  // also what an unlabelled control returns.
  get textContent() {
    return this.nodes.map((node) => node.textContent).join("");
  }

  set textContent(value) {
    this.nodes = [new Text(value)];
  }

  appendChild(node) {
    node.parentNode = this;
    this.nodes.push(node);
    return node;
  }

  replaceChildren(...nodes) {
    this.nodes.forEach((node) => {
      node.parentNode = null;
    });
    this.nodes = [];
    nodes.forEach((node) => this.appendChild(node));
  }

  // The parent walk, `this` included, matching on the tag alone - which is the one
  // form the code under test uses: `field.closest("label")`.
  closest(selector) {
    for (let at = this; at; at = at.parentNode) {
      if (at.tag === selector) {
        return at;
      }
    }
    return null;
  }
}

/**
 * One page. Its `querySelector` answers the two forms the readiness path uses and
 * REFUSES anything else, so a selector this stub cannot resolve fails the run
 * instead of silently returning null - which the code reads as "the field is not
 * on the page" and reports as an empty required field.
 */
class Page {
  constructor(elements, labels, byClass) {
    this.elements = elements;
    this.byId = new Map(elements.map((el) => [el.id, el]));
    this.labelFor = labels;
    this.byClass = byClass;
    // The page is a class target too: markPageClean takes the dirty marker off it, and a
    // stub without this throws inside the rejection arm rather than judging it.
    this.classList = new Classes();
    this.listeners = new Map();
    // Every element resolves selectors through the page it belongs to, so a lookup made
    // from inside a handler reaches the same fixture the arm built.
    elements.forEach((el) => {
      el.ownerPage = this;
    });
  }

  querySelector(selector) {
    if (selector.startsWith("#")) {
      return this.byId.get(selector.slice(1)) || null;
    }
    const label = /^label\[for="([^"]+)"\]$/.exec(selector);
    if (label) {
      return this.labelFor.get(label[1]) || null;
    }
    // A SINGLE CLASS, RESOLVED OUT OF THE MARKUP like every id here, because the fill path a
    // resolved read reaches asks for one: fillProvisioningTemplate looks its permissions
    // container up by class. Its BOUND is the one this whole stub has - a lookup is
    // page-global rather than scoped to the element it was made on, so where a page carries
    // the same class twice, once per protocol, the first in document order answers both. No
    // arm asserts anything about that container; it is resolved so the fill runs instead of
    // throwing inside a promise, which the unhandled-rejection count would then blame on the
    // page.
    const token = /^\.([a-z][a-z0-9-]*)$/.exec(selector);
    if (token) {
      return this.byClass.get(token[1]) || null;
    }
    throw new Error("the stub does not resolve the selector " + selector);
  }

  // TAG LISTS ONLY, which is the one form reached from here: editableControls asks for
  // "input, select, textarea" on the way to the unsaved-changes baseline that the failed-read
  // arm below takes. Written the same way tools/ui-unsaved-state.js writes it, because the
  // two stubs answer the same question and two different answers to "which controls are on
  // this page" would let one gate pass a page the other refuses.
  querySelectorAll(selector) {
    const tags = selector.split(",").map((part) => part.trim());
    return this.elements.filter((el) => tags.includes(el.tag));
  }

  addEventListener(name, handler) {
    if (!this.listeners.has(name)) {
      this.listeners.set(name, []);
    }
    this.listeners.get(name).push(handler);
  }

  // The page is a node too: the controller appends rows and cards to elements it
  // looked up, and one of those lookups can be the view itself.
  appendChild(node) {
    this.elements.push(node);
    return node;
  }

  append(...nodes) {
    nodes.forEach((node) => this.appendChild(node));
  }

  insertBefore(node) {
    return this.appendChild(node);
  }

  get children() {
    return [];
  }

  /*
   * One event, along the ancestor chain, innermost first.
   *
   * THIS IS THE WHOLE OF #1687 AND ITS WHOLE BOUND. A browser delivers a field's
   * `input` to every ancestor that registered for it, which is why the controller may
   * bind on the EDITOR rather than on 123 controls - so a fixture that called the
   * target's own listeners only would prove the handler and not the binding. The chain
   * walked here is the one `providersFixture` derived from the markup, so a field that
   * is not inside its editor does not reach the editor's listener here either.
   *
   * The capture phase is not modelled and neither is `stopPropagation`: nothing this
   * module registers asks for either, and a stub answering a question nobody poses is
   * a thing to get wrong for free.
   */
  dispatch(type, target) {
    for (let at = target; at; at = at.parentNode) {
      (at.listeners.get(type) || []).forEach((handler) =>
        handler({ type, target, currentTarget: at }),
      );
    }
    (this.listeners.get(type) || []).forEach((handler) =>
      handler({ type, target, currentTarget: this }),
    );
  }
}

// ---------------------------------------------------------------------------
// The fixture, read out of the shipped page.
// ---------------------------------------------------------------------------

/** Replaces every HTML comment with spaces, so a documented control is not a real one. */
function withoutComments(html) {
  return html.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, " "));
}

/** The value of `name="..."` where the name starts an attribute, as ui-mock-fields.js reads it. */
function attr(tag, name) {
  const m = tag.match(new RegExp("(?<![-\\w])" + name + '="([^"]*)"'));
  return m ? m[1] : "";
}

/** Whether the opening tag at `at` carries a bare `hidden` attribute. */
function shipsHidden(html, id) {
  const at = html.indexOf('id="' + id + '"');
  if (at === -1) {
    return false;
  }
  const tag = html.slice(html.lastIndexOf("<", at), html.indexOf(">", at) + 1);
  return tag.split(/[\s>]+/).includes("hidden");
}

/*
 * Where in the markup the element bearing `id` starts and ends.
 *
 * Walked to its own close with a depth counter over tags of the SAME NAME, which is the
 * discipline tools/ui-condensed-help.js uses for the same job - one reading of "where does
 * this element end", not two. A self-closed tag ends at its own bracket and holds nothing,
 * which is what every `<input />` on this page is.
 *
 * Returns null for an element that never closes. That is broken markup and it is not this
 * reader's to refuse: it makes the element an ancestor of nothing, and the arm that asks
 * whether a required field is inside its editor then refuses by name.
 */
function spanOf(html, id) {
  const at = html.indexOf('id="' + id + '"');
  if (at === -1) {
    return null;
  }
  const start = html.lastIndexOf("<", at);
  const name = /^<([a-z][a-z0-9]*)/.exec(html.slice(start, start + 32));
  const open = html.indexOf(">", at);
  if (name === null || open === -1) {
    return null;
  }
  if (html[open - 1] === "/") {
    return [start, open + 1];
  }
  const tags = new RegExp("<(/?)" + name[1] + "\\b[^>]*?(/?)>", "g");
  tags.lastIndex = open + 1;
  let depth = 0;
  let match;
  while ((match = tags.exec(html)) !== null) {
    if (match[2] === "/") {
      continue;
    }
    if (match[1] === "/") {
      if (depth === 0) {
        return [start, match.index + match[0].length];
      }
      depth -= 1;
      continue;
    }
    depth += 1;
  }
  return null;
}

/**
 * The label a field's name is read from, built with the same two shapes the page
 * authors and `readinessFieldName` reads differently:
 *
 *   <label for="X">Name of Thing: <span>*</span></label>   - direct text is the name
 *   <label><input id="X"> <span>Name of Thing</span></label> - the span is the name
 *
 * Both are built from the page's own bytes. Restating the names here would give
 * this fixture a second copy of every label to drift against, which is the defect
 * the code under test avoids by reading the label in the first place.
 */
function labelsOf(html, controls) {
  const labels = new Map();

  // The `for=` idiom. The element is cut out around the attribute rather than
  // matched, because these opening tags run over several lines and a pattern for
  // one is a second thing to get wrong.
  for (const m of html.matchAll(/<label\b[^>]*\bfor="([^"]+)"/g)) {
    const open = html.indexOf(">", m.index);
    const close = html.indexOf("</label", open);
    if (open === -1 || close === -1) {
      continue;
    }
    labels.set(m[1], labelFrom(html.slice(open + 1, close)));
  }

  // The wrapping idiom. Found from the control rather than from the label, because
  // the opening tag carries nothing that names the field.
  for (const control of controls) {
    if (labels.has(control.id) || !control.id) {
      continue;
    }
    const at = html.indexOf('id="' + control.id + '"');
    if (at === -1) {
      continue;
    }
    const open = html.lastIndexOf("<label", at);
    const close = html.indexOf("</label", at);
    if (open === -1 || close === -1 || close < at) {
      continue;
    }
    const label = labelFrom(html.slice(html.indexOf(">", open) + 1, close));
    labels.set(control.id, label);
    // `closest("label")` has to find it, which is the lookup the wrapped idiom
    // rests on: there is no `for=` to follow.
    control.parentNode = label;
  }

  return labels;
}

/**
 * One label element from its inner markup: the text OUTSIDE any child tag becomes
 * direct text nodes, and each child element becomes a child with its own text. The
 * split is the whole point - `readinessFieldName` takes the direct text nodes
 * first and the full text only as a fallback, so a fixture that flattened both
 * into one string would make the two idioms indistinguishable and the fallback
 * unreachable.
 */
function labelFrom(inner) {
  const label = new Element("label", "", "label");
  let at = 0;
  for (const m of inner.matchAll(/<(?<tag>[a-z][a-z0-9]*)\b[^>]*>/g)) {
    if (m.index > at) {
      label.appendChild(new Text(inner.slice(at, m.index)));
    }
    const open = m.index + m[0].length;
    const close = inner.indexOf("</" + m.groups.tag, open);
    const child = new Element(m.groups.tag, "", m.groups.tag);
    child.appendChild(new Text(close === -1 ? "" : inner.slice(open, close)));
    label.appendChild(child);
    at = close === -1 ? inner.length : inner.indexOf(">", close) + 1;
  }
  if (at < inner.length) {
    label.appendChild(new Text(inner.slice(at)));
  }
  return label;
}

/**
 * The Providers page as this stub sees it: every form control it declares, every
 * id it declares as a plain element, and the labels above. The regions the rail
 * writes into are ASSERTED against the markup rather than invented, because a
 * renamed region turns every render into a no-op that a stub building its own
 * regions would report as a pass.
 */
function providersFixture() {
  const html = withoutComments(fs.readFileSync(PROVIDERS_PAGE, "utf8"));
  const declared = [...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]);

  const controls = [
    ...html.matchAll(/<(input|select|textarea)\b[\s\S]*?>/g),
  ].map((m) => new Element(m[1], attr(m[0], "id"), attr(m[0], "type") || m[1]));
  if (controls.length === 0) {
    throw new Error(
      "providersPage.html declares no form control, so this fixture would prove nothing",
    );
  }

  for (const id of [INVITATION, LIST, EDITORS.oid, EDITORS.saml]) {
    if (!declared.includes(id)) {
      throw new Error(
        "providersPage.html declares no #" +
          id +
          ", so the rail would render into nothing",
      );
    }
  }

  const known = new Set(controls.map((control) => control.id));
  const others = declared
    .filter((id) => id && !known.has(id))
    .map((id) => new Element(id === LIST ? "ul" : "div", id, "div"));

  const elements = [...controls, ...others];
  // The markup's own starting state, read off each tag. A fixture that started the
  // editors open, or the list shown, would make an arm refuse for a reason the arm
  // did not set up - and the list shipping `hidden` is load-bearing: it is what a
  // page whose script never ran shows instead of a headed panel with no rows.
  elements.forEach((el) => {
    el.hidden = shipsHidden(html, el.id);
  });
  if (!elements.find((el) => el.id === LIST).hidden) {
    throw new Error(
      "the readiness list does not ship hidden, so a page whose script never ran shows a headed empty panel",
    );
  }

  /*
   * THE ANCESTOR CHAIN, DERIVED (#1687). Each id-bearing element's span is walked out of
   * the markup and its parent is the SMALLEST span that strictly contains it, so the chain
   * is a reading of the page rather than a declaration in this file: move a required field
   * out of its editor and it stops reaching the editor's listener here, exactly as it would
   * in a browser.
   *
   * ID-BEARING ELEMENTS ONLY, and that is the bound. The real tree has a `<div>` or two
   * between a field and its editor; those are not here, so this chain is shorter than the
   * document's and holds the same ORDER. Every listener this module registers is on an
   * element with an id, which is why the shorter chain answers the question.
   */
  // THE LABELS FIRST, BECAUSE THE WRAPPED IDIOM ALREADY CLAIMS A PARENT. labelsOf sets
  // `control.parentNode` to the `<label>` a checkbox is wrapped in, which `closest("label")`
  // needs, and the chain below has to go THROUGH that label rather than over it. Building
  // the labels after the chain overwrote it, and the arm that asks whether each field is
  // inside its editor said so by name for all seven flagged toggles - every one of them a
  // wrapped checkbox.
  const labels = labelsOf(html, controls);

  const spans = new Map();
  elements.forEach((el) => {
    const span = spanOf(html, el.id);
    if (span !== null) {
      spans.set(el, span);
    }
  });
  elements.forEach((el) => {
    const own = spans.get(el);
    if (own === undefined) {
      return;
    }
    let parent = null;
    let width = Infinity;
    spans.forEach((span, other) => {
      if (other === el || span[0] > own[0] || span[1] < own[1]) {
        return;
      }
      if (span[1] - span[0] >= width) {
        return;
      }
      parent = other;
      width = span[1] - span[0];
    });
    // A wrapping label is SPLICED IN rather than replaced, so both readings hold at once:
    // `closest("label")` still finds it and an event still travels from the control to the
    // editor. The label carries no id, so it is in no span and cannot be found any other way.
    const wrapper = el.parentNode;
    if (wrapper !== null && wrapper.tag === "label") {
      wrapper.parentNode = parent;
    } else {
      el.parentNode = parent;
    }
  });

  // One entry per class token, the FIRST element in document order that carries it. Read off
  // each element's own opening tag rather than listed here, so a class that leaves the page
  // leaves this map with it.
  const byClass = new Map();
  elements.forEach((el) => {
    const at = html.indexOf('id="' + el.id + '"');
    if (at === -1) {
      return;
    }
    const tag = html.slice(
      html.lastIndexOf("<", at),
      html.indexOf(">", at) + 1,
    );
    const classes = /class="([^"]*)"/.exec(tag);
    if (classes === null) {
      return;
    }
    classes[1]
      .split(/\s+/)
      .filter(Boolean)
      .forEach((name) => {
        if (!byClass.has(name)) {
          byClass.set(name, el);
        }
      });
  });

  return new Page(elements, labels, byClass);
}

// ---------------------------------------------------------------------------
// The reader. What the rail ought to hold, and every way it can be wrong.
// ---------------------------------------------------------------------------

/** The rows the list currently holds, as the strings appendReadinessRow wrote. */
function rowsOf(page) {
  return page
    .querySelector("#" + LIST)
    .childNodes.map((node) => node.textContent);
}

/**
 * Refuses one rail state against what it OUGHT to be.
 *
 * `expected.open` is the protocol the page is about, or null for neither, and
 * `expected.rows` is one matcher per row IN ORDER: its state word, the row label,
 * and a fragment its detail must contain. Matching a fragment rather than the
 * whole sentence is deliberate - the detail of a row listing field names is built
 * from the page's own labels, and pinning the whole string here would make this
 * reader a second copy of the catalogue.
 *
 * THE EMPTY STATE IS TWO REFUSALS AND NOT ONE, because a headed list with no rows
 * is the failure that reads as an answer: it says a provider answered nothing,
 * which is the opposite of the truth when no provider is open. So a closed rail is
 * refused both for showing the list and for holding rows behind it.
 */
function inspectRail(page, expected) {
  const refusals = [];
  const invitation = page.querySelector("#" + INVITATION);
  const list = page.querySelector("#" + LIST);
  const rows = rowsOf(page);

  if (expected.open === null) {
    if (invitation.hidden) {
      refusals.push(
        "no editor is open and the invitation is hidden, so the rail card is blank",
      );
    }
    if (!list.hidden) {
      refusals.push(
        "no editor is open and the readiness list is shown, so the rail answers for a provider nobody opened",
      );
    }
    if (rows.length !== 0) {
      refusals.push(
        "no editor is open and the list still holds " +
          rows.length +
          " row(s): " +
          JSON.stringify(rows[0]),
      );
    }
    return refusals;
  }

  if (!invitation.hidden) {
    refusals.push(
      "an editor is open and the invitation is still shown, so the card invites what is already open",
    );
  }
  if (list.hidden) {
    refusals.push(
      "an editor is open and the readiness list is hidden, so the only readiness signal on the page is absent",
    );
  }
  // A ROW TOO MANY IS COUNTED AND A ROW TOO FEW IS NAMED, and the split is not
  // tidiness. One check over both directions left the missing-row refusal below
  // unreachable - each of the two covered the other, so deleting either one kept the
  // gate green and neither could be proven. A longer list has no row to name, so the
  // count is the only thing to say about it; a shorter one does, and WHICH row went
  // missing is what a reader of the refusal needs.
  if (rows.length > expected.rows.length) {
    refusals.push(
      "the rail holds " +
        rows.length +
        " row(s) and this editor has " +
        expected.rows.length +
        " to answer: " +
        JSON.stringify(rows.slice(expected.rows.length)),
    );
  }

  expected.rows.forEach((want, index) => {
    // A ROW THAT IS NOT THERE IS REFUSED RATHER THAN READ. The count above returns,
    // so this cannot be reached on a short list today - and the proof run showed what
    // resting on that costs: deleting the count refusal turned this loop into a
    // TypeError, so the gate went red for the wrong reason and named no arm.
    const row = rows[index];
    if (row === undefined) {
      refusals.push(
        "row " +
          (index + 1) +
          " is missing, and it is the " +
          want.label +
          " row",
      );
      return;
    }
    if (!row.startsWith(want.state + " - " + want.label + " - ")) {
      refusals.push(
        "row " +
          (index + 1) +
          " should read " +
          JSON.stringify(want.state + " - " + want.label) +
          " and reads " +
          JSON.stringify(row),
      );
      return;
    }
    if (!row.includes(want.detail)) {
      refusals.push(
        "the " +
          want.label +
          " row should say " +
          JSON.stringify(want.detail) +
          " and says " +
          JSON.stringify(row),
      );
    }
  });

  return refusals;
}

// ---------------------------------------------------------------------------
// The calibration: a hand-built rail that is right, and one that is broken per
// refusal the reader can make. Run BEFORE the real page is opened.
// ---------------------------------------------------------------------------

/**
 * A rail with no page around it, in a named state. Nothing here is read from the
 * shipped markup on purpose: the calibration is about whether the READER can fail,
 * and a fixture derived from the real page would make a broken arm depend on what
 * the page happens to carry today.
 */
function handRail(open, rowTexts) {
  const invitation = new Element("div", INVITATION, "div");
  const list = new Element("ul", LIST, "ul");
  invitation.hidden = open !== null;
  list.hidden = open === null;
  rowTexts.forEach((text) => {
    const item = new Element("li", "", "li");
    item.textContent = text;
    list.appendChild(item);
  });
  return new Page([invitation, list], new Map(), new Map());
}

const GOOD_ROWS = [
  "Ready - Required fields - Every required field on this form is filled in.",
  "Needs attention - Field warnings - Reporting a problem: Endpoint",
];
const GOOD_EXPECTED = {
  open: "oid",
  rows: [
    { state: "Ready", label: "Required fields", detail: "Every required" },
    { state: "Needs attention", label: "Field warnings", detail: "Endpoint" },
  ],
};

function calibrate() {
  const arms = [];
  const record = (name, mustRefuse, refusals) => {
    const refused = refusals.length > 0;
    arms.push({ name, mustRefuse, ok: refused === mustRefuse, refusals });
  };

  // The positive, twice: the reader accepts a correct open rail and a correct
  // closed one. A reader that refused either would fail every arm below for its
  // own reason and the real page would never be reached.
  record(
    "open rail as it should be",
    false,
    inspectRail(handRail("oid", GOOD_ROWS), GOOD_EXPECTED),
  );
  record(
    "closed rail as it should be",
    false,
    inspectRail(handRail(null, []), { open: null, rows: [] }),
  );

  // One negative per refusal, each a ONE-CHANGE neighbour of a rail that passes.
  // A negative several changes away proves less: it would be refused by whichever
  // arm noticed first, and the refusal this row is for could be missing.
  {
    const page = handRail("oid", GOOD_ROWS);
    page.querySelector("#" + LIST).hidden = true;
    record(
      "an open editor whose list is hidden",
      true,
      inspectRail(page, GOOD_EXPECTED),
    );
  }
  {
    const page = handRail("oid", GOOD_ROWS);
    page.querySelector("#" + INVITATION).hidden = false;
    record(
      "an open editor still showing the invitation",
      true,
      inspectRail(page, GOOD_EXPECTED),
    );
  }
  {
    const page = handRail("oid", GOOD_ROWS.slice(0, 1));
    record(
      "an open editor missing a row",
      true,
      inspectRail(page, GOOD_EXPECTED),
    );
  }
  {
    const page = handRail("oid", GOOD_ROWS.concat([GOOD_ROWS[1]]));
    record(
      "an open editor with a row too many",
      true,
      inspectRail(page, GOOD_EXPECTED),
    );
  }
  {
    const page = handRail("oid", [
      GOOD_ROWS[0].replace("Ready", "Needs attention"),
      GOOD_ROWS[1],
    ]);
    record(
      "a row carrying the wrong state word",
      true,
      inspectRail(page, GOOD_EXPECTED),
    );
  }
  {
    const page = handRail("oid", [
      GOOD_ROWS[0],
      "Needs attention - Reply URL (ACS) - Computed once the provider has a name.",
    ]);
    record(
      "a row from the other protocol",
      true,
      inspectRail(page, GOOD_EXPECTED),
    );
  }
  {
    const page = handRail("oid", [
      GOOD_ROWS[0],
      "Needs attention - Field warnings - Reporting a problem: Client ID",
    ]);
    record(
      "a row naming the wrong field",
      true,
      inspectRail(page, GOOD_EXPECTED),
    );
  }
  {
    const page = handRail(null, []);
    page.querySelector("#" + INVITATION).hidden = true;
    record(
      "a closed rail with nothing in it at all",
      true,
      inspectRail(page, { open: null, rows: [] }),
    );
  }
  {
    const page = handRail(null, []);
    page.querySelector("#" + LIST).hidden = false;
    record(
      "a closed rail showing its list",
      true,
      inspectRail(page, { open: null, rows: [] }),
    );
  }
  {
    // THE HEADED EMPTY LIST, which is the state #1664 names and the one a reader
    // asking only about `hidden` would pass: the list is correctly hidden and the
    // invitation correctly shown, and the rows of the provider that was open a
    // moment ago are still behind it. The next unhide would show them under a
    // provider nobody chose.
    const page = handRail(null, []);
    const list = page.querySelector("#" + LIST);
    const stale = new Element("li", "", "li");
    stale.textContent = GOOD_ROWS[0];
    list.appendChild(stale);
    record(
      "a closed rail keeping the last provider's rows",
      true,
      inspectRail(page, { open: null, rows: [] }),
    );
  }

  return arms;
}

// ---------------------------------------------------------------------------
// The arms over the real page.
// ---------------------------------------------------------------------------

async function loadCore() {
  const source = fs.readFileSync(CORE, "utf8");
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64");
  const module = await import(url);
  // The controller as well as the object, because #1687's subject is what
  // initProvidersPage BINDS and the only way to ask is to run it.
  return { core: module.default, controllers: module.pageControllers };
}

/** The host globals the readiness path and the page's controller touch, and nothing else. */
function installHost(counter) {
  globalThis.Node = { TEXT_NODE: 3 };
  globalThis.document = {
    createElement: (tag) => new Element(tag, "", tag),
    createTextNode: (data) => new Text(data),
  };
  // initProvidersPage builds option rows for the preset pickers through the DOM's own
  // Option constructor, and asks the host three things on its way through. None of them
  // is reached by an arm's assertion; they are here so the controller runs rather than
  // throwing, which is the difference between driving the binding and asserting it.
  globalThis.Option = function (text, value) {
    const option = new Element("option", "", "option");
    option.textContent = text;
    option.value = value;
    return option;
  };
  globalThis.Dashboard = {
    alert() {},
    processPluginConfigurationUpdateResult() {},
  };
  // `document` RIDES ALONG ON window, because one call site reaches it that way:
  // populateProvisioningProfileOptions builds its option rows with
  // window.document.createElement. A window without it leaves that function throwing inside
  // a promise, which surfaces as four rejections nobody handled rather than as a failed arm -
  // and the arm that counts those rejections then blames the page.
  globalThis.window = {
    confirm: () => true,
    location: { search: "" },
    document: globalThis.document,
  };
  // node already defines navigator and refuses an assignment to it, so the one member the
  // controller reaches for is defined on the existing object instead.
  globalThis.navigator.clipboard = { writeText: () => Promise.resolve() };
  // EVERY CALL IS COUNTED AND NONE IS SERVED. The panel's whole claim is that it
  // reads what the form already holds, so a rebuild that reached the network would
  // be refused here by the count rather than by a reading of the file - and a
  // client that answered would let one slip past as a pass.
  globalThis.ApiClient = new Proxy(
    {},
    {
      get: (_target, name) => {
        if (name === "then" || typeof name === "symbol") {
          return undefined;
        }
        return (...args) => {
          counter.calls.push(String(name) + "(" + args.length + ")");
          // THE ONE REPLY THIS CLIENT CAN REFUSE (#1681), because a read that fails is a
          // state the page has to be driven through rather than reasoned about: the server
          // unreachable, a 500, a configuration the host cannot deserialize. Served as a
          // rejected promise and not as an empty object, which is what the success arm
          // already gets and is a different failure.
          // The two that answer with a VALUE rather than a promise. Both are read
          // synchronously - the computed URLs compose a string out of serverAddress, and
          // getUrl builds a route - so a promise here is not a slower answer, it is the
          // wrong type and the controller throws on it.
          if (name === "serverAddress") {
            return "https://jellyfin.example";
          }
          if (name === "getUrl") {
            return "https://jellyfin.example/" + String(args[0]);
          }
          // A READ CAN BE PARKED AND SETTLED LATER, IN ANY ORDER (#1693). A reply's order
          // relative to the clicks around it is the whole subject: a failing request is
          // typically the slower of two, so the stale case is the ordinary ordering rather
          // than an exotic one, and it cannot be reached by a client that answers at once.
          if (counter.park !== null && name === "getPluginConfiguration") {
            return new Promise((resolve, reject) =>
              counter.park.push({ resolve, reject }),
            );
          }
          // A 200 CARRYING WHATEVER THE ARM CHOOSES (#1694). A read that fulfils is not a read
          // that worked, and the bodies that matter here - a proxy's error page that parses, a
          // version-skewed member - arrive as resolved promises. A client that could only
          // reject or answer correctly could not reach either.
          if (
            counter.serve !== undefined &&
            name === "getPluginConfiguration"
          ) {
            return Promise.resolve(counter.serve);
          }
          if (counter.refuseRead && name === "getPluginConfiguration") {
            return Promise.reject(new Error("the stub refused this read"));
          }
          // THE SHAPE AND NOT THE CONTENT. The controller's own load path walks the three
          // members of a configuration and the managed-set report, so a bare `{}` makes it
          // throw on a `.map` of undefined - which would read as "the binding does not
          // work" when what failed is this client. Empty members are a server with nothing
          // configured, which is the state every arm here sets up by hand anyway.
          if (name === "getPluginConfiguration") {
            return Promise.resolve({
              OidConfigs: {},
              SamlConfigs: {},
              ProvisioningProfiles: {},
            });
          }
          // getJSON answers two routes, and which one is read off the route rather than
          // guessed: the managed-set report, and the library list whose `Items` the folder
          // checklists map over. A body with neither member makes the controller throw on a
          // `.map` of undefined, which is this client failing and not the page.
          if (name === "getJSON") {
            const route = String(args[0]);
            if (route.includes("Library/MediaFolders")) {
              return Promise.resolve({ Items: [] });
            }
            return Promise.resolve({
              OidConfigs: [],
              SamlConfigs: [],
              ProvisioningProfiles: [],
            });
          }
          return Promise.resolve({});
        };
      },
    },
  );
}

/** A required field, filled or emptied, named as the rail will name it. */
function nameOf(core, page, id) {
  return core.readinessFieldName(page, id);
}

function main() {
  const faults = [];
  const refuse = (leg, detail) => faults.push(leg + ": " + detail);

  // ---- the calibration, first ----
  const arms = calibrate();
  const bad = arms.filter((arm) => !arm.ok);
  if (bad.length > 0) {
    bad.forEach((arm) =>
      console.error(
        "CALIBRATION  " +
          arm.name +
          ": " +
          (arm.mustRefuse
            ? "the reader accepted a rail that is wrong"
            : "the reader refused a rail that is right - " +
              arm.refusals.join("; ")),
      ),
    );
    console.error(
      "the calibration disagreed, so the real page was not opened (#1678)",
    );
    return 1;
  }
  const mustPass = arms.filter((arm) => !arm.mustRefuse).length;

  return { arms, mustPass, faults, refuse };
}

async function run() {
  const started = main();
  if (typeof started === "number") {
    return started;
  }
  const { arms, mustPass, faults, refuse } = started;
  const counter = {
    calls: [],
    refuseRead: false,
    park: null,
    serve: undefined,
  };
  // EVERY REJECTION NOBODY HANDLED IS RECORDED, which is a thing node tells you and a
  // browser does not tell an administrator. The arm below asks for it by name, because
  // "it surfaces in the console" is exactly the reporting #1681 is about the absence of.
  const unhandled = [];
  process.on("unhandledRejection", (reason) => unhandled.push(String(reason)));
  installHost(counter);
  const { core, controllers } = await loadCore();

  // The spec is read from the module rather than restated, because an arm naming
  // its own required ids would stop testing the panel the day the spec changed and
  // would instead test a copy of what the spec used to be.
  const REQUIRED = core.readinessSpecs.oid.requiredIds;
  const SAML_REQUIRED = core.readinessSpecs.saml.requiredIds;

  /** The five rows an OpenID editor answers, in order, for a blank form. */
  const blankOid = (page) => ({
    open: "oid",
    rows: [
      {
        state: "Needs attention",
        label: "Required fields",
        detail:
          "Still empty: " +
          REQUIRED.map((id) => nameOf(core, page, id)).join(", "),
      },
      {
        state: "Ready",
        label: "Field warnings",
        detail: "No field on this form is reporting a problem.",
      },
      {
        state: "Needs attention",
        label: "Endpoint test",
        detail: "Not yet tested.",
      },
      {
        state: "Needs attention",
        label: "Redirect URI",
        detail: "Available once the provider is saved.",
      },
      {
        state: "Ready",
        label: "Insecure or sensitive options",
        detail: "None of the flagged options is active",
      },
    ],
  });

  /** The five rows a SAML editor answers, in order, for a blank form. */
  const blankSaml = (page) => ({
    open: "saml",
    rows: [
      {
        state: "Needs attention",
        label: "Required fields",
        detail:
          "Still empty: " +
          SAML_REQUIRED.map((id) => nameOf(core, page, id)).join(", "),
      },
      {
        state: "Ready",
        label: "Field warnings",
        detail: "No field on this form is reporting a problem.",
      },
      {
        state: "Needs attention",
        label: "Endpoint test",
        detail: "Not yet tested.",
      },
      {
        state: "Needs attention",
        label: "Reply URL (ACS)",
        detail: "Computed once the provider has a name.",
      },
      {
        state: "Ready",
        label: "Insecure or sensitive options",
        detail: "None of the flagged options is active",
      },
    ],
  });

  // ---- Arm: neither editor open ----
  {
    const page = providersFixture();
    core.railReadiness(page);
    inspectRail(page, { open: null, rows: [] }).forEach((detail) =>
      refuse("none-open", detail),
    );
  }

  // ---- Arm: the OpenID editor opened through the shipped opener ----
  //
  // THE SAML EDITOR IS OPENED FIRST, and that is not scene-setting. Both editors
  // ship hidden, so an arm that opened the OpenID one on a fresh fixture would find
  // the SAML one closed whether showEditor closed it or not - which is exactly what
  // the first draft of this arm did, and the proof run caught it: taking
  // hideSamlEditor out of showEditor left the gate green. The one-workspace rule
  // (#1527) is only readable from a page where the other workspace was open.
  {
    const page = providersFixture();
    core.showSamlEditor(page);
    core.showEditor(page);
    if (page.querySelector("#" + EDITORS.saml).hidden !== true) {
      refuse(
        "oid-open",
        "opening the OpenID editor left the SAML editor open, so the rail is answering for one of two forms on screen",
      );
    }
    inspectRail(page, blankOid(page)).forEach((detail) =>
      refuse("oid-open", detail),
    );
  }

  // ---- Arm: the SAML editor, whose rows are its own ----
  {
    const page = providersFixture();
    core.showEditor(page);
    core.showSamlEditor(page);
    if (page.querySelector("#" + EDITORS.oid).hidden !== true) {
      refuse(
        "saml-open",
        "opening the SAML editor left the OpenID editor open",
      );
    }
    const rows = rowsOf(page);
    // The ACS row is the one that separates the two protocols by NAME rather than
    // by count: both editors answer five rows, so a rail that answered for the
    // wrong one would match on length alone.
    if (!rows.some((row) => row.includes("Reply URL (ACS)"))) {
      refuse(
        "saml-open",
        "the SAML editor's rail carries no Reply URL row, so it is answering for the other protocol: " +
          JSON.stringify(rows),
      );
    }
    const missing = SAML_REQUIRED.map((id) => nameOf(core, page, id)).join(
      ", ",
    );
    if (!rows[0].includes(missing)) {
      refuse(
        "saml-open",
        "the SAML required row should name " +
          JSON.stringify(missing) +
          " and reads " +
          JSON.stringify(rows[0]),
      );
    }
  }

  // ---- Arm: switching protocols while one is open ----
  {
    const page = providersFixture();
    core.showEditor(page);
    const before = rowsOf(page);
    core.showSamlEditor(page);
    const after = rowsOf(page);
    if (after.some((row) => row.includes("Redirect URI"))) {
      refuse(
        "switch",
        "switching to the SAML editor left the OpenID redirect row standing in the rail: " +
          JSON.stringify(after),
      );
    }
    if (before.join("|") === after.join("|")) {
      refuse(
        "switch",
        "the rail did not change when the open protocol did, so this arm cannot tell a rebuild from a stale list",
      );
    }
    inspectRail(page, blankSaml(page)).forEach((detail) =>
      refuse("switch", detail),
    );
  }

  // ---- Arm: a reply that lost the race may not paint the other protocol ----
  //
  // This is the #1664 race, driven rather than reasoned: three callers reach
  // refreshReadiness asynchronously with a protocol decided when their request went
  // out. While each editor held its own list a late write was harmless. One shared
  // list removed that isolation.
  {
    const page = providersFixture();
    core.showSamlEditor(page);
    const before = rowsOf(page);
    core.refreshReadiness(page, "oid");
    const after = rowsOf(page);
    if (before.join("|") !== after.join("|")) {
      refuse(
        "late-write",
        "an OpenID reply arriving after the SAML editor opened repainted the rail: " +
          JSON.stringify(after),
      );
    }
  }

  // ---- Arm: closing the last open editor ----
  {
    const page = providersFixture();
    core.showEditor(page);
    if (rowsOf(page).length === 0) {
      refuse(
        "close",
        "the fixture for this arm never filled the rail, so it proves nothing",
      );
    }
    core.hideEditor(page);
    inspectRail(page, { open: null, rows: [] }).forEach((detail) =>
      refuse("close", detail),
    );
  }

  // ---- Arm: a required field filled rebuilds the rows, and asks nobody ----
  {
    const page = providersFixture();
    core.showEditor(page);
    const callsBefore = counter.calls.length;
    REQUIRED.forEach((id) => {
      page.querySelector("#" + id).value = "filled";
    });
    core.refreshReadiness(page, "oid");
    const rows = rowsOf(page);
    if (!rows[0].startsWith("Ready - Required fields - ")) {
      refuse(
        "field-rebuild",
        "every required field is filled and the rail still says they are not: " +
          JSON.stringify(rows[0]),
      );
    }
    // And back: the row has to move in BOTH directions, or an arm that only ever
    // fills fields would pass a panel that hard-coded the ready sentence.
    page.querySelector("#" + REQUIRED[0]).value = "";
    core.refreshReadiness(page, "oid");
    const emptied = rowsOf(page)[0];
    if (!emptied.includes(nameOf(core, page, REQUIRED[0]))) {
      refuse(
        "field-rebuild",
        "a required field emptied again is not named by the rail: " +
          JSON.stringify(emptied),
      );
    }
    if (counter.calls.length !== callsBefore) {
      refuse(
        "field-rebuild",
        "rebuilding the rail issued " +
          (counter.calls.length - callsBefore) +
          " request(s): " +
          counter.calls.slice(callsBefore).join(", "),
      );
    }
    // Twice in a row is one list, not two. The openers call railReadiness and the
    // field handler calls refreshReadiness, so a doubled call is an ordinary
    // arrival rather than an edge case.
    const once = rowsOf(page).length;
    core.refreshReadiness(page, "oid");
    if (rowsOf(page).length !== once) {
      refuse(
        "field-rebuild",
        "a second rebuild left " +
          rowsOf(page).length +
          " rows where the first left " +
          once,
      );
    }
  }

  // ---- Arm: each remaining row moves for its OWN reason ----
  //
  // One row per reason, because four rows built from one condition would pass with
  // three of them wired to the wrong input.
  {
    const page = providersFixture();
    core.showEditor(page);

    // A validator's own output box, which is where the warnings row reads from.
    const errored = core.readinessSpecs.oid.errorIds[1];
    const box = page.querySelector("#" + errored + "-error");
    if (!box) {
      refuse(
        "rows",
        "providersPage.html declares no #" +
          errored +
          "-error, so the warnings row reads from nothing",
      );
    } else {
      box.hidden = false;
      box.textContent = "This must be an absolute https URL.";
      core.refreshReadiness(page, "oid");
      if (!rowsOf(page)[1].includes(nameOf(core, page, errored))) {
        refuse(
          "rows",
          "a field reporting a problem is not named by the warnings row: " +
            JSON.stringify(rowsOf(page)[1]),
        );
      }
    }

    // The last Test Connection outcome, through the shipped recorder in both
    // directions - the pass is the arm that matters, because a row that said
    // "Needs attention" whatever happened would satisfy the failure arm alone.
    core.recordTestOutcome(page, "oid", false);
    if (!rowsOf(page)[2].includes("did not reach")) {
      refuse(
        "rows",
        "a failed Test Connection is not reported: " +
          JSON.stringify(rowsOf(page)[2]),
      );
    }
    core.recordTestOutcome(page, "oid", true);
    if (!rowsOf(page)[2].startsWith("Ready - Endpoint test - ")) {
      refuse(
        "rows",
        "a passing Test Connection is not reported: " +
          JSON.stringify(rowsOf(page)[2]),
      );
    }

    // The computed URL, which for OpenID is the server's answer and is blank until
    // the provider is saved.
    page.querySelector("#" + core.readinessSpecs.oid.urlId).value =
      "https://jellyfin.example/sso/OID/redirect/one";
    core.refreshReadiness(page, "oid");
    if (!rowsOf(page)[3].startsWith("Ready - Redirect URI - ")) {
      refuse(
        "rows",
        "a redirect URI on the form is not reported: " +
          JSON.stringify(rowsOf(page)[3]),
      );
    }

    // And a flagged toggle, named by its own label. This row is the one that is a
    // security statement rather than a convenience, so it is asked in both
    // directions too.
    const toggle = core.insecureFieldIds[0];
    page.querySelector("#" + toggle).checked = true;
    core.refreshReadiness(page, "oid");
    if (!rowsOf(page)[4].includes(nameOf(core, page, toggle))) {
      refuse(
        "rows",
        "an active insecure toggle is not named by the rail: " +
          JSON.stringify(rowsOf(page)[4]),
      );
    }
    page.querySelector("#" + toggle).checked = false;
    core.refreshReadiness(page, "oid");
    if (
      !rowsOf(page)[4].startsWith("Ready - Insecure or sensitive options - ")
    ) {
      refuse(
        "rows",
        "a toggle turned back off is still reported as active: " +
          JSON.stringify(rowsOf(page)[4]),
      );
    }
  }

  // ---- Arm: a field name is the page's own label, not an id ----
  //
  // The rail's detail sentences are the only place these names appear, so a
  // readinessFieldName that fell through to the id would leave an administrator
  // reading "Still empty: OidClientId" - which is not the text beside the field
  // they are looking at.
  {
    const page = providersFixture();
    REQUIRED.concat(core.insecureFieldIds).forEach((id) => {
      const name = nameOf(core, page, id);
      if (name === id) {
        refuse(
          "labels",
          "the rail would name " +
            id +
            " by its id, so the sentence does not match the form",
        );
      }
      if (/[:*]$/.test(name) || name !== name.trim()) {
        refuse(
          "labels",
          "the rail would name " +
            id +
            " as " +
            JSON.stringify(name) +
            ", with the label's punctuation still on it",
        );
      }
    });
  }

  // ---- Arm: a required field is inside the editor whose listener answers for it ----
  //
  // THE CHAIN IS ASKED ABOUT BEFORE IT IS RELIED ON (#1687). Every arm below rests on a
  // field's event reaching its editor, and the chain that carries it is derived from the
  // markup - so a field that has moved out of its editor would make those arms pass for
  // the wrong reason, by reaching a listener that is not there to reach. Asked for both
  // protocols, and for the flagged toggles as well as the required fields, because the
  // rail answers for those too.
  {
    const page = providersFixture();
    const inside = (id, editorId) => {
      const field = page.querySelector("#" + id);
      if (!field) {
        return false;
      }
      for (let at = field.parentNode; at; at = at.parentNode) {
        if (at.id === editorId) {
          return true;
        }
      }
      return false;
    };
    [
      [
        "oid",
        core.readinessSpecs.oid.requiredIds.concat(core.insecureFieldIds),
      ],
      [
        "saml",
        core.readinessSpecs.saml.requiredIds.concat(
          core.samlInsecureFieldIds.map((id) => "saml-" + id),
        ),
      ],
    ].forEach(([protocol, ids]) =>
      ids.forEach((id) => {
        if (!inside(id, EDITORS[protocol])) {
          refuse(
            "inside-its-editor",
            id +
              " is not inside #" +
              EDITORS[protocol] +
              ", so an event it raises never reaches the listener that rebuilds the rail for " +
              protocol,
          );
        }
      }),
    );
  }

  // ---- Arm: the wrapping-label idiom is in the fixture, not only in the map ----
  //
  // WITHOUT THIS ARM THE SPLICE ABOVE IS DRIVEN BY NOTHING, and the proof run said so:
  // taking it out left the gate green. A checkbox on this page is WRAPPED in a bare
  // `<label>` with no `for=`, and `readinessFieldName` reads that idiom through
  // `field.closest("label")` - the fallback half of a function whose first half is the
  // `label[for=...]` lookup. The fixture answers that first lookup for wrapped controls
  // too, out of the map `labelsOf` builds, so the fallback is never taken and the chain
  // could lose the label without any arm noticing.
  //
  // So the idiom is asked about directly: the control's nearest `<label>` ancestor, the
  // way the shipped code asks. That keeps the fixture modelling the page rather than
  // modelling what the other arms happen to need.
  {
    const page = providersFixture();
    const source = withoutComments(fs.readFileSync(PROVIDERS_PAGE, "utf8"));
    const wrapped = core.insecureFieldIds
      .concat(core.sensitiveFieldIds)
      .filter((id) => !source.includes('for="' + id + '"'));
    if (wrapped.length === 0) {
      refuse(
        "wrapped-label",
        "no flagged toggle on this page is wrapped in its label any more, so this arm proves nothing and the fallback in readinessFieldName is reached by nothing",
      );
    }
    wrapped.forEach((id) => {
      const field = page.querySelector("#" + id);
      const label = field === null ? null : field.closest("label");
      if (label === null) {
        refuse(
          "wrapped-label",
          id +
            ' is wrapped in a <label> on the page and closest("label") finds none here, so the fallback readinessFieldName takes for a checkbox is driven by nothing',
        );
        return;
      }
      if (label.textContent.trim() === "") {
        refuse(
          "wrapped-label",
          id +
            " has a wrapping label with no text, so the rail would name it by its id",
        );
      }
    });
  }

  // ---- Arm: a keystroke in a required field rebuilds the rail ----
  //
  // THE ROUTE, NOT THE HANDLER. Every other arm here calls refreshReadiness itself, so all
  // of them pass on a page whose controller bound nothing at all. This one runs the shipped
  // initProvidersPage and then dispatches the event a control raises, on the CONTROL, so the
  // only way the rail can move is along the chain to whatever the controller bound.
  //
  // BOTH EVENT TYPES, because they carry different controls: `change` alone leaves a text
  // field's typing unanswered until focus moves, and `input` alone leaves every checkbox and
  // select unanswered. And both protocols, because the pairing of a selector with a key is
  // the third way this can be wrong and the quietest - refreshReadiness drops a call for the
  // protocol that is not open at its own gate, so the rail simply never moves.
  for (const protocol of ["oid", "saml"]) {
    for (const type of ["input", "change"]) {
      const page = providersFixture();
      controllers.providers(page);
      const open = protocol === "oid" ? core.showEditor : core.showSamlEditor;
      open(page);
      const required = core.readinessSpecs[protocol].requiredIds;
      const field = page.querySelector("#" + required[0]);
      const before = rowsOf(page);
      if (
        before.length === 0 ||
        !before[0].includes(nameOf(core, page, required[0]))
      ) {
        refuse(
          "keystroke",
          protocol +
            ": the fixture for this arm did not start with " +
            required[0] +
            " named as empty, so it proves nothing: " +
            JSON.stringify(before),
        );
        continue;
      }
      required.forEach((id) => {
        page.querySelector("#" + id).value = "filled";
      });
      // Nothing calls refreshReadiness here. If the rail moves, it moved because the event
      // reached a listener the controller registered.
      page.dispatch(type, field);
      const after = rowsOf(page);
      if (!after[0].startsWith("Ready - Required fields - ")) {
        refuse(
          "keystroke",
          protocol +
            ": a " +
            type +
            " event on " +
            required[0] +
            " did not rebuild the rail - every required field is filled and it still reads " +
            JSON.stringify(after[0]),
        );
      }
      // And back, so the arm cannot pass on a rail that was rebuilt once at init and is
      // now simply showing a ready row it was born with.
      page.querySelector("#" + required[0]).value = "";
      page.dispatch(type, field);
      if (!rowsOf(page)[0].includes(nameOf(core, page, required[0]))) {
        refuse(
          "keystroke",
          protocol +
            ": a " +
            type +
            " event after the field was emptied again did not rebuild the rail: " +
            JSON.stringify(rowsOf(page)[0]),
        );
      }
    }
  }

  // ---- Arm: a reply that no longer speaks for the open editor changes nothing ----
  //
  // THE ORDERING IS THE ORDINARY ONE. A failing request is typically the slower of two, so
  // "the read that fails settles after the one that succeeded" is what a timeout looks like
  // rather than a race somebody has to contrive. Before #1693 the late FAILURE closed the
  // editor the administrator was working in and explained it by naming a provider they had
  // already left; the late SUCCESS was worse, because it wrote the old provider's values into
  // the open form under the new provider's title and a Save then persisted them.
  //
  // Both directions are driven, and so are the two ways the editor stops being about a
  // provider without any read being issued: it is CLOSED, and the other protocol is opened.
  // A serial counting reads answers neither of those, which is why the guard compares the
  // editor's subject instead.
  for (const protocol of ["oid", "saml"]) {
    const selectorId =
      protocol === "saml" ? "#saml-selectProvider" : "#selectProvider";
    const open = protocol === "oid" ? core.showEditor : core.showSamlEditor;
    const close = protocol === "oid" ? core.hideEditor : core.hideSamlEditor;
    const other = protocol === "oid" ? core.showSamlEditor : core.showEditor;
    const load = protocol === "oid" ? core.loadProvider : core.loadSamlProvider;
    const nameField =
      protocol === "saml" ? "#saml-provider-name" : "#OidProviderName";
    const member = protocol === "saml" ? "SamlConfigs" : "OidConfigs";

    /** Opens `which` the way openProvider does, and parks its read. */
    const openAndPark = (page, which) => {
      open(page);
      page.querySelector(selectorId).value = which;
      load(page, which);
    };
    const settled = () =>
      new Promise((resolve) => setImmediate(() => setImmediate(resolve)));

    // 1. a LATE FAILURE for the provider before the one on screen.
    {
      const page = providersFixture();
      counter.park = [];
      openAndPark(page, "a");
      openAndPark(page, "b");
      const [first, second] = counter.park;
      second.resolve({ [member]: { b: {} } });
      await settled();
      first.reject(new Error("the read for a failed late"));
      await settled();
      counter.park = null;
      if (page.querySelector("#" + EDITORS[protocol]).hidden) {
        refuse(
          "stale-reply",
          protocol +
            ": a late failure for the provider before this one closed the editor the administrator is working in",
        );
      }
      if (page.querySelector("#sso-page-status").textContent !== "") {
        refuse(
          "stale-reply",
          protocol +
            ": a late failure for another provider put a sentence on the page about one the reader has left: " +
            JSON.stringify(page.querySelector("#sso-page-status").textContent),
        );
      }
    }

    // 2. a LATE SUCCESS for the provider before the one on screen. The name field is what
    //    the fill writes first, so it is what says whose values landed.
    {
      const page = providersFixture();
      counter.park = [];
      openAndPark(page, "a");
      openAndPark(page, "b");
      const [first, second] = counter.park;
      second.resolve({ [member]: { b: {} } });
      await settled();
      first.resolve({ [member]: { a: {} } });
      await settled();
      counter.park = null;
      const shown = page.querySelector(nameField).value;
      if (shown !== "b") {
        refuse(
          "stale-reply",
          protocol +
            ": a late reply for another provider filled the open form - the name field reads " +
            JSON.stringify(shown) +
            " under an editor opened for b",
        );
      }
    }

    // 3. THE EDITOR CLOSED, which issues no read at all and is the case a serial cannot see.
    {
      const page = providersFixture();
      counter.park = [];
      openAndPark(page, "a");
      close(page);
      const [only] = counter.park;
      only.reject(new Error("the read for a failed after its editor closed"));
      await settled();
      counter.park = null;
      if (page.querySelector("#sso-page-status").textContent !== "") {
        refuse(
          "stale-reply",
          protocol +
            ": a failure for a provider whose editor was already closed still wrote a page status",
        );
      }
      inspectRail(page, { open: null, rows: [] }).forEach((detail) =>
        refuse("stale-reply", protocol + " (closed): " + detail),
      );
    }

    // 4. THE OTHER PROTOCOL OPENED, the second case a serial cannot see: one workspace at a
    //    time, so opening the other editor closes this one without any read being issued.
    {
      const page = providersFixture();
      counter.park = [];
      openAndPark(page, "a");
      other(page);
      const [only] = counter.park;
      only.reject(new Error("the read failed after the other protocol opened"));
      await settled();
      counter.park = null;
      const otherId = protocol === "oid" ? EDITORS.saml : EDITORS.oid;
      if (page.querySelector("#" + otherId).hidden) {
        refuse(
          "stale-reply",
          protocol +
            ": a failure for the protocol that is no longer open closed the editor that is",
        );
      }
      if (page.querySelector("#sso-page-status").textContent !== "") {
        refuse(
          "stale-reply",
          protocol +
            ": a failure for the protocol that is no longer open wrote a page status under the other form",
        );
      }
    }

    // 5. AND THE REPLY THAT IS STILL CURRENT STILL LANDS. Without this the guard could be
    //    "drop everything" and every arm above would pass.
    {
      const page = providersFixture();
      counter.park = [];
      openAndPark(page, "a");
      const [only] = counter.park;
      only.resolve({ [member]: { a: {} } });
      await settled();
      counter.park = null;
      if (page.querySelector(nameField).value !== "a") {
        refuse(
          "stale-reply",
          protocol +
            ": the reply for the provider that IS open did not fill the form - the name field reads " +
            JSON.stringify(page.querySelector(nameField).value),
        );
      }
    }
  }

  // ---- Arm: a 200 that is not the configuration, and a fill that throws ----
  //
  // A FULFILLED READ IS NOT A READ THAT WORKED (#1694). Each of the bodies below arrives as a
  // resolved promise, and before this each left the editor open over the fields resetEditor
  // blanked, the rail asserting "Still empty" about a provider that is saved and fully
  // configured, and the only trace in the browser console. The three states are kept apart
  // because the act they ask for differs: a server that could not be reached, a server that
  // answered with something else, and a document this form could not be filled from.
  for (const protocol of ["oid", "saml"]) {
    const member = protocol === "saml" ? "SamlConfigs" : "OidConfigs";
    const selectorId =
      protocol === "saml" ? "#saml-selectProvider" : "#selectProvider";
    const open = protocol === "oid" ? core.showEditor : core.showSamlEditor;
    const load = protocol === "oid" ? core.loadProvider : core.loadSamlProvider;
    const settled = () =>
      new Promise((resolve) => setImmediate(() => setImmediate(resolve)));

    const drive = async (body) => {
      const page = providersFixture();
      open(page);
      page.querySelector(selectorId).value = "a-saved-provider";
      counter.serve = body;
      load(page, "a-saved-provider");
      await settled();
      counter.serve = undefined;
      return page;
    };
    const closedAndSaid = async (what, body, fragment) => {
      const page = await drive(body);
      if (!page.querySelector("#" + EDITORS[protocol]).hidden) {
        refuse(
          "not-the-configuration",
          protocol +
            ": " +
            what +
            " left the editor open over the blanks resetEditor wrote, one Save away from replacing a configured provider with them",
        );
      }
      inspectRail(page, { open: null, rows: [] }).forEach((detail) =>
        refuse(
          "not-the-configuration",
          protocol + " (" + what + "): " + detail,
        ),
      );
      const status = page.querySelector("#sso-page-status").textContent;
      if (!status.includes(fragment)) {
        refuse(
          "not-the-configuration",
          protocol +
            ": " +
            what +
            " should be reported in its own words and the page says " +
            JSON.stringify(status),
        );
      }
      if (
        !page
          .querySelector("#sso-page-status")
          .classList.contains("sso-status-fail")
      ) {
        refuse(
          "not-the-configuration",
          protocol + ": " + what + " is not marked as a failure",
        );
      }
    };

    // A proxy's error page that happens to parse: an object with none of the members.
    await closedAndSaid(
      "a body carrying none of the configuration's members",
      { error: "Bad Gateway" },
      "is not this plugin's configuration",
    );
    // The member present and not an object, which is the version-skew shape: the OpenID
    // loader threw a TypeError on it and the SAML loader presented a blank provider as read.
    await closedAndSaid(
      "a body whose " + member + " is not a dictionary",
      { [member]: "unexpected" },
      "is not this plugin's configuration",
    );
    // A body of null, which `typeof` calls an object and which every member lookup throws on.
    await closedAndSaid(
      "a body of null",
      null,
      "is not this plugin's configuration",
    );

    // A WHOLE DOCUMENT, because the fill reads all three members and a body short of one
    // throws in the fill rather than failing the shape test - which the arm below would then
    // report as a server with nothing configured having its editor closed. Found by writing
    // the short version first and reading the refusal.
    const document = (providers) => ({
      OidConfigs: {},
      SamlConfigs: {},
      ProvisioningProfiles: {},
      [member]: providers,
    });

    // AND A DOCUMENT THAT IS THE DOCUMENT, whose provider holds a member of the wrong type, so
    // the FILL throws part way rather than the shape test catching it first. A different
    // sentence, because the read worked and this page is what could not use it.
    await closedAndSaid(
      "a provider whose role mapping is not a list",
      document({ "a-saved-provider": { FolderRoleMapping: 5 } }),
      "could not be filled from it",
    );

    // THE OTHER DIRECTION, which is what stops all of the above passing on a loader that
    // closes the editor for every reply: an EMPTY configuration is the commonest installation
    // there is, and it must fill the form and leave the rail answering.
    {
      const page = await drive(document({}));
      if (page.querySelector("#" + EDITORS[protocol]).hidden) {
        refuse(
          "not-the-configuration",
          protocol +
            ": a server with no provider of this protocol had its editor closed, which is every fresh installation",
        );
      }
      if (page.querySelector("#sso-page-status").textContent !== "") {
        refuse(
          "not-the-configuration",
          protocol +
            ": a server with nothing configured was reported as a failure: " +
            JSON.stringify(page.querySelector("#sso-page-status").textContent),
        );
      }
    }
  }

  // ---- Arm: the configuration read fails while an editor is being filled ----
  //
  // THE RAIL IS WHY THIS IS HERE RATHER THAN IN A GATE OF ITS OWN (#1681). An editor is
  // already open over the fields resetEditor blanked when the read is asked for, so a
  // failure used to leave the form reading as an empty provider AND the rail asserting
  // "Still empty" about a provider that is saved and fully configured. The rail is the
  // confident half: it was not silent, it was wrong, and what it said was the opposite of
  // the truth. So the three things this arm asks for are the editor, the rail and the
  // sentence, and the fourth is that node found nobody handling the rejection.
  for (const protocol of ["oid", "saml"]) {
    const page = providersFixture();
    const open = protocol === "oid" ? core.showEditor : core.showSamlEditor;
    const load = protocol === "oid" ? core.loadProvider : core.loadSamlProvider;
    open(page);
    // THE SELECTOR CARRIES WHICH PROVIDER THE EDITOR IS ABOUT, and openProvider sets it
    // before it loads. This arm sets it too, because both loaders drop a reply that no
    // longer speaks for what is on screen (#1693), and a fixture that left the selector
    // blank would have every reply read as stale - a pass for the wrong reason.
    page.querySelector(
      protocol === "saml" ? "#saml-selectProvider" : "#selectProvider",
    ).value = "a-saved-provider";
    if (rowsOf(page).length === 0) {
      refuse(
        "read-failed",
        "the " +
          protocol +
          " fixture for this arm never filled the rail, so it proves nothing",
      );
    }
    counter.refuseRead = true;
    load(page, "a-saved-provider");
    // Two turns: one for the rejection to settle and one for the handler's own work, and
    // a third for node to decide a rejection was nobody's.
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    counter.refuseRead = false;

    if (!page.querySelector("#" + EDITORS[protocol]).hidden) {
      refuse(
        "read-failed",
        "the " +
          protocol +
          " editor stayed open after the read failed, so its blanked fields read as the provider's values and one Save would write them over it",
      );
    }
    inspectRail(page, { open: null, rows: [] }).forEach((detail) =>
      refuse("read-failed", protocol + ": " + detail),
    );
    const status = page.querySelector("#sso-page-status");
    if (!status) {
      refuse(
        "read-failed",
        "providersPage.html declares no #sso-page-status, so a failed read has nowhere to be reported",
      );
    } else {
      if (status.textContent === "") {
        refuse(
          "read-failed",
          "the " +
            protocol +
            " read failed and the page said nothing, so the only report is in the browser console",
        );
      }
      // THE CLASS AS WELL AS THE WORDS. The page marks an outcome ok or failed, and a
      // failure rendered in the success colour is a worse read than no colour at all.
      if (!status.classList.contains("sso-status-fail")) {
        refuse(
          "read-failed",
          "the " +
            protocol +
            " read failure is not marked as one: " +
            JSON.stringify(status.textContent),
        );
      }
    }
  }
  if (unhandled.length > 0) {
    refuse(
      "read-failed",
      unhandled.length +
        " rejection(s) reached nobody: " +
        unhandled.join("; "),
    );
  }

  if (faults.length) {
    faults.forEach((fault) => console.error(fault));
    console.error(faults.length + " refusal(s) in the readiness rail (#1678)");
    return 1;
  }

  console.log(
    "calibration:       " +
      arms.length +
      " arms, " +
      mustPass +
      " that must pass and " +
      (arms.length - mustPass) +
      " that must be refused, all as expected",
  );
  console.log(
    "readiness rail:    every arm below run against the shipped sso-core.js and the shipped providersPage.html",
  );
  console.log(
    "  none-open        neither editor open: the invitation, an empty list, and no rows behind it",
  );
  console.log(
    "  oid-open / saml-open  an opener fills the rail for its own protocol and closes the other editor",
  );
  console.log(
    "  switch           switching protocol replaces the rows rather than leaving the last one's standing",
  );
  console.log(
    "  late-write       a reply for the protocol that is no longer open repaints nothing",
  );
  console.log(
    "  close            closing the last editor returns the invitation and empties the list",
  );
  console.log(
    "  field-rebuild    a required field filled and emptied moves the row, twice, and asks the server nothing",
  );
  console.log(
    "  rows             each of the other four rows moves for its own reason, in both directions",
  );
  console.log(
    "  labels           every field the rail names is named by the page's label and not by its id",
  );
  console.log(
    "  inside-its-editor  every field the rail answers for is inside the editor whose listener",
  );
  console.log(
    "                   rebuilds it, read from the markup rather than declared",
  );
  console.log(
    '  wrapped-label    a checkbox wrapped in a bare label is found by closest("label"), which is',
  );
  console.log(
    "                   the fallback half of the function that names it",
  );
  console.log(
    "  keystroke        an input and a change event raised on a required field reach the listener",
  );
  console.log(
    "                   initProvidersPage bound and rebuild the rail, on both protocols (#1687)",
  );
  console.log(
    "  stale-reply      a reply that no longer speaks for the open editor writes nothing and closes",
  );
  console.log(
    "                   nothing, in five orderings per protocol, and the current one still lands (#1693)",
  );
  console.log(
    "  not-the-configuration  a 200 whose body is not the configuration, and a fill that throws,",
  );
  console.log(
    "                   each close the editor and say so in their own words; an empty one fills (#1694)",
  );
  console.log(
    "  read-failed      a configuration read that fails closes the editor, returns the rail to its",
  );
  console.log(
    "                   invitation, says so on the page, and leaves no rejection unhandled (#1681)",
  );
  console.log(
    "  NOT driven:      the capture phase, stopPropagation, and any ancestor with no id - the chain",
  );
  console.log(
    "                   holds id-bearing elements only. No layout and no real focus.",
  );
  return 0;
}

run()
  .then((code) => process.exit(code))
  .catch((error) => {
    console.error(String((error && error.stack) || error));
    process.exit(1);
  });
