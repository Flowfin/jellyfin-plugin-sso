#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Drives the shipped provider wizard of sso-core.js over the shipped Providers page and
 * refuses each way it can be wrong (#1665).
 *
 * The arms press the wizard buttons after initProvidersPage, so a missing registration
 * fails too. Expected sentences come from en.json by key; a refusal naming the wrong key
 * with the right default is left to the C# catalogue suite. The DOM is a stub without
 * layout or screen reader output, which stays with the walk (#1528, #1665). A calibration
 * over hand-built right and broken wizards runs before the real page is opened.
 */

"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const CORE = path.join(root, "SSO-Auth", "Web", "sso-core.js");
const PROVIDERS_PAGE = path.join(root, "SSO-Auth", "Web", "providersPage.html");
const ENGLISH = path.join(root, "SSO-Auth", "Localization", "en.json");

// The ids and class tokens the wizard is made of; the markup is asserted to declare each one.
const WIZARD = "sso-wizard";
const START = "sso-wizard-start";
const REFUSAL = "sso-wizard-refusal";
const BACK = "sso-wizard-back";
const NEXT = "sso-wizard-next";
const FINISH = "sso-wizard-finish";
const LEAVE = "sso-wizard-leave";
const PICK = { oid: "sso-wizard-pick-oid", saml: "sso-wizard-pick-saml" };
const PANEL = "sso-wizard-panel";
const STATE = "sso-wizard-state";
const ROW = "sso-wizard-step";
const EDITORS = { oid: "sso-editor", saml: "saml-editor" };
const STEPS = 5;

// The stub: only the members an arm reaches.

// A minimal classList over a set of names.
class Classes {
  constructor(names) {
    this.set = new Set(names || []);
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

// A text node.
class Text {
  constructor(data) {
    this.nodeType = 3;
    this.textContent = String(data);
  }
}

// A DOM element with an ancestor chain, attributes and a classList.
class Element {
  constructor(tag, id, type, classes) {
    this.nodeType = 1;
    this.tag = tag;
    this.id = id || "";
    this.type = type || tag;
    this.value = "";
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.placeholder = "";
    this.title = "";
    this.dataset = {};
    this.parentNode = null;
    this.nodes = [];
    this.classList = new Classes(classes);
    this.listeners = new Map();
  }

  addEventListener(name, handler) {
    if (!this.listeners.has(name)) {
      this.listeners.set(name, []);
    }
    this.listeners.get(name).push(handler);
  }

  // Attributes are kept apart from properties because the wizard reads `data-step` through getAttribute.
  setAttribute(name, value) {
    this.attributes = this.attributes || {};
    this.attributes[name] = String(value);
  }

  getAttribute(name) {
    return this.attributes && this.attributes[name] !== undefined
      ? this.attributes[name]
      : null;
  }

  removeAttribute(name) {
    if (this.attributes) {
      delete this.attributes[name];
    }
  }

  /**
   * Answers the page-global forms through the page and a bare tag within this element's subtree,
   * so a toggle writing its own span label finds its own span.
   */
  querySelector(selector) {
    if (!this.ownerPage) {
      return null;
    }
    if (/^[a-z][a-z0-9]*$/.test(selector)) {
      return (
        this.ownerPage.elements.find(
          (el) => el.tag === selector && el !== this && el.isInside(this),
        ) || null
      );
    }
    return this.ownerPage.querySelector(selector);
  }

  isInside(other) {
    for (let at = this.parentNode; at; at = at.parentNode) {
      if (at === other) {
        return true;
      }
    }
    return false;
  }

  querySelectorAll(selector) {
    return this.ownerPage ? this.ownerPage.querySelectorAll(selector) : [];
  }

  focus() {}

  scrollIntoView() {}

  get childNodes() {
    return [...this.nodes];
  }

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

  // Unreached today; readinessFieldName falls back to it for a control without a label.
  closest(selector) {
    for (let at = this; at; at = at.parentNode) {
      if (at.tag === selector) {
        return at;
      }
    }
    return null;
  }
}

/** One page whose querySelector answers the forms this path uses and throws on any other. */
class Page {
  constructor(elements, labels) {
    this.elements = elements;
    this.byId = new Map(
      elements.filter((el) => el.id).map((el) => [el.id, el]),
    );
    this.labelFor = labels;
    this.classList = new Classes();
    this.listeners = new Map();
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
    const token = /^\.([a-z][a-z0-9-]*)$/.exec(selector);
    if (token) {
      return (
        this.elements.find((el) => el.classList.contains(token[1])) || null
      );
    }
    throw new Error("the stub does not resolve the selector " + selector);
  }

  /** Tag lists and one class token in document order, because the panels are the steps in order. */
  querySelectorAll(selector) {
    const token = /^\.([a-z][a-z0-9-]*)$/.exec(selector.trim());
    if (token) {
      return this.elements.filter((el) => el.classList.contains(token[1]));
    }
    const tags = selector.split(",").map((part) => part.trim());
    return this.elements.filter((el) => tags.includes(el.tag));
  }

  addEventListener(name, handler) {
    if (!this.listeners.has(name)) {
      this.listeners.set(name, []);
    }
    this.listeners.get(name).push(handler);
  }

  appendChild(node) {
    this.elements.push(node);
    return node;
  }

  /** One event, along the ancestor chain, innermost first, then the page. */
  dispatch(type, target) {
    for (let at = target; at; at = at.parentNode) {
      (at.listeners.get(type) || []).forEach((handler) =>
        handler({ type, target, currentTarget: at, preventDefault() {} }),
      );
    }
    (this.listeners.get(type) || []).forEach((handler) =>
      handler({ type, target, currentTarget: this, preventDefault() {} }),
    );
  }
}

// The fixture, read out of the shipped page.

/** Replaces every HTML comment with spaces, so a documented control is not a real one. */
function withoutComments(html) {
  return html.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, " "));
}

/** The value of `name="..."` on an opening tag, or an empty string. */
function attr(tag, name) {
  const m = tag.match(new RegExp("(?<![-\\w])" + name + '="([^"]*)"'));
  return m ? m[1] : "";
}

/** Where the element whose opening tag starts at `start` ends, walked with a depth counter. */
function spanFrom(html, start) {
  const name = /^<([a-z][a-z0-9]*)/.exec(html.slice(start, start + 32));
  const open = html.indexOf(">", start);
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

/** The label each control's name is read from, built from the page's own markup in both idioms. */
function labelsOf(html, controls) {
  const labels = new Map();

  for (const m of html.matchAll(/<label\b[^>]*\bfor="([^"]+)"/g)) {
    const open = html.indexOf(">", m.index);
    const close = html.indexOf("</label", open);
    if (open === -1 || close === -1) {
      continue;
    }
    labels.set(m[1], labelFrom(html.slice(open + 1, close)));
  }

  for (const control of controls) {
    if (!control.id || labels.has(control.id)) {
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
    labels.set(
      control.id,
      labelFrom(html.slice(html.indexOf(">", open) + 1, close)),
    );
  }

  return labels;
}

/** A label element holding the text and spans of the given inner markup. */
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
 * The Providers page as this stub sees it: every form control, every element with an id,
 * and every element with a class token the wizard reads back.
 */
function providersFixture() {
  const html = withoutComments(fs.readFileSync(PROVIDERS_PAGE, "utf8"));
  const found = new Map();

  const remember = (start, tag, id, type, classes) => {
    if (found.has(start)) {
      return;
    }
    const span = spanFrom(html, start);
    if (span === null) {
      return;
    }
    found.set(start, {
      el: new Element(tag, id, type, classes),
      span,
    });
  };

  const classesOf = (tag) =>
    (attr(tag, "class") || "").split(/\s+/).filter(Boolean);

  for (const m of html.matchAll(/<(input|select|textarea)\b[\s\S]*?>/g)) {
    remember(
      m.index,
      m[1],
      attr(m[0], "id"),
      attr(m[0], "type") || m[1],
      classesOf(m[0]),
    );
  }

  for (const m of html.matchAll(
    /<([a-z][a-z0-9]*)\b[^>]*?\sid="([^"]+)"[^>]*>/g,
  )) {
    remember(m.index, m[1], m[2], m[1], classesOf(m[0]));
  }

  for (const m of html.matchAll(
    /<([a-z][a-z0-9]*)\b[^>]*?\sclass="([^"]*\bsso-wizard-[^"]*)"[^>]*>/g,
  )) {
    remember(m.index, m[1], attr(m[0], "id"), m[1], classesOf(m[0]));
  }

  // Every span, because several controls write their own label into a child span found by tag.
  for (const m of html.matchAll(/<span\b[^>]*>/g)) {
    remember(m.index, "span", attr(m[0], "id"), "span", classesOf(m[0]));
  }

  const entries = [...found.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([, entry]) => entry);
  const elements = entries.map((entry) => entry.el);

  // Every id the wizard's controller reaches, asserted against the markup.
  for (const id of [
    WIZARD,
    START,
    REFUSAL,
    BACK,
    NEXT,
    FINISH,
    LEAVE,
    PICK.oid,
    PICK.saml,
    EDITORS.oid,
    EDITORS.saml,
  ]) {
    if (!elements.some((el) => el.id === id)) {
      throw new Error(
        "providersPage.html declares no #" +
          id +
          ", so the wizard would render into nothing",
      );
    }
  }

  // The starting state is the markup's own; the wizard ships `hidden`.
  entries.forEach(({ el, span }) => {
    const tag = html.slice(span[0], html.indexOf(">", span[0]) + 1);
    el.hidden = tag.split(/[\s>]+/).includes("hidden");
    const step = attr(tag, "data-step");
    if (step !== "") {
      el.setAttribute("data-step", step);
    }
  });

  // Each element's parent is the smallest span that strictly contains it.
  entries.forEach(({ el, span }) => {
    let parent = null;
    let width = Infinity;
    entries.forEach((other) => {
      if (
        other.el === el ||
        other.span[0] > span[0] ||
        other.span[1] < span[1] ||
        other.span[1] - other.span[0] >= width
      ) {
        return;
      }
      parent = other.el;
      width = other.span[1] - other.span[0];
    });
    el.parentNode = parent;
  });

  const controls = elements.filter((el) =>
    ["input", "select", "textarea"].includes(el.tag),
  );
  if (controls.length === 0) {
    throw new Error(
      "providersPage.html declares no form control, so this fixture would prove nothing",
    );
  }

  return new Page(elements, labelsOf(html, controls));
}

// The reader: what the wizard ought to show, and every way it can be wrong.

const catalogue = JSON.parse(fs.readFileSync(ENGLISH, "utf8"));

/** One catalogue row with its placeholders filled the way tr()'s own fallback fills them. */
function says(key, params) {
  const value = catalogue[key];
  if (value === undefined) {
    throw new Error("en.json carries no " + key);
  }
  if (!params) {
    return value;
  }
  return value.replace(/\{(\w+)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(params, name) ? params[name] : match,
  );
}

/** The state word a step row shows at `index` while the wizard is at `step`. */
const STATE_WORD = (index, step) =>
  index < step
    ? says("config.wizard_state_done")
    : index === step
      ? says("config.wizard_state_here")
      : says("config.wizard_state_todo");

/** Every way the wizard disagrees with `expected`, read from the page rather than the module. */
function inspectWizard(page, expected) {
  const refusals = [];
  const complain = (what) => refusals.push(what);

  const wizard = page.querySelector("#" + WIZARD);
  const start = page.querySelector("#" + START);
  const panels = page.querySelectorAll("." + PANEL);
  const states = page.querySelectorAll("." + STATE);
  const rows = page.querySelectorAll("." + ROW);
  const box = page.querySelector("#" + REFUSAL);

  if (Boolean(wizard.hidden) === Boolean(expected.open)) {
    complain(
      expected.open
        ? "the wizard is hidden where it should be on screen"
        : "the wizard is on screen where it should be hidden",
    );
  }
  if (Boolean(start.hidden) !== Boolean(expected.open)) {
    complain(
      expected.open
        ? "the start button is still offered beside an open wizard"
        : "the start button is hidden with no wizard to start",
    );
  }

  if (expected.open) {
    if (
      panels.length !== STEPS ||
      states.length !== STEPS ||
      rows.length !== STEPS
    ) {
      complain(
        "the wizard holds " +
          panels.length +
          " panel(s), " +
          rows.length +
          " row(s) and " +
          states.length +
          " state(s); " +
          STEPS +
          " of each is expected",
      );
      return refusals;
    }

    const shown = panels
      .map((panel, index) => (panel.hidden ? null : index))
      .filter((index) => index !== null);
    if (shown.length !== 1 || shown[0] !== expected.step) {
      complain(
        "panel(s) " +
          (shown.length ? shown.join(", ") : "none") +
          " are on screen where only " +
          expected.step +
          " should be",
      );
    }

    states.forEach((state, index) => {
      const want = says("config.wizard_step_state", {
        state: STATE_WORD(index, expected.step),
        n: index + 1,
        total: STEPS,
      });
      if (state.textContent !== want) {
        complain(
          "row " +
            (index + 1) +
            ' says "' +
            state.textContent +
            '" where it should say "' +
            want +
            '"',
        );
      }
    });

    const current = rows
      .map((row, index) => (row.getAttribute("aria-current") ? index : null))
      .filter((index) => index !== null);
    if (current.length !== 1 || current[0] !== expected.step) {
      complain(
        "aria-current is on row(s) " +
          (current.length ? current.map((i) => i + 1).join(", ") : "none") +
          " where it belongs on " +
          (expected.step + 1),
      );
    }

    const back = page.querySelector("#" + BACK);
    const next = page.querySelector("#" + NEXT);
    const finish = page.querySelector("#" + FINISH);
    if (Boolean(back.disabled) !== (expected.step === 0)) {
      complain(
        expected.step === 0
          ? "Back is live on the first step, where there is nothing to go back to"
          : "Back is closed on a step that has one before it",
      );
    }
    if (Boolean(next.hidden) !== (expected.step === STEPS - 1)) {
      complain(
        expected.step === STEPS - 1
          ? "Next is still offered on the last step"
          : "Next is hidden on a step that has one after it",
      );
    }
    if (Boolean(finish.hidden) !== (expected.step !== STEPS - 1)) {
      complain(
        expected.step === STEPS - 1
          ? "Finish is hidden on the last step"
          : "Finish is offered before the last step",
      );
    }
  }

  const refusal = expected.refusal === undefined ? null : expected.refusal;
  if (refusal === null) {
    if (!box.hidden || box.textContent !== "") {
      complain(
        'a refusal is still on screen ("' +
          box.textContent +
          '") with none owed',
      );
    }
  } else if (box.hidden) {
    complain("the refusal is written into a hidden region, so nobody reads it");
  } else if (box.textContent !== refusal) {
    complain(
      'the refusal says "' +
        box.textContent +
        '" where it should say "' +
        refusal +
        '"',
    );
  }

  return refusals;
}

// The calibration: a wizard that is right, then one broken wizard per refusal.

/** A hand-built wizard, correct at `step`, before any arm breaks one thing in it. */
function handWizard(step, open) {
  const elements = [];
  const add = (tag, id, classes) => {
    const el = new Element(tag, id, tag, classes);
    elements.push(el);
    return el;
  };

  const wizard = add("div", WIZARD, ["sso-wizard"]);
  wizard.hidden = !open;
  add("button", START, []).hidden = open;

  for (let index = 0; index < STEPS; index += 1) {
    const row = add("li", "", [ROW]);
    const state = add("span", "", [STATE]);
    state.parentNode = row;
    state.textContent = says("config.wizard_step_state", {
      state: STATE_WORD(index, step),
      n: index + 1,
      total: STEPS,
    });
    if (index === step) {
      row.setAttribute("aria-current", "step");
    }
  }

  for (let index = 0; index < STEPS; index += 1) {
    add("div", PANEL + "-" + index, [PANEL]).hidden = index !== step;
  }

  add("button", BACK, []).disabled = step === 0;
  add("button", NEXT, []).hidden = step === STEPS - 1;
  add("button", FINISH, []).hidden = step !== STEPS - 1;
  add("button", LEAVE, []);
  const box = add("div", REFUSAL, []);
  box.hidden = true;

  return new Page(elements, new Map());
}

/** Runs the reader over the correct hand wizards and over one broken wizard per refusal. */
function calibrate() {
  const arms = [];
  const record = (name, mustRefuse, refusals) =>
    arms.push({
      name,
      mustRefuse,
      refusals,
      ok: mustRefuse ? refusals.length > 0 : refusals.length === 0,
    });

  const expected = (step) => ({ open: true, step, refusal: null });

  // The positives. A correct wizard at each of its five steps, and a correct closed one.
  for (let step = 0; step < STEPS; step += 1) {
    record(
      "a correct wizard at step " + (step + 1),
      false,
      inspectWizard(handWizard(step, true), expected(step)),
    );
  }
  record(
    "a wizard nobody has started",
    false,
    inspectWizard(handWizard(0, false), {
      open: false,
      step: 0,
      refusal: null,
    }),
  );
  {
    const page = handWizard(1, true);
    const box = page.querySelector("#" + REFUSAL);
    box.hidden = false;
    box.textContent = says("config.wizard_refuse_protocol");
    record(
      "a refusal that is on screen and says what it should",
      false,
      inspectWizard(page, {
        open: true,
        step: 1,
        refusal: says("config.wizard_refuse_protocol"),
      }),
    );
  }

  // The negatives, one per refusal the reader can make.
  {
    const page = handWizard(2, true);
    page.querySelector("#" + WIZARD).hidden = true;
    record(
      "a wizard hidden while it is supposed to be on screen",
      true,
      inspectWizard(page, expected(2)),
    );
  }
  {
    const page = handWizard(2, true);
    page.querySelector("#" + START).hidden = false;
    record(
      "the start button still offered beside an open wizard",
      true,
      inspectWizard(page, expected(2)),
    );
  }
  {
    const page = handWizard(2, true);
    page.querySelectorAll("." + PANEL)[3].hidden = false;
    record(
      "two panels on screen at once",
      true,
      inspectWizard(page, expected(2)),
    );
  }
  {
    const page = handWizard(2, true);
    page.querySelectorAll("." + PANEL).forEach((panel) => {
      panel.hidden = true;
    });
    record("no panel on screen at all", true, inspectWizard(page, expected(2)));
  }
  {
    const page = handWizard(2, true);
    page.querySelectorAll("." + PANEL)[2].hidden = true;
    page.querySelectorAll("." + PANEL)[1].hidden = false;
    record(
      "the panel of the step before the one the wizard is on",
      true,
      inspectWizard(page, expected(2)),
    );
  }
  {
    // A state word that never moves off "you are here".
    const page = handWizard(2, true);
    page.querySelectorAll("." + STATE)[0].textContent = says(
      "config.wizard_step_state",
      { state: says("config.wizard_state_here"), n: 1, total: STEPS },
    );
    record(
      "a finished step still saying the reader is on it",
      true,
      inspectWizard(page, expected(2)),
    );
  }
  {
    const page = handWizard(2, true);
    page.querySelectorAll("." + ROW)[0].setAttribute("aria-current", "step");
    record(
      "aria-current on two rows at once",
      true,
      inspectWizard(page, expected(2)),
    );
  }
  {
    const page = handWizard(2, true);
    page
      .querySelectorAll("." + ROW)
      .forEach((row) => row.removeAttribute("aria-current"));
    record(
      "no row carrying aria-current",
      true,
      inspectWizard(page, expected(2)),
    );
  }
  {
    const page = handWizard(0, true);
    page.querySelector("#" + BACK).disabled = false;
    record(
      "Back live on the first step",
      true,
      inspectWizard(page, expected(0)),
    );
  }
  {
    const page = handWizard(STEPS - 1, true);
    page.querySelector("#" + NEXT).hidden = false;
    record(
      "Next still offered on the last step",
      true,
      inspectWizard(page, expected(STEPS - 1)),
    );
  }
  {
    const page = handWizard(1, true);
    page.querySelector("#" + FINISH).hidden = false;
    record(
      "Finish offered before the last step",
      true,
      inspectWizard(page, expected(1)),
    );
  }
  {
    // The refusal written into a hidden region, which no one hears.
    const page = handWizard(1, true);
    const box = page.querySelector("#" + REFUSAL);
    box.textContent = says("config.wizard_refuse_protocol");
    record(
      "a refusal written into a hidden region",
      true,
      inspectWizard(page, {
        open: true,
        step: 1,
        refusal: says("config.wizard_refuse_protocol"),
      }),
    );
  }
  {
    const page = handWizard(1, true);
    const box = page.querySelector("#" + REFUSAL);
    box.hidden = false;
    box.textContent = says("config.wizard_refuse_untested");
    record(
      "a refusal naming the wrong thing",
      true,
      inspectWizard(page, {
        open: true,
        step: 1,
        refusal: says("config.wizard_refuse_protocol"),
      }),
    );
  }
  {
    const page = handWizard(1, true);
    const box = page.querySelector("#" + REFUSAL);
    box.hidden = false;
    box.textContent = says("config.wizard_refuse_protocol");
    record(
      "a refusal left standing where none is owed",
      true,
      inspectWizard(page, expected(1)),
    );
  }

  return arms;
}

// The arms over the real page.

// Imports the shipped sso-core.js as a data URL module, since this tree has no package.json.
async function loadCore() {
  const source = fs.readFileSync(CORE, "utf8");
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64");
  const module = await import(url);
  return { core: module.default, controllers: module.pageControllers };
}

/** The host globals this path touches, and nothing else. */
function installHost(host) {
  globalThis.Node = { TEXT_NODE: 3 };
  globalThis.document = {
    createElement: (tag) => new Element(tag, "", tag),
    createTextNode: (data) => new Text(data),
  };
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
  // `confirm` is recorded and answered by the arm, so a decline can be driven.
  globalThis.window = {
    confirm: (text) => {
      host.confirms.push(text);
      return host.confirmAnswer;
    },
    location: { hash: host.hash, search: "" },
    document: globalThis.document,
  };
  globalThis.navigator.clipboard = { writeText: () => Promise.resolve() };
  // Every call is counted, because the wizard issues no request of its own.
  globalThis.ApiClient = new Proxy(
    {},
    {
      get: (_target, name) => {
        if (name === "then" || typeof name === "symbol") {
          return undefined;
        }
        return (...args) => {
          host.calls.push(String(name));
          if (name === "serverAddress") {
            return "https://jellyfin.example";
          }
          if (name === "getUrl") {
            return "https://jellyfin.example/" + String(args[0]);
          }
          if (name === "getPluginConfiguration") {
            return Promise.resolve({
              OidConfigs: {},
              SamlConfigs: {},
              ProvisioningProfiles: {},
            });
          }
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

/** A press of a wizard button, as a browser would deliver it. */
function press(page, id) {
  page.dispatch("click", page.querySelector("#" + id));
}

/** The form's own localized name for a field, which is how the refusal names it. */
function nameOf(core, page, id) {
  return core.readinessFieldName(page, id);
}

/** Runs the calibration and answers its arms, or null when any disagreed. */
function main() {
  const arms = calibrate();
  const bad = arms.filter((arm) => !arm.ok);
  if (bad.length > 0) {
    bad.forEach((arm) =>
      console.error(
        "CALIBRATION  " +
          arm.name +
          ": " +
          (arm.mustRefuse
            ? "the reader accepted a wizard that is wrong"
            : "the reader refused a wizard that is right - " +
              arm.refusals.join("; ")),
      ),
    );
    console.error(
      "the calibration disagreed, so the real page was not opened (#1665)",
    );
    return null;
  }
  return arms;
}

/** Runs the calibration, then every arm over the real page, and exits non-zero on a refusal. */
async function run() {
  const arms = main();
  if (arms === null) {
    return 1;
  }

  const faults = [];
  const refuse = (leg, detail) => faults.push(leg + ": " + detail);
  const check = (leg, page, expected) => {
    const refusals = inspectWizard(page, expected);
    refusals.forEach((detail) => refuse(leg, detail));
    return refusals.length === 0;
  };

  const host = {
    calls: [],
    confirms: [],
    confirmAnswer: true,
    hash: "#/configurationpage?name=SSO-Auth-providers",
  };
  installHost(host);
  const { core, controllers } = await loadCore();

  /** A fresh Providers page with its controller run over it, as the dashboard would. */
  const opened = async () => {
    const page = providersFixture();
    controllers.providers(page);
    // Let the controller's load settle before an arm judges the page.
    await new Promise((resolve) => setImmediate(resolve));
    return page;
  };

  /** A fresh page walked, through its buttons, to a last step that every earlier step allows. */
  const walkedToTheLastStep = async () => {
    const walked = await opened();
    press(walked, START);
    press(walked, PICK.oid);
    press(walked, NEXT);
    core.readinessSpecs.oid.requiredIds.forEach((id) => {
      walked.querySelector("#" + id).value = "value-" + id;
    });
    press(walked, NEXT);
    walked.querySelector("#" + core.readinessSpecs.oid.urlId).value =
      "https://jellyfin.example/sso/OID/redirect/example";
    press(walked, NEXT);
    core.recordTestOutcome(walked, "oid", true);
    press(walked, NEXT);
    inspectWizard(walked, { open: true, step: 4, refusal: null }).forEach(
      (detail) =>
        refuse(
          "walk-setup",
          detail + " - the arms that start from the last step set nothing up",
        ),
    );
    return walked;
  };

  // ---- the wizard nobody has started ----
  {
    const page = await opened();
    check("closed", page, { open: false, step: 0, refusal: null });
    if (core.openEditorKey(page) !== null) {
      refuse(
        "closed",
        "an editor is open on a page nobody has touched, so the arms below would not be setting up what they think",
      );
    }
  }

  // ---- starting it ----
  let page = await opened();
  press(page, START);
  check("start", page, { open: true, step: 0, refusal: null });

  // ---- step one refuses with no protocol ----
  press(page, NEXT);
  check("refuse-protocol", page, {
    open: true,
    step: 0,
    refusal: says("config.wizard_refuse_protocol"),
  });

  // ---- picking a protocol opens that editor and advances nothing ----
  const before = host.calls.length;
  press(page, PICK.oid);
  if (core.openEditorKey(page) !== "oid") {
    refuse(
      "pick",
      "pressing Use OpenID Connect left the OpenID editor closed, so every step after it reads a form that is not on screen",
    );
  }
  if (!page.querySelector("#" + EDITORS.saml).hidden) {
    refuse(
      "pick",
      "both editors are open at once, so openEditorKey answers for whichever attribute was written last",
    );
  }
  check("pick", page, { open: true, step: 0, refusal: null });

  // ---- step two names every required field that is empty ----
  press(page, NEXT);
  check("advance-protocol", page, { open: true, step: 1, refusal: null });
  press(page, NEXT);
  const required = core.readinessSpecs.oid.requiredIds;
  check("refuse-required", page, {
    open: true,
    step: 1,
    refusal: says("config.wizard_refuse_required", {
      fields: required.map((id) => nameOf(core, page, id)).join(", "),
    }),
  });

  // One field short is still a refusal, and it names that field.
  required.slice(0, -1).forEach((id) => {
    page.querySelector("#" + id).value = "value-" + id;
  });
  press(page, NEXT);
  check("refuse-required-last", page, {
    open: true,
    step: 1,
    refusal: says("config.wizard_refuse_required", {
      fields: nameOf(core, page, required[required.length - 1]),
    }),
  });

  page.querySelector("#" + required[required.length - 1]).value = "filled";
  press(page, NEXT);
  check("advance-required", page, { open: true, step: 2, refusal: null });

  // ---- step three waits for the address the server computes ----
  press(page, NEXT);
  check("refuse-url", page, {
    open: true,
    step: 2,
    refusal: says("config.wizard_refuse_url_oid"),
  });

  page.querySelector("#" + core.readinessSpecs.oid.urlId).value =
    "https://jellyfin.example/sso/OID/redirect/example";
  press(page, NEXT);
  check("advance-url", page, { open: true, step: 3, refusal: null });

  // ---- step four tells a test nobody ran from a test that failed ----
  press(page, NEXT);
  check("refuse-untested", page, {
    open: true,
    step: 3,
    refusal: says("config.wizard_refuse_untested"),
  });

  core.recordTestOutcome(page, "oid", false);
  press(page, NEXT);
  check("refuse-test-failed", page, {
    open: true,
    step: 3,
    refusal: says("config.wizard_refuse_test_failed"),
  });

  core.recordTestOutcome(page, "oid", true);
  press(page, NEXT);
  check("advance-test", page, { open: true, step: 4, refusal: null });

  // ---- step five: enabled, and saved ----
  if (page.querySelector("#Enabled").checked) {
    refuse(
      "fail-closed",
      "a provider opened by the wizard arrives with Enabled already on, so the last step's refusal is never reached",
    );
  }
  press(page, FINISH);
  check("refuse-disabled", page, {
    open: true,
    step: 4,
    refusal: says("config.wizard_refuse_disabled"),
  });

  page.querySelector("#Enabled").checked = true;
  core.markPageDirty(page);
  press(page, FINISH);
  check("refuse-unsaved", page, {
    open: true,
    step: 4,
    refusal: says("config.wizard_refuse_unsaved"),
  });

  // ---- Back is never refused, and it clears the refusal it came from ----
  press(page, BACK);
  check("back", page, { open: true, step: 3, refusal: null });
  press(page, NEXT);
  check("back-forward", page, { open: true, step: 4, refusal: null });

  // ---- finishing ----
  core.markPageClean(page);
  press(page, FINISH);
  check("finish", page, { open: false, step: 4, refusal: null });
  if (
    page.querySelector("#sso-page-status").textContent !==
    says("config.wizard_done")
  ) {
    refuse(
      "finish",
      'the page says "' +
        page.querySelector("#sso-page-status").textContent +
        '" when the wizard finished, rather than the outcome',
    );
  }

  // ---- leaving changes nothing about the editor ----
  {
    const leaving = await opened();
    press(leaving, START);
    press(leaving, PICK.oid);
    const openBefore = core.openEditorKey(leaving);
    leaving.querySelector("#OidProviderName").value = "half-typed";
    const callsBefore = host.calls.length;
    press(leaving, LEAVE);
    check("leave", leaving, { open: false, step: 0, refusal: null });
    if (core.openEditorKey(leaving) !== openBefore) {
      refuse(
        "leave",
        "leaving the wizard closed the editor, so the work in it went off screen without being saved",
      );
    }
    if (leaving.querySelector("#OidProviderName").value !== "half-typed") {
      refuse(
        "leave",
        "leaving the wizard emptied a field the administrator had filled in",
      );
    }
    if (host.calls.length !== callsBefore) {
      refuse(
        "leave",
        "leaving the wizard asked the server for " +
          (host.calls.length - callsBefore) +
          " thing(s); it holds no state a server knows about",
      );
    }
  }

  // ---- the protocol switch is confirmed, and a decline changes nothing ----
  {
    const switching = await opened();
    press(switching, START);
    press(switching, PICK.oid);
    switching.querySelector("#OidProviderName").value = "typed";
    core.markPageDirty(switching);

    host.confirms.length = 0;
    host.confirmAnswer = false;
    press(switching, PICK.saml);
    if (host.confirms.length !== 1) {
      refuse(
        "switch-confirm",
        "changing the protocol over unsaved work asked " +
          host.confirms.length +
          " question(s); it empties the editor and nothing else would say so",
      );
    }
    if (core.openEditorKey(switching) !== "oid") {
      refuse(
        "switch-confirm",
        "a declined confirmation changed the protocol anyway, which is the data loss the question exists to prevent",
      );
    }
    if (switching.querySelector("#OidProviderName").value !== "typed") {
      refuse(
        "switch-confirm",
        "a declined confirmation emptied the field it was asking about",
      );
    }

    host.confirmAnswer = true;
    press(switching, PICK.saml);
    if (core.openEditorKey(switching) !== "saml") {
      refuse(
        "switch-confirm",
        "an accepted confirmation did not change the protocol, so the question answers nothing",
      );
    }

    // The SAML half of step three has its own sentence, because its address is computed client-side.
    core.readinessSpecs.saml.requiredIds.forEach((id) => {
      switching.querySelector("#" + id).value = "value";
    });
    press(switching, NEXT);
    press(switching, NEXT);
    switching.querySelector("#" + core.readinessSpecs.saml.urlId).value = "";
    press(switching, NEXT);
    check("refuse-url-saml", switching, {
      open: true,
      step: 2,
      refusal: says("config.wizard_refuse_url_saml"),
    });
  }

  // ---- an editor closed mid-wizard takes the wizard's answer with it ----
  // The refusal names the pick buttons, so it is written on the first panel where they live.
  {
    const closing = await opened();
    press(closing, START);
    press(closing, PICK.oid);
    press(closing, NEXT);
    core.hideEditor(closing);
    press(closing, NEXT);
    check("editor-closed", closing, {
      open: true,
      step: 0,
      refusal: says("config.wizard_refuse_protocol"),
    });
    if (closing.querySelectorAll("." + PANEL)[0].hidden) {
      refuse(
        "editor-closed",
        "the refusal names the two pick buttons and the panel holding them is hidden, so it asks for a control nobody can see",
      );
    }
  }

  // ---- a step already passed can stop being true, and the last step notices ----
  // Clicking a saved provider's card at the last step empties the editor and its test outcome.
  {
    const reloaded = await walkedToTheLastStep();
    core.openProvider(reloaded, "another");
    await new Promise((resolve) => setImmediate(resolve));
    reloaded.querySelector("#Enabled").checked = true;
    core.markPageClean(reloaded);
    press(reloaded, FINISH);
    // resetEditor empties the form first, so the required-fields refusal is what the walk meets.
    check("reloaded-finish", reloaded, {
      open: true,
      step: 4,
      refusal: says("config.wizard_refuse_required", {
        fields: core.readinessSpecs.oid.requiredIds
          .slice(1)
          .map((id) => nameOf(core, reloaded, id))
          .join(", "),
      }),
    });
  }

  // ---- and the same walk with only the test outcome gone ----
  {
    const forgotten = await walkedToTheLastStep();
    // The one value resetEditor writes, so the arm reaches the test step.
    core.readinessTestState.oid = null;
    forgotten.querySelector("#Enabled").checked = true;
    core.markPageClean(forgotten);
    press(forgotten, FINISH);
    check("forgotten-test", forgotten, {
      open: true,
      step: 4,
      refusal: says("config.wizard_refuse_untested"),
    });
  }

  // ---- a green test stops speaking when the fields it was about move ----
  {
    const edited = await walkedToTheLastStep();
    edited.querySelector("#OidEndpoint").value = "https://typo.example/";
    edited.querySelector("#Enabled").checked = true;
    core.markPageClean(edited);
    press(edited, FINISH);
    check("stale-test", edited, {
      open: true,
      step: 4,
      refusal: says("config.wizard_refuse_test_stale"),
    });

    // It speaks again once the field is what it was.
    edited.querySelector("#OidEndpoint").value = "value-OidEndpoint";
    press(edited, FINISH);
    check("stale-test-restored", edited, {
      open: false,
      step: 4,
      refusal: null,
    });
  }

  // ---- ticking Enabled is not a reason to re-test ----
  // The subject is the spec's required ids, not the whole form.
  {
    const enabling = await walkedToTheLastStep();
    enabling.querySelector("#Enabled").checked = true;
    core.markPageClean(enabling);
    press(enabling, FINISH);
    check("enable-is-not-a-retest", enabling, {
      open: false,
      step: 4,
      refusal: null,
    });
  }

  // ---- a provider a configuration source owns is not enabled from here ----
  // The freeze (#1104) disables every form control, so the last step says why instead.
  {
    const frozen = await walkedToTheLastStep();
    frozen.querySelector("#Enabled").disabled = true;
    press(frozen, FINISH);
    check("managed", frozen, {
      open: true,
      step: 4,
      refusal: says("config.wizard_refuse_managed"),
    });
    if (frozen.querySelector("#" + LEAVE).disabled) {
      refuse(
        "managed",
        "the way out of a frozen provider is disabled too, which is the trap the wizard must not build",
      );
    }
  }

  // ---- a row removed by a button is work, and the dirty class does not know it ----
  // handleRoleMappingRemove dispatches nothing, so the protocol switch asks on the baseline reading.
  {
    const removing = await opened();
    press(removing, START);
    press(removing, PICK.oid);
    // A change no event announced: the baseline diverges, the class does not.
    removing.querySelector("#OidEndpoint").value = "typed-with-no-event";
    if (core.isPageDirty(removing)) {
      refuse(
        "silent-edit",
        "the fixture raised the dirty class by itself, so this arm is not set up and proves nothing",
      );
    }
    host.confirms.length = 0;
    host.confirmAnswer = false;
    press(removing, PICK.saml);
    if (host.confirms.length !== 1) {
      refuse(
        "silent-edit",
        "a change nothing dispatched an event for was replaced with no question asked",
      );
    }
    if (
      removing.querySelector("#OidEndpoint").value !== "typed-with-no-event"
    ) {
      refuse("silent-edit", "the declined switch emptied the field anyway");
    }
    host.confirmAnswer = true;
  }

  // ---- both protocols arrive with the provider switched off ----
  {
    const saml = await opened();
    press(saml, START);
    press(saml, PICK.saml);
    if (saml.querySelector("#saml-Enabled").checked) {
      refuse(
        "fail-closed-saml",
        "a SAML provider opened by the wizard arrives with Enabled already on",
      );
    }
  }

  // ---- `hidden` has to hide, and on this dashboard it does not on its own ----
  // jellyfin-web's `.emby-button` display rule beats the user-agent `[hidden]` rule, so the stylesheet must carry one.
  {
    const css = fs.readFileSync(
      path.join(root, "SSO-Auth", "Web", "style.css"),
      "utf8",
    );
    const rule =
      /\.sso-page\s+\[hidden\]\s*\{[^}]*display:\s*none\s*!important/.test(css);
    if (!rule) {
      refuse(
        "hidden-hides",
        "style.css carries no rule making `hidden` display:none inside .sso-page, so a hidden .emby-button stays on screen and stays pressable",
      );
    }
    const providers = withoutComments(fs.readFileSync(PROVIDERS_PAGE, "utf8"));
    if (!/class="[^"]*\bsso-page\b/.test(providers)) {
      refuse(
        "hidden-hides",
        "the Providers page carries no .sso-page ancestor, so the rule that makes `hidden` hide does not reach the wizard",
      );
    }
  }

  // ---- the stepper is painted again once the catalogue lands ----
  // The step rows are written before the catalogue can arrive and carry no marker applyTo can rewrite.
  {
    const source = fs.readFileSync(CORE, "utf8");
    const at = source.indexOf("loadCatalog().then(");
    const end = source.indexOf("localize", at) + 1;
    const branch = at === -1 ? "" : source.slice(at, at + 1200);
    if (!branch.includes("renderWizard(view)")) {
      refuse(
        "catalogue-repaint",
        "nothing paints the wizard again when the catalogue arrives, so a deep link opens a stepper that stays English for the life of the page",
      );
    }
    if (end === 0) {
      refuse(
        "catalogue-repaint",
        "sso-core.js carries no catalogue-arrival branch to read, so this arm is judging nothing",
      );
    }
  }
  // ---- the deep link, both ways ----
  {
    host.hash = "#/configurationpage?name=SSO-Auth-providers&wizard=1";
    globalThis.window.location.hash = host.hash;
    const linked = await opened();
    if (!check("deep-link", linked, { open: true, step: 0, refusal: null })) {
      refuse(
        "deep-link",
        "Overview's Add provider card names the flag this page is supposed to read on load",
      );
    }

    host.hash = "#/configurationpage?name=SSO-Auth-providers";
    globalThis.window.location.hash = host.hash;
    const plain = await opened();
    check("no-deep-link", plain, { open: false, step: 0, refusal: null });
  }

  // ---- the deep link on a view the dashboard hands back from its cache (#1721) ----
  // A cached view runs no controller, so `viewshow` reads the flag too, and only while the wizard is closed.
  {
    const settled = () => new Promise((resolve) => setImmediate(resolve));

    host.hash = "#/configurationpage?name=SSO-Auth-providers";
    globalThis.window.location.hash = host.hash;
    const shown = await opened();
    check("cached-view-setup", shown, { open: false, step: 0, refusal: null });
    host.hash = "#/configurationpage?name=SSO-Auth-providers&wizard=1";
    globalThis.window.location.hash = host.hash;
    shown.dispatch("viewshow", null);
    await settled();
    if (!check("cached-view", shown, { open: true, step: 0, refusal: null })) {
      refuse(
        "cached-view",
        "a view the dashboard hands back from its cache is shown with the flag and the wizard stays closed, so once the Providers tab has been seen the card on Overview opens the tab and not the wizard",
      );
    }

    const inProgress = await walkedToTheLastStep();
    inProgress.dispatch("viewshow", null);
    await settled();
    if (
      !check("cached-view-in-progress", inProgress, {
        open: true,
        step: 4,
        refusal: null,
      })
    ) {
      refuse(
        "cached-view-in-progress",
        "a wizard at its last step is shown again with the flag still in the address and is reset, so leaving the tab and coming back throws the walk away",
      );
    }

    host.hash = "#/configurationpage?name=SSO-Auth-providers";
    globalThis.window.location.hash = host.hash;
    const unasked = await opened();
    unasked.dispatch("viewshow", null);
    await settled();
    check("cached-view-no-flag", unasked, {
      open: false,
      step: 0,
      refusal: null,
    });
  }

  // ---- Overview's card points at the flag this page reads ----
  {
    const overview = fs.readFileSync(
      path.join(root, "SSO-Auth", "Web", "configPage.html"),
      "utf8",
    );
    const link = /href="#\/configurationpage\?name=([^"&]+)&amp;wizard=1"/.exec(
      withoutComments(overview),
    );
    if (link === null) {
      refuse(
        "overview-card",
        "configPage.html carries no link with the wizard flag, so the card on Overview opens the tab and not the wizard",
      );
    } else if (link[1] !== "SSO-Auth-providers") {
      refuse(
        "overview-card",
        'the card links to "' +
          link[1] +
          '", which is not the page whose controller reads the flag',
      );
    }
  }

  faults.forEach((fault) => console.error("REFUSED  " + fault));
  if (faults.length > 0) {
    console.error(
      faults.length + " way(s) the provider wizard is wrong (#1665)",
    );
    return 1;
  }

  console.log(
    "calibration:      " +
      arms.length +
      " arms, " +
      arms.filter((arm) => !arm.mustRefuse).length +
      " that must pass and " +
      arms.filter((arm) => arm.mustRefuse).length +
      " that must be refused, all as expected",
  );
  console.log(
    "the wizard:       " +
      STEPS +
      " steps driven through their buttons on the shipped Providers page, in both protocols",
  );
  console.log(
    "every step refuses to open the next on its own missing field and names it, Back is never refused,",
  );
  console.log(
    "the protocol switch is confirmed before it empties the editor, and leaving changes nothing",
  );
  console.log(
    "the deep link opens the wizard on a view shown again from the dashboard's cache, and never restarts one in progress (#1721)",
  );
  console.log(
    "a step already passed that stops being true stops the ones after it, so the last step never",
  );
  console.log("asserts a Test Connection this page has forgotten");
  console.log(
    "NOT driven:       layout, focus order, what a screen reader announces, and whether the step on",
  );
  console.log(
    "                  screen is the step being read - those are the walk (#1665, decision D4)",
  );
  return 0;
}

run().then(
  (code) => process.exit(code),
  (error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
  },
);
