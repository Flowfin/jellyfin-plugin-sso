#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Runs the shipped readiness rail of sso-core.js against the shipped Providers page and
 * refuses each way it can be wrong (#1678).
 *
 * Since #1664 the rail is the only place readiness appears, so a rail that is wrong or
 * silent removes the signal. Controls, regions and labels are read from
 * providersPage.html, and an ancestor chain derived from the markup lets a field's event
 * reach the editor listener initProvidersPage binds (#1687). The stub models no layout,
 * capture phase or screen reader. A calibration runs before the real page is opened.
 */

"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const CORE = path.join(root, "SSO-Auth", "Web", "sso-core.js");
const PROVIDERS_PAGE = path.join(root, "SSO-Auth", "Web", "providersPage.html");

// The two rail ids and the two editors whose `hidden` decides which protocol it answers for.
const INVITATION = "sso-rail-readiness";
const LIST = "sso-rail-readiness-list";
const EDITORS = { oid: "sso-editor", saml: "saml-editor" };

// The stub: only the members the code under test reaches.

// A minimal classList over a set of names.
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

// A text node.
class Text {
  constructor(data) {
    this.nodeType = 3;
    this.textContent = String(data);
  }
}

// A DOM element with children, attributes, listeners and a parent chain.
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
    // Listeners per element, because which element a listener sits on is the subject of #1687.
    this.listeners = new Map();
    // Properties initProvidersPage sets on controls; `dataset` carries the Save gate's frozen flag.
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

  /*
   * A select loses its value when the selected option is removed, as a browser does (#1696).
   * Only for a select; the insert half of the reset algorithm is not modelled, and the arms
   * rely only on the selector no longer naming its provider after a rebuild.
   */
  removeChild(node) {
    this.nodes = this.nodes.filter((other) => other !== node);
    node.parentNode = null;
    if (
      this.tag === "select" &&
      node.tag === "option" &&
      node.value === this.value
    ) {
      const first = this.nodes.find((other) => other.tag === "option");
      this.value = first === undefined ? "" : first.value;
    }
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

  // The page's answer plus this element's own children, one level deep, so appended options are found (#1696).
  querySelectorAll(selector) {
    const tags = selector.split(",").map((part) => part.trim());
    const own = this.nodes.filter(
      (node) => node instanceof Element && tags.includes(node.tag),
    );
    const page = this.ownerPage
      ? this.ownerPage.querySelectorAll(selector)
      : [];
    return [...new Set([...page, ...own])];
  }

  focus() {}

  scrollIntoView() {}

  get childNodes() {
    return [...this.nodes];
  }

  // Concatenated like a browser, because readinessFieldName falls back to the whole label text.
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

  // The parent walk, `this` included, matching on the tag alone as `field.closest("label")` needs.
  closest(selector) {
    for (let at = this; at; at = at.parentNode) {
      if (at.tag === selector) {
        return at;
      }
    }
    return null;
  }
}

/** One page whose querySelector answers the forms the readiness path uses and throws on any other. */
class Page {
  constructor(elements, labels, byClass) {
    this.elements = elements;
    this.byId = new Map(elements.map((el) => [el.id, el]));
    this.labelFor = labels;
    this.byClass = byClass;
    // The page carries a classList because markPageClean removes the dirty marker from it.
    this.classList = new Classes();
    this.listeners = new Map();
    // Every element resolves selectors through its page.
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
    // A single class token, resolved from the markup and page-global, so fillProvisioningTemplate runs.
    const token = /^\.([a-z][a-z0-9-]*)$/.exec(selector);
    if (token) {
      return this.byClass.get(token[1]) || null;
    }
    throw new Error("the stub does not resolve the selector " + selector);
  }

  // Tag lists only, answered the same way as tools/ui-unsaved-state.js.
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

  // The page is a node too, because the controller can append to the view itself.
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

  /**
   * One event along the ancestor chain, innermost first (#1687).
   * The capture phase and stopPropagation are not modelled.
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

// The fixture, read out of the shipped page.

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

/**
 * Where the element bearing `id` starts and ends, walked with a same-name depth counter,
 * or null for an element that never closes.
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
 * The label each control's name is read from, built from the page's own markup in both
 * the `for=` idiom and the wrapping idiom.
 */
function labelsOf(html, controls) {
  const labels = new Map();

  // The `for=` idiom, cut out around the attribute because these tags span lines.
  for (const m of html.matchAll(/<label\b[^>]*\bfor="([^"]+)"/g)) {
    const open = html.indexOf(">", m.index);
    const close = html.indexOf("</label", open);
    if (open === -1 || close === -1) {
      continue;
    }
    labels.set(m[1], labelFrom(html.slice(open + 1, close)));
  }

  // The wrapping idiom, found from the control because the label names nothing.
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
    // `closest("label")` must find the wrapping label.
    control.parentNode = label;
  }

  return labels;
}

/**
 * One label element whose text outside child tags becomes direct text nodes, because
 * readinessFieldName reads those before falling back to the full text.
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
 * The Providers page as this stub sees it: its controls, its id-bearing elements and the
 * labels, with the rail regions asserted against the markup.
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
  // The markup's own starting state; the list ships `hidden`.
  elements.forEach((el) => {
    el.hidden = shipsHidden(html, el.id);
  });
  if (!elements.find((el) => el.id === LIST).hidden) {
    throw new Error(
      "the readiness list does not ship hidden, so a page whose script never ran shows a headed empty panel",
    );
  }

  /*
   * Derives the ancestor chain (#1687): each id-bearing element's parent is the smallest span
   * that strictly contains it. Labels are built first so the chain passes through a wrapping label.
   */
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
    // A wrapping label is spliced into the chain, so closest and event delivery both hold.
    const wrapper = el.parentNode;
    if (wrapper !== null && wrapper.tag === "label") {
      wrapper.parentNode = parent;
    } else {
      el.parentNode = parent;
    }
  });

  // The first element in document order per class token, read from the markup.
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

// The reader: what the rail ought to hold, and every way it can be wrong.

/** The rows the list currently holds, as the strings appendReadinessRow wrote. */
function rowsOf(page) {
  return page
    .querySelector("#" + LIST)
    .childNodes.map((node) => node.textContent);
}

/**
 * Refuses one rail state against `expected`: `open` is the protocol or null, and `rows` is
 * one matcher per row in order. A closed rail is refused both for showing the list and for
 * holding rows behind it.
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
  // A row too many is counted and a row too few is named, so each refusal stays reachable.
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
    // A missing row is refused rather than read.
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

// The calibration: a correct hand rail, then one broken rail per refusal, run first.

/** A hand-built rail in a named state, deliberately not read from the shipped markup. */
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

/** Runs the reader over correct hand rails and over one broken rail per refusal. */
function calibrate() {
  const arms = [];
  const record = (name, mustRefuse, refusals) => {
    const refused = refusals.length > 0;
    arms.push({ name, mustRefuse, ok: refused === mustRefuse, refusals });
  };

  // The positives: a correct open rail and a correct closed one.
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

  // One negative per refusal, each one change away from a passing rail.
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
    // The headed empty list: hidden correctly, but still holding the previous provider's rows (#1664).
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

// The arms over the real page.

// Imports the shipped sso-core.js as a data URL module, since this tree has no package.json.
async function loadCore() {
  const source = fs.readFileSync(CORE, "utf8");
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64");
  const module = await import(url);
  // The controllers too, because #1687 is about what initProvidersPage binds.
  return { core: module.default, controllers: module.pageControllers };
}

/** The host globals the readiness path and the page's controller touch, and nothing else. */
function installHost(counter) {
  globalThis.Node = { TEXT_NODE: 3 };
  globalThis.document = {
    createElement: (tag) => new Element(tag, "", tag),
    createTextNode: (data) => new Text(data),
  };
  // The Option constructor and host members the controller needs to run without throwing.
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
  // `document` rides on window because populateProvisioningProfileOptions reaches it that way.
  globalThis.window = {
    confirm: () => true,
    location: { search: "" },
    document: globalThis.document,
  };
  // node refuses an assignment to navigator, so the member is set on the existing object.
  globalThis.navigator.clipboard = { writeText: () => Promise.resolve() };
  // Every call is counted, because the rail must not reach the network.
  globalThis.ApiClient = new Proxy(
    {},
    {
      get: (_target, name) => {
        if (name === "then" || typeof name === "symbol") {
          return undefined;
        }
        return (...args) => {
          counter.calls.push(String(name) + "(" + args.length + ")");
          // serverAddress and getUrl answer with a value, because the controller reads them synchronously.
          if (name === "serverAddress") {
            return "https://jellyfin.example";
          }
          if (name === "getUrl") {
            return "https://jellyfin.example/" + String(args[0]);
          }
          // A read can be parked and settled later in any order (#1693).
          if (counter.park !== null && name === "getPluginConfiguration") {
            return new Promise((resolve, reject) =>
              counter.park.push({ resolve, reject }),
            );
          }
          // A 200 carrying whatever the arm chooses (#1694).
          if (
            counter.serve !== undefined &&
            name === "getPluginConfiguration"
          ) {
            return Promise.resolve(counter.serve);
          }
          // A read that fails, served as a rejected promise (#1681).
          if (counter.refuseRead && name === "getPluginConfiguration") {
            return Promise.reject(new Error("the stub refused this read"));
          }
          // An empty configuration with every member, so the load path does not throw.
          if (name === "getPluginConfiguration") {
            return Promise.resolve({
              OidConfigs: {},
              SamlConfigs: {},
              ProvisioningProfiles: {},
            });
          }
          // getJSON answers the managed-set report and the library list, chosen by route.
          if (name === "getJSON") {
            const route = String(args[0]);
            if (route.includes("Library/MediaFolders")) {
              return Promise.resolve({ Items: [] });
            }
            // The redirect URI route is served as a string (#1710).
            if (
              counter.redirect !== undefined &&
              route.includes("RedirectUri")
            ) {
              return Promise.resolve(counter.redirect);
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

// How many configuration reads a save issues after its write; OpenID adds a secret read-back (#1872).
function reloadsAfterSave(protocol) {
  return protocol === "oid" ? 3 : 2;
}

/** Runs the calibration and answers the arms and refusal collector, or a number when it disagreed. */
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

/** Runs the calibration, then every arm over the real page, and answers the exit code. */
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
  // Every unhandled rejection is recorded, because #1681 is about failures only the console saw.
  const unhandled = [];
  process.on("unhandledRejection", (reason) => unhandled.push(String(reason)));
  installHost(counter);
  const { core, controllers } = await loadCore();

  // The spec is read from the module rather than restated.
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
  // The SAML editor is opened first, so the one-workspace rule (#1527) is observable.
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
    // The ACS row separates the protocols by name, since both answer five rows.
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
  // The #1664 race: three callers reach refreshReadiness with a protocol decided earlier.
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
    // And back, so the row moves in both directions.
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
    // Twice in a row is one list, not two.
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

  // ---- Arm: each remaining row moves for its own reason ----
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

    // The last Test Connection outcome, in both directions.
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

    // The computed URL, which for OpenID stays blank until the provider is saved.
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

    // And a flagged toggle, named by its own label, in both directions.
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
  // The chain is checked before the arms below rely on it (#1687).
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
  // Asks for the control's nearest `<label>` ancestor the way readinessFieldName does.
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
  // Drives the route, not the handler: the event is dispatched on the control, for both event
  // types and both protocols.
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
      // Nothing calls refreshReadiness here, so a move means a bound listener answered.
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
      // And back, so a rail rebuilt once at init cannot pass.
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
  // Late failure, late success, a closed editor and the other protocol opened, plus the current reply (#1693).
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

    // 1. A late failure for the provider before the one on screen.
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

    // 2. A late success for the provider before the one on screen, seen in the name field.
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

    // 3. The editor closed, which issues no read.
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

    // 4. The other protocol opened, which closes this editor without a read.
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

    // 5. The reply that is still current still lands.
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
  // A fulfilled read is not a read that worked (#1694); unreachable, wrong body and unfillable stay apart.
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
    // The member present and not an object, the version-skew shape.
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

    // A whole document, because a body short of a member throws in the fill instead.
    const document = (providers) => ({
      OidConfigs: {},
      SamlConfigs: {},
      ProvisioningProfiles: {},
      [member]: providers,
    });

    // A valid document whose provider holds a member of the wrong type, so the fill throws.
    await closedAndSaid(
      "a provider whose role mapping is not a list",
      document({ "a-saved-provider": { FolderRoleMapping: 5 } }),
      "could not be filled from it",
    );

    // The other direction: an empty configuration fills the form and leaves the rail answering.
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
  // Asks for the editor, the rail and the sentence, and that no rejection went unhandled (#1681).
  for (const protocol of ["oid", "saml"]) {
    const page = providersFixture();
    const open = protocol === "oid" ? core.showEditor : core.showSamlEditor;
    const load = protocol === "oid" ? core.loadProvider : core.loadSamlProvider;
    open(page);
    // The selector names the provider, because both loaders drop a stale reply (#1693).
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
    // Let the rejection and its handler settle before node judges it unhandled.
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
      // The failure class as well as the words.
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

  // ---- Arm: a configuration read that lands first does not take the selector with it ----
  // A save issues loadConfiguration and loadProvider together; the configuration read landing
  // first must not empty the selector the loaders and applyManagedState compare against (#1696, #1693).
  {
    const leaked = unhandled.length;
    for (const protocol of ["oid", "saml"]) {
      const page = providersFixture();
      const open = protocol === "oid" ? core.showEditor : core.showSamlEditor;
      const save =
        protocol === "oid" ? core.saveProvider : core.saveSamlProvider;
      const selectorId =
        protocol === "saml" ? "#saml-selectProvider" : "#selectProvider";
      const nameField =
        protocol === "saml" ? "#saml-provider-name" : "#OidProviderName";
      // Two providers, because with a single option the defect hides.
      const body = () => ({
        OidConfigs: { a: {}, b: { OidEndpoint: "https://b.example" } },
        SamlConfigs: { a: {}, b: { SamlEndpoint: "https://b.example" } },
        ProvisioningProfiles: {},
      });
      const settled = () =>
        new Promise((resolve) => setImmediate(() => setImmediate(resolve)));
      const selector = page.querySelector(selectorId);

      // The configuration read once already, so the selector holds an option per provider.
      counter.serve = body();
      core.loadConfiguration(page);
      await settled();
      counter.serve = undefined;
      if (selector.querySelectorAll("option").length !== 2) {
        refuse(
          "selector-survives",
          protocol +
            ": the first configuration read left " +
            selector.querySelectorAll("option").length +
            " option(s) under " +
            selectorId +
            ", so this arm would prove nothing",
        );
        continue;
      }

      // openProvider is unreachable from this stub, so the editor is put into the state it leaves.
      open(page);
      selector.value = "b";
      page.querySelector(nameField).value = "b";

      counter.park = [];
      let outcome = "never settled";
      save(page, "b").then(
        () => {
          outcome = "resolved";
        },
        (error) => {
          outcome = "rejected: " + error.message;
        },
      );
      await settled();
      if (counter.park.length !== 1) {
        refuse(
          "selector-survives",
          protocol +
            ": the save asked for " +
            counter.park.length +
            " configuration read(s) before its write, so the ordering below is not the one this arm describes",
        );
        counter.park = null;
        continue;
      }
      // The save's read, its write, the two reloads and for OpenID the secret read-back (#1872).
      counter.park[0].resolve(body());
      await settled();
      if (
        counter.park.length !== 1 + reloadsAfterSave(protocol) ||
        outcome !== "resolved"
      ) {
        refuse(
          "selector-survives",
          protocol +
            ": a save that should have parked " +
            reloadsAfterSave(protocol) +
            " reads and resolved parked " +
            (counter.park.length - 1) +
            " and " +
            outcome,
        );
        counter.park = null;
        continue;
      }

      // The losing ordering: the configuration read settles while the provider read is out.
      counter.park[1].resolve(body());
      await settled();
      if (selector.value !== "b") {
        refuse(
          "selector-survives",
          protocol +
            ": the configuration read rebuilt " +
            selectorId +
            " and the page's record of which provider it is about did not survive it - the selector now reads " +
            JSON.stringify(selector.value),
        );
      }

      // The emptied selector drops the provider reply and leaves the saved form blank.
      page.querySelector(nameField).value = "";
      counter.park[2].resolve(body());
      await settled();
      counter.park = null;
      if (page.querySelector(nameField).value !== "b") {
        refuse(
          "selector-survives",
          protocol +
            ": the provider read that followed the configuration read filled nothing, so the editor is left blank over a provider that is saved - " +
            nameField +
            " reads " +
            JSON.stringify(page.querySelector(nameField).value),
        );
      }

      // applyManagedState compares the selector too, so an emptied one leaves a managed form editable.
      const owned = protocol === "saml" ? "SamlConfigs" : "OidConfigs";
      const named = core.managedProviders[owned];
      core.managedProviders[owned] = ["b"];
      await core.applyManagedState(page, protocol, "b");
      core.managedProviders[owned] = named;
      if (!page.querySelector(nameField).disabled) {
        refuse(
          "selector-survives",
          protocol +
            ": a provider a configuration file owns was not frozen after the rebuild, so its form is editable and its Save is live over a value the server will put back",
        );
      }
    }
    if (unhandled.length > leaked) {
      refuse(
        "selector-survives",
        unhandled.length -
          leaked +
          " rejection(s) reached nobody: " +
          unhandled.slice(leaked).join("; "),
      );
    }
  }

  // ---- Arm: a provider saved for the first time still names itself, and its address arrives ----
  // A name no option carries reads back empty from the selector, so both loaders dropped the reply
  // and the redirect URI never arrived (#1710, #1696, #1693).
  {
    const leaked = unhandled.length;
    for (const protocol of ["oid", "saml"]) {
      const page = providersFixture();
      const open = protocol === "oid" ? core.showEditor : core.showSamlEditor;
      const save =
        protocol === "oid" ? core.saveProvider : core.saveSamlProvider;
      const selectorId =
        protocol === "saml" ? "#saml-selectProvider" : "#selectProvider";
      const nameField =
        protocol === "saml" ? "#saml-provider-name" : "#OidProviderName";
      const before = () => ({
        OidConfigs: { a: {} },
        SamlConfigs: { a: {} },
        ProvisioningProfiles: {},
      });
      const after = () => ({
        OidConfigs: { a: {}, fresh: {} },
        SamlConfigs: { a: {}, fresh: {} },
        ProvisioningProfiles: {},
      });
      const settled = () =>
        new Promise((resolve) => setImmediate(() => setImmediate(resolve)));
      const selector = page.querySelector(selectorId);
      // A value no option carries reads back empty on this selector only, the mechanism of #1710.
      Object.defineProperty(selector, "value", {
        configurable: true,
        get() {
          return this.chosenValue === undefined ? "" : this.chosenValue;
        },
        set(next) {
          this.chosenValue = this.nodes.some(
            (node) => node.tag === "option" && node.value === next,
          )
            ? next
            : "";
        },
      });
      counter.serve = before();
      core.loadConfiguration(page);
      await settled();
      counter.serve = undefined;
      if (
        [...selector.querySelectorAll("option")].some(
          (option) => option.value === "fresh",
        )
      ) {
        refuse(
          "first-save",
          protocol +
            ": the selector already held an option for the name this arm saves, so it would prove nothing",
        );
        continue;
      }
      // The state addProvider leaves: the editor open on a blank form and the selector empty.
      open(page);
      selector.value = "";
      page.querySelector(nameField).value = "fresh";
      counter.redirect = "https://jellyfin.example/sso/OID/redirect/fresh";
      counter.park = [];
      let outcome = "never settled";
      save(page, "fresh").then(
        () => {
          outcome = "resolved";
        },
        (error) => {
          outcome = "rejected: " + error.message;
        },
      );
      await settled();
      if (counter.park.length !== 1) {
        refuse(
          "first-save",
          protocol +
            ": the save asked for " +
            counter.park.length +
            " configuration read(s) before its write, so the ordering below is not the one this arm describes",
        );
        counter.park = null;
        counter.redirect = undefined;
        continue;
      }
      counter.park[0].resolve(before());
      await settled();
      if (
        counter.park.length !== 1 + reloadsAfterSave(protocol) ||
        outcome !== "resolved"
      ) {
        refuse(
          "first-save",
          protocol +
            ": a save that should have parked " +
            reloadsAfterSave(protocol) +
            " reads and resolved parked " +
            (counter.park.length - 1) +
            " and " +
            outcome,
        );
        counter.park = null;
        counter.redirect = undefined;
        continue;
      }
      if (selector.value !== "fresh") {
        refuse(
          "first-save",
          protocol +
            ": the save left " +
            selectorId +
            " reading " +
            JSON.stringify(selector.value) +
            " for the provider it had just written, so every reply about that provider is dropped as stale",
        );
      }
      counter.park[1].resolve(after());
      await settled();
      page.querySelector(nameField).value = "";
      counter.park[2].resolve(after());
      await settled();
      counter.park = null;
      if (page.querySelector(nameField).value !== "fresh") {
        refuse(
          "first-save",
          protocol +
            ": the provider read after a first save filled nothing - " +
            nameField +
            " reads " +
            JSON.stringify(page.querySelector(nameField).value),
        );
      }
      if (protocol === "oid") {
        // The fill asks for the address after the code's own timer, so this waits on the clock.
        await new Promise((resolve) => setTimeout(resolve, 400));
        const address = page.querySelector("#OidRedirectUri").value;
        if (address !== counter.redirect) {
          refuse(
            "first-save",
            "the redirect URI after a first save reads " +
              JSON.stringify(address) +
              " rather than the address the server serves, so the wizard's third step refuses the provider it just saved",
          );
        }
      }
      counter.redirect = undefined;
    }
    if (unhandled.length > leaked) {
      refuse(
        "first-save",
        unhandled.length -
          leaked +
          " rejection(s) reached nobody: " +
          unhandled.slice(leaked).join("; "),
      );
    }
  }

  // ---- Arm: a path base in the Base URL Override is accepted, and the plugin's own route is not ----
  // A path base is valid under a mounted Jellyfin (#1712); /sso/ routes, queries and fragments are refused.
  for (const protocol of ["oid", "saml"]) {
    const page = providersFixture();
    const open = protocol === "oid" ? core.showEditor : core.showSamlEditor;
    const validate =
      protocol === "oid" ? core.validateBaseUrl : core.validateSamlBaseUrl;
    const field =
      protocol === "oid" ? "BaseUrlOverride" : "saml-BaseUrlOverride";
    const route =
      protocol === "oid" ? "/sso/OID/redirect/one" : "/sso/SAML/post/one";
    open(page);
    const input = page.querySelector("#" + field);
    const box = page.querySelector("#" + field + "-error");
    if (!input || !box) {
      refuse(
        "path-base",
        protocol +
          ": providersPage.html declares no #" +
          field +
          " with its -error box, so the validator has nothing to write to",
      );
      continue;
    }
    const shown = () => Boolean(!box.hidden && box.textContent);

    input.value = "https://jellyfin.example.com/jellyfin";
    validate(page);
    if (shown()) {
      refuse(
        "path-base",
        protocol +
          ": a path-base override is refused beside the field: " +
          JSON.stringify(box.textContent),
      );
    }
    core.refreshReadiness(page, protocol);
    if (!rowsOf(page)[1].startsWith("Ready - Field warnings - ")) {
      refuse(
        "path-base",
        protocol +
          ": a path-base override is listed under Needs attention: " +
          JSON.stringify(rowsOf(page)[1]),
      );
    }

    for (const wrong of [
      "https://jellyfin.example.com" + route,
      "https://jellyfin.example.com/jellyfin?x=1",
      "https://jellyfin.example.com/jellyfin#top",
    ]) {
      input.value = wrong;
      validate(page);
      if (!shown()) {
        refuse(
          "path-base",
          protocol + ": " + wrong + " is accepted as a base URL",
        );
      } else if (/no path/i.test(box.textContent)) {
        refuse(
          "path-base",
          protocol +
            ": the refusal still calls the path itself the error: " +
            JSON.stringify(box.textContent),
        );
      }
    }
    core.refreshReadiness(page, protocol);
    if (!rowsOf(page)[1].includes(nameOf(core, page, field))) {
      refuse(
        "path-base",
        protocol +
          ": a refused override is not named by the warnings row: " +
          JSON.stringify(rowsOf(page)[1]),
      );
    }
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
    "  selector-survives  a save whose configuration read lands before its provider read keeps the",
  );
  console.log(
    "                   page's record of which provider it is about: the reply still lands, and a",
  );
  console.log(
    "                   managed provider is still frozen, on both protocols (#1696)",
  );
  console.log(
    "  first-save       a provider saved under a name no option held yet still names itself: the",
  );
  console.log(
    "                   reply lands, and on OpenID the redirect URI arrives, on both protocols (#1710)",
  );
  console.log(
    "  path-base        a Base URL Override carrying Jellyfin's path base passes the validator and",
  );
  console.log(
    "                   leaves the warnings row Ready; the plugin's own /sso/... route, a query and a",
  );
  console.log(
    "                   fragment are still refused without calling the path the error (#1712)",
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
