#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Runs the REAL unsaved-changes state of sso-core.js against the REAL Server
 * page and refuses each way it can be wrong (#1572).
 *
 * WHY THIS EXISTS AS A RUNNING PROOF AND NOT AS A CONFORMANCE RULE. Every other
 * rule this repository has over the admin assets reads their TEXT: the C# rules
 * in ArchitectureConformanceTests.WebUi ask whether the surface still carries a
 * field, a marker class or a call, and tools/ui-mock-fields.js asks where each
 * control lives. Neither can ask what the code DOES, and what #1572 asks for is
 * behaviour: a page with an untouched control is not dirty, a page with a
 * changed one is and says so, and a Save closed by two different parties stays
 * closed while either of them wants it closed. A text rule matching a token
 * passes on a file where the condition around it is inverted, and inverted is
 * exactly how this state fails.
 *
 * WHY IT IS NODE AND NOT A BROWSER OR A DOM LIBRARY. The means check, per the
 * standpoint: node is already carried by this tree - tools/ui-mock-fields.js is
 * run by the .NET workflow with no install - and a DOM library would add a
 * dependency and a lockfile to a repository that has neither. What that costs is
 * stated below rather than hidden.
 *
 * WHAT THE STUB CAN AND CANNOT SAY, AND THIS BOUND IS THE PART TO READ. The DOM
 * below is a stub: id lookup, tag filtering, a class list, a dataset, and a
 * direct call of the page's own listeners. It is NOT a browser and it has NO
 * TREE, so it has no propagation and no phases - which means it cannot judge the
 * capture-phase registration `sso-core.js` calls load-bearing, and a mutation
 * turning that capture into a bubble passes every arm below. That property was
 * measured in a real browser instead, and the measurement is recorded at the
 * code it is about rather than here.
 *
 * It also cannot say anything about layout, about which listener a real browser
 * would run first, or about an event a real control emits that this stub does
 * not. What keeps it from being a proof about ITSELF is that the CONTROLS are
 * read out of the shipped serverPage.html by the same regex
 * tools/ui-mock-fields.js counts with - so a control removed from the page is
 * removed from this fixture - and that the code under test is the shipped
 * sso-core.js loaded whole, not a copy and not an extract.
 *
 * WHY THE MODULE IS LOADED THROUGH A DATA URL. sso-core.js is an ES module and
 * this tree carries no package.json, so node would read a `.js` file as
 * CommonJS and fail on its `export`. Importing the bytes as a data: URL loads
 * the same source as a module without writing a temporary file beside the tree.
 *
 * EVERY LEG REFUSES BY NAME AND THE PASS IS PRINTED. A proof whose result
 * nobody sees reads exactly like one that never ran.
 */

"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const CORE = path.join(root, "SSO-Auth", "Web", "sso-core.js");
const SERVER_PAGE = path.join(root, "SSO-Auth", "Web", "serverPage.html");
const POLICIES_PAGE = path.join(root, "SSO-Auth", "Web", "policiesPage.html");

/** Replaces every HTML comment with spaces, so a documented control is not a real one. */
function withoutComments(html) {
  return html.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, " "));
}

/** The value of `name="..."` where the name starts an attribute, as ui-mock-fields.js reads it. */
function attr(tag, name) {
  const m = tag.match(new RegExp("(?<![-\\w])" + name + '="([^"]*)"'));
  return m ? m[1] : "";
}

// ---------------------------------------------------------------------------
// The stub. Small on purpose: every method here is one the code under test
// calls, and nothing is added for completeness.
// ---------------------------------------------------------------------------

class Classes {
  constructor() {
    this.set = new Set();
  }
  add(name) {
    this.set.add(name);
  }
  remove(...names) {
    names.forEach((name) => this.set.delete(name));
  }
  contains(name) {
    return this.set.has(name);
  }
}

class Element {
  constructor(tag, id, type) {
    this.tag = tag;
    this.id = id;
    this.type = type;
    this.value = "";
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.textContent = "";
    this.dataset = {};
    this.classList = new Classes();
  }
}

class Page {
  constructor(elements) {
    this.elements = elements;
    this.byId = new Map(elements.map((e) => [e.id, e]));
    this.dataset = {};
    this.classList = new Classes();
    this.listeners = new Map();
  }

  querySelector(selector) {
    if (!selector.startsWith("#")) {
      throw new Error("the stub resolves id selectors only: " + selector);
    }
    return this.byId.get(selector.slice(1)) || null;
  }

  querySelectorAll(selector) {
    const tags = selector.split(",").map((s) => s.trim());
    return this.elements.filter((e) => tags.includes(e.tag));
  }

  addEventListener(name, handler) {
    if (!this.listeners.has(name)) {
      this.listeners.set(name, []);
    }
    this.listeners.get(name).push(handler);
  }

  /** Dispatches one event. `trusted` is the property the whole design rests on. */
  dispatch(name, target, trusted) {
    (this.listeners.get(name) || []).forEach((handler) =>
      handler({ isTrusted: trusted, target, type: name }),
    );
  }
}

/**
 * A Page carrying every form control the shipped Server page declares, plus the
 * two regions the state writes into. Read from the markup rather than typed
 * here, so a control that leaves the page leaves this fixture with it.
 */
function serverPageFixture() {
  return pageFixture(SERVER_PAGE, [
    "sso-unsaved",
    "sso-page-status",
    "SaveServerSettings",
  ]);
}

/**
 * The Policies page, where the Save gate actually DECIDES something: its gate
 * has no region and one required control, so both directions of
 * `updateSaveAvailability` are reachable. The Server page cannot judge it - that
 * gate carries an empty required set and can never block.
 */
function policiesPageFixture() {
  return pageFixture(POLICIES_PAGE, ["sso-unsaved", "SaveProvisioningProfile"]);
}

function pageFixture(file, regionIds) {
  const html = withoutComments(fs.readFileSync(file, "utf8"));
  const controls = [
    ...html.matchAll(/<(input|select|textarea)\b[\s\S]*?>/g),
  ].map((m) => new Element(m[1], attr(m[0], "id"), attr(m[0], "type") || m[1]));
  if (controls.length === 0) {
    throw new Error(
      path.basename(file) +
        " declares no form control, so this fixture would prove nothing",
    );
  }

  // The regions the state writes into. Their ids are asserted against the page
  // below rather than trusted, because a renamed region silently turns every
  // render into a no-op that this stub would otherwise report as a pass.
  const regions = regionIds.map((id) => new Element("div", id, "div"));
  const declared = new Set(
    [...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]),
  );
  regions.forEach((region) => {
    if (!declared.has(region.id)) {
      throw new Error(
        path.basename(file) +
          " declares no #" +
          region.id +
          ", so the state would render into nothing",
      );
    }
  });

  return new Page([...controls, ...regions]);
}

// ---------------------------------------------------------------------------
// The legs.
// ---------------------------------------------------------------------------

async function loadCore() {
  const source = fs.readFileSync(CORE, "utf8");
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64");
  return (await import(url)).default;
}

/**
 * Wires one fixture the way initSharedPage does: bind the tracking, then take
 * the baseline. Nothing is substituted - every function under test is the
 * shipped one.
 */
function wire(core, page) {
  core.bindUnsavedChangeTracking(page);
  core.markPageClean(page);
}

async function main() {
  const core = await loadCore();
  const faults = [];
  const refuse = (leg, detail) => faults.push(leg + ": " + detail);

  // ---- Arm one: a page with an untouched control ----
  {
    const page = serverPageFixture();
    wire(core, page);
    const notice = page.querySelector("#sso-unsaved");
    const save = page.querySelector("#SaveServerSettings");

    if (core.isPageDirty(page)) {
      refuse("untouched", "a page nobody has typed into reads as dirty");
    }
    if (!notice.hidden || notice.textContent !== "") {
      refuse("untouched", "the unsaved indicator is showing on a clean page");
    }

    if (save.disabled) {
      refuse(
        "untouched",
        "the Save is closed on a page with nothing left to fill in",
      );
    }
  }

  // ---- Arm two: a page with a changed control ----
  {
    const page = serverPageFixture();
    wire(core, page);
    const notice = page.querySelector("#sso-unsaved");
    const toggle = page.querySelector("#ManageLoginPageButtons");

    toggle.checked = true;
    page.dispatch("change", toggle, true);

    if (!core.isPageDirty(page)) {
      refuse(
        "changed",
        "a control an administrator changed did not mark the page dirty",
      );
    }
    if (notice.hidden || notice.textContent === "") {
      refuse("changed", "the unsaved indicator is hidden on a dirty page");
    }
    // The sentence has to name the loss, not merely announce a state: an
    // indicator that says "unsaved changes" and nothing about what ends them is
    // one an administrator learns to ignore.
    if (!/lost/.test(notice.textContent)) {
      refuse(
        "changed",
        "the indicator does not say what happens to the changes: " +
          notice.textContent,
      );
    }
    // And it goes away again when the page is read afresh.
    core.markPageClean(page);
    if (core.isPageDirty(page) || !notice.hidden) {
      refuse("changed", "a page read afresh went on showing the indicator");
    }
  }

  // ---- The host's own synthetic events, in both directions ----
  //
  // `emby-checkbox` toggles `checked` and dispatches its own bubbling
  // CustomEvent('change') when the control is operated from the KEYBOARD, and
  // `emby-select` dispatches `new Event('change', { bubbles: false })` when the
  // action sheet sets a value. Both carry isTrusted false. A state that read
  // that flag would let a keyboard user change every switch on this page while
  // it went on reading as clean, and the next return to the tab would discard
  // the lot - so the flag is not read, and these two arms are why.
  {
    // The value moved with the synthetic event: that is a person, and it is dirty.
    const page = serverPageFixture();
    wire(core, page);
    const toggle = page.querySelector("#ManageLoginPageButtons");
    toggle.checked = true;
    page.dispatch("change", toggle, false);
    if (!core.isPageDirty(page)) {
      refuse(
        "host-synthetic",
        "a switch changed from the keyboard did not mark the page dirty, so the next tab return would discard it",
      );
    }
  }
  {
    // The value did NOT move: whoever dispatched it changed nothing, so nothing
    // is unsaved. This is the arm that keeps the comparison from reading every
    // event as an edit.
    const page = serverPageFixture();
    wire(core, page);
    const toggle = page.querySelector("#ManageLoginPageButtons");
    page.dispatch("change", toggle, false);
    page.dispatch("change", toggle, true);
    if (core.isPageDirty(page)) {
      refuse(
        "no-op-event",
        "an event that moved no value marked the page dirty",
      );
    }
  }
  {
    // And back again: a control changed and then changed back holds nothing
    // unsaved, which is the same comparison read in the other direction.
    const page = serverPageFixture();
    wire(core, page);
    const toggle = page.querySelector("#ManageLoginPageButtons");
    toggle.checked = true;
    page.dispatch("change", toggle, true);
    toggle.checked = false;
    page.dispatch("change", toggle, true);
    if (core.isPageDirty(page)) {
      refuse(
        "undone",
        "a control changed and changed back left the page reading as edited",
      );
    }
  }

  // ---- The two exclusions, each in its own arm ----
  {
    const page = serverPageFixture();
    wire(core, page);
    const file = page.querySelector("#ImportConfigFile");
    // The chooser really does put a name on the control, so the arm has to move
    // the value: a dispatch that changed nothing would pass whether the input is
    // excluded or not.
    file.value = "sso-config.json";
    page.dispatch("change", file, true);
    if (core.isPageDirty(page)) {
      refuse(
        "file-input",
        "choosing a file to import marked the page dirty, so the tab would stop refreshing over a control nothing saves",
      );
    }
  }
  {
    // A navigation control refills the form, so it CLEANS a dirty page rather
    // than dirtying it. Run on a page that is dirty first, because a leg that
    // starts clean cannot tell "cleans" from "does nothing".
    const page = serverPageFixture();
    wire(core, page);
    const toggle = page.querySelector("#ManageLoginPageButtons");
    toggle.checked = true;
    page.dispatch("change", toggle, true);
    if (!core.isPageDirty(page)) {
      refuse(
        "navigation",
        "the fixture for this leg never became dirty, so it proves nothing",
      );
    }
    const selector = new Element("select", "selectProvider", "select");
    page.elements.push(selector);
    page.byId.set(selector.id, selector);
    page.dispatch("change", selector, true);
    if (core.isPageDirty(page)) {
      refuse(
        "navigation",
        "choosing another provider left the page reading as edited",
      );
    }
  }

  // ---- The Save gate, in the direction that is a fail-open ----
  //
  // The freeze on a provider or a profile a configuration file owns (#1104)
  // disables that form's Save, and the gate must not hand it back when it finds
  // nothing of its own left to block. The first draft of the gate did exactly
  // that, by remembering what IT had disabled instead of reading what the freeze
  // declares; the sequence below is the reproduction, in the order the Policies
  // tab produces it.
  {
    const page = serverPageFixture();
    wire(core, page);
    const save = page.querySelector("#SaveServerSettings");

    // 1. the gate closes it for its own reason
    core.setSaveBlocked(save, true);
    if (!save.disabled) {
      refuse(
        "save-gate",
        "the gate did not close a Save it had a reason to close",
      );
    }

    // 2. the freeze closes it for its own, and says so where the gate can read it
    save.disabled = true;
    save.dataset.ssoManaged = "true";

    // 3. the gate's reason goes away
    core.setSaveBlocked(save, false);
    if (!save.disabled) {
      refuse(
        "save-gate",
        "the gate handed back a Save the declarative-source freeze had closed",
      );
    }

    // ... and the freeze lifting is what re-opens it, not the gate forgetting.
    save.dataset.ssoManaged = "";
    core.setSaveBlocked(save, false);
    if (save.disabled) {
      refuse(
        "save-gate",
        "the Save stayed closed after both reasons were gone, so nothing can re-open it",
      );
    }
  }

  // ---- The gate's decision, in both directions ----
  //
  // On the Policies page the profile Save carries one required control and no
  // region, so both answers are reachable. The Server page cannot judge this:
  // its gate has an empty required set and can never block, which is why an
  // earlier version of this file proved nothing about the decision at all.
  {
    const page = policiesPageFixture();
    const save = page.querySelector("#SaveProvisioningProfile");
    const selector = page.querySelector("#selectProvisioningProfile");
    wire(core, page);

    if (!save.disabled) {
      refuse(
        "gate-decision",
        "the profile Save is open with no profile selected, and a save then has nothing to write to",
      );
    }

    selector.value = "Standard";
    page.dispatch("change", selector, true);
    if (save.disabled) {
      refuse(
        "gate-decision",
        "the profile Save stayed closed after a profile was selected",
      );
    }
  }

  // ---- The hidden-region skip ----
  //
  // A gate whose editor is closed must be left alone: the button is unreachable
  // and writing to it would fight whoever hid it.
  {
    const page = policiesPageFixture();
    wire(core, page);
    const save = page.querySelector("#SaveProvisioningProfile");
    save.disabled = false;
    // Give this gate a region and hide it, the shape the two provider gates have.
    const region = new Element("div", "sso-editor", "div");
    region.hidden = true;
    page.elements.push(region);
    page.byId.set(region.id, region);
    const gates = core.saveGates;
    core.saveGates = () =>
      gates().map((gate) =>
        gate.button === "#SaveProvisioningProfile"
          ? { ...gate, region: "#sso-editor" }
          : gate,
      );
    core.updateSaveAvailability(page);
    core.saveGates = gates;
    if (save.disabled) {
      refuse(
        "hidden-region",
        "the gate closed a Save inside an editor that is not on screen",
      );
    }
  }

  if (faults.length) {
    faults.forEach((fault) => console.error(fault));
    console.error(
      faults.length + " refusal(s) in the unsaved-changes state (#1572)",
    );
    process.exit(1);
  }

  console.log(
    "unsaved state:     eight arms run against the shipped sso-core.js and the pages it serves",
  );
  console.log(
    "  untouched        a page nobody typed into is clean, shows nothing, and its Save is open",
  );
  console.log(
    "  changed          a changed control marks it dirty and the line names what is at stake",
  );
  console.log(
    "  host-synthetic   a switch changed from the keyboard marks it dirty despite isTrusted=false",
  );
  console.log(
    "  file-input       choosing a file to import does not mark it dirty",
  );
  console.log(
    "  navigation       choosing another provider cleans a dirty page instead of dirtying it",
  );
  console.log(
    "  no-op / undone   an event that moved nothing, and a change undone, leave it clean",
  );
  console.log(
    "  save-gate        the gate never re-enables a Save that something else disabled",
  );
  console.log(
    "  gate-decision    the profile Save is closed with no profile selected and open with one",
  );
  console.log(
    "  hidden-region    a gate whose editor is off screen is left alone",
  );
}

main().catch((error) => {
  console.error(String((error && error.stack) || error));
  process.exit(1);
});
