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
const PROVIDERS_PAGE = path.join(root, "SSO-Auth", "Web", "providersPage.html");

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

/**
 * The Providers page, which is the only one that carries an editor - two of them - and the two library
 * checklists a re-read used to empty (#1576). The regions are asserted against the markup like every
 * other fixture's, so a renamed editor or checklist container fails here rather than passing silently.
 */
function providersPageFixture() {
  return pageFixture(PROVIDERS_PAGE, [
    "sso-unsaved",
    "sso-editor",
    "saml-editor",
    "EnabledFolders",
    "saml-EnabledFolders",
  ]);
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

  // The editors ship `hidden` in the markup, and a fixture that started them open would make the
  // refresh refuse for a reason the arm did not set up. Read off the tag rather than assumed, so a
  // region that stops shipping hidden fails an arm here instead of quietly changing what it proves.
  regions.forEach((region) => {
    // Read by cutting the tag out around the id rather than by matching one, because an opening tag in
    // this markup runs over several lines and a pattern for it is a second thing to get wrong.
    const at = html.indexOf('id="' + region.id + '"');
    const tag =
      at === -1
        ? ""
        : html.slice(html.lastIndexOf("<", at), html.indexOf(">", at) + 1);
    region.hidden = tag.split(/[\s>]+/).includes("hidden");
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

  // ---- The refresh on return to a tab (#1576) ----
  //
  // WHAT THESE FIVE ARMS CAN AND CANNOT SAY. The subject is the DECISION - whether the refresh runs at
  // all, and whether the fill it triggers writes anything - so the fills themselves are substituted and
  // counted rather than executed. That is the honest bound: an arm below reddens when a guard is taken
  // off, and none of them says the fills are correct, which is what every other route over this file
  // already asks. The configuration fetch is substituted for the same reason, and because the stub is
  // node and `ApiClient` is the dashboard's.
  //
  // The order is the issue's: the library-checklist case first, because it is the one that costs users
  // their libraries.
  const refreshHarness = (page) => {
    const original = {
      loadManagedProviders: core.loadManagedProviders,
      showUnreadableConfigurationNotice: core.showUnreadableConfigurationNotice,
      populateProviders: core.populateProviders,
      populateSamlProviders: core.populateSamlProviders,
      populateProvisioningProfiles: core.populateProvisioningProfiles,
      renderOverviewFrom: core.renderOverviewFrom,
      populateFolders: core.populateFolders,
      apiClient: globalThis.ApiClient,
    };
    const seen = { folders: 0, fills: 0 };
    let settle = null;
    core.loadManagedProviders = () => {};
    core.showUnreadableConfigurationNotice = () => Promise.resolve();
    core.populateProviders = () => {};
    core.populateSamlProviders = () => {};
    // The checklist fill is a REQUEST OF ITS OWN and it appends id-less checkboxes the signature counts,
    // so the substitute has to do both of those things or the arms cannot see the ordering that broke
    // the baseline. It settles when the arm says so, not when it is called.
    let releaseFolders = null;
    core.populateFolders = (container) => {
      seen.folders += 1;
      return new Promise((resolve) => {
        const previous = releaseFolders;
        releaseFolders = () => {
          if (previous) {
            previous();
          }
          const box = new Element("input", "", "checkbox");
          page.elements.push(box);
          container.appended = (container.appended || 0) + 1;
          resolve();
        };
      });
    };
    // The fill counter is on the ONE call the `.then` makes unconditionally. Counting on
    // populateProviders instead reads zero on the Server page, which has no #selectProvider - so the
    // in-flight arm's first assertion would have been vacuous there.
    core.populateProvisioningProfiles = () => {
      seen.fills += 1;
    };
    core.renderOverviewFrom = () => {};
    globalThis.ApiClient = {
      getUrl: (u) => u,
      getJSON: () => Promise.resolve({}),
      getPluginConfiguration: () =>
        new Promise((resolve) => {
          settle = () => resolve({ OidConfigs: {}, SamlConfigs: {} });
        }),
    };
    // Enough turns to drain the chain the load builds: the configuration `.then`, the Promise.all over
    // the checklist fills, and the `.then` that takes the baseline. Counted generously rather than
    // exactly, because an arm that under-drains passes by not looking.
    const drain = async () => {
      for (let turn = 0; turn < 12; turn += 1) {
        await Promise.resolve();
      }
    };
    return {
      seen,
      drain,
      // Answers the CONFIGURATION request. The checklist fills stay outstanding, which is the ordering
      // that broke the baseline and the one an arm has to be able to produce.
      deliver: async () => {
        settle();
        await drain();
      },
      // Answers the checklist fills, appending their controls, after the configuration has landed.
      deliverFolders: async () => {
        if (releaseFolders) {
          releaseFolders();
          releaseFolders = null;
        }
        await drain();
      },
      restore: () => {
        Object.keys(original).forEach((key) => {
          if (key !== "apiClient") {
            core[key] = original[key];
          }
        });
        globalThis.ApiClient = original.apiClient;
      },
      page,
    };
  };

  // ---- Arm: the library checklists are not rebuilt by a refresh ----
  {
    const page = providersPageFixture();
    wire(core, page);
    const h = refreshHarness(page);
    core.loadConfiguration(page, { refreshing: true });
    await h.deliver();
    if (h.seen.folders !== 0) {
      refuse(
        "refresh-folders",
        "a refresh repopulated a library checklist, which rebuilds it with nothing ticked and does not run loadProvider - the next save then persists an empty EnabledFolders and every user of that provider loses library access",
      );
    }
    // The near-miss: an ordinary load - a save, a delete, an import reading itself back - must still
    // fill them. A guard that skipped the checklists for every caller would pass the arm above.
    core.loadConfiguration(page);
    await h.deliver();
    h.restore();
    if (h.seen.folders === 0) {
      refuse(
        "refresh-folders",
        "an ordinary load stopped filling the library checklists, so an editor opened after a save shows none",
      );
    }
  }

  // ---- Arm: the baseline covers the checklist fills, not just the configuration ----
  {
    // The ordering that broke this, reproduced: a load is THREE requests, and the configuration answers
    // before the two checklist reads. Each of those appends id-less checkboxes the signature counts, so
    // a baseline taken in the configuration `.then` alone left the Providers page differing from its own
    // baseline for the life of the view - the refresh then refused forever AND the page asserted unsaved
    // changes on a tab nobody had touched, which is the indicator that says a real edit is at risk.
    const page = providersPageFixture();
    wire(core, page);
    const h = refreshHarness(page);
    core.loadConfiguration(page);
    await h.deliver();
    if (h.seen.folders !== 2) {
      refuse(
        "refresh-baseline",
        "the fixture issued no checklist fill, so this arm cannot produce the ordering it is about",
      );
    }
    await h.deliverFolders();
    const differs = core.pageDiffersFromBaseline(page);

    const loads = [];
    const real = core.loadConfiguration;
    core.loadConfiguration = (_, options) => loads.push(options);
    core.refreshOnShow(page);
    core.loadConfiguration = real;
    h.restore();

    if (differs) {
      refuse(
        "refresh-baseline",
        "a page nobody touched differed from its own baseline once the library checklists landed, so the baseline does not cover the whole load",
      );
    }
    if (loads.length !== 1) {
      refuse(
        "refresh-baseline",
        "the tab refused to re-read on a page nobody had touched, so the refresh never runs on Providers at all",
      );
    }
    if (core.isPageDirty(page)) {
      refuse(
        "refresh-baseline",
        "the page asserted unsaved changes with nothing typed and no editor open, which trains away the indicator that says a real edit is at risk",
      );
    }
  }

  // ---- Arm: an open editor refuses the refresh outright ----
  {
    const page = providersPageFixture();
    wire(core, page);
    const editor = page.querySelector("#sso-editor");
    if (editor.hidden !== true) {
      refuse(
        "refresh-editor",
        "the fixture starts with the editor open, so this arm proves nothing",
      );
    }
    const loads = [];
    const real = core.loadConfiguration;
    core.loadConfiguration = (_, options) => loads.push(options);

    editor.hidden = false;
    core.refreshOnShow(page);
    if (loads.length !== 0) {
      refuse(
        "refresh-editor",
        "a tab returned to with the editor open re-read the server, which clears the hidden selector the save reads its target from and empties the checklists",
      );
    }

    editor.hidden = true;
    core.refreshOnShow(page);
    core.loadConfiguration = real;
    if (loads.length !== 1) {
      refuse(
        "refresh-editor",
        "a clean tab with every editor closed did not re-read, so it goes on showing whatever it last loaded",
      );
    }
  }

  // ---- Arm: a removed row is an unsaved edit, and nothing dispatched an event for it ----
  {
    const page = policiesPageFixture();
    wire(core, page);
    const notice = page.querySelector("#sso-unsaved");
    // Removing a permission row is `row.remove()`: no input, no change, so the tracking never runs and
    // the page is never MARKED dirty. The decision must read the controls, not the mark.
    // A control the state actually tracks, taken from the page's own list rather than guessed: the first
    // control on this page is the profile SELECTOR, which is excluded as a navigation control, so
    // removing that one would change no signature and the arm would prove nothing.
    const removed = core.editableControls(page)[0];
    page.elements.splice(page.elements.indexOf(removed), 1);
    page.byId.delete(removed.id);
    if (core.isPageDirty(page)) {
      refuse(
        "refresh-removed-row",
        "the fixture was already marked dirty, so this arm cannot tell the mark from the signature",
      );
    }
    const loads = [];
    const real = core.loadConfiguration;
    core.loadConfiguration = () => loads.push(1);
    core.refreshOnShow(page);
    core.loadConfiguration = real;
    if (loads.length !== 0) {
      refuse(
        "refresh-removed-row",
        "a page holding a removed row re-read the server, which renders the removed row straight back out of storage",
      );
    }
    if (!core.isPageDirty(page) || notice.hidden) {
      refuse(
        "refresh-removed-row",
        "the tab refused to refresh and said nothing about why",
      );
    }
  }

  // ---- Arm: an edit made while the configuration is in flight is not overwritten ----
  {
    const page = serverPageFixture();
    wire(core, page);
    const h = refreshHarness(page);
    const toggle = page.querySelector("#ManageLoginPageButtons");

    core.loadConfiguration(page, { refreshing: true });
    // The decision has been taken and the request is out. Now an administrator types.
    toggle.checked = true;
    page.dispatch("change", toggle, true);
    await h.deliver();
    h.restore();

    if (h.seen.fills !== 0) {
      refuse(
        "refresh-in-flight",
        "a refresh overtaken by an edit went on filling the page, which is the check-then-act the review refused",
      );
    }
    if (!toggle.checked || !core.isPageDirty(page)) {
      refuse(
        "refresh-in-flight",
        "an edit made while the configuration was in flight was reverted and the page then read as clean",
      );
    }
  }

  // ---- Arm: an editor opened while the refresh is in flight also stops the fill ----
  {
    // `mayReplacePageContents` is a conjunction and the arm above only exercises the dirty half. This is
    // the other one, and it is the half with the worse outcome: `populateProviders` clears the hidden
    // #selectProvider, whose value is the provider a save writes to, so a fill landing into a freshly
    // opened editor writes the wrong provider or none at all. It has to be on the Providers page,
    // because the Server page declares no editor and could never reach this.
    const page = providersPageFixture();
    wire(core, page);
    const h = refreshHarness(page);

    core.loadConfiguration(page, { refreshing: true });
    // The decision has been taken and the request is out. Now an administrator clicks a provider card.
    page.querySelector("#sso-editor").hidden = false;
    await h.deliver();
    h.restore();

    if (h.seen.fills !== 0) {
      refuse(
        "refresh-in-flight-editor",
        "a refresh overtaken by an opened editor went on filling the page, which clears the hidden selector the save reads its target from",
      );
    }
  }

  // ---- Arm: an ordinary load still replaces the page, whatever state it is in ----
  {
    // The near-miss for the two guards above. A save, a delete or an import has just changed the stored
    // configuration and is reading it back; it must write the page even with an editor open and the page
    // dirty, or every one of those paths stops showing its own result.
    const page = providersPageFixture();
    wire(core, page);
    const h = refreshHarness(page);
    page.querySelector("#sso-editor").hidden = false;
    const toggle = page.querySelector("#OidEnabled");
    if (toggle) {
      toggle.checked = !toggle.checked;
      page.dispatch("change", toggle, true);
    }

    core.loadConfiguration(page);
    await h.deliver();
    h.restore();

    if (h.seen.fills !== 1) {
      refuse(
        "refresh-ordinary-load",
        "an ordinary load refused to write the page, so a save no longer shows what it saved",
      );
    }
  }

  // ---- The managed set survives a failed read (#1589) ----
  //
  // WHAT THIS ARM CAN AND CANNOT SAY, and the bound is the same one this file's header states. It judges
  // the DATA the freeze is decided from and not the freeze itself: the stub has no tree, so
  // `applyManagedState` - which walks a form's own children - cannot run here at all, and the note this
  // change paints is outside every arm in this file. What IS reachable is the failure arm of
  // `loadManagedProviders` and the two predicates the editors ask, and that is where #1589's defect sat: a
  // rejected read emptied the set, every provider a configuration file owns answered `false`, and the
  // editor rendered an ordinary editable form over a value the server would refuse to change.
  {
    const originalClient = globalThis.ApiClient;
    const originalSet = core.managedProviders;
    const originalUnread = core.managedReportUnread;
    let rejecting = false;
    globalThis.ApiClient = {
      getUrl: (url) => url,
      getJSON: () =>
        rejecting
          ? Promise.reject(new Error("sso/Config/Managed answered 500"))
          : Promise.resolve({
              OidConfigs: ["file-owned"],
              SamlConfigs: [],
              ProvisioningProfiles: ["file-profile"],
            }),
    };

    // The report arrives once, which is the state a transient failure then has to survive.
    await core.loadManagedProviders();
    if (!core.isManagedProvider("oid", "file-owned")) {
      refuse(
        "managed-report-failure",
        "a served report did not mark the provider it names as managed, so this arm would prove nothing",
      );
    }

    rejecting = true;
    await core.loadManagedProviders();
    if (!core.isManagedProvider("oid", "file-owned")) {
      refuse(
        "managed-report-failure",
        "a failed read unfroze a provider a configuration file owns",
      );
    }
    if (!core.isManagedProfile("file-profile")) {
      refuse(
        "managed-report-failure",
        "a failed read unfroze a profile a configuration file defines",
      );
    }
    if (!core.managedReportUnread) {
      refuse(
        "managed-report-failure",
        "a failed read left the page claiming it knows what is managed",
      );
    }
    // The freeze that survives now rests on the last answer rather than a current one, and the note the
    // FROZEN editor paints has to say so. The note itself is out of reach here - the stub has no tree - so
    // what is judged is the sentence the two editors append, which is where that qualifier lives.
    if (core.staleReportSuffix() === "") {
      refuse(
        "managed-report-failure",
        "a frozen editor said nothing about the read that failed underneath it",
      );
    }

    // The same qualifier has to reach the messages that REFUSE an act, which is where a wrong certainty
    // costs something: they send an administrator to a source that may no longer define what they are
    // being refused. Driven through the shipped refusal rather than by reading the string, so the arm
    // reddens when the append is dropped from the call site.
    {
      const profilePage = policiesPageFixture();
      const selector = profilePage.querySelector("#selectProvisioningProfile");
      selector.value = "file-profile";
      const said = [];
      const realStatus = core.provisioningProfileStatus;
      core.provisioningProfileStatus = (_page, message) => said.push(message);
      core.deleteProvisioningProfile(profilePage);
      core.provisioningProfileStatus = realStatus;
      if (said.length !== 1) {
        refuse(
          "managed-report-failure",
          "the delete of a managed profile said something other than one thing, so this arm proves nothing",
        );
      } else if (!said[0].endsWith(core.staleReportSuffix())) {
        refuse(
          "managed-report-failure",
          "a refusal sent an administrator to a configuration file without saying the report was unread",
        );
      }
    }

    // And the unfrozen note is a decision about a name, so both directions are asked: a loaded editor
    // says the report failed, a blank add-new form says nothing at all.
    if (core.unreadNoteFor("some-provider") === "") {
      refuse(
        "managed-report-failure",
        "an unfrozen editor looked identical to a provider nothing owns",
      );
    }
    if (core.unreadNoteFor("") !== "") {
      refuse(
        "managed-report-failure",
        "the blank add-new form warned about ownership of a provider that does not exist yet",
      );
    }

    // And the flag comes back off, so one transient failure does not leave every editor after it carrying
    // a warning about a report that is now being read fine.
    rejecting = false;
    await core.loadManagedProviders();
    if (core.managedReportUnread) {
      refuse(
        "managed-report-failure",
        "a report that was read again went on being reported as unread",
      );
    }
    if (core.staleReportSuffix() !== "") {
      refuse(
        "managed-report-failure",
        "a frozen editor went on warning about a report that is being read fine",
      );
    }
    if (core.unreadNoteFor("some-provider") !== "") {
      refuse(
        "managed-report-failure",
        "an unfrozen editor went on warning about a report that is being read fine",
      );
    }

    globalThis.ApiClient = originalClient;
    core.managedProviders = originalSet;
    core.managedReportUnread = originalUnread;
  }

  if (faults.length) {
    faults.forEach((fault) => console.error(fault));
    console.error(
      faults.length + " refusal(s) in the unsaved-changes state (#1572)",
    );
    process.exit(1);
  }

  console.log(
    "unsaved state:     sixteen arms run against the shipped sso-core.js and the pages it serves",
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
  console.log(
    "  refresh-folders  a refresh leaves the library checklists alone, and an ordinary load fills them",
  );
  console.log(
    "  refresh-baseline the baseline covers the checklist fills, so an untouched tab re-reads and stays quiet",
  );
  console.log(
    "  refresh-editor   an open editor refuses the refresh, a closed one lets it run",
  );
  console.log(
    "  refresh-removed  a removed row refuses the refresh and the page says so",
  );
  console.log(
    "  refresh-in-flight an edit made while the configuration was in flight is not overwritten,",
  );
  console.log(
    "                   and neither is an editor opened inside the same window",
  );
  console.log(
    "  refresh-ordinary a save, delete or import still replaces the page whatever state it is in",
  );
  console.log(
    "  managed-report-failure a failed managed-set read keeps the last set it read and says it failed",
  );
}

main().catch((error) => {
  console.error(String((error && error.stack) || error));
  process.exit(1);
});
