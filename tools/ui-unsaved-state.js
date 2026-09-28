#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Runs the shipped sso-core.js unsaved-changes state against the shipped admin pages
 * and refuses each way it can be wrong (#1572). Controls are read from the markup and
 * the module is loaded whole through a data URL, since the tree has no package.json.
 * The stub has no tree, so it cannot judge capture-phase listeners.
 * Run with `node tools/ui-unsaved-state.js`; no dependencies.
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

// The stub: only the methods the code under test calls.

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

/** A Page carrying every control the shipped Server page declares, read from the markup. */
function serverPageFixture() {
  return pageFixture(SERVER_PAGE, [
    "sso-unsaved",
    "sso-page-status",
    "SaveServerSettings",
  ]);
}

/**
 * The Policies page, whose profile Save gate can answer both ways; the Server page's
 * gate has an empty required set and never blocks.
 */
function policiesPageFixture() {
  return pageFixture(POLICIES_PAGE, ["sso-unsaved", "SaveProvisioningProfile"]);
}

/** The Providers page: its two editors and the library checklists a re-read used to empty (#1576). */
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
  ].map((m) => {
    const control = new Element(
      m[1],
      attr(m[0], "id"),
      attr(m[0], "type") || m[1],
    );
    // Read off the tag, since the state leaves read-only controls out of the baseline (#1701).
    control.readOnly = m[0].split(/[\s>]+/).includes("readonly");
    return control;
  });
  if (controls.length === 0) {
    throw new Error(
      path.basename(file) +
        " declares no form control, so this fixture would prove nothing",
    );
  }

  // Region ids are asserted against the page, so a renamed region fails instead of passing.
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

  // The editors ship hidden; read off the tag so a change to that fails an arm.
  regions.forEach((region) => {
    // Cut the tag out around the id, since an opening tag here spans several lines.
    const at = html.indexOf('id="' + region.id + '"');
    const tag =
      at === -1
        ? ""
        : html.slice(html.lastIndexOf("<", at), html.indexOf(">", at) + 1);
    region.hidden = tag.split(/[\s>]+/).includes("hidden");
  });

  return new Page([...controls, ...regions]);
}

// The legs.

async function loadCore() {
  const source = fs.readFileSync(CORE, "utf8");
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64");
  return (await import(url)).default;
}

/** Wires one fixture the way initSharedPage does: bind the tracking, then take the baseline. */
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
    // The sentence must name the loss, not merely announce a state.
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
  // emby-checkbox and emby-select dispatch untrusted change events for keyboard and
  // action-sheet edits, so the state must not read isTrusted.
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
    // The value did not move, so nothing is unsaved.
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
    // Changed and changed back holds nothing unsaved.
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
    // The value must move, or the arm passes whether the input is excluded or not.
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
    // Starts dirty, since a navigation control cleans the page rather than dirtying it.
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
  // A Save the managed-config freeze disabled (#1104) stays disabled when the gate's own reason goes.
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
  // The Policies profile Save has one required control and no region, so both answers are reachable.
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
  // A gate whose editor is closed is left alone.
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
  // These arms judge the refresh decision; the fills and the configuration fetch are substituted and counted.
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
    // The checklist fill is its own request appending id-less checkboxes, settled when the arm says.
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
    // Counted on the call the `.then` always makes; populateProviders never runs on the Server page.
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
    // Enough turns to drain the load's chain, counted generously so an arm cannot under-drain.
    const drain = async () => {
      for (let turn = 0; turn < 12; turn += 1) {
        await Promise.resolve();
      }
    };
    return {
      seen,
      drain,
      // Answers the configuration request and leaves the checklist fills outstanding.
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
    // An ordinary load must still fill them.
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
    // The configuration answers before the two checklist reads, so the baseline must wait for both.
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
    // `row.remove()` fires no event, so the decision must read the controls, not the dirty mark.
    // Taken from editableControls, since the page's first control is the excluded profile selector.
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
    // The editor half of `mayReplacePageContents`: a fill into an open editor clears #selectProvider.
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
    // A save, delete or import reads back and must write the page even when dirty with an editor open.
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

  // ---- Arm: one workspace at a time, so the page never carries two Saves (#1527) ----
  {
    // Both directions: opening either editor must close the other (#1527).
    const page = providersPageFixture();
    wire(core, page);
    const oid = page.querySelector("#sso-editor");
    const saml = page.querySelector("#saml-editor");
    if (oid.hidden !== true || saml.hidden !== true) {
      refuse(
        "one-workspace",
        "the fixture starts with an editor already open, so this arm proves nothing",
      );
    }

    core.showSamlEditor(page);
    core.showEditor(page);
    if (saml.hidden !== true) {
      refuse(
        "one-workspace",
        "opening the OpenID editor left the SAML one open, so the page carries two Save buttons under one unsaved-changes notice that cannot say which is which",
      );
    }
    if (oid.hidden === true) {
      refuse(
        "one-workspace",
        "the OpenID editor did not open at all, so closing its sibling cost the thing it was opened for",
      );
    }

    core.showSamlEditor(page);
    if (oid.hidden !== true) {
      refuse(
        "one-workspace",
        "opening the SAML editor left the OpenID one open, which is the same two-Save page from the other direction",
      );
    }
    if (saml.hidden === true) {
      refuse(
        "one-workspace",
        "the SAML editor did not open at all, so closing its sibling cost the thing it was opened for",
      );
    }
  }

  // ---- The managed set survives a failed read (#1589) ----
  // Judges the data the freeze is decided from; applyManagedState needs a tree the stub lacks.
  {
    const originalClient = globalThis.ApiClient;
    const originalSet = core.managedProviders;
    const originalUnread = core.managedReportUnread;
    let rejecting = false;
    let serving = {
      OidConfigs: ["file-owned"],
      SamlConfigs: [],
      ProvisioningProfiles: ["file-profile"],
    };
    globalThis.ApiClient = {
      getUrl: (url) => url,
      getJSON: () =>
        rejecting
          ? Promise.reject(new Error("sso/Config/Managed answered 500"))
          : Promise.resolve(serving),
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
    // A freeze resting on the last answer must say so in the suffix the editors append.
    if (core.staleReportSuffix() === "") {
      refuse(
        "managed-report-failure",
        "a frozen editor said nothing about the read that failed underneath it",
      );
    }

    // Refusal messages carry the same qualifier, driven through the shipped refusal.
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

    // The unfrozen note speaks for a loaded editor and says nothing on a blank add-new form.
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

    // The flag clears on the next good read.
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

    // A 200 that is not the report (#1597) must not empty the set or clear the flag.
    serving = { detail: "502 Bad Gateway" };
    await core.loadManagedProviders();
    if (!core.isManagedProvider("oid", "file-owned")) {
      refuse(
        "managed-report-failure",
        "a body that is not the report unfroze a provider a configuration file owns",
      );
    }
    if (!core.managedReportUnread) {
      refuse(
        "managed-report-failure",
        "a body that is not the report was counted as having read the set",
      );
    }

    serving = null;
    await core.loadManagedProviders();
    if (
      !core.isManagedProvider("oid", "file-owned") ||
      !core.managedReportUnread
    ) {
      refuse(
        "managed-report-failure",
        "a body of null was read as a report saying nothing is managed",
      );
    }

    // Three empty lists is an ordinary server's report and must be read as one.
    serving = { OidConfigs: [], SamlConfigs: [], ProvisioningProfiles: [] };
    await core.loadManagedProviders();
    if (core.managedReportUnread) {
      refuse(
        "managed-report-failure",
        "a server with nothing managed was treated as one whose report could not be read",
      );
    }
    if (core.isManagedProvider("oid", "file-owned")) {
      refuse(
        "managed-report-failure",
        "an empty report left a provider frozen from the set before it",
      );
    }

    // A report naming one member is still the report.
    serving = { SamlConfigs: ["saml-owned"] };
    await core.loadManagedProviders();
    if (!core.isManagedProvider("saml", "saml-owned")) {
      refuse(
        "managed-report-failure",
        "a report naming one member was thrown away as though it were not the report",
      );
    }
    if (core.managedReportUnread) {
      refuse(
        "managed-report-failure",
        "a report naming one member was counted as a read that did not happen",
      );
    }

    globalThis.ApiClient = originalClient;
    core.managedProviders = originalSet;
    core.managedReportUnread = originalUnread;
  }

  // ---- A computed address is not an edit (#1701) ----
  // The redirect address reply lands after the baseline, so tracking the read-only field made
  // every loaded provider look edited. The flag is read off the shipped tag.
  {
    const page = providersPageFixture();
    const uri = page.querySelector("#OidRedirectUri");
    if (uri === null) {
      refuse(
        "computed-address",
        "the Providers page declares no #OidRedirectUri, so this arm judges nothing",
      );
    } else {
      if (uri.readOnly !== true) {
        refuse(
          "computed-address",
          "#OidRedirectUri is not read-only in the markup, so the page now offers an address the server computes as something to type into",
        );
      }
      wire(core, page);

      // The reply, landing after the baseline exactly as the load leaves it.
      uri.value = "https://jellyfin.example/sso/OID/redirect/example";
      page.dispatch("input", uri, true);

      if (core.isPageDirty(page)) {
        refuse(
          "computed-address",
          "the address the server answered with was counted as something an administrator typed",
        );
      }
      if (core.pageDiffersFromBaseline(page)) {
        refuse(
          "computed-address",
          "a page holding nothing but the address the server computed reads as holding an edit, so the tab asserts one and stops re-reading",
        );
      }
      if (!core.mayReplacePageContents(page)) {
        refuse(
          "computed-address",
          "a tab that has only received its computed address refuses to be re-read",
        );
      }

      // The near miss: a real edit in the same window is still an edit.
      const endpoint = page.querySelector("#OidEndpoint");
      endpoint.value = "https://idp.example/";
      page.dispatch("input", endpoint, true);
      if (!core.isPageDirty(page)) {
        refuse(
          "computed-address",
          "a field an administrator typed into beside the computed address did not mark the page dirty",
        );
      }
      if (!core.pageDiffersFromBaseline(page)) {
        refuse(
          "computed-address",
          "a real edit went invisible to the baseline, which is the repair overshooting into the loss it exists to prevent",
        );
      }
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
    "unsaved state:     seventeen arms run against the shipped sso-core.js and the pages it serves",
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
    "  one-workspace    opening either protocol editor closes the other, so one Save is on the page",
  );
  console.log(
    "  managed-report-failure a failed managed-set read keeps the last set it read and says it failed",
  );
  console.log(
    "  computed-address the address the server answers with is not an edit, and a real one beside it still is",
  );
}

main().catch((error) => {
  console.error(String((error && error.stack) || error));
  process.exit(1);
});
