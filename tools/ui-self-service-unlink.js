#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Drives the shipped linking.js self-service page and refuses an unlink that acts
 * without asking or is refused without saying why (#1731). A link on a disabled
 * provider is not a way in (#1720), and every sentence comes from the catalogue.
 * Run with `node tools/ui-self-service-unlink.js`; no dependencies.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.join(HERE, "..", "SSO-Auth", "Web");
const LOCALIZATION = path.join(HERE, "..", "SSO-Auth", "Localization");

// The stranding refusal's sentence, read from the controller so a server-side reword fails here.
const CONTROLLER = path.join(
  HERE,
  "..",
  "SSO-Auth",
  "Api",
  "Http",
  "SSOController.Links.cs",
);

function read(file) {
  return fs.readFileSync(file, "utf8");
}

function catalogue(name) {
  return JSON.parse(read(path.join(LOCALIZATION, `${name}.json`)));
}

const faults = [];
const refuse = (leg, detail) => faults.push(leg + ": " + detail);

// The stub.

class Element {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.attributes = {};
    this.dataset = {};
    this.classes = new Set();
    this.listeners = {};
    this.text = "";
    this.hidden = false;
    this.checked = false;
    this.disabled = false;
    this.parent = null;
    this.classList = {
      add: (...names) => names.forEach((name) => this.classes.add(name)),
      contains: (name) => this.classes.has(name),
    };
  }

  set innerHTML(value) {
    if (String(value) === "") {
      this.children = [];
    }
  }

  set textContent(value) {
    this.text = String(value);
    this.children = [];
  }

  get textContent() {
    return this.children.length
      ? this.children.map((child) => child.textContent).join(" ")
      : this.text;
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }

  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }

  hasAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name);
  }

  addEventListener(name, handler) {
    (this.listeners[name] ??= []).push(handler);
  }

  fire(name, event) {
    return (this.listeners[name] ?? []).map((handler) => handler(event));
  }

  appendChild(child) {
    child.parent = this;
    this.children.push(child);
    return child;
  }

  append(...nodes) {
    nodes.forEach((node) => this.appendChild(node));
  }

  remove() {
    if (this.parent) {
      this.parent.children = this.parent.children.filter(
        (child) => child !== this,
      );
      this.parent = null;
    }
  }

  /** Every element under this one, at any depth, this one included. */
  walk() {
    return [this, ...this.children.flatMap((child) => child.walk())];
  }

  querySelectorAll(selector) {
    return this.walk()
      .slice(1)
      .filter((node) => matches(node, selector));
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null;
  }
}

/*
 * The three selector shapes the page uses: `#id`, `.class` and `.class[data-name="value"]`.
 * Deliberately narrow, so the stub never answers a selector the page does not write.
 */
const SELECTOR = /^(?:#([\w-]+)|\.([\w-]+)(?:\[data-([\w-]+)="(.*)"\])?)$/;

function matches(node, selector) {
  const parsed = SELECTOR.exec(selector);
  if (!parsed) {
    throw new Error(`the stub does not implement the selector "${selector}"`);
  }
  const [, id, className, dataName, dataValue] = parsed;
  if (id !== undefined) {
    return node.attributes.id === id;
  }
  if (!node.classes.has(className)) {
    return false;
  }
  if (dataName === undefined) {
    return true;
  }
  return (
    node.dataset[dataName.replace(/-(\w)/g, (m, c) => c.toUpperCase())] ===
    dataValue
  );
}

// The page's banners live on the document, as the served markup authors them.
const banners = {
  "sso-linking-error": new Element("div"),
  "sso-linking-refused": new Element("div"),
  "sso-linking-signed-out": new Element("div"),
};
Object.entries(banners).forEach(([id, node]) => {
  node.setAttribute("id", id);
  node.hidden = true;
});

globalThis.document = {
  createElement: (tag) => new Element(tag),
  querySelector: (selector) => banners[selector.replace(/^#/, "")] ?? null,
  querySelectorAll: () => [],
};

globalThis.CSS = { escape: (value) => String(value) };

// What each arm sets, and what the page asked and sent. `links` is the links feed after a removal
// (#1882): null is the rendered feed, a function the answer after the sign-out. Reset by render().
const answers = {
  confirm: true,
  delete: () => Promise.resolve({}),
  links: null,
};
const asked = [];
const sent = [];
const reloads = { count: 0 };
const probes = { count: 0 };

globalThis.window = {
  document: globalThis.document,
  confirm: (question) => {
    asked.push(question);
    return answers.confirm;
  },
  location: {
    reload: () => {
      reloads.count += 1;
    },
  },
};

const USER = "3fa85f64-5717-4562-b3fc-2c963f66afa6";

// The feeds the page loads: enabled-provider names per protocol and the holder's links.
const server = { names: { oid: [], saml: [] }, links: { oid: {}, saml: {} } };

globalThis.ApiClient = {
  getUrl: (route) => "/" + route,
  getCurrentUserId: () => USER,
  fetch: (request) => {
    const url = String(request.url);
    if (request.type === "GET" && url.endsWith("/GetNames")) {
      const mode = /sso\/(OID|SAML)\/GetNames$/.exec(url)[1].toLowerCase();
      return Promise.resolve({
        json: () => Promise.resolve(server.names[mode]),
      });
    }
    if (request.type === "GET" && url.includes("/links/")) {
      if (answers.links !== null) {
        probes.count += 1;
        return answers.links();
      }
      const mode = /sso\/(oid|saml)\/links\//.exec(url)[1];
      return Promise.resolve({
        json: () => Promise.resolve(server.links[mode]),
      });
    }
    sent.push(request);
    return answers.delete(request);
  },
};

// The catalogue the page fetches through i18n.js. Set per arm.
const culture = { values: catalogue("en") };
globalThis.fetch = () =>
  Promise.resolve({ ok: true, json: () => Promise.resolve(culture.values) });

// Rendering one page.

const linking = await import(pathToFileURL(path.join(WEB, "linking.js")).href);

function viewWith() {
  const view = new Element("div");
  const enable = new Element("input");
  enable.setAttribute("id", "enable-delete");
  const button = new Element("button");
  button.setAttribute("id", "btn-delete-selected-links");
  button.disabled = true;
  const oid = new Element("div");
  oid.setAttribute("id", "sso-provider-list-oid");
  const saml = new Element("div");
  saml.setAttribute("id", "sso-provider-list-saml");
  view.append(enable, button, oid, saml);
  return { view, enable, button };
}

/*
 * Builds the page through its own entry point, catalogue load and feeds, and returns
 * the checkbox rows it drew. Draining microtasks stands in for the browser's turn.
 */
async function render(scenario) {
  server.names = scenario.names;
  server.links = scenario.links;
  culture.values = catalogue(scenario.culture ?? "en");
  asked.length = 0;
  sent.length = 0;
  reloads.count = 0;
  probes.count = 0;
  answers.links = null;
  Object.values(banners).forEach((banner) => {
    banner.hidden = true;
    banner.textContent = "";
  });

  const { view, enable, button } = viewWith();
  linking.default(view);
  for (let turn = 0; turn < 20; turn += 1) {
    await Promise.resolve();
  }

  enable.checked = true;
  enable.fire("change", { target: enable });

  return {
    view,
    enable,
    button,
    rows: view.querySelectorAll(".sso-link-checkbox"),
  };
}

/** Presses Delete with the named canonical names ticked, and lets the page settle. */
async function press(page, names) {
  page.rows.forEach((row) => {
    row.checked = names.includes(row.dataset.id);
  });
  await page.button.fire("click", { target: page.button })[0];
  for (let turn = 0; turn < 20; turn += 1) {
    await Promise.resolve();
  }
}

// One enabled OpenID provider holding one link: the shape the whole issue is about.
const ONE_WAY_IN = {
  names: { oid: ["keycloak"], saml: [] },
  links: { oid: { keycloak: ["alice@example.com"] }, saml: {} },
};

// Two enabled providers, one link each.
const TWO_WAYS_IN = {
  names: { oid: ["keycloak", "authentik"], saml: [] },
  links: {
    oid: { keycloak: ["alice@example.com"], authentik: ["alice"] },
    saml: {},
  },
};

// The migration shape: two rows, only one of them on an enabled provider.
const ONE_ENABLED_ONE_DISABLED = {
  names: { oid: ["keycloak"], saml: [] },
  links: {
    oid: { keycloak: ["alice@example.com"], legacy: ["alice"] },
    saml: {},
  },
};

/** A rejected DELETE, the way ApiClient.fetch rejects: with the Response. */
function rejectWith(status, body) {
  return () => Promise.reject({ status, text: () => Promise.resolve(body) });
}

// The legs.

const english = catalogue("en");
const german = catalogue("de");

// ---- Arm: the sentence the endpoint writes is the one the page matches ----
{
  const controller = read(CONTROLLER);
  if (!/last SSO link that can sign you in/.test(controller)) {
    refuse(
      "server-sentence",
      'SSOController no longer writes "last SSO link that can sign you in" in its stranding refusal, so the page below is matching a sentence the server does not send and every refusal falls to the generic banner',
    );
  }
  const page = read(path.join(WEB, "linking.js"));
  if (!/last SSO link that can sign you in/.test(page)) {
    refuse(
      "server-sentence",
      "linking.js no longer matches the endpoint's own words, so the stranding refusal cannot be told apart from the other 403s this route answers",
    );
  }
  // The second clause separates the administrator's refusal from the user's (#1732).
  if (!/no other administrator on this server/.test(controller)) {
    refuse(
      "server-sentence",
      'SSOController no longer writes "no other administrator on this server" in its stranding refusal, so an administrator who strands the whole server is told to ask an administrator about it',
    );
  }
  if (!/no other administrator on this server/.test(page)) {
    refuse(
      "server-sentence",
      "linking.js no longer matches the clause that separates the two stranding refusals, so the administrator's refusal is shown with the user's advice",
    );
  }
}

// ---- Arm: removing the only way in asks first, and names the consequence ----
{
  const page = await render(ONE_WAY_IN);
  answers.confirm = false;
  await press(page, ["alice@example.com"]);
  if (asked.length !== 1) {
    refuse(
      "confirm-last",
      `removing the only link that can sign the holder in asked ${asked.length} times; the page must say it before the press, which is the courtesy the server's refusal does not replace (#1720)`,
    );
  } else if (asked[0] !== english["link.delete_last_confirm"]) {
    refuse(
      "confirm-last",
      `the question was "${asked[0]}", which is not the catalogue row link.delete_last_confirm`,
    );
  }
}

/*
 * ---- Arm: the question names the consequence and never promises the refusal ----
 *
 * The guard does not cover administrators (#1732) or accounts without a minted-password
 * record (#1733), so a row promising a refusal would mislead exactly there.
 */
{
  const PROMISES_A_REFUSAL = {
    en: /\brefus\w*\b|\bdeclin\w*\b|nothing changes/i,
    de: /\bablehn\w*|\babgelehnt\b|\blehnt\b|\bverweiger\w*|ändert sich nichts/i,
  };
  Object.entries(PROMISES_A_REFUSAL).forEach(([code, shape]) => {
    const row = catalogue(code)["link.delete_last_confirm"];
    if (shape.test(row)) {
      refuse(
        "promises-nothing",
        `the ${code} confirmation says the server will refuse ("${row}"); the guard is off for an administrator (#1732) and for an account sealed before the minted-password record existed (#1733), so for those the removal goes through and the sentence is the reason they pressed`,
      );
    }
  });
}

// ---- Arm: a declined confirmation sends nothing and does not reload ----
{
  const page = await render(ONE_WAY_IN);
  answers.confirm = false;
  await press(page, ["alice@example.com"]);
  if (sent.length !== 0) {
    refuse(
      "declined",
      `${sent.length} DELETE(s) went out after the question was declined`,
    );
  }
  if (reloads.count !== 0) {
    refuse(
      "declined",
      "a declined question reloaded the page, which shows the holder the same page a removal shows",
    );
  }
}

// ---- Arm: an accepted confirmation still sends the removal ----
{
  const page = await render(ONE_WAY_IN);
  answers.confirm = true;
  answers.delete = () => Promise.resolve({});
  await press(page, ["alice@example.com"]);
  if (sent.length !== 1 || sent[0].type !== "DELETE") {
    refuse(
      "accepted",
      `an accepted question sent ${sent.length} request(s); the confirmation is a question and not a second refusal`,
    );
  }
}

// ---- Arm: removing one of two ways in asks nothing ----
{
  const page = await render(TWO_WAYS_IN);
  answers.confirm = true;
  answers.delete = () => Promise.resolve({});
  await press(page, ["alice@example.com"]);
  if (asked.length !== 0) {
    refuse(
      "not-the-last",
      `removing one of two links that can sign the holder in asked "${asked[0]}"; a question on every press is furniture and stops being read`,
    );
  }
  if (sent.length !== 1) {
    refuse(
      "not-the-last",
      `${sent.length} DELETE(s) went out for one ticked row`,
    );
  }
}

// ---- Arm: a link on a switched-off provider does not keep the page quiet ----
{
  const page = await render(ONE_ENABLED_ONE_DISABLED);
  answers.confirm = false;
  await press(page, ["alice@example.com"]);
  if (asked.length !== 1) {
    refuse(
      "disabled-is-not-a-way-in",
      "removing the only link on an ENABLED provider asked nothing while a link on a switched-off provider was still listed; that link cannot sign anybody in, which is the migration case the server's own guard was corrected for (#1720)",
    );
  }
}

// ---- Arm: removing a link that is not a way in asks nothing ----
{
  const page = await render(ONE_ENABLED_ONE_DISABLED);
  answers.confirm = true;
  answers.delete = () => Promise.resolve({});
  await press(page, ["alice"]);
  if (asked.length !== 0) {
    refuse(
      "removing-a-dead-link",
      `removing a link on a switched-off provider asked "${asked[0]}"; it takes no way in away, so there is nothing to warn about`,
    );
  }
}

/*
 * ---- Arm: a page whose rows may no longer be true stops offering the button ----
 *
 * After a partial failure the rows disagree with the server, and a retry counted off
 * them could remove the last way in without the question.
 */
{
  const page = await render(TWO_WAYS_IN);
  answers.confirm = true;
  let call = 0;
  answers.delete = () => {
    call += 1;
    return call === 1
      ? Promise.resolve({})
      : Promise.reject({ status: 500, text: () => Promise.resolve("") });
  };
  await press(page, ["alice@example.com", "alice"]);

  if (!page.button.disabled || !page.enable.disabled) {
    refuse(
      "stale-page",
      "a failed batch left the delete control usable; the page can no longer say which links the holder still holds, and the next press is counted off rows that are known to be wrong",
    );
  }
  if (page.enable.checked) {
    refuse(
      "stale-page",
      "the delete switch stayed ticked after a failed batch, so one tick of it re-enables the button the failure took away",
    );
  }

  const before = sent.length;
  await press(page, ["alice"]);
  if (sent.length !== before) {
    refuse(
      "stale-page",
      `a second press after a failed batch sent ${sent.length - before} more request(s) off rows the page can no longer speak for`,
    );
  }
}

/*
 * ---- Arm: the one shape that keeps the control is the one the server declined ----
 *
 * A single declined request changed nothing, so the rows stay true and the holder can
 * still remove a leftover link on a switched-off provider.
 */
{
  const page = await render(ONE_ENABLED_ONE_DISABLED);
  answers.confirm = true;
  answers.delete = rejectWith(
    403,
    "This is the last SSO link that can sign you in, and this server does not accept a password for your account, so removing it would leave you unable to sign in at all.",
  );
  await press(page, ["alice@example.com"]);
  if (page.button.disabled || page.enable.disabled) {
    refuse(
      "refused-keeps-the-control",
      "a single removal the server DECLINED took the delete control away; nothing changed, the rows are still true, and the holder can no longer remove the switched-off provider's leftover link the refusal just sent them to deal with",
    );
  }

  answers.delete = () => Promise.resolve({});
  const before = sent.length;
  await press(page, ["alice"]);
  if (sent.length !== before + 1) {
    refuse(
      "refused-keeps-the-control",
      `after a refusal the holder could not remove the leftover link on the switched-off provider; ${sent.length - before} request(s) went out`,
    );
  }
}

// ---- Arm: the stranding refusal gets its own sentence ----
{
  const page = await render(ONE_WAY_IN);
  answers.confirm = true;
  answers.delete = rejectWith(
    403,
    "This is the last SSO link that can sign you in, and this server does not accept a password for your account, so removing it would leave you unable to sign in at all. Link another provider first and then remove this one, or ask an administrator to switch your account back to password sign-in.",
  );
  await press(page, ["alice@example.com"]);
  if (banners["sso-linking-refused"].hidden) {
    refuse(
      "refusal",
      "a refused removal left the refusal banner hidden, so the holder is told only that something went wrong about a request the server understood and declined",
    );
  } else if (
    banners["sso-linking-refused"].textContent !==
    english["link.delete_refused_would_strand"]
  ) {
    refuse(
      "refusal",
      `the refusal banner said "${banners["sso-linking-refused"].textContent}", which is not the catalogue row link.delete_refused_would_strand`,
    );
  }
  if (!banners["sso-linking-error"].hidden) {
    refuse(
      "refusal",
      "the generic banner was shown beside the refusal, so the page says both that it cannot be trusted as shown and that the server declined",
    );
  }
  if (reloads.count !== 0) {
    refuse("refusal", "a refused removal reloaded the page");
  }
}

// ---- Arm: the administrator who would strand the SERVER gets the other sentence (#1732) ----
// Both refusals share an opening clause, so this pins the clause that separates them.
{
  const page = await render(ONE_WAY_IN);
  answers.confirm = true;
  answers.delete = rejectWith(
    403,
    "This is the last SSO link that can sign you in, and no other administrator on this server holds an SSO link that can sign them in either, so removing it could leave this server with no administrator able to reach it. Ask another administrator to remove it for you, or link another provider to your account first and then remove this one.",
  );
  await press(page, ["alice@example.com"]);
  if (
    banners["sso-linking-refused"].textContent !==
    english["link.delete_refused_would_strand_server"]
  ) {
    refuse(
      "refusal-server",
      `the refusal banner said "${banners["sso-linking-refused"].textContent}", which is not the catalogue row link.delete_refused_would_strand_server`,
    );
  }
  if (!banners["sso-linking-error"].hidden) {
    refuse(
      "refusal-server",
      "the generic banner was shown beside the administrator's refusal",
    );
  }
}

// ---- Arm: the OTHER 403 this route answers stays generic ----
{
  const page = await render(ONE_WAY_IN);
  answers.confirm = true;
  answers.delete = rejectWith(
    403,
    "This SSO link carries an access deadline and can be removed only by an administrator.",
  );
  await press(page, ["alice@example.com"]);
  if (!banners["sso-linking-refused"].hidden) {
    refuse(
      "other-403",
      "the time-limited refusal was shown as the stranding one, which tells the holder their account takes no password when the server said nothing of the kind",
    );
  }
  if (banners["sso-linking-error"].hidden) {
    refuse("other-403", "a refused removal showed no banner at all");
  }
}

// ---- Arm: a server error stays generic ----
{
  const page = await render(ONE_WAY_IN);
  answers.confirm = true;
  answers.delete = rejectWith(500, "");
  await press(page, ["alice@example.com"]);
  if (!banners["sso-linking-refused"].hidden) {
    refuse("generic", "a 500 was reported as the stranding refusal");
  }
  if (banners["sso-linking-error"].hidden) {
    refuse("generic", "a 500 showed no banner at all");
  }
}

// ---- Arm: both sentences come from the catalogue, so a translated instance is translated ----
{
  const page = await render({ ...ONE_WAY_IN, culture: "de" });
  answers.confirm = true;
  answers.delete = rejectWith(
    403,
    "This is the last SSO link that can sign you in, and this server does not accept a password for your account, so removing it would leave you unable to sign in at all.",
  );
  await press(page, ["alice@example.com"]);
  if (asked[0] !== german["link.delete_last_confirm"]) {
    refuse(
      "translated",
      `a de-DE reader was asked "${asked[0]}", not the German catalogue row; a sentence written into the page instead of read from the catalogue is the drift this page has had before`,
    );
  }
  if (
    banners["sso-linking-refused"].textContent !==
    german["link.delete_refused_would_strand"]
  ) {
    refuse(
      "translated",
      `a de-DE reader was refused with "${banners["sso-linking-refused"].textContent}", not the German catalogue row`,
    );
  }
}

/*
 * ---- Arm: removing the last way in says the sign-out happened, not that something went wrong ----
 *
 * The server ends every session once the last SSO link is gone, so after any removal the page
 * probes the links feed and answers a 401 with the signed-out sentence and no reload (#1882).
 */
{
  const page = await render(ONE_WAY_IN);
  answers.confirm = true;
  answers.delete = () => Promise.resolve({});
  answers.links = () => Promise.reject({ status: 401 });
  // Both other banners start up, so the arm can see them go down.
  banners["sso-linking-error"].hidden = false;
  banners["sso-linking-refused"].hidden = false;
  await press(page, ["alice@example.com"]);
  if (probes.count !== 1) {
    refuse(
      "signed-out",
      `removing the last way in asked the links feed ${probes.count} time(s) after the removal; the 401 the sign-out leaves behind is the one fact that separates it from a removal the session survived`,
    );
  }
  if (banners["sso-linking-signed-out"].hidden) {
    refuse(
      "signed-out",
      "the last way in was removed and the session ended, and the page did not say so",
    );
  }
  if (
    !banners["sso-linking-error"].hidden ||
    !banners["sso-linking-refused"].hidden
  ) {
    refuse(
      "signed-out",
      "a banner from an earlier press stayed up beside the signed-out sentence, so the page says both that something went wrong or was declined and that the removal did what the question said",
    );
  }
  if (reloads.count !== 0) {
    refuse(
      "signed-out",
      "the page reloaded after the sign-out, which draws the generic banner over two feeds answering 401",
    );
  }
  if (!page.button.disabled || !page.enable.disabled) {
    refuse(
      "signed-out",
      "the delete control stayed usable on a dead session; a second press could only answer 401 and raise the generic banner beside the sentence",
    );
  }
}

// The only link left sits on a switched-off provider: no question, but the server still revokes.
{
  const page = await render({
    names: { oid: [], saml: [] },
    links: { oid: { legacy: ["alice"] }, saml: {} },
  });
  answers.confirm = true;
  answers.delete = () => Promise.resolve({});
  answers.links = () => Promise.reject({ status: 401 });
  await press(page, ["alice"]);
  if (asked.length !== 0) {
    refuse(
      "dead-link-signs-out",
      `removing a link on a switched-off provider asked "${asked[0]}"`,
    );
  }
  if (banners["sso-linking-signed-out"].hidden || reloads.count !== 0) {
    refuse(
      "dead-link-signs-out",
      "the only link left sat on a switched-off provider; the server revoked the session all the same and the page reloaded into the generic banner instead of saying so",
    );
  }
}

// A probe that fails for any reason but 401 is not a sign-out.
{
  const page = await render(ONE_WAY_IN);
  answers.confirm = true;
  answers.delete = () => Promise.resolve({});
  answers.links = () => Promise.reject({ status: 500 });
  await press(page, ["alice@example.com"]);
  if (!banners["sso-linking-signed-out"].hidden) {
    refuse(
      "probe-failed",
      "a feed that failed with 500 was read as the sign-out; only the 401 the revocation leaves behind is",
    );
  }
  if (reloads.count !== 1) {
    refuse(
      "probe-failed",
      `a failed probe reloaded ${reloads.count} time(s); anything but a 401 reloads as before`,
    );
  }
}

{
  const page = await render(ONE_WAY_IN);
  answers.confirm = true;
  answers.delete = () => Promise.resolve({});
  answers.links = () =>
    Promise.resolve({ json: () => Promise.resolve({ legacy: ["alice"] }) });
  await press(page, ["alice@example.com"]);
  if (!banners["sso-linking-signed-out"].hidden) {
    refuse(
      "session-survived",
      "the links feed still answered after the removal, so the session is alive, and the page told the holder it had ended",
    );
  }
  if (reloads.count !== 1) {
    refuse(
      "session-survived",
      `a removal the session survived reloaded ${reloads.count} time(s); the reload is what draws the links the holder still holds`,
    );
  }
}

{
  const page = await render(TWO_WAYS_IN);
  answers.confirm = true;
  answers.delete = () => Promise.resolve({});
  answers.links = () =>
    Promise.resolve({
      json: () => Promise.resolve({ authentik: ["alice"] }),
    });
  await press(page, ["alice@example.com"]);
  if (reloads.count !== 1 || !banners["sso-linking-signed-out"].hidden) {
    refuse(
      "not-the-last-reloads",
      "removing one of two ways in, with the feed still answering, did not simply reload the page",
    );
  }
}

// ---- Arm: the sentence is authored around its own sign-in link and both catalogues carry it ----
{
  const markup = read(path.join(WEB, "linking.html"));
  const start = markup.indexOf('id="sso-linking-signed-out"');
  const banner =
    start < 0 ? "" : markup.slice(start, markup.indexOf("</div>", start));
  const href = /href="([^"]*)"/.exec(banner);
  if (
    !banner.includes('data-i18n-parts="link.signed_out"') ||
    !banner.includes('data-i18n="link.sign_in_again"') ||
    !href
  ) {
    refuse(
      "signed-out-markup",
      "linking.html no longer authors the signed-out banner around a sign-in link filled from link.signed_out and link.sign_in_again",
    );
  } else if (href[1] !== "../web/index.html") {
    refuse(
      "signed-out-markup",
      `the sign-in link points at "${href[1]}"; a relative ../web/index.html is what survives a server under a path prefix`,
    );
  }
  [english, german].forEach((rows, index) => {
    const code = index === 0 ? "en" : "de";
    if (
      typeof rows["link.signed_out"] !== "string" ||
      !rows["link.signed_out"].includes("{0}")
    ) {
      refuse(
        "signed-out-markup",
        `the ${code} row link.signed_out is missing or names no {0} slot for the sign-in link, so the parts pass leaves the English standing`,
      );
    }
    if (
      typeof rows["link.sign_in_again"] !== "string" ||
      rows["link.sign_in_again"] === ""
    ) {
      refuse(
        "signed-out-markup",
        `the ${code} row link.sign_in_again is missing`,
      );
    }
  });
  if (english["link.signed_out"] === german["link.signed_out"]) {
    refuse(
      "signed-out-markup",
      "the German signed-out sentence is the English one",
    );
  }
}

if (faults.length) {
  faults.forEach((fault) => console.error(fault));
  console.error(
    faults.length + " refusal(s) in the self-service unlink (#1731, #1882)",
  );
  process.exit(1);
}

console.log(
  "self-service unlink: nineteen arms run against the shipped SSO-Auth/Web/linking.js",
);
console.log(
  "  server-sentence          the endpoint and the page name the same refusal, read from both trees",
);
console.log(
  "  confirm-last             removing the only way in asks first, with the catalogue row",
);
console.log(
  "  promises-nothing         the question names the consequence and never says the server will refuse",
);
console.log(
  "  declined / accepted      a declined question sends nothing and reloads nothing; an accepted one still removes",
);
console.log(
  "  not-the-last             removing one of two ways in asks nothing",
);
console.log(
  "  disabled-is-not-a-way-in a link on a switched-off provider does not keep the page quiet",
);
console.log(
  "  removing-a-dead-link     removing a link that cannot sign anybody in asks nothing",
);
console.log(
  "  stale-page               a failed batch takes the delete control away, so no press is counted off rows the page cannot speak for",
);
console.log(
  "  refused-keeps-the-control a single removal the server declined changed nothing, so the control stays",
);
console.log(
  "  refusal                  the stranding 403 gets its own sentence, and not the generic banner beside it",
);
console.log(
  "  refusal-server           the administrator who would strand the server gets the OTHER sentence",
);
console.log(
  "  other-403 / generic      a time-limited refusal and a 500 stay generic",
);
console.log(
  "  translated               both sentences come from the catalogue, driven against de.json",
);
console.log(
  "  signed-out               a removal asks the links feed once; its 401 is answered with the signed-out sentence, no reload, controls gone",
);
console.log(
  "  dead-link-signs-out      the only link left on a switched-off provider asks nothing and still ends in the sentence",
);
console.log(
  "  probe-failed             a feed failing with anything but 401 reloads as before",
);
console.log(
  "  session-survived         a feed that still answers means the session is alive, and the page reloads as before",
);
console.log(
  "  not-the-last-reloads     removing one of two ways in, the feed still answering, reloads",
);
console.log(
  "  signed-out-markup        the banner is authored around a relative sign-in link and both catalogues carry the sentence",
);
