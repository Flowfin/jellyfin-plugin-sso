#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Drives the REAL self-service linking page of the shipped SSO-Auth/Web/linking.js
 * and refuses each way its "Sign out everywhere" control can put a credential where
 * it does not belong, act on a ticket it never got, or hide a refusal (#1768).
 *
 * WHY THIS IS A RUNNING PROOF. The control exists so that the RP-initiated logout
 * can be reached with one press and WITHOUT the access token in a URL. Whether it
 * keeps that promise is decided at press time and not in the source: the URL it
 * navigates to is built from what the server answered, so a page that fell back to
 * the token when the mint failed, navigated before the ticket arrived, or minted
 * twice for one press reads identically to a rule over the text. A rule reading
 * these assets sees a fetch and a navigation and can say nothing about their order
 * or their contents.
 *
 * THE TOKEN IS A SENTINEL THE STUB KNOWS. The recording ApiClient answers a fixed
 * access token, and every arm below asks whether that value, or an api_key
 * parameter, reached any URL the page built. That is the Done-when of the issue,
 * read on the URL rather than believed from the code.
 *
 * WHAT THE STUB CAN AND CANNOT SAY. The DOM below is the smallest one the page
 * touches. It is not a browser: no layout, no CSS, no focus and no event dispatch,
 * so it cannot say that the control is visible or reachable by keyboard. What it
 * can say is which requests were sent, in what order, what the page navigated to,
 * and which sentence was written - which is what the properties above are about.
 * The routes the page navigates to are driven against real identity providers by
 * the end-to-end harness (test/e2e/harness/harness.sh), which is where the two
 * halves of the redirect - a provider that advertises an end_session_endpoint and
 * one that does not - are exercised over the wire.
 *
 * THE SENTENCES ARE READ FROM THE CATALOGUE AND NOT FROM THIS FILE. The last arm
 * loads de.json instead of en.json and requires the label and the refusal to
 * change, so a sentence hard-coded into the page is refused rather than reviewed.
 *
 * Node is preinstalled on the runner and this tool has no dependencies, in the
 * same terms as tools/ui-self-service-unlink.js.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.join(HERE, "..", "SSO-Auth", "Web");
const LOCALIZATION = path.join(HERE, "..", "SSO-Auth", "Localization");

function read(file) {
  return fs.readFileSync(file, "utf8");
}

function catalogue(name) {
  return JSON.parse(read(path.join(LOCALIZATION, `${name}.json`)));
}

const faults = [];
const refuse = (leg, detail) => faults.push(leg + ": " + detail);

// ---------------------------------------------------------------------------
// The stub.
// ---------------------------------------------------------------------------

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
 * The three selector shapes this page uses, and nothing else: `#id`, `.class`, and
 * `.class[data-name="value"]`. Deliberately not a selector engine - a wider one would
 * quietly accept a selector the page does not write and answer it differently from a
 * browser, which is the kind of stub that proves the stub.
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

// The two banners the page owns live on the document, not inside the view, exactly as the served
// markup authors them, so a page that filled the wrong one is visible here.
const banners = {
  "sso-linking-error": new Element("div"),
  "sso-linking-refused": new Element("div"),
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

// The credential the page holds and must never write into a URL. A value no route and no provider
// name contains, so a hit below is the token and not a coincidence.
const TOKEN = "SENTINEL-ACCESS-TOKEN-6f1c2a9e";
const USER = "3fa85f64-5717-4562-b3fc-2c963f66afa6";

// What each arm sets: what a mint answers, and what the page sent and navigated to.
const answers = { mint: () => Promise.resolve(mintOf("ticket-1")) };
const sent = [];
const navigations = [];

globalThis.window = {
  document: globalThis.document,
  confirm: () => true,
  location: {
    reload: () => {},
    assign: (url) => {
      navigations.push(String(url));
    },
  },
};

// The feeds the page loads from: the enabled-provider names per protocol, and the links the holder
// holds. An arm sets these before it renders.
const server = { names: { oid: [], saml: [] }, links: { oid: {}, saml: {} } };

globalThis.ApiClient = {
  accessToken: () => TOKEN,
  // The shipped client builds `<server>/<route>` and appends `params` as a query string, and appends
  // nothing else - the api_key form is something a caller has to write on purpose. Mirrored here so
  // the URL an arm reads is the URL the page asked for.
  getUrl: (route, params) =>
    "/" + route + (params ? "?" + new URLSearchParams(params).toString() : ""),
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
      const mode = /sso\/(oid|saml)\/links\//.exec(url)[1];
      return Promise.resolve({
        json: () => Promise.resolve(server.links[mode]),
      });
    }
    sent.push(request);
    if (url.includes("/logout-ticket/")) {
      return answers.mint(request);
    }
    return Promise.resolve({});
  },
};

// The catalogue the page fetches through i18n.js. Set per arm.
const culture = { values: catalogue("en") };
globalThis.fetch = () =>
  Promise.resolve({ ok: true, json: () => Promise.resolve(culture.values) });

/** A successful mint, the way ApiClient.fetch resolves it: with the Response. */
function mintOf(ticket) {
  return { json: () => Promise.resolve({ ticket }) };
}

/** A refused mint, the way ApiClient.fetch rejects: with the Response. */
function refusedWith(status) {
  return () => Promise.reject({ status, text: () => Promise.resolve("") });
}

// ---------------------------------------------------------------------------
// Rendering one page.
// ---------------------------------------------------------------------------

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
  return view;
}

async function settle() {
  for (let turn = 0; turn < 20; turn += 1) {
    await Promise.resolve();
  }
}

/*
 * Builds the page the way a browser does - the module's own entry point, its own
 * catalogue load, its own two feeds - and hands back the sign-out controls it drew.
 */
async function render(scenario) {
  server.names = scenario.names;
  server.links = scenario.links;
  culture.values = catalogue(scenario.culture ?? "en");
  sent.length = 0;
  navigations.length = 0;
  Object.values(banners).forEach((banner) => {
    banner.hidden = true;
    banner.textContent = "";
  });

  const view = viewWith();
  linking.default(view);
  await settle();

  return { view, buttons: view.querySelectorAll(".sso-provider-sign-out") };
}

/** Presses one sign-out control and lets the page settle. */
async function press(button) {
  // The handler's own promise is deliberately not awaited: one arm leaves the mint pending for ever,
  // and the question there is what the page did while it waited.
  button.fire("click", { target: button });
  await settle();
}

const mints = () => sent.filter((request) => request.type === "POST");

// One enabled OpenID provider the holder has signed in with: the shape the whole issue is about.
const SIGNED_IN = {
  names: { oid: ["keycloak"], saml: [] },
  links: { oid: { keycloak: ["alice@example.com"] }, saml: {} },
};

// An enabled OpenID provider the holder has never signed in with, beside a SAML provider they have.
const NOT_THIS_ONE = {
  names: { oid: ["keycloak"], saml: ["adfs"] },
  links: { oid: {}, saml: { adfs: ["alice"] } },
};

// Two OpenID providers, both signed in with.
const TWO = {
  names: { oid: ["keycloak", "authentik"], saml: [] },
  links: {
    oid: { keycloak: ["alice@example.com"], authentik: ["alice"] },
    saml: {},
  },
};

// A provider name carrying characters that mean something in a path and a query.
const RESERVED = {
  names: { oid: ["a/b?c"], saml: [] },
  links: { oid: { "a/b?c": ["alice"] }, saml: {} },
};

// ---------------------------------------------------------------------------
// The legs.
// ---------------------------------------------------------------------------

const english = catalogue("en");
const german = catalogue("de");

// ---- Arm: the control is offered where the holder has signed in, and nowhere else ----
{
  const page = await render(SIGNED_IN);
  if (page.buttons.length !== 1) {
    refuse(
      "offered",
      `a holder signed in with one OpenID provider was drawn ${page.buttons.length} sign-out control(s), not one`,
    );
  } else {
    const button = page.buttons[0];
    if (button.dataset.provider !== "keycloak") {
      refuse(
        "offered",
        `the control names provider "${button.dataset.provider}", not the one the holder signed in with`,
      );
    }
    if (!button.textContent.includes(english["link.sign_out_everywhere"])) {
      refuse(
        "offered",
        `the control reads "${button.textContent}", which is not the catalogue row link.sign_out_everywhere`,
      );
    }
  }

  const other = await render(NOT_THIS_ONE);
  if (other.buttons.length !== 0) {
    refuse(
      "offered",
      `${other.buttons.length} sign-out control(s) were drawn for a provider the holder never signed in with or for a SAML provider; the OpenID ticket ends an OpenID session and a link is the only fact this page has about which one`,
    );
  }
}

// ---- Arm: one press mints once and navigates with the ticket ----
{
  const page = await render(SIGNED_IN);
  answers.mint = () => Promise.resolve(mintOf("ticket-abc"));
  await press(page.buttons[0]);
  if (mints().length !== 1) {
    refuse("one-press", `one press sent ${mints().length} mint request(s)`);
  } else if (mints()[0].url !== "/sso/OID/logout-ticket/keycloak") {
    refuse(
      "one-press",
      `the mint went to "${mints()[0].url}", not to the provider's logout-ticket route`,
    );
  }
  if (navigations.length !== 1) {
    refuse(
      "one-press",
      `one press navigated ${navigations.length} time(s), not once`,
    );
  } else if (navigations[0] !== "/sso/OID/logout/keycloak?ticket=ticket-abc") {
    refuse(
      "one-press",
      `the page navigated to "${navigations[0]}", which is not the logout route carrying the ticket the server answered`,
    );
  }
}

// ---- Arm: no credential reaches a URL ----
//
// THIS IS THE DONE-WHEN OF THE ISSUE, read on the URLs rather than believed. Every URL the page
// built during the press - the mint request and the navigation - is asked whether it carries the
// access token the client holds or an api_key parameter, which is the form the ticket exists to
// replace.
{
  const page = await render(SIGNED_IN);
  answers.mint = () => Promise.resolve(mintOf("ticket-abc"));
  await press(page.buttons[0]);
  const urls = [...sent.map((request) => String(request.url)), ...navigations];
  urls.forEach((url) => {
    if (url.includes(TOKEN)) {
      refuse(
        "no-token",
        `the access token reached a URL the page built: "${url}"`,
      );
    }
    if (/[?&]api_key=/i.test(url)) {
      refuse(
        "no-token",
        `an api_key parameter reached a URL the page built: "${url}"`,
      );
    }
  });
}

// ---- Arm: nothing navigates before the ticket arrives, and a second press mints nothing more ----
{
  const page = await render(SIGNED_IN);
  answers.mint = () => new Promise(() => {});
  await press(page.buttons[0]);
  await press(page.buttons[0]);
  if (navigations.length !== 0) {
    refuse(
      "ticket-first",
      `the page navigated to "${navigations[0]}" while the mint had not answered; a navigation without a ticket is refused by the route and would look to the holder like a broken sign-out`,
    );
  }
  if (mints().length !== 1) {
    refuse(
      "ticket-first",
      `two presses while the first mint was in flight sent ${mints().length} mint request(s); every mint is a ticket in the holder's own bounded share, and a press that is already underway must not spend a second one`,
    );
  }
}

// ---- Arm: a mint answered 404 says Single Logout is off, and takes every control away ----
{
  const page = await render(TWO);
  answers.mint = refusedWith(404);
  await press(page.buttons[0]);
  if (navigations.length !== 0) {
    refuse("feature-off", "a refused mint was followed by a navigation");
  }
  if (banners["sso-linking-refused"].hidden) {
    refuse(
      "feature-off",
      "a mint refused because Single Logout is off left the refusal banner hidden, so the holder pressed a control that did nothing and was told nothing",
    );
  } else if (
    banners["sso-linking-refused"].textContent !==
    english["link.sign_out_unavailable"]
  ) {
    refuse(
      "feature-off",
      `the refusal banner said "${banners["sso-linking-refused"].textContent}", which is not the catalogue row link.sign_out_unavailable`,
    );
  }
  if (!page.buttons.every((button) => button.disabled)) {
    refuse(
      "feature-off",
      "a control stayed usable after the server said Single Logout is off; the switch is global, so what refused this provider refuses the other one too",
    );
  }
}

// ---- Arm: a mint answered 503 or 429 says come back, and the control stays usable ----
{
  for (const status of [503, 429]) {
    const page = await render(SIGNED_IN);
    answers.mint = refusedWith(status);
    await press(page.buttons[0]);
    if (navigations.length !== 0) {
      refuse(
        "busy",
        `a mint refused with ${status} was followed by a navigation`,
      );
    }
    if (
      banners["sso-linking-refused"].textContent !==
      english["link.sign_out_busy"]
    ) {
      refuse(
        "busy",
        `a mint refused with ${status} showed "${banners["sso-linking-refused"].textContent}", not the catalogue row link.sign_out_busy`,
      );
    }
    if (page.buttons[0].disabled) {
      refuse(
        "busy",
        `a mint refused with ${status} took the control away; that refusal clears by waiting, and the page told the holder to try again`,
      );
    }
    answers.mint = () => Promise.resolve(mintOf("ticket-later"));
    await press(page.buttons[0]);
    if (navigations.length !== 1) {
      refuse(
        "busy",
        `the press after a ${status} navigated ${navigations.length} time(s), not once`,
      );
    }
  }
}

// ---- Arm: any other refusal, and an answer with no ticket in it, say so and navigate nowhere ----
{
  const page = await render(SIGNED_IN);
  answers.mint = refusedWith(401);
  await press(page.buttons[0]);
  if (navigations.length !== 0) {
    refuse("refused", "a mint refused with 401 was followed by a navigation");
  }
  if (
    banners["sso-linking-refused"].textContent !==
    english["link.sign_out_failed"]
  ) {
    refuse(
      "refused",
      `a mint refused with 401 showed "${banners["sso-linking-refused"].textContent}", not the catalogue row link.sign_out_failed`,
    );
  }

  const empty = await render(SIGNED_IN);
  answers.mint = () => Promise.resolve({ json: () => Promise.resolve({}) });
  await press(empty.buttons[0]);
  if (navigations.length !== 0) {
    refuse(
      "refused",
      `a mint that answered no ticket was followed by a navigation to "${navigations[0]}"; the route refuses a navigation with no ticket, so the page must not make one`,
    );
  }
  if (
    banners["sso-linking-refused"].textContent !==
    english["link.sign_out_failed"]
  ) {
    refuse(
      "refused",
      "a mint that answered no ticket showed no refusal sentence, so the holder was told nothing about a press that did nothing",
    );
  }
}

// ---- Arm: a provider name with reserved characters is encoded in both URLs ----
{
  const page = await render(RESERVED);
  answers.mint = () => Promise.resolve(mintOf("ticket-abc"));
  await press(page.buttons[0]);
  if (
    mints().length !== 1 ||
    mints()[0].url !== "/sso/OID/logout-ticket/a%2Fb%3Fc"
  ) {
    refuse(
      "encoded",
      `the mint for provider "a/b?c" went to "${mints()[0]?.url}", so a slash or a question mark in a provider name changed the route`,
    );
  }
  if (navigations[0] !== "/sso/OID/logout/a%2Fb%3Fc?ticket=ticket-abc") {
    refuse(
      "encoded",
      `the navigation for provider "a/b?c" was "${navigations[0]}", so a reserved character in a provider name changed the route or the query`,
    );
  }
}

// ---- Arm: the label and the refusal come from the catalogue, so a translated instance is translated ----
{
  const page = await render({ ...SIGNED_IN, culture: "de" });
  if (
    !page.buttons[0].textContent.includes(german["link.sign_out_everywhere"])
  ) {
    refuse(
      "translated",
      `a de-DE reader was shown "${page.buttons[0].textContent}", not the German catalogue row; a label written into the page instead of read from the catalogue is the drift this page has had before`,
    );
  }
  answers.mint = refusedWith(404);
  await press(page.buttons[0]);
  if (
    banners["sso-linking-refused"].textContent !==
    german["link.sign_out_unavailable"]
  ) {
    refuse(
      "translated",
      `a de-DE reader was refused with "${banners["sso-linking-refused"].textContent}", not the German catalogue row`,
    );
  }
}

if (faults.length) {
  faults.forEach((fault) => console.error(fault));
  console.error(
    faults.length + " refusal(s) in the sign-out-everywhere control (#1768)",
  );
  process.exit(1);
}

console.log(
  "sign out everywhere: nine arms run against the shipped SSO-Auth/Web/linking.js",
);
console.log(
  "  offered        the control is drawn beside an OpenID provider the holder has signed in with, and nowhere else",
);
console.log(
  "  one-press      one press mints once and navigates once, to the logout route carrying the ticket the server answered",
);
console.log(
  "  no-token       neither the access token nor an api_key parameter reaches any URL the page built",
);
console.log(
  "  ticket-first   nothing navigates before the ticket arrives, and a second press in flight mints nothing more",
);
console.log(
  "  feature-off    a 404 says Single Logout is off, with the catalogue row, and every control is taken away",
);
console.log(
  "  busy           a 503 or a 429 says come back, and the control stays usable",
);
console.log(
  "  refused        any other refusal, and an answer with no ticket, say so and navigate nowhere",
);
console.log(
  "  encoded        a reserved character in a provider name is encoded in both URLs",
);
console.log(
  "  translated     the label and the refusal come from the catalogue, driven against de.json",
);
