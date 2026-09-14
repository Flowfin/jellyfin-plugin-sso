#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Drives the REAL self-service linking page of the shipped SSO-Auth/Web/linking.js
 * and refuses each way its unlink can act without asking or refuse without saying
 * why (#1731).
 *
 * WHY THIS IS A RUNNING PROOF. Both properties are decisions rather than strings.
 * Whether the page ASKS before the press depends on counting the links that could
 * still sign the holder in, over rows built by two different branches; whether it
 * SAYS why afterwards depends on telling one 403 from another 403 by the body the
 * endpoint wrote. A rule reading these assets as text sees a `window.confirm` call
 * and a catalogue key and can say nothing about either question, and both fail
 * silently: a page that never asks looks exactly like one whose condition is
 * wrong, and a refusal shown as the generic banner looks exactly like a server
 * that fell over.
 *
 * A LINK ON A SWITCHED-OFF PROVIDER IS NOT A WAY IN, in both directions, because
 * that is the reading the server's refusal takes (#1720). A leftover link on a
 * provider somebody disabled must not keep the page quiet about the removal of
 * the last working one - that is the migration case the review of #1720 found -
 * and removing such a link on its own must not raise a question at all, because
 * it takes nothing away. Two arms below, one per direction.
 *
 * THE REFUSAL IS TOLD APART BY THE SENTENCE THE ENDPOINT WROTE, and this drives
 * the two 403s that route actually answers: the stranding refusal, which gets its
 * own sentence, and a time-limited link, which is a different refusal and must
 * fall to the generic banner rather than tell the holder that their account takes
 * no password. The bound is written where it is read: a reword on the server side
 * silently returns the generic banner, which is the harmless direction, and this
 * gate is what catches the reword rather than a user.
 *
 * WHAT THE STUB CAN AND CANNOT SAY. The DOM below is the smallest one the page
 * touches - createElement, append/appendChild, textContent, dataset, classList,
 * addEventListener, remove, and querySelector/querySelectorAll by id, class and
 * one data attribute. It is not a browser: no layout, no CSS, no focus and no
 * event dispatch, so it cannot say that the banner is visible on screen or that
 * the confirmation is reachable by keyboard. What it can say is which requests
 * were sent, whether a question was asked, and which sentence was written - which
 * is what the properties above are about.
 *
 * THE SENTENCES ARE READ FROM THE CATALOGUE AND NOT FROM THIS FILE. The last arm
 * loads de.json instead of en.json and requires the question to change, so a
 * sentence hard-coded into the page - the drift this page has had before - is
 * refused rather than reviewed.
 *
 * Node is preinstalled on the runner and this tool has no dependencies, in the
 * same terms as tools/ui-account-filter.js and tools/ui-pending-approvals.js.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.join(HERE, "..", "SSO-Auth", "Web");
const LOCALIZATION = path.join(HERE, "..", "SSO-Auth", "Localization");

// The endpoint's own words for the stranding refusal, quoted from the controller so this gate and the
// page cannot drift apart from the server behind each other's back. Read from the tree rather than
// typed here: the page matches the server's sentence, so a reword that changes the server without the
// page is exactly the state this tool exists to fail on, and a hand copy here would hide it.
const CONTROLLER = path.join(
  HERE,
  "..",
  "SSO-Auth",
  "Api",
  "Http",
  "SSOController.cs",
);

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

// What each arm sets: the answer to the confirmation, what a DELETE does, and what was asked and sent.
const answers = { confirm: true, delete: () => Promise.resolve({}) };
const asked = [];
const sent = [];
const reloads = { count: 0 };

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

// The feeds the page loads from: the enabled-provider names per protocol, and the links the holder
// holds. An arm sets these before it renders.
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
  return { view, enable, button };
}

/*
 * Builds the page the way a browser does - the module's own entry point, its own
 * catalogue load, its own two feeds - and hands back the checkbox rows it drew.
 *
 * The awaits are the page's own promise chain settling: `loadCatalog().then()` and
 * the two feeds inside it. Draining the microtask queue a few times is what stands
 * in for the browser's turn, and a row that never appears fails the arm reading it
 * rather than hanging here.
 */
async function render(scenario) {
  server.names = scenario.names;
  server.links = scenario.links;
  culture.values = catalogue(scenario.culture ?? "en");
  asked.length = 0;
  sent.length = 0;
  reloads.count = 0;
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

// The migration shape: a new provider is up and the old one is switched off, so the holder still sees
// two rows and only one of them can sign them in.
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

// ---------------------------------------------------------------------------
// The legs.
// ---------------------------------------------------------------------------

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
 * THIS IS A NEGATIVE ASSERTION ON WHAT THE ROW SAYS, and it is here because the arm
 * above only asks that the page shows the ROW: a row rewritten to promise a refusal
 * would keep every other arm green. The first draft of this change promised one, and
 * it is false in the two populations the server's guard is documented not to cover -
 * an administrator, exempt from it (#1732), and an account carrying a password this
 * plugin minted and never recorded (#1733). For both the removal goes through, so a
 * dialog whose only named outcomes are benign turns a hesitant press into a confident
 * one on the press that costs the account.
 *
 * The vocabulary is per language and is the smallest set that catches the sentence
 * that was written rather than every way of writing it - a floor, like every word
 * list, and the review is what catches a shape nobody has written yet.
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
        `the ${code} confirmation says the server will refuse ("${row}"); the guard is off for an administrator (#1732) and for a minted password (#1733), so for those two the removal goes through and the sentence is the reason they pressed`,
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
 * THE COURTESY IS COUNTED OFF THE RENDERED ROWS, so a page that has stopped agreeing
 * with the server can skip it in silence. Two ticked links, the first removed and the
 * second failing: `Promise.all` reports the rejection, the reload never runs, and both
 * rows stay on screen although one link is gone. A retry of the failed one would then
 * be counted as one of two ways in and go out with no question at all - which is the
 * lockout press, without the sentence this whole change exists to show. Measured on the
 * shipped page during the review of this change, which is why it is an arm and not a
 * sentence in a comment.
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
 * THE EXEMPTION IS NOT AN AFTERTHOUGHT AND IT IS THE COMMON CASE. A SINGLE request the
 * server answered by declining changed nothing, so the rows are still exactly true, and
 * taking the control away there would refuse the largest refusal population the very
 * tidy-up the refusal sends them to: removing a leftover link on a switched-off
 * provider is never refused, and is how somebody clears the state this page shows.
 * Driven with the migration shape, because that is where a holder has something left to
 * remove after being refused.
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

if (faults.length) {
  faults.forEach((fault) => console.error(fault));
  console.error(
    faults.length + " refusal(s) in the self-service unlink (#1731)",
  );
  process.exit(1);
}

console.log(
  "self-service unlink: twelve arms run against the shipped SSO-Auth/Web/linking.js",
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
  "  other-403 / generic      a time-limited refusal and a 500 stay generic",
);
console.log(
  "  translated               both sentences come from the catalogue, driven against de.json",
);
