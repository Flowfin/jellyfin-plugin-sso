#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Drives the REAL pending-approvals panel of the shipped sso-core.js and
 * refuses each way it can grant the wrong thing or say the wrong thing (#1529).
 *
 * WHY THIS IS A RUNNING PROOF. The panel decides which accounts an
 * administrator is offered to ENABLE, and every property that matters is a
 * decision rather than a string: which rows are built, what the button sends,
 * and what the page says when the server refuses. None of that is visible to
 * a rule that reads the assets as text, and all of it fails silently.
 *
 * THE ROWS ARE THE SERVER'S ANSWER AND NOTHING ELSE. A row is built for
 * exactly the links whose pending instant the roster carries. The page never
 * infers a waiting account from anything - not from a disabled flag, not from
 * a missing login - because the one row this panel must never contain is the
 * account somebody disabled on purpose, and the server is the only party that
 * can tell that account from one this plugin created inert.
 *
 * THE BUTTON SENDS EXACTLY THE REQUEST THE ENDPOINT PARSES: the mode token
 * the route reads, the provider in the path, and the canonical name as the
 * JSON body, so a subject with a slash in it reaches the server whole.
 *
 * THE LIST IS BOUNDED AND SAYS SO. A provider with a wide audience fills the
 * list as fast as it can log in, and a panel that drew every row would be the
 * page that breaks under the load the feature was built to absorb; a panel
 * that cut silently would be lying about how many are waiting.
 *
 * WHAT THE STUB CAN AND CANNOT SAY. The DOM below is the smallest one the
 * renderer touches, and ApiClient is a recorder that answers what a test
 * tells it to. It is not a browser: it cannot say what the table looks like,
 * only which rows were built, what was sent, and which sentence was written -
 * which is what the properties above are about.
 *
 * Node is preinstalled on the runner and this tool has no dependencies, in the
 * same terms as tools/ui-account-filter.js.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORE = path.join(HERE, "..", "SSO-Auth", "Web", "sso-core.js");

// ---------------------------------------------------------------------------
// The stub.
// ---------------------------------------------------------------------------

class Element {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.attributes = {};
    this.classes = new Set();
    this.listeners = {};
    this.value = "";
    this.text = "";
    this.classList = {
      add: (...names) => names.forEach((name) => this.classes.add(name)),
    };
  }

  set className(value) {
    this.classes = new Set(String(value).split(/\s+/).filter(Boolean));
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
    this.attributes[name] = value;
  }

  addEventListener(name, handler) {
    (this.listeners[name] ??= []).push(handler);
  }

  /** Fires the handlers a test wants to press, with the event shape they read. */
  click() {
    (this.listeners.click ?? []).forEach((handler) =>
      handler({ preventDefault() {} }),
    );
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  replaceChildren(...nodes) {
    this.children = nodes;
    this.text = "";
  }

  /** Every element under this one with the given tag, at any depth. */
  all(tag) {
    return this.children.flatMap((child) => [
      ...(child.tag === tag ? [child] : []),
      ...child.all(tag),
    ]);
  }
}

function pageWith() {
  const nodes = {
    LinkedAccountsFilter: new Element("input"),
    LinkedAccountsResult: new Element("div"),
    PendingApprovalsResult: new Element("div"),
    PendingApprovalsActionResult: new Element("div"),
  };
  return {
    page: { querySelector: (selector) => nodes[selector.slice(1)] ?? null },
    nodes,
  };
}

globalThis.document = {
  createElement: (tag) => new Element(tag),
};

// The confirmation is answered by whatever the arm set, and the recorder holds
// every request the panel made so an arm can read back what was sent.
const answers = { confirm: true, fetch: () => Promise.resolve() };
const sent = [];
globalThis.window = {
  document: globalThis.document,
  confirm: () => answers.confirm,
};
globalThis.ApiClient = {
  getUrl: (route) => "/" + route,
  getJSON: () => Promise.resolve(current.roster),
  fetch: (request) => {
    sent.push(request);
    return answers.fetch(request);
  },
};

// ---------------------------------------------------------------------------
// The fixture and the legs.
// ---------------------------------------------------------------------------

const SINCE = "2026-09-11T09:00:00Z";

function link(provider, protocol, canonical, pending) {
  return {
    Provider: provider,
    Protocol: protocol,
    CanonicalName: canonical,
    LastSsoLoginUtc: null,
    PendingApprovalSinceUtc: pending ? SINCE : null,
  };
}

/** Three accounts: two waiting on different protocols, one that merely holds a link. */
const ROSTER = {
  Accounts: [
    {
      Username: "alice",
      UserId: "1",
      AccountExists: true,
      Links: [link("keycloak", "OpenID", "alice@example.com", true)],
    },
    {
      Username: "bob",
      UserId: "2",
      AccountExists: true,
      Links: [link("authentik", "OpenID", "bob@example.com", false)],
    },
    {
      Username: "carol",
      UserId: "3",
      AccountExists: true,
      Links: [link("adfs", "SAML", "S-1-5-21/carol", true)],
    },
  ],
};

const current = { roster: ROSTER };

async function loadCore() {
  const source = fs.readFileSync(CORE, "utf8");
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64");
  return (await import(url)).default;
}

const core = await loadCore();
const faults = [];
const refuse = (leg, detail) => faults.push(leg + ": " + detail);

/** Holds a roster the way the load does, then draws the pending panel from it. */
function render(roster) {
  current.roster = roster;
  const { page, nodes } = pageWith();
  core.renderLinkedAccounts(page, nodes.LinkedAccountsResult, roster);
  core.renderPendingApprovals(page, nodes.PendingApprovalsResult);
  const rows = nodes.PendingApprovalsResult.all("tbody").flatMap(
    (body) => body.children,
  );
  const notes = nodes.PendingApprovalsResult.children
    .filter((child) => child.tag !== "table")
    .map((child) => child.textContent);
  return { page, nodes, rows, notes };
}

// ---- Arm: a row for exactly the links the server reports as waiting ----
{
  const { rows } = render(ROSTER);
  const names = rows.map((row) => row.children[0].textContent);
  if (names.join(",") !== "alice,carol") {
    refuse(
      "rows",
      `the panel drew rows for "${names.join(",")}" where the server reported alice and carol waiting; a row the server did not report is an offer to enable an account nobody provisioned inert`,
    );
  }
  const identity = rows[1] && rows[1].children[1].textContent;
  if (!/adfs/.test(identity || "") || !/S-1-5-21\/carol/.test(identity || "")) {
    refuse(
      "rows",
      `a row must name the provider and the subject it is about; it said "${identity}"`,
    );
  }
}

// ---- Arm: nothing waiting says so, and does not say the links are gone ----
{
  const { nodes } = render({
    Accounts: [ROSTER.Accounts[1]],
  });
  const said = nodes.PendingApprovalsResult.textContent;
  if (!/waiting for approval/i.test(said)) {
    refuse(
      "empty",
      `a panel with nothing waiting said "${said}", which does not say that nothing is waiting`,
    );
  }
  if (/holds an SSO link/.test(said)) {
    refuse(
      "empty",
      "a panel with nothing waiting claimed the server holds no linked account, which is the other panel's sentence and a statement about the links",
    );
  }
}

// ---- Arm: the list is bounded, and says how many it cut ----
{
  const many = {
    Accounts: Array.from({ length: 150 }, (_, i) => ({
      Username: "user" + i,
      UserId: String(i),
      AccountExists: true,
      Links: [link("keycloak", "OpenID", "user" + i + "@example.com", true)],
    })),
  };
  const { rows, notes } = render(many);
  if (rows.length !== 100) {
    refuse(
      "bound",
      `${rows.length} rows drawn for 150 waiting accounts; the list is bounded at 100 so a wide audience cannot make this the page that breaks`,
    );
  }
  if (notes.length !== 1 || !/100/.test(notes[0]) || !/150/.test(notes[0])) {
    refuse(
      "bound",
      `a cut list must say how many of how many it shows; it said "${notes.join(" ")}"`,
    );
  }
}

// ---- Arm: an uncut list carries no count line ----
{
  const { notes } = render(ROSTER);
  if (notes.length !== 0) {
    refuse(
      "uncut",
      `an uncut list carries the line "${notes.join(" ")}", and furniture that is always there stops being read`,
    );
  }
}

// ---- Arm: the button sends exactly the request the endpoint parses ----
{
  sent.length = 0;
  answers.confirm = true;
  answers.fetch = () => Promise.resolve();
  const { rows } = render(ROSTER);
  rows[1].all("button")[0].click();
  await new Promise((resolve) => setTimeout(resolve, 0));
  const request = sent[0];
  if (!request) {
    refuse("request", "pressing Approve sent nothing");
  } else {
    if (request.type !== "POST") {
      refuse("request", `the approve was sent as ${request.type}, not POST`);
    }
    if (request.url !== "/sso/Links/Approve/SAML/adfs") {
      refuse(
        "request",
        `the approve was sent to "${request.url}"; the route is Links/Approve/{mode}/{provider} with the protocol's short token`,
      );
    }
    if (request.data !== JSON.stringify("S-1-5-21/carol")) {
      refuse(
        "request",
        `the body was ${request.data}; the canonical name travels as the JSON body so a slash in a subject reaches the server whole`,
      );
    }
    if (request.contentType !== "application/json") {
      refuse("request", `the body was sent as ${request.contentType}`);
    }
  }
}

// ---- Arm: declining the confirmation sends nothing ----
{
  sent.length = 0;
  answers.confirm = false;
  const { rows } = render(ROSTER);
  rows[0].all("button")[0].click();
  await new Promise((resolve) => setTimeout(resolve, 0));
  if (sent.length !== 0) {
    refuse(
      "declined",
      "the confirmation was declined and the approve was sent anyway",
    );
  }
  answers.confirm = true;
}

// ---- Arm: the administrator refusal is told apart and says where to go ----
{
  sent.length = 0;
  answers.fetch = () =>
    Promise.reject({
      status: 403,
      text: () =>
        Promise.resolve(
          "That account is an administrator. Enable an administrator account in the Jellyfin dashboard, not from here.",
        ),
    });
  const { rows, nodes } = render(ROSTER);
  rows[0].all("button")[0].click();
  await new Promise((resolve) => setTimeout(resolve, 10));
  const said = nodes.PendingApprovalsActionResult.textContent;
  if (!/administrator/i.test(said) || !/dashboard/i.test(said)) {
    refuse(
      "administrator",
      `a refused administrator must be sent to the dashboard; the page said "${said}"`,
    );
  }
  if (/can sign in now/i.test(said)) {
    refuse("administrator", "a refusal was reported as an approval");
  }
}

// ---- Arm: an elevation refusal is NOT read as the administrator one ----
{
  answers.fetch = () =>
    Promise.reject({ status: 403, text: () => Promise.resolve("") });
  const { rows, nodes } = render(ROSTER);
  rows[0].all("button")[0].click();
  await new Promise((resolve) => setTimeout(resolve, 10));
  const said = nodes.PendingApprovalsActionResult.textContent;
  if (/is an administrator/i.test(said)) {
    refuse(
      "elevation",
      `a bare 403 - the elevation policy's refusal - was reported as "that account is an administrator": "${said}"`,
    );
  }
  if (!/signed in as an administrator/i.test(said)) {
    refuse(
      "elevation",
      `a bare 403 must fall to the generic sentence naming the elevation; the page said "${said}"`,
    );
  }
}

// ---- Arm: a stale row is re-read rather than left standing ----
{
  const reads = [];
  globalThis.ApiClient.getJSON = () => {
    reads.push(1);
    return Promise.resolve(current.roster);
  };
  answers.fetch = () =>
    Promise.reject({ status: 404, text: () => Promise.resolve("no record") });
  const { rows, nodes } = render(ROSTER);
  rows[0].all("button")[0].click();
  await new Promise((resolve) => setTimeout(resolve, 10));
  const said = nodes.PendingApprovalsActionResult.textContent;
  if (!/no longer waiting/i.test(said)) {
    refuse(
      "stale",
      `a 404 means the server no longer offers the row; the page said "${said}"`,
    );
  }
  if (reads.length !== 1) {
    refuse(
      "stale",
      `a stale row must re-read the roster once; it read ${reads.length} times`,
    );
  }
}

// ---- Arm: a success re-reads the roster and reports the approval ----
{
  const reads = [];
  globalThis.ApiClient.getJSON = () => {
    reads.push(1);
    return Promise.resolve({ Accounts: [] });
  };
  answers.fetch = () => Promise.resolve();
  const { rows, nodes } = render(ROSTER);
  rows[0].all("button")[0].click();
  await new Promise((resolve) => setTimeout(resolve, 10));
  const said = nodes.PendingApprovalsActionResult.textContent;
  if (!/alice/.test(said) || !/can sign in now/i.test(said)) {
    refuse(
      "approved",
      `a successful approve must say so; the page said "${said}"`,
    );
  }
  if (reads.length !== 1) {
    refuse(
      "approved",
      `a successful approve must re-read the roster once rather than editing its own table; it read ${reads.length} times`,
    );
  }
  const remaining = nodes.PendingApprovalsResult.all("tbody").flatMap(
    (body) => body.children,
  );
  if (remaining.length !== 0) {
    refuse(
      "approved",
      `${remaining.length} rows survived a re-read that reported nothing waiting`,
    );
  }
}

if (faults.length) {
  faults.forEach((fault) => console.error(fault));
  console.error(
    faults.length + " refusal(s) in the pending-approvals panel (#1529)",
  );
  process.exit(1);
}

console.log(
  "pending approvals: ten arms run against the shipped sso-core.js panel",
);
console.log(
  "  rows             a row for exactly the links the server reports as waiting, naming provider and subject",
);
console.log(
  "  empty            nothing waiting says so, and never that the links are gone",
);
console.log(
  "  bound / uncut    the first hundred are drawn and a cut list says how many of how many",
);
console.log(
  "  request          Approve posts the mode token, the provider and the canonical name as the JSON body",
);
console.log("  declined         a declined confirmation sends nothing");
console.log(
  "  administrator    the administrator refusal is told apart and points at the dashboard",
);
console.log(
  "  elevation        a bare 403 falls to the generic sentence, never to the administrator one",
);
console.log(
  "  stale / approved a 404 and a success both re-read the roster rather than editing the table",
);
