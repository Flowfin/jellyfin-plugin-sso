#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Drives the REAL linked-accounts renderer of the shipped sso-core.js and
 * refuses each way its filter can mislead (#1529).
 *
 * WHY THIS IS A RUNNING PROOF. Every rule this tree has over these assets reads
 * their TEXT, and a filter is not a string: it is a decision about which rows a
 * reader is shown and whether the page says so. The two ways it goes wrong are
 * both silent.
 *
 * A NARROWED TABLE THAT DOES NOT SAY IT IS NARROWED looks exactly like a
 * complete one. An administrator counting rows to answer "how many accounts are
 * linked" then gets the filter's answer instead of the server's, and nothing on
 * the page contradicts them. So a filtered render must carry a count line, and
 * an unfiltered one must not - furniture that is always there stops being read.
 *
 * A FILTER THAT MATCHES NOTHING MUST NOT SAY THE SERVER HAS NOTHING. "No account
 * holds a link" is a statement about the server; "nothing matches what you
 * typed" is about the box. A reader who saw the first after typing would
 * conclude the links were gone, and on a page whose other button revokes links
 * that is a conclusion with consequences.
 *
 * THE THIRD PROPERTY IS THAT IT ASKS THE SERVER FOR NOTHING. The roster is
 * elevation-gated and rate-limited; a filter that re-fetched would spend one
 * call per keystroke on data that has not changed, and would hit the limiter on
 * a six-letter word.
 *
 * WHAT THE STUB CAN AND CANNOT SAY. The DOM below is the smallest one the
 * renderer touches: createElement for the tags it builds, appendChild,
 * replaceChildren, textContent, classList, setAttribute, addEventListener and
 * querySelector by id. It is not a browser and it has no layout, no CSS and no
 * event dispatch, so it cannot say what the table LOOKS like or that the input
 * is reachable by keyboard. What it can say is which rows were built and which
 * sentence was written, which is what the three properties above are about.
 *
 * Node is preinstalled on the runner and this tool has no dependencies, in the
 * same terms as tools/ui-mock-fields.js and tools/ui-untranslated.js.
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

  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }

  addEventListener() {}

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

function pageWith(filterValue) {
  const filter = new Element("input");
  filter.value = filterValue;
  const container = new Element("div");
  const nodes = {
    LinkedAccountsFilter: filter,
    LinkedAccountsResult: container,
  };
  return {
    page: { querySelector: (selector) => nodes[selector.slice(1)] ?? null },
    filter,
    container,
  };
}

// BOTH spellings, because the renderer uses both. The row builder reaches for a
// bare `document` and renderTransferMessage for `window.document`; one stub
// object behind both names is what keeps this a test of the shipped code rather
// than of whichever spelling the stub happened to provide.
globalThis.document = {
  createElement: (tag) => new Element(tag),
};
globalThis.window = { document: globalThis.document };

// ---------------------------------------------------------------------------
// The fixture and the legs.
// ---------------------------------------------------------------------------

/** Three accounts whose only overlap is deliberate, so each arm can aim. */
const ROSTER = {
  Accounts: [
    {
      Username: "alice",
      UserId: "1",
      AccountExists: true,
      Links: [
        {
          Provider: "keycloak",
          Protocol: "OIDC",
          CanonicalName: "alice@example.com",
          LastSsoLoginUtc: null,
        },
      ],
    },
    {
      Username: "bob",
      UserId: "2",
      AccountExists: true,
      Links: [
        {
          Provider: "authentik",
          Protocol: "OIDC",
          CanonicalName: "bob@example.com",
          LastSsoLoginUtc: null,
        },
      ],
    },
    {
      Username: "carol",
      UserId: "3",
      AccountExists: true,
      Links: [
        {
          Provider: "keycloak",
          Protocol: "SAML",
          CanonicalName: "S-1-5-21-carol",
          LastSsoLoginUtc: null,
        },
      ],
    },
  ],
};

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

/** Renders the fixture through the shipped renderer and reports what came out. */
function render(filterValue, roster = ROSTER) {
  const { page, container } = pageWith(filterValue);
  core.renderLinkedAccounts(page, container, roster);
  const rows = container.all("tbody").flatMap((body) => body.children);
  const notes = container.children
    .filter((child) => child.tag !== "table")
    .map((child) => child.textContent);
  return { rows, notes, container };
}

// ---- Arm: no filter shows every row and adds no count line ----
{
  const { rows, notes } = render("");
  if (rows.length !== 3) {
    refuse(
      "unfiltered",
      `${rows.length} rows rendered where the roster holds 3`,
    );
  }
  if (notes.length !== 0) {
    refuse(
      "unfiltered",
      `an unfiltered table carries the line "${notes.join(" ")}", and furniture that is always there stops being read`,
    );
  }
}

// ---- Arm: a narrowing filter shows the matches AND says it narrowed ----
{
  const { rows, notes } = render("bob");
  if (rows.length !== 1) {
    refuse(
      "narrowed",
      `${rows.length} rows rendered where one account matches "bob"`,
    );
  }
  if (notes.length !== 1 || !/1/.test(notes[0]) || !/3/.test(notes[0])) {
    refuse(
      "narrowed",
      `a narrowed table must say how many of how many are shown; it said "${notes.join(" ")}"`,
    );
  }
}

// ---- Arm: the filter reaches the provider and the subject, not just the name ----
for (const [leg, needle, expected] of [
  ["by-provider", "keycloak", 2],
  ["by-protocol", "saml", 1],
  ["by-subject", "example.com", 2],
  ["case", "KEYCLOAK", 2],
]) {
  const { rows } = render(needle);
  if (rows.length !== expected) {
    refuse(
      leg,
      `"${needle}" matched ${rows.length} rows where ${expected} were expected, so the filter does not reach every value a reader arrives with`,
    );
  }
}

// ---- Arm: a filter matching nothing says so, and does not say the server is empty ----
{
  const { rows, container } = render("nobody-by-that-name");
  const said = container.children.map((child) => child.textContent).join(" ");
  if (rows.length !== 0) {
    refuse("no-match", `${rows.length} rows survived a filter nothing matches`);
  }
  if (!/filter/i.test(said)) {
    refuse(
      "no-match",
      `a filter with no match said "${said}", which does not name the filter as the reason`,
    );
  }
  if (/No Jellyfin account holds an SSO link/.test(said)) {
    refuse(
      "no-match",
      "a filter with no match claimed the server holds no linked account, which is a statement about the server and not about the box",
    );
  }
}

// ---- Arm: an empty roster says the server is empty, whatever is typed ----
{
  const { container } = render("alice", { Accounts: [] });
  const said = container.children.map((child) => child.textContent).join(" ");
  if (!/No Jellyfin account holds an SSO link/.test(said)) {
    refuse(
      "empty-roster",
      `a server with no linked account said "${said}" instead of saying so`,
    );
  }
}

// ---- Arm: re-rendering asks the server for nothing ----
{
  // The roster is passed ONCE and then held. A second render without one must
  // still draw the table: if it fetched instead, this call would need ApiClient,
  // which is not defined here at all, and the arm would throw rather than pass.
  const { page, container } = pageWith("");
  core.renderLinkedAccounts(page, container, ROSTER);
  const again = pageWith("carol");
  core.renderLinkedAccounts(again.page, again.container);
  const rows = again.container.all("tbody").flatMap((body) => body.children);
  if (rows.length !== 1) {
    refuse(
      "held-roster",
      `a re-render without a roster drew ${rows.length} rows, so the filter does not work off what is already loaded`,
    );
  }
}

if (faults.length) {
  faults.forEach((fault) => console.error(fault));
  console.error(
    faults.length + " refusal(s) in the linked-accounts filter (#1529)",
  );
  process.exit(1);
}

console.log(
  "account filter:    eight arms run against the shipped sso-core.js renderer",
);
console.log("  unfiltered       every row is drawn and no count line is added");
console.log(
  "  narrowed         the matches are drawn and the page says how many of how many",
);
console.log(
  "  by-provider / by-protocol / by-subject / case   the filter reaches every value a reader arrives with",
);
console.log(
  "  no-match         a filter with no match names the filter, and never claims the server is empty",
);
console.log(
  "  empty-roster     a server with no linked account says so, whatever is typed",
);
console.log(
  "  held-roster      a re-render works off the roster already loaded and asks for nothing",
);
