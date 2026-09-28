#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Drives the shipped Overview renderer of sso-core.js and refuses each way the
 * downgrade mark on a provider card can mislead (#1727).
 *
 * A card with DisableHttps or AllowExistingAccountLink on must differ from a clean one,
 * so every positive arm is paired with a clean card in the same render that must carry
 * no mark. The mark names the class rather than a count. The DOM is a stub without
 * layout or CSS; the visual check stays with the walk on a real server (#1727).
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORE = path.join(HERE, "..", "SSO-Auth", "Web", "sso-core.js");
const ENGLISH = path.join(HERE, "..", "SSO-Auth", "Localization", "en.json");

// The catalogue keys the mark is built from, read from en.json so a renamed row fails here.
const SENTENCE_KEY = "config.insecure_option_active";
const INSECURE_KEY = "config.security_insecure_heading";
const ADOPTION_KEY = "config.security_adoption_heading";

// A minimal DOM element with the members the renderer touches.

class Element {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.attributes = {};
    this.dataset = {};
    this.classes = new Set();
    this.hidden = false;
    this.text = "";
    this.classList = {
      add: (...names) => names.forEach((name) => this.classes.add(name)),
    };
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

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  replaceChildren(...nodes) {
    this.children = nodes;
    this.text = "";
  }

  /** Every element under this one carrying the given class, at any depth. */
  withClass(name) {
    return this.children.flatMap((child) => [
      ...(child.classes.has(name) ? [child] : []),
      ...child.withClass(name),
    ]);
  }
}

/** The four regions paintOverview refuses to run without. */
function overviewPage() {
  const nodes = {
    "sso-overview-providers": new Element("div"),
    "sso-overview-providers-empty": new Element("p"),
    "sso-overview-next": new Element("ul"),
    "sso-overview-state": new Element("div"),
  };
  return {
    page: { querySelector: (selector) => nodes[selector.slice(1)] ?? null },
    cards: nodes["sso-overview-providers"],
  };
}

// Both spellings, because the card builder uses `document` and renderTransferMessage `window.document`.
globalThis.document = { createElement: (tag) => new Element(tag) };
globalThis.window = { document: globalThis.document };

// The fixture.

const catalogue = JSON.parse(fs.readFileSync(ENGLISH, "utf8"));
const SENTENCE = catalogue[SENTENCE_KEY];
const INSECURE = catalogue[INSECURE_KEY];
const ADOPTION = catalogue[ADOPTION_KEY];

/** One report row per provider named, with Ready and Enabled held true so arms test the mark alone. */
const rowsFor = (names) =>
  names.map(([protocol, provider]) => ({
    Protocol: protocol,
    Provider: provider,
    Ready: true,
    Enabled: true,
    MissingFields: [],
    Problem: null,
  }));

// Imports the shipped sso-core.js as a data URL module.
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

/** Paints one report and answers the status-row texts per provider card, with no roster. */
function paint(names, config) {
  const { page, cards } = overviewPage();
  core.paintOverview(page, { Providers: rowsFor(names) }, null, config);
  const painted = {};
  cards.children.forEach((card, index) => {
    painted[names[index][1]] = card
      .withClass("sso-check-list")
      .flatMap((list) => list.children)
      .map((item) => item.textContent);
  });
  return painted;
}

/** The mark's row on a card, or null where the card carries none. */
const markOn = (rows) => rows.find((text) => text.startsWith(SENTENCE)) ?? null;

/** One paired arm: a card that must name each expected class and a clean card in the same render. */
function paired(leg, names, config, flagged, expected) {
  const painted = paint(names, config);

  const mark = markOn(painted[flagged] || []);
  if (!mark) {
    refuse(
      leg,
      `the card for "${flagged}" carries no mark, and its rows were ${JSON.stringify(painted[flagged])}`,
    );
  } else {
    expected.forEach((name) => {
      if (!mark.includes(name)) {
        refuse(
          leg,
          `the mark on "${flagged}" does not name the class "${name}"; it reads "${mark}"`,
        );
      }
    });
    [INSECURE, ADOPTION]
      .filter((name) => !expected.includes(name))
      .forEach((name) => {
        if (mark.includes(name)) {
          refuse(
            leg,
            `the mark on "${flagged}" names "${name}", which no setting on that provider is in`,
          );
        }
      });
    if (/\d/.test(mark)) {
      refuse(
        leg,
        `the mark on "${flagged}" carries a digit ("${mark}"), and a count here is a different population from the fold summary that uses the same wording`,
      );
    }
  }

  Object.keys(painted)
    .filter((name) => name !== flagged)
    .forEach((name) => {
      if (markOn(painted[name])) {
        refuse(
          leg,
          `the card for "${name}" carries the mark, and nothing on that provider is switched on`,
        );
      }
    });
}

// ---- Arm: an insecure OpenID toggle is named, a clean provider beside it is not ----
paired(
  "oid-insecure",
  [
    ["OpenID", "downgraded"],
    ["OpenID", "clean"],
  ],
  {
    OidConfigs: {
      downgraded: { DisableHttps: true },
      clean: {},
    },
    SamlConfigs: {},
  },
  "downgraded",
  [INSECURE],
);

// ---- Arm: adoption alone names the adoption class and not the insecure one ----
paired(
  "oid-adoption",
  [
    ["OpenID", "adopts"],
    ["OpenID", "clean"],
  ],
  {
    OidConfigs: {
      adopts: { AllowExistingAccountLink: true },
      clean: {},
    },
    SamlConfigs: {},
  },
  "adopts",
  [ADOPTION],
);

// ---- Arm: both classes on names both ----
paired(
  "oid-both",
  [
    ["OpenID", "both"],
    ["OpenID", "clean"],
  ],
  {
    OidConfigs: {
      both: {
        AllowPrivateNetworkAddresses: true,
        AllowExistingAccountLink: true,
      },
      clean: {},
    },
    SamlConfigs: {},
  },
  "both",
  [INSECURE, ADOPTION],
);

// ---- Arm: the SAML list is the SAML one ----
// A renderer reading one id list for both protocols flags the wrong card here.
paired(
  "saml-insecure",
  [
    ["SAML", "saml-downgraded"],
    ["SAML", "saml-clean"],
  ],
  {
    OidConfigs: {},
    SamlConfigs: {
      "saml-downgraded": { DoNotValidateAudience: true },
      "saml-clean": { DisableHttps: true },
    },
  },
  "saml-downgraded",
  [INSECURE],
);

// ---- Arm: a hardening toggle is not a downgrade ----
// These default off, and switching one on makes the provider more secure.
{
  const painted = paint(
    [
      ["OpenID", "hardened"],
      ["OpenID", "downgraded"],
    ],
    {
      OidConfigs: {
        hardened: {
          RequirePkce: true,
          RequireVerifiedEmailForLogin: true,
          RequireVerifiedEmailForAdoption: true,
        },
        downgraded: { DoNotValidateIssuerName: true },
      },
      SamlConfigs: {},
    },
  );
  if (markOn(painted.hardened)) {
    refuse(
      "hardening-is-not-a-downgrade",
      "a provider whose only non-default settings make it MORE secure carries the mark",
    );
  }
  if (!markOn(painted.downgraded)) {
    refuse(
      "hardening-is-not-a-downgrade",
      "the downgraded provider rendered beside it carries none, so this arm proves nothing",
    );
  }
}

// ---- Arm: a configuration that did not load draws the cards and marks nothing ----
// The read answers null on failure, and the cards must still appear.
{
  const painted = paint([["OpenID", "unknown"]], null);
  if (!painted.unknown || painted.unknown.length === 0) {
    refuse(
      "configuration-unread",
      "no card was drawn when the configuration read failed",
    );
  } else if (markOn(painted.unknown)) {
    refuse(
      "configuration-unread",
      "a card carried the mark although no configuration was read, so the mark is not answering the saved state",
    );
  }
}

// ---- Arm: a provider the configuration does not hold is not marked ----
{
  const painted = paint([["OpenID", "missing"]], {
    OidConfigs: { somebody_else: { DisableHttps: true } },
    SamlConfigs: {},
  });
  if (markOn(painted.missing)) {
    refuse(
      "row-without-a-record",
      "a row with no record in the configuration took another provider's downgrade",
    );
  }
}

// ---- Arm: the mark is the Providers list's own sentence, from the catalogue ----
{
  if (!SENTENCE || !INSECURE || !ADOPTION) {
    refuse(
      "one-wording",
      `en.json is missing one of ${SENTENCE_KEY}, ${INSECURE_KEY}, ${ADOPTION_KEY}, so the mark and the fold it points at cannot be one wording`,
    );
  }
  const core_source = fs.readFileSync(CORE, "utf8");
  [SENTENCE_KEY, INSECURE_KEY, ADOPTION_KEY].forEach((key) => {
    if (!core_source.includes('"' + key + '"')) {
      refuse(
        "one-wording",
        `the renderer does not read ${key}, so the card would carry a second copy of a sentence the catalogue already holds`,
      );
    }
  });
}

if (faults.length) {
  faults.forEach((fault) => console.error(fault));
  console.error(
    faults.length + " refusal(s) in the Overview downgrade mark (#1727)",
  );
  process.exit(1);
}

console.log(
  "overview mark:     seven arms run against the shipped sso-core.js renderer",
);
console.log(
  "  oid-insecure / oid-adoption / oid-both   the class on the provider is named, and only that class",
);
console.log(
  "  saml-insecure    the SAML list decides a SAML card, and an OpenID id on one marks nothing",
);
console.log(
  "  hardening-is-not-a-downgrade   a fail-closed toggle switched ON is never flagged",
);
console.log(
  "  configuration-unread / row-without-a-record   an unread or absent record draws a card and marks nothing",
);
console.log(
  "  one-wording      the sentence and both class names come from the catalogue rows the Providers form uses",
);
console.log(
  "  every arm pairs a flagged card with a clean one in the SAME render, so a mark on everything fails too",
);
