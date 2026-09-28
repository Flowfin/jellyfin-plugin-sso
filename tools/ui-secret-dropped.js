#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Drives the shipped sso-core.js decisions about whether a provider save dropped the
 * stored client secret and what the page says about it (#1872).
 *
 * The server does not carry a stored secret over to a provider whose discovery endpoint
 * or client id changed, so the page reads the configuration back after the save and
 * compares OidSecretStored before and after. Every source search is bounded to
 * saveProvider, and a missing anchor refuses rather than passes.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORE = path.join(HERE, "..", "SSO-Auth", "Web", "sso-core.js");

// Imports the shipped sso-core.js as a data URL module.
async function loadCore() {
  const source = fs.readFileSync(CORE, "utf8");
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64");
  return (await import(url)).default;
}

// The two readings per case: the secret is never sent back, so OidSecretStored is the only signal.
const DECISIONS = [
  [
    "dropped",
    true,
    { OidSecretStored: false },
    true,
    "a secret that was stored and is not stored after the save was dropped by it",
  ],
  [
    "kept",
    true,
    { OidSecretStored: true },
    false,
    "a secret still stored after the save was kept, or rotated, and nothing is reported",
  ],
  [
    "nothing-was-stored",
    false,
    { OidSecretStored: false },
    false,
    "a provider that had no secret drops none, and claiming otherwise sends an administrator hunting for one that never existed",
  ],
  [
    "new-provider",
    false,
    undefined,
    false,
    "a provider being created for the first time reports nothing, whatever the read-back holds",
  ],
  [
    "flag-absent-reads-as-dropped",
    true,
    {},
    true,
    "a read-back that carries no flag at all says nothing is stored, and that is a drop, not a pass",
  ],
  [
    "read-back-without-the-provider",
    true,
    undefined,
    null,
    "a read-back that does not hold the provider answers neither way, and the page says that rather than 'saved'",
  ],
];

// Refuses unless each answer maps to its own sentence and colour.
function sentenceLeg(core, refuse) {
  if (typeof core.saveStatusFor !== "function") {
    refuse(
      "sentence",
      "sso-core.js exports no saveStatusFor, so the page cannot choose what to say about a save",
    );
    return;
  }
  const plain = core.saveStatusFor({ secretDropped: false });
  const dropped = core.saveStatusFor({ secretDropped: true });
  const unknown = core.saveStatusFor({ secretDropped: null });
  const bare = core.saveStatusFor(undefined);
  if (plain.ok !== true || !plain.message) {
    refuse(
      "sentence-kept",
      "a save that kept the secret must render the plain sentence in the success colour",
    );
  }
  if (bare.ok !== true || bare.message !== plain.message) {
    refuse(
      "sentence-bare",
      "an outcome carrying no answer is an ordinary save and must read as the plain sentence",
    );
  }
  if (dropped.ok !== false || dropped.message === plain.message) {
    refuse(
      "sentence-dropped",
      "a save that dropped the secret must render its own sentence in the failure colour, not 'saved'",
    );
  }
  if (
    unknown.ok !== false ||
    unknown.message === plain.message ||
    unknown.message === dropped.message
  ) {
    refuse(
      "sentence-unknown",
      "a read-back that did not answer must render its own sentence in the failure colour, neither 'saved' nor 'dropped'",
    );
  }
}

// Refuses unless saveProvider captures the first reading early and reads back after the save.
function sourceLegs(refuse) {
  const source = fs.readFileSync(CORE, "utf8");
  const start = source.indexOf("\n  saveProvider: (page, provider_name) => {");
  if (start < 0) {
    refuse(
      "capture-order",
      "no saveProvider is in sso-core.js, so neither ordering leg knows where to read",
    );
    return;
  }
  // The next page-object member bounds every search below.
  const next = /\n {2}[A-Za-z_$][\w$]*: /g;
  next.lastIndex = start + 1;
  const bound = next.exec(source);
  const end = bound ? bound.index : source.length;
  const within = (anchor, from) => {
    const at = source.indexOf(anchor, from);
    return at < 0 || at >= end ? -1 : at;
  };
  const countWithin = (anchor, from) => {
    let count = 0;
    let at = within(anchor, from);
    while (at >= 0) {
      count += 1;
      at = within(anchor, at + anchor.length);
    }
    return count;
  };

  const capture = within("const secret_was_stored = ", start);
  const overwrite = within("form_elements.text_fields.forEach", start);
  if (capture < 0) {
    refuse(
      "capture-order",
      "no secret_was_stored reading is in saveProvider, so nothing holds the state the save is compared against",
    );
  } else if (overwrite < 0) {
    refuse(
      "capture-order",
      "no text_fields loop is in saveProvider, so this leg cannot say what the reading runs before",
    );
  } else if (capture > overwrite) {
    refuse(
      "capture-order",
      "the first reading is taken AFTER the form loops touch the stored provider in place, so it reads the posted state rather than the stored one",
    );
  }

  const save = within("ApiClient.updatePluginConfiguration(", start);
  const readBack =
    save < 0 ? -1 : within("ApiClient.getPluginConfiguration(", save);
  if (save < 0) {
    refuse(
      "read-back",
      "no updatePluginConfiguration call is in saveProvider, so this leg cannot say what the read-back follows",
    );
  } else if (readBack < 0) {
    refuse(
      "read-back",
      "no getPluginConfiguration call follows the save inside saveProvider, so the second reading is never taken and every save reports nothing",
    );
  } else if (countWithin("secretDroppedByThisSave(", readBack) !== 2) {
    refuse(
      "read-back",
      "the read-back's two arms must each hand the first reading to secretDroppedByThisSave: a second rule beside it, or an arm that resolves without asking, is where the answer goes quiet",
    );
  }
}

// Runs every leg and exits non-zero on any refusal.
async function main() {
  const core = await loadCore();
  const faults = [];
  const refuse = (leg, detail) => faults.push(leg + ": " + detail);

  if (typeof core.secretDroppedByThisSave !== "function") {
    refuse(
      "decision",
      "sso-core.js exports no secretDroppedByThisSave, so the page cannot answer whether a save dropped the secret",
    );
  } else {
    for (const [leg, wasStored, saved, expected, why] of DECISIONS) {
      const answer = core.secretDroppedByThisSave(wasStored, saved);
      if (answer !== expected) {
        refuse(
          leg,
          `expected ${String(expected)} and got ${String(answer)} - ${why}`,
        );
      }
    }
  }

  sentenceLeg(core, refuse);
  sourceLegs(refuse);

  if (faults.length > 0) {
    console.error("sso-core.js refuses the dropped-secret report:");
    faults.forEach((fault) => console.error("  " + fault));
    process.exit(1);
  }

  console.log(
    `sso-core.js reports a dropped client secret: ${DECISIONS.length} decision(s), the sentence for each answer, the capture order and the read-back`,
  );
  DECISIONS.forEach(([leg, , , , why]) => console.log("  " + leg + "  " + why));
  console.log(
    "  sentence         a drop and an unanswered read-back each get their own sentence in the failure colour; only a kept secret reads as saved",
  );
  console.log(
    "  capture-order    the first reading is taken before the form touches the stored provider",
  );
  console.log(
    "  read-back        the second reading is asked of the server after the save has landed, and both arms hand it to the decision",
  );
}

main().catch((error) => {
  console.error(String((error && error.stack) || error));
  process.exit(1);
});
