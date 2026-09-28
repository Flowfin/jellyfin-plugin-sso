#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Counts the text runs and localizable attributes the page templates show without
 * a catalog marker, and refuses the number moving either way (#1529). Code-like
 * content, value options, one-token placeholders and the EXEMPT list do not count.
 * It cannot see a tr() call that runs before the catalog arrives.
 * Run with `node tools/ui-untranslated-markup.js`; no dependencies.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.join(HERE, "..", "SSO-Auth", "Web");

// The pinned count: it goes down in the commit that keys runs, and never up.
const PINNED = 0;
const PINNED_ATTRIBUTES = 0;

// The five dashboard pages and the self-service page.
const TEMPLATES = [
  "configPage.html",
  "providersPage.html",
  "accountsPage.html",
  "policiesPage.html",
  "serverPage.html",
  "linking.html",
];

// Text the script owns, each with its reason; matched exactly, and a stale entry is refused.
const EXEMPT = [
  {
    text: "New provider",
    why:
      'The editor heading, written by sso-core.js through tr("config.new_provider"). The markup ' +
      "beside it explains the rest: the script writes the LOADED provider's name here, so a marker " +
      'would let a late applyTo() overwrite "keycloak-prod" with the blank-editor wording over an ' +
      "editor that has a provider in it, and the Save path targets that provider by name.",
  },
  {
    text: "authelia",
    why:
      "A product name, and the same string in every language. It is the label of the link in the " +
      "scopes help that points at the issue where Authelia's extra scope requirement was worked out. " +
      "A catalogue row for it would be a row nobody could ever change, which is the same reason " +
      'tools/ui-untranslated.js exempts "Microsoft Entra ID (Azure AD)" on the script side.',
  },
];

// Elements whose content is an identifier or a sample rather than prose.
const OPAQUE = new Set([
  "code",
  "kbd",
  "samp",
  "pre",
  "title",
  "script",
  "style",
]);

// The attributes i18n.js localizes, and only those.
const ATTRIBUTES = ["title", "placeholder", "aria-label"];

// HTML elements that never close, so nothing is ever nested inside them.
const VOID = new Set([
  "area",
  "base",
  "br",
  "col",
  "embed",
  "hr",
  "img",
  "input",
  "link",
  "meta",
  "param",
  "source",
  "track",
  "wbr",
]);

/** Blanks comments and the doctype, keeping every line and column in place. */
function blankNonMarkup(html) {
  const blank = (match) => match.replace(/[^\n]/g, " ");
  return html
    .replace(/<!--[\s\S]*?-->/g, blank)
    .replace(/<!doctype[^>]*>/gi, blank);
}

function attributeOf(tagText, name) {
  const found = tagText.match(new RegExp("\\s" + name + '\\s*=\\s*"([^"]*)"'));
  return found ? found[1] : null;
}

// Every exempt text met in a template; one missing at the end is a stale entry.
const seenExempt = new Set();

/** Walks one template's tag stream and returns the runs and attributes the catalog never sees. */
function scan(file) {
  const html = blankNonMarkup(fs.readFileSync(path.join(WEB, file), "utf8"));
  const runs = [];
  const attributes = [];
  const tag = /<\/?([a-zA-Z][\w-]*)\b([^>]*?)\/?>/g;
  const open = [];
  let match;
  let textStart = 0;

  const lineAt = (index) => html.slice(0, index).split("\n").length;

  while ((match = tag.exec(html)) !== null) {
    const text = html.slice(textStart, match.index).replace(/\s+/g, " ").trim();
    if (text && /[A-Za-z]{2}/.test(text)) {
      const parent = open[open.length - 1];
      // Either marker covers the run: data-i18n replaces it, data-i18n-parts rewrites around it (#1529).
      const marked = parent ? parent.marker !== null : false;
      const opaque = parent ? OPAQUE.has(parent.name) : false;
      const declared =
        parent !== undefined &&
        parent.name === "option" &&
        parent.value === text;
      const scriptOwned = EXEMPT.some((entry) => entry.text === text);
      if (scriptOwned) {
        seenExempt.add(text);
      } else if (!marked && !opaque && !declared) {
        runs.push({ line: lineAt(textStart), text });
      }
    }
    textStart = tag.lastIndex;

    const name = match[1].toLowerCase();
    const closing = match[0][1] === "/";
    const selfClosing = match[0].endsWith("/>") || VOID.has(name);

    if (closing) {
      open.pop();
    } else {
      for (const attribute of ATTRIBUTES) {
        const value = attributeOf(match[2], attribute);
        const sampleValue =
          attribute === "placeholder" && !/\s/.test(value ?? "");
        if (
          value &&
          /[A-Za-z]{2}/.test(value) &&
          !sampleValue &&
          attributeOf(match[2], "data-i18n-" + attribute) === null
        ) {
          attributes.push({ line: lineAt(match.index), attribute, value });
        }
      }
      if (!selfClosing) {
        open.push({
          name,
          marker:
            attributeOf(match[2], "data-i18n") ??
            attributeOf(match[2], "data-i18n-parts"),
          value: attributeOf(match[2], "value"),
        });
      }
    }
  }

  return { runs, attributes };
}

const listing = process.argv.includes("--list");
let totalRuns = 0;
let totalAttributes = 0;
const perFile = [];

for (const file of TEMPLATES) {
  const { runs, attributes } = scan(file);
  totalRuns += runs.length;
  totalAttributes += attributes.length;
  perFile.push({ file, runs, attributes });
}

if (listing) {
  for (const { file, runs, attributes } of perFile) {
    for (const run of runs) {
      console.log(`${file}:${run.line}\ttext\t${run.text}`);
    }
    for (const attribute of attributes) {
      console.log(
        `${file}:${attribute.line}\t${attribute.attribute}\t${attribute.value}`,
      );
    }
  }
}

const faults = [];
if (totalRuns !== PINNED) {
  faults.push(
    `${totalRuns} text run(s) the catalog never sees, and the pin says ${PINNED}. ` +
      (totalRuns > PINNED
        ? "Something new is on the page in one language only."
        : "Runs were keyed without lowering the pin, which leaves slack the next ones hide in."),
  );
}
if (totalAttributes !== PINNED_ATTRIBUTES) {
  faults.push(
    `${totalAttributes} localizable attribute(s) without a marker, and the pin says ${PINNED_ATTRIBUTES}. ` +
      (totalAttributes > PINNED_ATTRIBUTES
        ? "A new title, placeholder or label is on the page in one language only."
        : "Attributes were marked without lowering the pin."),
  );
}

for (const entry of EXEMPT) {
  if (!seenExempt.has(entry.text)) {
    faults.push(
      `no template carries the exempt text "${entry.text}" any more, so its exemption grants nothing and the reason beside it is about something that is gone.`,
    );
  }
}

if (faults.length) {
  faults.forEach((fault) => console.error(fault));
  console.error("Run with --list to see them, then key them and move the pin.");
  process.exit(1);
}

console.log(
  `${totalRuns} text run(s) and ${totalAttributes} attribute(s) in the templates still bypass the catalog, which is the pinned count.`,
);
console.log(
  `  exempt   ${EXEMPT.length} text(s) the script owns, with the reason beside each`,
);
for (const { file, runs, attributes } of perFile) {
  console.log(
    `  ${file.padEnd(20)} ${String(runs.length).padStart(3)} text  ${String(attributes.length).padStart(2)} attr`,
  );
}
