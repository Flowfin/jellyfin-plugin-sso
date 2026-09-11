#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Counts the text the page TEMPLATES show without going through the catalog,
 * and refuses the number moving in either direction (#1529).
 *
 * WHY A SECOND COUNTER BESIDE tools/ui-untranslated.js. That one asks the same
 * question of the SCRIPTS, and it reached zero. The templates are a different
 * surface with different rules and it never looked at them: a sentence written
 * between two tags is not a literal in a bundle, and no amount of scanning
 * JavaScript finds it. The walk of 2026-09-11 read a de-DE client and found the
 * five pages mixing both languages while every localization check in the tree
 * was green, which is what two surfaces and one counter buys.
 *
 * WHAT COUNTS, AND WHY IT IS A RUN AND NOT AN ELEMENT. The house pattern in
 * these templates is a `<span data-i18n="key">` around ONE SENTENCE, because
 * `i18n.applyTo` assigns `el.textContent`, which replaces every child an element
 * has. So a paragraph of mixed content - prose with an `<a>` or a `<strong>` in
 * the middle - cannot carry one marker; it carries several, one per sentence,
 * and the bare text between them is its own run. Counting ELEMENTS would report
 * such a paragraph as handled the moment any one of its spans was marked. The
 * unit here is therefore the text run: a stretch of characters between two tags,
 * whose enclosing element carries no marker.
 *
 * The three attributes i18n.js can localize are counted too. They are user-
 * visible text in every other respect, and the collapse headers of the provider
 * editor - each one a `title=` - are among the largest untranslated surfaces on
 * the page.
 *
 * WHAT DOES NOT COUNT, AND EACH EXEMPTION IS STRUCTURAL RATHER THAN A LIST OF
 * STRINGS. A list of strings ages badly: it grants its exemption to whatever the
 * text is changed to, and nobody re-reads it. These are properties instead.
 *
 *  - Content of `code`, `kbd`, `samp`, `pre` and `title`. An identifier, a
 *    command or a code sample is the same in every language, and a catalog row
 *    for `DisablePasswordLogin` would be a row nobody could ever change.
 *  - An `<option>` whose text IS its `value`. Those name a value the server
 *    declares rather than saying something: the help beside the subtitle-mode
 *    picker states outright that the options are the exact mode names Jellyfin
 *    declares and that the spelling is what a save accepts. Translating one
 *    would break the field it belongs to.
 *  - A `placeholder` with no whitespace in it. A placeholder is a sample of what
 *    to type, and a one-token sample is a VALUE: `preferred_username` is a claim
 *    name and `https://idp.example.com/metadata` is an address. Prose in a
 *    placeholder has spaces in it, so the rule keeps the one that reads "...or
 *    paste the metadata XML here" and drops the two that are examples. Scoped to
 *    placeholders on purpose: a `title` of one word is usually a section heading
 *    and needs translating, which is why the same rule would be wrong there.
 *
 * A run with fewer than two letters is not text: it is the comma between two
 * links, or an entity, or whitespace the formatter left behind.
 *
 * THE RATCHET, same shape and same reason as the script-side counter. It refuses
 * an increase, which is the drift. It refuses a decrease too, because a tranche
 * that keys thirty runs and leaves the pin alone lets the next thirty arrive
 * unseen behind the slack. The pin moves in the same commit as the work.
 *
 * WHAT THIS TOOL CANNOT SAY, and the bound belongs here rather than in a commit
 * message nobody will find. It counts what the catalog never sees. It cannot see
 * a string that DOES reach the catalog and is English on the screen anyway,
 * which happens when a `tr()` call runs during init while the catalog is still
 * arriving. That defect is real, it was measured on the same walk, and it is
 * invisible to this tool and to its script-side sibling alike, because both read
 * the source and neither can see WHEN a line runs.
 *
 * Node is preinstalled on the runner and this tool has no dependencies, in the
 * same terms as tools/ui-mock-fields.js and tools/ui-untranslated.js.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.join(HERE, "..", "SSO-Auth", "Web");

// The pinned count. It goes DOWN as runs are keyed, in the same commit that keys
// them, and it never goes up.
const PINNED = 330;
const PINNED_ATTRIBUTES = 18;

// The six templates a reader of this plugin actually sees: the five dashboard
// pages and the self-service page.
const TEMPLATES = [
  "configPage.html",
  "providersPage.html",
  "accountsPage.html",
  "policiesPage.html",
  "serverPage.html",
  "linking.html",
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

// The attributes i18n.js will localize, and the only ones it will: the allowlist
// there is deliberate, so this asks about exactly those three.
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

/**
 * Walks the tag stream of one template and returns the runs and attributes the
 * catalog never sees. Deliberately a tag walk and not a parser: the templates
 * are well-formed and generated by nothing, a parser would be a dependency, and
 * what this needs to know - which element encloses this text, and does it carry
 * a marker - is exactly what a walk with a stack knows.
 */
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
      const marked = parent ? parent.marker !== null : false;
      const opaque = parent ? OPAQUE.has(parent.name) : false;
      const declared =
        parent !== undefined &&
        parent.name === "option" &&
        parent.value === text;
      if (!marked && !opaque && !declared) {
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
          marker: attributeOf(match[2], "data-i18n"),
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

if (faults.length) {
  faults.forEach((fault) => console.error(fault));
  console.error("Run with --list to see them, then key them and move the pin.");
  process.exit(1);
}

console.log(
  `${totalRuns} text run(s) and ${totalAttributes} attribute(s) in the templates still bypass the catalog, which is the pinned count.`,
);
for (const { file, runs, attributes } of perFile) {
  console.log(
    `  ${file.padEnd(20)} ${String(runs.length).padStart(3)} text  ${String(attributes.length).padStart(2)} attr`,
  );
}
