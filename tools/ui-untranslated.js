#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Counts the English sentences the settings surface writes without going through
 * the catalog, and refuses the number moving in either direction (#1602).
 *
 * WHY A COUNT AND NOT A LIST. `de.json` and `en.json` carry the same keys and
 * nothing is missing from either, so every check the localization has is green
 * while a `de-DE` administrator reads a page that is half English. The reason is
 * not the catalogs: a sentence written as a literal in the bundle never reaches
 * them, so it cannot be reported as absent from something it was never in. The
 * gap is invisible to a completeness check by construction.
 *
 * What it is NOT invisible to is a count, and the count is what this pins. It
 * refuses an increase, which is the drift - one more literal is one more
 * sentence a translator will never see. It refuses a decrease too, which is not
 * pedantry: a tranche that wraps ten of them and leaves the pin alone would let
 * the next ten arrive unseen behind the slack it left. The pin moves in the same
 * commit as the work, and that is what makes it a ratchet rather than a number.
 *
 * THE PIN IS ZERO NOW, so in practice this refuses the next literal outright.
 * The ratchet shape is kept rather than replaced by a flat "none allowed": the
 * exemptions below are what "none" actually means, and a future sentence that
 * genuinely cannot reach a catalog belongs in that list with its reason beside
 * it, not in a number nobody can read a reason out of.
 *
 * WHAT COUNTS. A double-quoted literal of twenty characters or more, opening
 * with a capital and containing a space, that is not the English default of a
 * `tr(...)` or `t(...)` call. That is deliberately coarse. It matches things
 * that are not prose and misses prose written without a capital, and both are
 * fine for a ratchet: what it has to be is STABLE, so the same tree always
 * yields the same number and a change to the number is always a change somebody
 * made.
 *
 * Comments are stripped character by character rather than line by line,
 * because this file's siblings in `SSO-Auth/Web` carry paragraphs of reasoning
 * with sentences in them, and a line-based strip would count the reasoning.
 *
 * Node is preinstalled on the runner and this tool has no dependencies, in the
 * same terms as tools/ui-mock-fields.js and tools/ui-unsaved-state.js.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.join(HERE, "..", "SSO-Auth", "Web");

// The pinned count. It goes DOWN as sentences are wrapped, in the same commit
// that wraps them, and it never goes up. ZERO since 2026-09-11: every sentence the
// settings surface writes goes through the catalog, and the two that stay literal are
// named in EXEMPT below with the reason each cannot.
const PINNED = 0;

// Files that are not this plugin's prose: the vendored API client, and the
// translator itself, which cannot translate through the thing it is.
const SKIP = new Set(["jellyfin-apiClient.esm.min.js", "i18n.js"]);

// Sentences that stay literal on purpose, each with the reason it cannot go
// through the catalog. Matched on the exact text, and a stale entry - one no
// file carries any more - is refused, so this list cannot quietly grant an
// exemption to a sentence that has since changed.
const EXEMPT = [
  {
    text:
      "This settings page could not finish loading, so its controls will not do anything and " +
      "nothing typed into them would be saved. Reload the page; if it keeps happening the plugin's " +
      "assets are not being served, and the server log will say why.",
    why:
      "The bootstrap banner of the five page controllers. It is written exactly when the dynamic " +
      "import of the core did not arrive, and the localization module is loaded by the core through " +
      "the same route - so at the moment this sentence is needed there is no translator to ask. A " +
      "catalog lookup here would fail in the same way the page just did.",
  },
  {
    text: "Microsoft Entra ID (Azure AD)",
    why:
      "A product name, and the same string in every language. The template label beside it that " +
      "DESCRIBES rather than names - 'Generic OpenID Connect' - carries a key and is translated; this " +
      "one would be a catalog row nobody could ever change, saying Microsoft Entra ID in every locale.",
  },
];

/** Replaces comment CONTENT with spaces, keeping every line and column in place. */
function withoutComments(source) {
  let out = "";
  let index = 0;
  let inLine = false;
  let inBlock = false;
  let quote = null;

  while (index < source.length) {
    const ch = source[index];
    const two = source.slice(index, index + 2);

    if (inLine) {
      if (ch === "\n") {
        inLine = false;
        out += ch;
      } else {
        out += " ";
      }
      index += 1;
    } else if (inBlock) {
      if (two === "*/") {
        inBlock = false;
        out += "  ";
        index += 2;
      } else {
        out += ch === "\n" ? "\n" : " ";
        index += 1;
      }
    } else if (quote) {
      out += ch;
      if (ch === "\\") {
        out += source[index + 1] ?? "";
        index += 2;
        continue;
      }
      if (ch === quote) {
        quote = null;
      }
      index += 1;
    } else if (two === "//") {
      inLine = true;
      out += "  ";
      index += 2;
    } else if (two === "/*") {
      inBlock = true;
      out += "  ";
      index += 2;
    } else if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      out += ch;
      index += 1;
    } else {
      out += ch;
      index += 1;
    }
  }

  return out;
}

const SENTENCE = /"([A-Z][^"]{19,})"/g;

// The English default of a catalog call, in the two shapes this tree uses. `tr(key, english)`
// is the core's own wrapper, which puts the default second. `t(key, params, english)` is what
// i18n.js exports and the linking page calls directly, and it puts the default THIRD, behind
// the parameter object - so a regex that only knew the first shape counted a translated string
// as untranslated. The object is matched without nesting on purpose: a parameter bag here is a
// flat map of names to values, and accepting a nested one would start excusing anything that
// merely looked like a call.
//
// The THIRD shape is for text that cannot be wrapped where it is written. The provider
// templates are object literals built when the module loads, which is before the
// localization module has resolved, so a tr() call there would freeze the English
// default into the object once and for good. Each template therefore carries its KEY
// beside the English - `noteKey` next to `note`, `labelKey` next to `label` - and the
// catalog lookup happens where the template is rendered. The English is still the
// fallback, still one copy, and ScriptEnglishDefaults_MatchTheCatalog still pins it
// equal to the catalog, so the property this tool exists for is unchanged.
const AS_DEFAULT = [
  /\btr?\(\s*"[a-z0-9_.]+"\s*,\s*$/,
  /\bt\(\s*"[a-z0-9_.]+"\s*,\s*\{[^{}]*\}\s*,\s*$/,
  /\w+Key:\s*"[a-z0-9_.]+"\s*,\s*\w+:\s*$/,
];

/*
 * Reads the WHOLE file rather than a line at a time, and that is not a detail. The
 * formatter breaks a long catalog call across four lines, so the key sits on the line
 * above its English default:
 *
 *     tr(
 *       "config.validation_endpoint_https",
 *       "Use an https:// URL for the OpenID endpoint.",
 *     ),
 *
 * A line-based test sees only the sentence and calls a translated string untranslated.
 * The first draft of this tool did exactly that, and its pinned baseline counted
 * sentences that already went through the catalog - which the first tranche exposed by
 * moving the number two instead of eleven.
 */
function findIn(file) {
  const source = withoutComments(fs.readFileSync(file, "utf8"));
  const found = [];

  SENTENCE.lastIndex = 0;
  let match;
  while ((match = SENTENCE.exec(source)) !== null) {
    const text = match[1];
    if (!text.includes(" ")) {
      continue;
    }
    // Anchored at the end, so it reads the text immediately before the literal, across
    // any newlines and indentation the formatter put there.
    const before = source.slice(0, match.index);
    if (AS_DEFAULT.some((shape) => shape.test(before))) {
      continue;
    }
    const line = source.slice(0, match.index).split("\n").length;
    found.push({ file: path.basename(file), line, text });
  }

  return found;
}

function main() {
  const files = fs
    .readdirSync(WEB)
    .filter((name) => name.endsWith(".js") && !SKIP.has(name))
    .sort()
    .map((name) => path.join(WEB, name));

  const all = files.flatMap(findIn);
  const exemptTexts = new Set(EXEMPT.map((entry) => entry.text));
  const counted = all.filter((entry) => !exemptTexts.has(entry.text));

  const faults = [];

  // A stale exemption is refused: an entry naming a sentence no file carries any
  // more is an exemption nobody can see the effect of, and the next edit to that
  // sentence would silently lose it.
  const present = new Set(all.map((entry) => entry.text));
  EXEMPT.filter((entry) => !present.has(entry.text)).forEach((entry) =>
    faults.push(
      `a stale exemption: no file carries "${entry.text.slice(0, 60)}..." any more, so remove it`,
    ),
  );

  if (counted.length > PINNED) {
    const byFile = new Map();
    counted.forEach((entry) => {
      byFile.set(entry.file, (byFile.get(entry.file) ?? 0) + 1);
    });
    faults.push(
      `${counted.length} sentences bypass the catalog, ${counted.length - PINNED} more than the pinned ${PINNED}. ` +
        `Wrap the new one in tr("<key>", "<English>") and add the key to en.json and de.json. Per file: ` +
        [...byFile.entries()]
          .map(([file, count]) => `${file} ${count}`)
          .join(", "),
    );
  } else if (counted.length < PINNED) {
    faults.push(
      `${counted.length} sentences bypass the catalog, ${PINNED - counted.length} fewer than the pinned ${PINNED}. ` +
        `That is the work going in the right direction - lower PINNED to ${counted.length} in this same commit, ` +
        `so the slack cannot hide the next one that arrives.`,
    );
  }

  if (faults.length > 0) {
    faults.forEach((fault) => console.error("REFUSED  " + fault));
    process.exit(1);
  }

  console.log(
    `${counted.length} sentences still bypass the catalog, which is the pinned count.`,
  );
  console.log(
    `  exempt   ${EXEMPT.length} sentence(s) stay literal on purpose, with the reason beside each`,
  );
  console.log(
    `  scanned  ${files.length} files under SSO-Auth/Web, comments stripped`,
  );
}

main();
