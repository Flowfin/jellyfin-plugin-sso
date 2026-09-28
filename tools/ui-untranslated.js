#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Counts the English literals the settings scripts write without going through the
 * catalog, and refuses the number moving either way (#1602). A counted literal is a
 * double-quoted string opening with a capital and holding a space, with no length
 * floor (#1725); literals handed to the save-status (#1723) and progress (#1739)
 * renderers are refused by site. Exceptions go in EXEMPT with their reason.
 * Run with `node tools/ui-untranslated.js`; no dependencies.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.join(HERE, "..", "SSO-Auth", "Web");

// The pinned count: it goes down in the commit that wraps sentences, and never up.
const PINNED = 0;

// Not this plugin's prose: the vendored API client, and the translator itself.
const SKIP = new Set(["jellyfin-apiClient.esm.min.js", "i18n.js"]);

// Sentences that stay literal, each with its reason; matched exactly, and a stale entry is refused.
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
  {
    text: "URL candidates:",
    why:
      "The label of a console.debug line in ApiClient.js that lists the server addresses the linking " +
      "page is about to probe. It is written to the browser console for whoever is debugging that " +
      "page and never into the page itself, and the console is not a localized surface.",
  },
  {
    text: "SSO Account Linking",
    why:
      "The device name the linking page registers its session under, which Jellyfin stores and shows " +
      "in its device list as the name of that device. It is an identifier the server keeps rather " +
      "than prose this page renders: translated, the same device would be listed under a different " +
      "name depending on the language of the browser that linked, and the comment beside it in " +
      "ApiClient.js says why it is fixed and non-identifying.",
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

// No length floor (#1725); the space test separates a sentence from a token.
const SENTENCE = /"([A-Z][^"]+)"/g;

// The English default of a catalog call: `tr(key, english)`, `t(key, params, english)` with a flat
// object or `undefined` as params (#1731), and a template's `noteKey`/`labelKey` beside its English,
// looked up where the template renders because it is built before the catalog loads.
const AS_DEFAULT = [
  /\btr?\(\s*"[a-z0-9_.]+"\s*,\s*$/,
  /\bt\(\s*"[a-z0-9_.]+"\s*,\s*(?:\{[^{}]*\}|undefined)\s*,\s*$/,
  /\w+Key:\s*"[a-z0-9_.]+"\s*,\s*\w+:\s*$/,
];

// A literal handed to a save-status renderer (#1723), read by site so a one-word literal is refused too.
const STATUS_LITERAL = /\brender(?:Saml)?SaveStatus\(\s*\w+\s*,\s*"([^"]+)"/g;

// A literal handed to a progress renderer (#1739), read by site for the same reason.
const PROGRESS_LITERAL =
  /\brender(?:Test|Transfer)Message\(\s*\w+\s*,\s*"([^"]+)"/g;

/*
 * Reads the whole file, since the formatter can put a catalog call's key on the line
 * above its English default and a line-based test would count it as untranslated.
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
    // Anchored at the end, so it reads the text right before the literal across newlines.
    const before = source.slice(0, match.index);
    if (AS_DEFAULT.some((shape) => shape.test(before))) {
      continue;
    }
    const line = source.slice(0, match.index).split("\n").length;
    found.push({ file: path.basename(file), line, text });
  }

  return found;
}

// The literals a by-site pattern finds, shared by both renderer arms.
function siteLiteralsIn(file, pattern) {
  const source = withoutComments(fs.readFileSync(file, "utf8"));
  const found = [];

  pattern.lastIndex = 0;
  let match;
  while ((match = pattern.exec(source)) !== null) {
    const line = source.slice(0, match.index).split("\n").length;
    found.push({ file: path.basename(file), line, text: match[1] });
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

  // A stale exemption is refused, so a changed sentence cannot silently lose it.
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

  [
    { pattern: STATUS_LITERAL, renderer: "save-status renderer" },
    { pattern: PROGRESS_LITERAL, renderer: "progress renderer" },
  ].forEach(({ pattern, renderer }) =>
    files
      .flatMap((file) => siteLiteralsIn(file, pattern))
      .forEach((entry) =>
        faults.push(
          `${entry.file}:${entry.line} hands the literal "${entry.text}" to a ${renderer}. ` +
            `Wrap it in tr("<key>", "<English>") and add the key to en.json and de.json.`,
        ),
      ),
  );

  if (faults.length > 0) {
    faults.forEach((fault) => console.error("REFUSED  " + fault));
    process.exit(1);
  }

  console.log(
    `${counted.length} sentences still bypass the catalog, which is the pinned count.`,
  );
  console.log(
    `  status   no save-status renderer is handed a literal; each message is a catalog call`,
  );
  console.log(
    `  progress no test or transfer progress line is a literal; each goes through the catalog`,
  );
  console.log(
    `  exempt   ${EXEMPT.length} sentence(s) stay literal on purpose, with the reason beside each`,
  );
  console.log(
    `  scanned  ${files.length} files under SSO-Auth/Web, comments stripped`,
  );
}

main();
