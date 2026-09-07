#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Reconciles docs/ui/mock/FIELDS.md against the inputs of the configuration
 * page it promises to rehouse (#1526).
 *
 * WHY THE COUNT IS DERIVED AND NOT WRITTEN DOWN. Stage 0 asks that every field
 * of the old page reappears in the mock under a new home, and a table saying so
 * is worth only what checks it. A count typed into a document drifts against
 * the page the moment a field moves; a count read off the page cannot.
 *
 * WHY COMMENTS ARE STRIPPED FIRST. configPage.html documents its own hidden
 * `selectProvider` inside an HTML comment, and that comment contains a second
 * `<select>` tag. A reader that greps the raw bytes counts it and reaches 124;
 * a reader that strips comments reaches 123. Only one of the two is the set of
 * controls an administrator can reach, so the stripping happens here rather
 * than being left to whoever runs this.
 *
 * WHY IT COMPARES SETS AND NOT SIZES. A row kept for a field that was deleted
 * and a field added with no row cancel out in a count. They do not cancel out
 * in a set comparison, which is the drift the count exists to catch.
 */

"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const PAGE = path.join(root, "SSO-Auth", "Web", "configPage.html");
const TABLE = path.join(root, "docs", "ui", "mock", "FIELDS.md");
const DATA = path.join(root, "docs", "ui", "mock", "fields.js");

/** Replaces every HTML comment with spaces, so line numbers and offsets survive. */
function withoutComments(html) {
  return html.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, " "));
}

/** The value of `name="..."` on a tag, where the name starts an attribute. */
function attr(tag, name) {
  const key = name + '="';
  let i = 0;
  while ((i = tag.indexOf(key, i)) !== -1) {
    const before = tag[i - 1];
    if (
      before === " " ||
      before === "\n" ||
      before === "\r" ||
      before === "\t"
    ) {
      return tag.slice(i + key.length, tag.indexOf('"', i + key.length));
    }
    i += key.length;
  }
  return "";
}

/** Index of the `</div>` that closes the element opening at `start`. */
function regionEnd(html, start) {
  const re = /<div\b[^>]*>|<\/div>/g;
  re.lastIndex = start;
  let depth = 0;
  let m;
  while ((m = re.exec(html)) !== null) {
    if (m[0] === "</div>") {
      depth -= 1;
      if (depth === 0) return m.index;
    } else {
      depth += 1;
    }
  }
  return html.length;
}

function regionsOf(html, className) {
  const re = new RegExp(
    '<div [^>]*class="[^"]*' + className + '[^"]*"[^>]*>',
    "g",
  );
  const out = [];
  let m;
  while ((m = re.exec(html)) !== null)
    out.push({ a: m.index, b: regionEnd(html, m.index) });
  return out;
}

/** Every reachable form control of the page, in document order. */
function readPage() {
  const html = withoutComments(fs.readFileSync(PAGE, "utf8"));
  const sections = [
    ...html.matchAll(/<div\b[^>]*class="[^"]*verticalSection[^"]*"[^>]*>/g),
  ].map((m) => ({ at: m.index, title: attr(m[0], "title") }));
  const forms = [...html.matchAll(/<form\b[^>]*>/g)].map((m) => ({
    at: m.index,
    id: attr(m[0], "id"),
  }));
  const sensitive = regionsOf(html, "sso-sensitive-region");
  const insecure = regionsOf(html, "sso-danger-zone");
  const before = (list, at) => list.filter((x) => x.at < at).pop();
  const inside = (list, at) => list.some((r) => at > r.a && at < r.b);

  return [...html.matchAll(/<(input|select|textarea)\b[\s\S]*?>/g)].map(
    (m) => ({
      line: html.slice(0, m.index).split("\n").length,
      id: attr(m[0], "id"),
      tag: m[1],
      type: attr(m[0], "type") || m[1],
      form: (before(forms, m.index) || { id: "" }).id,
      block: (before(sections, m.index) || { title: "" }).title.replace(
        /&amp;/g,
        "&",
      ),
      risk: inside(insecure, m.index)
        ? "insecure"
        : inside(sensitive, m.index)
          ? "sensitive"
          : "",
    }),
  );
}

/** The `Field` column of every body row of the table in FIELDS.md. */
function readTable() {
  if (!fs.existsSync(TABLE)) return null;
  return fs
    .readFileSync(TABLE, "utf8")
    .split(/\r?\n/)
    .filter((l) => /^\|\s*`/.test(l))
    .map((l) => l.split("|")[1].trim().replace(/`/g, ""));
}

/**
 * The ids of docs/ui/mock/fields.js, which is what the mock pages render from.
 * It is loaded the way a browser loads it - a plain script assigning to a
 * global - rather than parsed, so this reads exactly what the mock reads.
 */
function readData() {
  if (!fs.existsSync(DATA)) return null;
  const shim = {};
  new Function("window", fs.readFileSync(DATA, "utf8"))(shim);
  return (shim.SSO_MOCK_FIELDS || []).map((f) => f.id);
}

function emit(fields) {
  for (const f of fields) {
    console.log(
      [
        "",
        "`" + f.id + "`",
        f.type,
        f.block || "(outside every block)",
        f.risk || "-",
        "",
        "",
      ].join(" | "),
    );
  }
}

function main() {
  const fields = readPage();
  if (process.argv.includes("--emit")) {
    emit(fields);
    return 0;
  }

  const pageIds = fields.map((f) => f.id);
  const rows = readTable();
  const faults = [];

  const anonymous = fields.filter((f) => !f.id);
  if (anonymous.length) {
    faults.push(
      anonymous.length +
        " control(s) on the page carry no id and cannot be keyed, at line(s) " +
        anonymous.map((f) => f.line).join(", "),
    );
  }
  const repeated = [
    ...new Set(pageIds.filter((id, i) => pageIds.indexOf(id) !== i)),
  ];
  if (repeated.length)
    faults.push("the page repeats id(s): " + repeated.join(", "));

  const data = readData();
  const against = (name, list) => {
    if (list === null) {
      faults.push(
        name + " does not exist, so nothing reconciles against the page",
      );
      return;
    }
    const twice = [...new Set(list.filter((id, i) => list.indexOf(id) !== i))];
    if (twice.length) faults.push(name + " names twice: " + twice.join(", "));
    const unlisted = pageIds.filter((id) => !list.includes(id));
    const orphaned = list.filter((id) => !pageIds.includes(id));
    if (unlisted.length)
      faults.push(
        "on the page and not in " + name + ": " + unlisted.join(", "),
      );
    if (orphaned.length)
      faults.push(
        "in " + name + " and not on the page: " + orphaned.join(", "),
      );
  };
  against("FIELDS.md", rows);
  against("fields.js", data);

  console.log(
    "configPage.html: " +
      fields.length +
      " form controls outside HTML comments",
  );
  console.log(
    "FIELDS.md:       " + (rows === null ? "absent" : rows.length + " rows"),
  );
  console.log(
    "fields.js:       " + (data === null ? "absent" : data.length + " entries"),
  );
  if (faults.length) {
    console.error("");
    for (const f of faults) console.error("FAIL " + f);
    return 1;
  }
  console.log(
    "every field of the page has one row, and no row names a field the page lost",
  );

  return 0;
}

process.exit(main());
