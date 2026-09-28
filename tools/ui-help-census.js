#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Counts every help text the five settings pages show, page by page and field by
 * field, and refuses the count moving in either direction (#1661). It reconciles
 * tools/ui/HELP-CENSUS.md, one row per site (one field on one page naming one
 * help key), against the tree, and checks that each site's English text appears
 * exactly once inside the innermost field that names it. It reads bytes, not a
 * rendered page; calibration fixtures run first and stop the run on a mismatch.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..");
const WEB = path.join(ROOT, "SSO-Auth", "Web");
const CATALOG = path.join(ROOT, "SSO-Auth", "Localization", "en.json");
const CENSUS = path.join(ROOT, "tools", "ui", "HELP-CENSUS.md");

// Void elements, so the reader never looks for a closing tag for them.
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

// The containers the settings pages draw around one control and its help text.
const FIELD_CONTAINERS = ["inputContainer", "checkboxContainer"];

/*
 * Decodes the entities this markup uses the way the C# rule does, `&amp;` last
 * so `&amp;lt;` stops at `&lt;`.
 */
function decodeEntities(text) {
  return text
    .split("&lt;")
    .join("<")
    .split("&gt;")
    .join(">")
    .split("&mdash;")
    .join("—")
    .split("&rarr;")
    .join("→")
    .split("&nbsp;")
    .join(" ")
    .split("&amp;")
    .join("&");
}

/** Collapses runs of whitespace into one space and trims. */
function collapse(text) {
  return text.replace(/\s+/g, " ").trim();
}

/** Returns where an ordinary tag ends given the offset of its `<`, skipping quoted `>`. */
function endOfTag(source, start) {
  let scan = start + 1;
  let quote = null;
  while (scan < source.length) {
    const ch = source[scan];
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === ">") {
      return scan;
    }
    scan += 1;
  }
  return source.length - 1;
}

/*
 * Blanks the inside of comments, `<script>`, `<style>` and angle brackets in
 * quoted attribute values, one space per byte, so offsets survive. Everything
 * below reads the masked page, so a tag merely mentioned in a comment cannot
 * move an element's end.
 */
function maskInert(source) {
  const out = source.split("");
  const blank = (from, to) => {
    for (let index = from; index < to && index < out.length; index += 1) {
      if (out[index] !== "\n") out[index] = " ";
    }
  };

  let index = 0;
  while (index < source.length) {
    if (source.startsWith("<!--", index)) {
      const close = source.indexOf("-->", index + 4);
      const end = close === -1 ? source.length : close;
      blank(index + 4, end);
      index = close === -1 ? source.length : close + 3;
      continue;
    }
    if (source[index] === "<") {
      const tagEnd = endOfTag(source, index);
      let quote = null;
      for (let scan = index + 1; scan < tagEnd; scan += 1) {
        const ch = source[scan];
        if (quote) {
          if (ch === quote) quote = null;
          else if (ch === "<" || ch === ">") out[scan] = " ";
        } else if (ch === '"' || ch === "'") {
          quote = ch;
        }
      }
      const name = /^<(script|style)\b/i.exec(source.slice(index, index + 8));
      if (name && source[tagEnd - 1] !== "/") {
        const closer = "</" + name[1].toLowerCase();
        const close = source.toLowerCase().indexOf(closer, tagEnd);
        const end = close === -1 ? source.length : close;
        blank(tagEnd + 1, end);
        index = end;
        continue;
      }
      index = tagEnd + 1;
      continue;
    }
    index += 1;
  }

  return out.join("");
}

/*
 * Returns the page as a browser reads it, tags gone, entities decoded and
 * whitespace collapsed, with the source offset of every character. A tag
 * boundary is not a space, since inline elements do not separate words.
 */
function flatten(source) {
  let text = "";
  const at = [];
  let index = 0;
  let pendingSpace = false;

  const push = (chars, origin) => {
    for (const ch of chars) {
      text += ch;
      at.push(origin);
    }
  };

  while (index < source.length) {
    if (source[index] === "<") {
      index = endOfTag(source, index) + 1;
      continue;
    }

    if (/\s/.test(source[index])) {
      pendingSpace = text.length > 0;
      index += 1;
      continue;
    }

    if (source[index] === "&") {
      const semicolon = source.indexOf(";", index);
      if (semicolon !== -1 && semicolon - index <= 8) {
        const entity = source.slice(index, semicolon + 1);
        const decoded = decodeEntities(entity);
        if (decoded !== entity) {
          // A whitespace entity such as `&nbsp;` goes through the same collapse as a space.
          if (/^\s+$/.test(decoded)) {
            pendingSpace = text.length > 0;
            index = semicolon + 1;
            continue;
          }
          if (pendingSpace) {
            push(" ", index);
            pendingSpace = false;
          }
          push(decoded, index);
          index = semicolon + 1;
          continue;
        }
      }
    }

    if (pendingSpace) {
      push(" ", index);
      pendingSpace = false;
    }

    push(source[index], index);
    index += 1;
  }

  return { text, at };
}

/** Finds the next `<tag` or `</tag` whose name ends there, so `<input` skips `<inputContainer`. */
function nameBoundary(source, token, from) {
  let cursor = from;
  while (cursor < source.length) {
    const found = source.indexOf(token, cursor);
    if (found === -1) return -1;
    if (/[\s/>]/.test(source[found + token.length] || ">")) return found;
    cursor = found + token.length;
  }
  return -1;
}

/*
 * Returns the element whose opening tag contains the offset: its tag name, its
 * content span and its end. A scan, because opening tags hold `>` in URLs and
 * span many lines.
 */
function elementAround(source, offset) {
  let start = offset;
  while (start >= 0 && source[start] !== "<") start -= 1;

  const name = /^<([a-zA-Z0-9-]+)/.exec(source.slice(start, start + 32));
  if (name === null) {
    throw new Error("no opening tag around offset " + offset);
  }
  const tag = name[1].toLowerCase();

  const scan = endOfTag(source, start);
  const contentStart = scan + 1;
  const selfClosing = VOID.has(tag) || source[scan - 1] === "/";
  if (selfClosing) {
    return {
      tag,
      start,
      contentStart,
      contentEnd: contentStart,
      end: contentStart,
    };
  }

  let depth = 1;
  let cursor = contentStart;
  const opening = "<" + tag;
  const closing = "</" + tag;
  while (cursor < source.length) {
    // The closing side needs the boundary test too, or `</abbr>` ends an `<a>`.
    const nextOpen = nameBoundary(source, opening, cursor);
    const nextClose = nameBoundary(source, closing, cursor);
    if (nextClose === -1) break;
    if (nextOpen !== -1 && nextOpen < nextClose) {
      depth += 1;
      cursor = nextOpen + opening.length;
      continue;
    }
    depth -= 1;
    const after = source.indexOf(">", nextClose);
    cursor = after + 1;
    if (depth === 0) {
      return { tag, start, contentStart, contentEnd: nextClose, end: cursor };
    }
  }

  throw new Error("unterminated <" + tag + "> at offset " + start);
}

/** The direct children of an element, as source spans. */
function childrenOf(source, contentStart, contentEnd) {
  const out = [];
  let index = contentStart;
  while (index < contentEnd) {
    if (source[index] === "<" && /[a-zA-Z]/.test(source[index + 1] || "")) {
      const child = elementAround(source, index + 1);
      out.push(source.slice(child.start, child.end));
      index = child.end;
      continue;
    }
    index += 1;
  }
  return out;
}

/** Returns the value of an attribute on an element's opening tag, or null; the name is anchored at a space. */
function attributeOf(source, element, attribute) {
  const opening = source.slice(element.start, element.contentStart);
  const found = opening.match(new RegExp("\\s" + attribute + '="([^"]*)"'));
  return found ? found[1] : null;
}

/*
 * Returns the field a marker belongs to: the nearest field container and the
 * id of the control inside it. A section-level text takes the id of the
 * nearest ancestor that has one, and the key when none does.
 */
function fieldOf(source, marker, key) {
  const ancestors = [];
  let cursor = marker.start;
  let sectionId = null;
  while (cursor > 0) {
    const open = source.lastIndexOf("<", cursor - 1);
    if (open === -1) break;
    cursor = open;
    if (!/[a-zA-Z]/.test(source[open + 1] || "")) continue;
    let element;
    try {
      element = elementAround(source, open + 1);
    } catch {
      continue;
    }
    if (element.end < marker.end) continue;
    ancestors.push(element);
    const classes = attributeOf(source, element, "class") || "";
    if (FIELD_CONTAINERS.some((name) => classes.split(/\s+/).includes(name))) {
      const control = source
        .slice(element.contentStart, element.contentEnd)
        .match(/\sid="([^"]+)"/);
      return {
        scope: element,
        field: control ? control[1] : "(" + key + ")",
      };
    }
    if (sectionId === null) {
      sectionId = attributeOf(source, element, "id");
    }
  }

  return {
    scope: ancestors[0] || marker,
    field: sectionId === null ? "(" + key + ")" : "(" + sectionId + ")",
  };
}

/*
 * Returns every help site on one page with its field and expected text. A
 * `data-i18n-parts` text is its catalog row with each `{n}` replaced by the
 * marker's nth child.
 */
function sitesOf(source, page, catalog) {
  const sites = [];
  for (const match of source.matchAll(/data-i18n(-parts)?="([^"]+)"/g)) {
    const key = match[2];
    if (!key.endsWith("_help")) continue;
    if (!Object.prototype.hasOwnProperty.call(catalog, key)) {
      sites.push({ page, key, field: "?", text: null, scope: null });
      continue;
    }
    const marker = elementAround(source, match.index);
    const { scope, field } = fieldOf(source, marker, key);
    let text = catalog[key];
    if (match[1]) {
      // Each child is read by the same reader as the page it must be found in.
      const children = childrenOf(
        source,
        marker.contentStart,
        marker.contentEnd,
      ).map((child) => flatten(child).text);
      text = text.replace(/\{(\d+)\}/g, (whole, slot) =>
        children[Number(slot)] === undefined ? whole : children[Number(slot)],
      );
    }
    // The catalog holds text, never entities, so only the markup side is decoded.
    sites.push({ page, key, field, text: collapse(text), scope });
  }
  return sites;
}

/*
 * Returns where each site's text is on the page. Texts are searched longest
 * first and masked, so a substring of a longer text is not counted twice.
 */
function occurrencesOf(source, sites) {
  const page = flatten(source);
  const masked = new Array(page.text.length).fill(false);
  const texts = [...new Set(sites.map((site) => site.text).filter(Boolean))];
  texts.sort((a, b) => b.length - a.length);

  const found = new Map();
  for (const text of texts) {
    const hits = [];
    let from = 0;
    let index;
    while ((index = page.text.indexOf(text, from)) !== -1) {
      let clear = true;
      for (let scan = index; scan < index + text.length; scan += 1) {
        if (masked[scan]) {
          clear = false;
          break;
        }
      }
      if (clear) {
        for (let scan = index; scan < index + text.length; scan += 1) {
          masked[scan] = true;
        }
        hits.push(page.at[index]);
      }
      from = index + 1;
    }
    found.set(text, hits);
  }
  return found;
}

/**
 * Reads the census table as `page | key | field` rows, in the shape of
 * tools/ui/mock/FIELDS.md; all three cells identify a row.
 */
function readCensus() {
  if (!fs.existsSync(CENSUS)) return null;
  return fs
    .readFileSync(CENSUS, "utf8")
    .split(/\r?\n/)
    .filter((line) => /^\|\s*`/.test(line))
    .map((line) => {
      const cells = line.split("|");
      return [1, 2, 3]
        .map((cell) => (cells[cell] || "").trim().replace(/`/g, ""))
        .join(" | ");
    });
}

/** The spans of every `<details>` element on a page. */
function detailsSpans(source) {
  const spans = [];
  let cursor = 0;
  let found;
  while ((found = nameBoundary(source, "<details", cursor)) !== -1) {
    const element = elementAround(source, found + 1);
    spans.push(element);
    cursor = found + 8;
  }
  return spans;
}

/*
 * Gives each occurrence to the innermost site whose scope holds it and returns
 * how many each site got. A plain count or a maximum matching passes a page
 * where one of two copies moved into the wrong field or a section text was
 * deleted; scopes nest, so the innermost site is unique.
 */
function attributeHits(sites, hits) {
  const owned = new Map(sites.map((site) => [site, []]));
  const unowned = [];
  for (const hit of hits) {
    const holders = sites.filter(
      (site) => hit >= site.scope.start && hit < site.scope.end,
    );
    if (holders.length === 0) {
      unowned.push(hit);
      continue;
    }
    const innermost = holders.reduce((best, site) =>
      site.scope.end - site.scope.start < best.scope.end - best.scope.start
        ? site
        : best,
    );
    owned.get(innermost).push(hit);
  }
  return { owned, unowned };
}

/*
 * Runs the whole judgement over pages given as source, so the calibration can
 * drive it. `expected` is the census row list, or null to skip reconciliation.
 */
function census(pages, catalog, expected) {
  const faults = [];
  const perPage = [];
  const seen = new Set();
  const rows = [];

  for (const [page, raw] of pages) {
    const source = maskInert(raw);
    // Markup the reader cannot walk, including an unclosed `<details>`, is a refusal naming the page.
    let sites;
    let folds;
    try {
      sites = sitesOf(source, page, catalog);
      folds = detailsSpans(source);
    } catch (trouble) {
      faults.push(`${page} could not be read as markup: ${trouble.message}`);
      perPage.push({ page, sites: 0, keys: 0, behindDetails: 0 });
      continue;
    }
    sites.forEach((site) => seen.add(site.key));

    const unknown = sites.filter((site) => site.text === null);
    unknown.forEach((site) =>
      faults.push(
        `${page} marks ${site.key}, which the English catalog does not carry`,
      ),
    );

    const known = sites.filter((site) => site.text !== null);
    known.forEach((site) => rows.push(`${page} | ${site.key} | ${site.field}`));
    const occurrences = occurrencesOf(source, known);
    let behindDetails = 0;

    // Grouped by text; two keys with the same sentence are separated by attribution.
    const groups = new Map();
    known.forEach((site) => {
      if (!groups.has(site.text)) groups.set(site.text, []);
      groups.get(site.text).push(site);
    });

    for (const [text, group] of groups) {
      const hits = occurrences.get(text) || [];
      const named = [...new Set(group.map((site) => site.key))].join(" and ");
      if (hits.length !== group.length) {
        faults.push(
          `${page} names ${named} at ${group.length} field(s) and shows that help text ${hits.length} time(s): ` +
            (hits.length < group.length
              ? "a help text was deleted rather than moved"
              : "a help text was copied rather than moved, so the next edit changes one copy"),
        );
        continue;
      }
      const { owned, unowned } = attributeHits(group, hits);
      unowned.forEach(() =>
        faults.push(
          `${page} shows the help text of ${named} outside the field that names it`,
        ),
      );
      for (const [site, mine] of owned) {
        if (mine.length !== 1) {
          faults.push(
            `${page} shows the help text of ${site.key} the right number of times over the page ` +
              `and ${mine.length} time(s) in ${site.field}: another field of that text holds the copy this one lost`,
          );
        }
        mine
          .filter((hit) =>
            folds.some((fold) => hit >= fold.start && hit < fold.end),
          )
          .forEach(() => {
            behindDetails += 1;
          });
      }
    }

    perPage.push({
      page,
      sites: known.length,
      keys: new Set(known.map((site) => site.key)).size,
      behindDetails,
    });
  }

  // A catalog key no page names is a help text written for nobody.
  Object.keys(catalog)
    .filter((key) => key.endsWith("_help") && !seen.has(key))
    .forEach((key) =>
      faults.push(
        `the catalog carries ${key} and no settings page names it, so that help text reaches nobody`,
      ),
    );

  if (expected !== null) {
    const have = new Set(rows);
    const want = new Set(expected);
    [...want]
      .filter((row) => !have.has(row))
      .forEach((row) =>
        faults.push(
          `HELP-CENSUS.md names a site the pages no longer hold: ${row}`,
        ),
      );
    [...have]
      .filter((row) => !want.has(row))
      .forEach((row) =>
        faults.push(`a help site no row of HELP-CENSUS.md names: ${row}`),
      );
    [
      ...new Set(rows.filter((row, index) => rows.indexOf(row) !== index)),
    ].forEach((row) =>
      faults.push(`one field names one help key twice: ${row}`),
    );
    // The set comparison cannot see a row written twice.
    if (expected.length !== rows.length) {
      faults.push(
        `HELP-CENSUS.md holds ${expected.length} row(s) for ${rows.length} help site(s), ` +
          `so a row is written twice or one is missing`,
      );
    }
  }

  return { faults, perPage, seen, rows };
}

// Calibration: one positive and one negative per refusal, run before the real pages.

const FIXTURE_CATALOG = {
  "probe.one_help": "The first help text, which says one thing.",
  "probe.two_help": "The second help text, which says another.",
  "probe.parts_help": "Read the {0} before changing this.",
  "probe.long_help":
    "The first help text, which says one thing. And then keeps going.",
  // The same sentence as probe.one_help, which the grouping must keep apart.
  "probe.echo_help": "The first help text, which says one thing.",
  "probe.nobody_help": "A help text no page shows.",
  // A catalog row is text, so this stays a literal `&amp;` and is not decoded.
  "probe.entity_help": "Write &amp; where the document needs an ampersand.",
  "probe.hardspace_help": "Set it to 10 seconds at the most.",
};

/** Wraps fixture bodies into a single probe page. */
function fixture(bodies) {
  return [["probe.html", "<div>" + bodies.join("") + "</div>"]];
}

/*
 * Returns the catalog rows an arm's fixture names, so an arm is not refused for
 * keys it does not mention.
 */
function narrow(pages) {
  const marked = new Set();
  pages.forEach(([, source]) => {
    for (const match of source.matchAll(/data-i18n(?:-parts)?="([^"]+)"/g)) {
      marked.add(match[1]);
    }
  });
  return Object.fromEntries(
    Object.entries(FIXTURE_CATALOG).filter(([key]) => marked.has(key)),
  );
}

const FIELD_ONE =
  '<div class="inputContainer"><input id="One" />' +
  '<div class="fieldDescription" data-i18n="probe.one_help">' +
  "The first help text, which says one thing.</div></div>";

const FIELD_TWO =
  '<div class="inputContainer"><input id="Two" />' +
  '<div class="fieldDescription" data-i18n="probe.two_help">' +
  "The second help text, which says another.</div></div>";

const FIELD_PARTS =
  '<div class="inputContainer"><input id="Parts" />' +
  '<p class="fieldDescription" data-i18n-parts="probe.parts_help">Read the ' +
  '<a href="#">guide</a> before changing this.</p></div>';

const ARMS = [
  {
    name: "green",
    why: "three fields each holding their own help text once",
    pages: fixture([FIELD_ONE, FIELD_TWO, FIELD_PARTS]),
    rows: [
      "probe.html | probe.one_help | One",
      "probe.html | probe.two_help | Two",
      "probe.html | probe.parts_help | Parts",
    ],
    expect: null,
  },
  {
    name: "deleted",
    why: "a field whose help text was emptied out",
    pages: fixture([
      FIELD_ONE.replace("The first help text, which says one thing.", ""),
      FIELD_TWO,
    ]),
    rows: null,
    expect: "shows that help text 0 time(s)",
  },
  {
    name: "copied",
    why: "a help text left standing as well as moved",
    pages: fixture([
      FIELD_ONE.replace(
        "</div></div>",
        "</div><p>The first help text, which says one thing.</p></div>",
      ),
      FIELD_TWO,
    ]),
    rows: null,
    expect: "shows that help text 2 time(s)",
  },
  {
    name: "moved-in-place",
    why: "a help text behind a <details> of its own field",
    pages: fixture([
      FIELD_ONE.replace(
        '<div class="fieldDescription" data-i18n="probe.one_help">' +
          "The first help text, which says one thing.</div>",
        "<details><summary>More</summary>" +
          '<div class="fieldDescription" data-i18n="probe.one_help">' +
          "The first help text, which says one thing.</div></details>",
      ),
      FIELD_TWO,
    ]),
    rows: [
      "probe.html | probe.one_help | One",
      "probe.html | probe.two_help | Two",
    ],
    expect: null,
    // The reported figure, since a reader counting both folds or neither would also pass.
    counts: { sites: 2, behindDetails: 1 },
  },
  {
    name: "moved-to-a-foreign-field",
    why: "a help text behind a <details> of the next field over",
    pages: fixture([
      FIELD_ONE.replace("The first help text, which says one thing.", ""),
      FIELD_TWO.replace(
        "</div></div>",
        "</div><details><summary>More</summary>" +
          "The first help text, which says one thing.</details></div>",
      ),
    ]),
    rows: null,
    expect: "outside the field that names it",
  },
  {
    name: "site-the-table-lost",
    why: "a census row for a field the page no longer has",
    pages: fixture([FIELD_ONE]),
    rows: [
      "probe.html | probe.one_help | One",
      "probe.html | probe.two_help | Two",
    ],
    expect: "names a site the pages no longer hold",
  },
  {
    name: "site-the-table-never-saw",
    why: "a field the census does not name",
    pages: fixture([FIELD_ONE, FIELD_TWO]),
    rows: ["probe.html | probe.one_help | One"],
    expect: "no row of HELP-CENSUS.md names",
  },
  {
    name: "one-field-twice",
    why: "one field naming the same help key twice",
    pages: fixture([
      FIELD_ONE.replace(
        "</div></div>",
        '</div><div class="fieldDescription" data-i18n="probe.one_help">' +
          "The first help text, which says one thing.</div></div>",
      ),
    ]),
    rows: ["probe.html | probe.one_help | One"],
    expect: "names one help key twice",
  },
  {
    name: "key-outside-the-catalog",
    why: "a marker naming a help key no catalog row carries",
    pages: fixture([FIELD_ONE.replace("probe.one_help", "probe.absent_help")]),
    rows: null,
    expect: "which the English catalog does not carry",
  },
  {
    name: "one-text-inside-another",
    why: "a help text that is the opening of a longer one, both present once",
    pages: fixture([
      FIELD_ONE,
      '<div class="inputContainer"><input id="Long" />' +
        '<div class="fieldDescription" data-i18n="probe.long_help">' +
        "The first help text, which says one thing. And then keeps going." +
        "</div></div>",
    ]),
    rows: [
      "probe.html | probe.one_help | One",
      "probe.html | probe.long_help | Long",
    ],
    expect: null,
  },
  {
    name: "one-key-two-fields",
    why: "a key at two fields, each showing it once",
    pages: fixture([FIELD_ONE, FIELD_ONE.replace(/"One"/g, '"Other"')]),
    rows: [
      "probe.html | probe.one_help | One",
      "probe.html | probe.one_help | Other",
    ],
    expect: null,
  },
  {
    name: "one-of-two-fields-shows-it-twice",
    why: "a key at two fields, one showing it twice and one not at all",
    pages: fixture([
      FIELD_ONE.replace(
        "</div></div>",
        "</div><details><summary>More</summary>" +
          "The first help text, which says one thing.</details></div>",
      ),
      FIELD_ONE.replace(/"One"/g, '"Other"').replace(
        "The first help text, which says one thing.",
        "",
      ),
    ]),
    rows: [
      "probe.html | probe.one_help | One",
      "probe.html | probe.one_help | Other",
    ],
    expect: "0 time(s) in Other",
  },
  {
    name: "two-keys-one-sentence",
    why: "two keys carrying the same sentence, each shown once in its own field",
    pages: fixture([
      FIELD_ONE,
      FIELD_ONE.replace(/"One"/g, '"Echo"').replace(
        "probe.one_help",
        "probe.echo_help",
      ),
    ]),
    rows: [
      "probe.html | probe.one_help | One",
      "probe.html | probe.echo_help | Echo",
    ],
    expect: null,
  },
  {
    name: "two-keys-one-sentence-one-lost",
    why: "two keys with one sentence, one field showing it twice and one never",
    pages: fixture([
      FIELD_ONE.replace(
        "</div></div>",
        "</div><details><summary>More</summary>" +
          "The first help text, which says one thing.</details></div>",
      ),
      FIELD_ONE.replace(/"One"/g, '"Echo"')
        .replace("probe.one_help", "probe.echo_help")
        .replace("The first help text, which says one thing.", ""),
    ]),
    rows: [
      "probe.html | probe.one_help | One",
      "probe.html | probe.echo_help | Echo",
    ],
    expect: "0 time(s) in Echo",
  },
  {
    name: "a-row-written-twice",
    why: "a census row pasted a second time",
    pages: fixture([FIELD_ONE]),
    rows: [
      "probe.html | probe.one_help | One",
      "probe.html | probe.one_help | One",
    ],
    expect: "so a row is written twice or one is missing",
  },
  {
    name: "key-nobody-shows",
    why: "a catalog help key no page names",
    pages: fixture([FIELD_ONE]),
    catalog: {
      "probe.one_help": FIXTURE_CATALOG["probe.one_help"],
      "probe.nobody_help": FIXTURE_CATALOG["probe.nobody_help"],
    },
    rows: ["probe.html | probe.one_help | One"],
    expect: "no settings page names it",
  },
  {
    name: "a-comment-that-names-a-tag",
    why: "a comment inside a field that mentions a closing tag",
    pages: fixture([
      FIELD_ONE.replace(
        '<input id="One" />',
        '<input id="One" /><!-- the JS closes this </div> itself -->',
      ),
      FIELD_TWO,
    ]),
    rows: [
      "probe.html | probe.one_help | One",
      "probe.html | probe.two_help | Two",
    ],
    expect: null,
  },
  {
    name: "an-id-written-in-a-comment",
    why: "a comment naming another control's id ahead of the real one",
    pages: fixture([
      FIELD_ONE.replace(
        '<input id="One" />',
        '<!-- paired with id="Elsewhere" in the bundle --><input id="One" />',
      ),
    ]),
    rows: ["probe.html | probe.one_help | One"],
    expect: null,
  },
  {
    name: "a-script-that-holds-an-angle-bracket",
    why: "a page script comparing two numbers ahead of a help text",
    pages: fixture(["<script>if (a < b) { render(); }</script>", FIELD_ONE]),
    rows: ["probe.html | probe.one_help | One"],
    expect: null,
  },
  {
    name: "a-section-text-lost-inside-its-own-block",
    why: "a block's own help text deleted while a field inside it shows that text twice",
    pages: [
      [
        "probe.html",
        '<div id="block"><p data-i18n="probe.echo_help"></p>' +
          '<div class="inputContainer"><input id="Ctl" />' +
          '<div class="fieldDescription" data-i18n="probe.one_help">' +
          "The first help text, which says one thing.</div>" +
          "<details><summary>More</summary>" +
          "The first help text, which says one thing.</details>" +
          "</div></div>",
      ],
    ],
    rows: null,
    expect: "0 time(s) in (block)",
  },
  {
    name: "a-tag-whose-name-extends-another",
    why: "an <abbr> inside the <a> of a parts sentence",
    pages: fixture([
      FIELD_PARTS.replace(
        '<a href="#">guide</a>',
        '<a href="#"><abbr title="t">TLS</abbr> guide</a>',
      ),
    ]),
    rows: ["probe.html | probe.parts_help | Parts"],
    expect: null,
  },
  {
    name: "an-attribute-whose-name-ends-in-another",
    why: "a container and a control carrying a longer attribute name first",
    pages: fixture([
      FIELD_ONE.replace(
        '<div class="inputContainer"><input id="One" />',
        '<div sso-class="decoy" class="inputContainer">' +
          '<input data-testid="Decoy" id="One" />',
      ),
    ]),
    rows: ["probe.html | probe.one_help | One"],
    expect: null,
  },
  {
    name: "a-container-that-closed-before-the-marker",
    why: "a field container standing beside the marker rather than around it",
    pages: [
      [
        "probe.html",
        '<div id="block"><div class="inputContainer"><input id="Before" />' +
          "</div>" +
          '<p class="fieldDescription" data-i18n="probe.one_help">' +
          "The first help text, which says one thing.</p></div>",
      ],
    ],
    rows: ["probe.html | probe.one_help | (block)"],
    expect: null,
  },
  {
    name: "a-catalog-value-that-spells-an-entity",
    why: "a help text whose wording contains the characters of an entity",
    pages: fixture([
      FIELD_ONE.replace("probe.one_help", "probe.entity_help").replace(
        "The first help text, which says one thing.",
        "Write &amp;amp; where the document needs an ampersand.",
      ),
    ]),
    rows: ["probe.html | probe.entity_help | One"],
    expect: null,
  },
  {
    name: "an-attribute-that-holds-a-closing-tag",
    why: "a title written with markup in it, beside a help text",
    pages: fixture([
      FIELD_ONE.replace(
        '<input id="One" />',
        '<input id="One" title="the JS writes </div> here" />',
      ),
      FIELD_TWO,
    ]),
    rows: [
      "probe.html | probe.one_help | One",
      "probe.html | probe.two_help | Two",
    ],
    expect: null,
  },
  {
    name: "a-help-text-with-a-hard-space",
    why: "a help text using &nbsp; beside ordinary whitespace",
    pages: fixture([
      FIELD_ONE.replace("probe.one_help", "probe.hardspace_help").replace(
        "The first help text, which says one thing.",
        "Set it to\n  10&nbsp;seconds at the most.",
      ),
    ]),
    rows: ["probe.html | probe.hardspace_help | One"],
    expect: null,
  },
  {
    name: "a-details-nobody-closed",
    why: "an unclosed <details>, the element stage 2 adds to every field",
    pages: fixture([
      FIELD_ONE.replace(
        "</div></div>",
        "</div><details><summary>More</summary>dangling</div>",
      ),
    ]),
    rows: null,
    expect: "could not be read as markup",
  },
  {
    name: "markup-that-cannot-be-read",
    why: "a comment opened inside an opening tag, which leaves a marker nowhere",
    pages: fixture([
      FIELD_ONE.replace(
        '<div class="fieldDescription"',
        '<div class="fieldDescription" <!-- a note -->',
      ),
    ]),
    rows: null,
    expect: "could not be read as markup",
  },
  {
    name: "a-parts-sentence-that-lost-a-piece",
    why: "a parts element whose linked child was taken out",
    pages: fixture([
      FIELD_PARTS.replace('<a href="#">guide</a>', ""),
      FIELD_ONE,
    ]),
    rows: null,
    expect: "shows that help text 0 time(s)",
  },
];

/** Runs every calibration arm and returns the disagreements. */
function calibrate() {
  const wrong = [];
  for (const arm of ARMS) {
    const { faults, perPage } = census(
      arm.pages,
      arm.catalog ?? narrow(arm.pages),
      arm.rows,
    );
    // Reported figures are pinned too, since a wrong count prints the same green line.
    Object.entries(arm.counts ?? {}).forEach(([name, value]) => {
      if (perPage[0][name] !== value) {
        wrong.push(
          `${arm.name}: ${arm.why} reported ${name} ${perPage[0][name]} where ${value} is the answer`,
        );
      }
    });
    if (arm.expect === null) {
      if (faults.length > 0) {
        wrong.push(
          `${arm.name}: ${arm.why} was refused - ${faults.join("; ")}`,
        );
      }
      continue;
    }
    if (!faults.some((fault) => fault.includes(arm.expect))) {
      wrong.push(
        `${arm.name}: ${arm.why} was not refused for "${arm.expect}" - ` +
          (faults.length ? faults.join("; ") : "nothing was refused"),
      );
    }
  }
  return wrong;
}

/** Calibrates, then runs the census over the real pages and exits non-zero on a refusal. */
function main() {
  const wrong = calibrate();
  if (wrong.length > 0) {
    wrong.forEach((line) => console.error("CALIBRATION  " + line));
    console.error(
      `${wrong.length} of ${ARMS.length} calibration arm(s) gave the wrong answer, so nothing was counted`,
    );
    process.exit(1);
  }
  console.log(
    `calibration:        ${ARMS.length} arms, ${ARMS.filter((arm) => arm.expect === null).length} that must pass and ` +
      `${ARMS.filter((arm) => arm.expect !== null).length} that must be refused, all as expected`,
  );

  const catalog = JSON.parse(fs.readFileSync(CATALOG, "utf8"));
  const helpKeys = Object.keys(catalog).filter((key) => key.endsWith("_help"));
  const pages = fs
    .readdirSync(WEB)
    .filter((name) => name.endsWith("Page.html"))
    .sort()
    .map((name) => [name, fs.readFileSync(path.join(WEB, name), "utf8")]);

  // A missing census table is not covered by the calibration, so the run stops here.
  const rows = readCensus();
  const faults = [];
  if (rows === null) {
    faults.push(
      "tools/ui/HELP-CENSUS.md is missing, so there is nothing to measure the pages against",
    );
  }

  const { faults: found, perPage } = census(pages, catalog, rows);
  faults.push(...found);

  if (faults.length > 0) {
    faults.forEach((fault) => console.error("REFUSED  " + fault));
    console.error(`${faults.length} refusal(s) in the help census (#1661)`);
    process.exit(1);
  }

  let sites = 0;
  let behind = 0;
  perPage.forEach((entry) => {
    sites += entry.sites;
    behind += entry.behindDetails;
    console.log(
      `${(entry.page + ":").padEnd(20)}${String(entry.sites).padStart(3)} help site(s), ` +
        `${entry.keys} distinct key(s), ${entry.behindDetails} behind a <details>`,
    );
  });
  console.log(
    `${"the five pages:".padEnd(20)}${String(sites).padStart(3)} help site(s) in total, ` +
      `${behind} behind a <details>`,
  );
  console.log(
    `${"HELP-CENSUS.md:".padEnd(20)}${String(rows.length).padStart(3)} row(s), one per site`,
  );
  console.log(
    `${"en.json:".padEnd(20)}${String(helpKeys.length).padStart(3)} *_help key(s), every one named by a page`,
  );
  console.log(
    "every help text is on the page its row names, inside the field that names it, exactly once",
  );
}

main();
