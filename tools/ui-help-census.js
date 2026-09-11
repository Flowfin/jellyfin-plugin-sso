#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Counts every help text the five settings pages show, page by page and field by
 * field, and refuses the count moving in either direction (#1661).
 *
 * WHY A CENSUS AND NOT ANOTHER CATALOG RULE. Stage 2 of the 4.4 surface moves
 * every help text these pages show: the sentence under the field becomes the
 * first sentence, the whole text goes behind a `<details>`, and the same whole
 * text is written into the rail when the field is focused. The promise made to
 * the reader of that change is "nothing is deleted, only moved", and it is worth
 * exactly as much as the thing that checks it. How many that is, is printed by
 * this tool rather than written here.
 *
 * Nothing checked it. The C# rules in `LocalizationCatalogTests` read the
 * catalogs and the markers: `MarkupBuiltInEnglish_MatchesTheCatalog` says a
 * marked element's built-in English equals its catalog row, and
 * `UiCatalogKeys_AreAllReferencedBySomeWebAsset` says no key is orphaned. Both
 * are key-wise over ALL assets at once, so neither can see a page. Delete the
 * whole `config.template_bitrate_help` field from the Policies page and both
 * stay green, because the Providers page still names that key twice. That is
 * the exact shape a move produces when it drops a field on the way.
 *
 * WHAT THIS ADDS is the two numbers those rules do not hold: WHICH page names a
 * key, and HOW OFTEN. `docs/ui/HELP-CENSUS.md` is the census - one row per
 * SITE, a site being one field on one page naming one help key - and this tool
 * reconciles that table against the tree in both directions. A site the table
 * names and the tree lost is a deleted help text; a site the tree holds and the
 * table does not is one that arrived unmeasured. Both are refused by name.
 *
 * AND THE TEXT ITSELF, which is a different question from the marker. A marker
 * says a field claims a key; it does not say the prose is on the page. So each
 * site's text is counted in the page's own visible text, and the count has to
 * equal the number of sites naming it: zero is a text that vanished, two is one
 * that was copied rather than moved - which is the failure mode of slice 1
 * specifically, where the same sentence is meant to exist once behind a
 * `<details>` and not also be left standing where it was.
 *
 * WHERE the text sits is checked too, because "moved" has a destination. An
 * occurrence must lie inside the field scope of a site that names it - the
 * nearest `inputContainer` or `checkboxContainer` around the marker, or the
 * marker's parent where the page has neither. A `<details>` opened in the right
 * field passes; the same text copied into the next field over does not.
 *
 * AND EVERY OCCURRENCE IS ATTRIBUTED TO ONE SITE, which the first draft of this
 * did not do and which the review of 2026-09-11 refuted it on twice. A count
 * alone is satisfied by "twice in the OIDC form, never in the SAML one" - both
 * totals agree and every occurrence has an owner - and that is precisely the
 * accident stage 2 will have, because 14 keys on the Providers page sit in both
 * protocol forms and get edited twice. A maximum MATCHING, which was the first
 * repair, is satisfied one nesting further in: it hands a section-level site the
 * second copy belonging to a field inside it, so the section text can be deleted
 * outright and the page still passes. Each occurrence therefore goes to the
 * innermost site holding it, and a field left with none is named.
 *
 * WHAT IT CANNOT SAY. It reads bytes, so it says nothing about what a browser
 * renders, nothing about the German catalog (the texts are compared against
 * `en.json` only, because the markup's built-in English is what the pages ship),
 * and nothing about whether a first sentence derived at runtime is a good one.
 * It cannot tell a help text that was moved from one that was deleted and
 * rewritten identically inside the same field. And the field scope it measures
 * "elsewhere" against is only as tight as the page's own containers: the 117
 * control-level sites sit in scopes of 1.5 KB at the median, but the 16
 * section-level ones reach 2.5 KB at the median and 19.5 KB for the two
 * starting-policy blocks, which enclose every `Tmpl-*` field of their form. For
 * those two, "outside the field that names it" means outside the whole block.
 *
 * THE CALIBRATION RUNS FIRST AND THE REAL PAGES SECOND. A census that counts
 * everything passes its own arithmetic, so the arms below drive the same reader
 * over fixtures whose answers are known - a positive for each shape that must
 * pass, and one negative per refusal the reader can make - and stop before the
 * pages are opened if any of them disagrees. The pass is printed, because a
 * calibration nobody sees the result of reads exactly like one that was never
 * run. One refusal is outside it and says so where it is raised: the census
 * table being absent altogether is `fs.existsSync` rather than a judgement.
 *
 * Node is preinstalled on the runner and this tool has no dependencies, in the
 * same terms as tools/ui-mock-fields.js and tools/ui-untranslated.js.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..");
const WEB = path.join(ROOT, "SSO-Auth", "Web");
const CATALOG = path.join(ROOT, "SSO-Auth", "Localization", "en.json");
const CENSUS = path.join(ROOT, "docs", "ui", "HELP-CENSUS.md");

// Elements that never carry content, so the reader below must not look for a
// closing tag for them. The list is the one these five pages actually use plus
// the rest of the HTML void set, because a page gaining an `<img>` tomorrow
// should not hang the reader.
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

// What counts as the field a help key belongs to. These are the two containers
// the settings pages draw around one control and its description; a help text
// that leaves its own container has left its field, whatever it looks like on
// screen.
const FIELD_CONTAINERS = ["inputContainer", "checkboxContainer"];

/*
 * The entities this markup uses, decoded the way the C# rule beside it decodes
 * them: `&amp;` LAST, so `&amp;lt;` becomes `&lt;` and stops there rather than
 * being read a second time into a `<` the text never had. The pages carry five
 * of the six - `&nbsp;` is here for the hard space a condensed sentence invites
 * rather than for anything written today. A SEVENTH would not be decoded, and
 * the site would be refused as deleted rather than as unreadable, which is loud
 * and misleading in the same breath.
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

function collapse(text) {
  return text.replace(/\s+/g, " ").trim();
}

/*
 * Where an ordinary tag ends, given the offset of its `<`. Quote-aware, which is
 * not for these pages - no attribute value in any of the six HTML assets holds an
 * angle bracket today - but so that the day one does, the reader stops at the
 * tag's own `>` rather than at a `>` somebody wrote inside a title.
 */
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
 * The page with everything that only LOOKS like markup replaced by spaces, one
 * for one, so every offset in the result still names the same byte of the file:
 * the inside of every comment, of every `<script>` and `<style>`, and every
 * angle bracket sitting inside a quoted attribute value.
 *
 * Everything below reads the masked page, and that is not an optimisation. The
 * readers here scan for `<div` and `</div` as strings, and this repository's
 * markup is heavily commented - `providersPage.html` already carries comments
 * containing `<select`, `<span>...</span>` and `<name`. A comment that merely
 * MENTIONS a tag would otherwise move an element's end, and the refusal that
 * came out of it would name the wrong key on a page nobody had touched. The same
 * goes for an `id="..."` written in a comment to point at the script that reads
 * it, which is a thing this markup also does, and for a `</div>` written into a
 * `title=` - no attribute value on these five pages holds an angle bracket
 * today, and the reader should not be the thing that decides whether one may.
 *
 * Blanking rather than deleting is what keeps the offsets: a help text found in
 * the flattened page has to be placed back in the markup to say which field it
 * is sitting in, and a reader that shortened the page could not do it.
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
 * The page as a browser would read it - tags gone, entities decoded, runs of
 * whitespace collapsed - with the source offset of every character kept beside
 * it. It reads a page that maskInert has already been over.
 *
 * A TAG BOUNDARY IS NOT A SPACE, and the first draft of this made it one. An
 * inline element does not separate words: the Providers page writes
 * `<a>authelia</a>), additional scopes` and a browser reads `authelia),`, so a
 * space at the boundary produced `authelia ),` and 15 assembled sentences
 * stopped matching their own page. What the boundary cannot do is separate two
 * BLOCK elements written with nothing between them. That shape IS in this tree -
 * `providersPage.html` writes `later.<br />A common option` - and it is harmless
 * only because that site is a parts element whose slot absorbs the `<br />`. A
 * plain marked element written the same way would splice two texts into a string
 * that matches neither and be refused for both, which is loud rather than
 * silent, and is the residual this paragraph is the disclosure of.
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
          // An entity that decodes to whitespace - `&nbsp;`, the "do not break
          // this line here" idiom - goes through the same collapsing as a real
          // space. Pushed straight in, it escaped the collapse and a `&nbsp;`
          // written beside an ordinary newline produced two spaces where the
          // catalog has one, which reads as the help text having been deleted.
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

/*
 * The next `<tag` or `</tag` whose NAME ends there - so `<input` does not match
 * `<inputContainer` and `</a` does not match `</abbr`.
 */
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
 * The element whose opening tag contains the given offset: its tag name, where
 * its content starts and ends, and where the whole thing ends.
 *
 * Written as a scan rather than as a pair of regular expressions because the
 * attribute values in these pages contain `>` (a `data-i18n-parts` slot marker
 * does not, but a URL query does), and because the formatter breaks an opening
 * tag across a dozen lines.
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
    // Both sides need the boundary test, and the closing side is the one that
    // was missing it: without it `</abbr>` ends an `<a>`, and the element stops
    // seven bytes early with nothing saying so.
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

/*
 * The value of an attribute on an element's opening tag, or null.
 *
 * The name is anchored at a space, so asking for `class` does not answer with
 * `sso-class` and asking for `id` does not answer with `data-testid`. Neither
 * pair exists on these pages today; the first one that does would take the field
 * container away from `fieldOf` below and be refused as a site nobody named.
 */
function attributeOf(source, element, attribute) {
  const opening = source.slice(element.start, element.contentStart);
  const found = opening.match(new RegExp("\\s" + attribute + '="([^"]*)"'));
  return found ? found[1] : null;
}

/*
 * The field a marker belongs to: the nearest enclosing container the settings
 * pages draw around one control, and the id of the control inside it.
 *
 * Some help texts are about a SECTION rather than about a control - the two
 * empty-state paragraphs on the Providers page, the sentence that opens the
 * starting-policy block in each of the two provider forms. Those get the id of
 * the nearest ancestor that carries one, which is what separates the OIDC copy
 * from the SAML copy of an identical sentence, and their scope stays the
 * marker's own parent so the "outside its field" refusal is no weaker for them
 * than for a control. A page with no ancestor id at all falls back to the key,
 * which keeps a scope for every site rather than silently skipping the ones it
 * cannot place.
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
 * Every help site on one page: the marker, the field it belongs to, and the text
 * the page is supposed to be showing for it.
 *
 * The text of a `data-i18n` site is the catalog row. The text of a
 * `data-i18n-parts` site is that row with each `{n}` replaced by the nth direct
 * child of the marker, because the whole point of a parts element is that the
 * sentence on the screen is assembled from pieces and no single node holds it.
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
      // Each child is read by the SAME reader as the page it has to be found
      // in, rather than by a tag-stripping replace of its own. Two readers for
      // one question drift, the strip handled no entity, and a single-pass
      // strip is `js/incomplete-multi-character-sanitization` to CodeQL - a
      // sanitizer is not what this is, and code that looks like a broken one is
      // its own defect.
      const children = childrenOf(
        source,
        marker.contentStart,
        marker.contentEnd,
      ).map((child) => flatten(child).text);
      text = text.replace(/\{(\d+)\}/g, (whole, slot) =>
        children[Number(slot)] === undefined ? whole : children[Number(slot)],
      );
    }
    // The catalog holds TEXT and never entities - the applier writes through
    // createTextNode - so only the markup side is decoded, which the parts
    // children above already were.
    sites.push({ page, key, field, text: collapse(text), scope });
  }
  return sites;
}

/*
 * Where each site's text actually is on the page.
 *
 * Distinct texts are searched longest first and the matched span is masked, so a
 * help text that is a substring of a longer one is not counted twice. No two
 * help texts stand in that relation today; the ordering is here because the one
 * that arrives will be found by a reader of a refusal that names the wrong key,
 * which is the most expensive way to learn it.
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

/*
 * The census table: one row per site, as `page | key | field`.
 *
 * Rows are read by the same shape as docs/ui/mock/FIELDS.md, which is the table
 * this repository already reconciles against the tree. A row is identified by
 * all three cells together, because the same key on two fields of one page is
 * two sites and losing one of them is exactly the loss this file exists to
 * refuse.
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
 * Gives each occurrence to the INNERMOST site whose scope holds it, and reports
 * how many each site ended up with.
 *
 * COUNTING IS NOT ENOUGH AND THAT IS THE WHOLE REASON THIS IS AN ATTRIBUTION.
 * Two sites of one key with two occurrences balance as a count while both
 * occurrences sit in ONE of the two fields and the other shows nothing - which
 * is exactly what a stage-2 edit produces when the OIDC form is condensed twice
 * and the SAML form is dropped, and 14 keys on the Providers page have that
 * shape. So each site must own an occurrence of its own.
 *
 * INNERMOST, AND NOT A MAXIMUM MATCHING, and the first draft of this was the
 * matching. The two agree wherever the scopes are disjoint, and they disagree
 * exactly where a section-level site encloses a control-level one: a maximum
 * matching hands the outer site the inner site's second copy and calls both
 * satisfied, so the section text can be deleted outright while the page passes.
 * Scopes in a tree are nested or disjoint, never crossing, so "the smallest
 * scope that holds it" is one site and the attribution is a function.
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
 * The whole judgement, over a set of pages given as source, so the calibration
 * below can drive it against fixtures whose answers are known.
 *
 * `expected` is the census row list, or null to skip the reconciliation - which
 * the calibration arms that are about the TEXT rather than about the table do,
 * so that one arm refuses one thing.
 */
function census(pages, catalog, expected) {
  const faults = [];
  const perPage = [];
  const seen = new Set();
  const rows = [];

  for (const [page, raw] of pages) {
    const source = maskInert(raw);
    // Markup the readers below cannot walk - an unclosed element, a comment
    // opened inside an opening tag - is a refusal with the page named, not a
    // stack trace. The reader is strict on purpose; what it may not do is fail
    // in a shape nobody can act on. The `<details>` walk is inside this guard
    // and not outside it, which the first draft got wrong: `<details>` is the
    // one element stage 2 adds to every field, so an unclosed one is the most
    // likely way to reach here at all.
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

    // Grouped by the TEXT, because that is what an occurrence is an occurrence
    // OF. Two keys carrying the same sentence share a group and are separated by
    // the attribution below rather than by the count, which is the only way
    // round that neither merges them nor refuses each of them for the other.
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

  // A key the catalog carries that no page names is a help text written for
  // nobody. It is judged here rather than in main(), so the calibration below
  // reaches it like every other refusal.
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
    // The set comparison above cannot see a row written twice, and the document
    // is only worth anything as one row per site: without this the run would
    // print 133 sites and 134 rows on the same screen and exit 0.
    if (expected.length !== rows.length) {
      faults.push(
        `HELP-CENSUS.md holds ${expected.length} row(s) for ${rows.length} help site(s), ` +
          `so a row is written twice or one is missing`,
      );
    }
  }

  return { faults, perPage, seen, rows };
}

// ---------------------------------------------------------------------------
// Calibration. One positive and one negative per refusal, run before the real
// pages are opened, because a census that counts everything passes its own
// arithmetic.
// ---------------------------------------------------------------------------

const FIXTURE_CATALOG = {
  "probe.one_help": "The first help text, which says one thing.",
  "probe.two_help": "The second help text, which says another.",
  "probe.parts_help": "Read the {0} before changing this.",
  "probe.long_help":
    "The first help text, which says one thing. And then keeps going.",
  // Deliberately the same sentence as probe.one_help: two keys with one wording
  // is the case the grouping has to keep apart without refusing either.
  "probe.echo_help": "The first help text, which says one thing.",
  "probe.nobody_help": "A help text no page shows.",
  // A catalog row is TEXT, so these are eight characters a reader sees and not
  // an ampersand. Decoding this side would turn them into one.
  "probe.entity_help": "Write &amp; where the document needs an ampersand.",
  "probe.hardspace_help": "Set it to 10 seconds at the most.",
};

function fixture(bodies) {
  return [["probe.html", "<div>" + bodies.join("") + "</div>"]];
}

/*
 * The catalog rows an arm's own fixture names, so an arm about one refusal is
 * not also refused for the five keys it does not mention. The orphan arm hands
 * in its own catalog instead.
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
    // The reported figure, held here because it is what stage 2 will be read by:
    // one of the two texts is behind a fold and the other is not, and a reader
    // that counted both or neither would print the same green run.
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

function calibrate() {
  const wrong = [];
  for (const arm of ARMS) {
    const { faults, perPage } = census(
      arm.pages,
      arm.catalog ?? narrow(arm.pages),
      arm.rows,
    );
    // The figures an arm pins, for the ones that are reported rather than
    // refused: a run that counted every fold or none of them prints the same
    // green line, and that line is what stage 2 will be read by.
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

// ---------------------------------------------------------------------------

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

  // The one refusal the calibration does not cover, because it is the absence
  // of a file rather than a judgement about one: without the table there is
  // nothing to compare and the run stops instead of counting.
  const rows = readCensus();
  const faults = [];
  if (rows === null) {
    faults.push(
      "docs/ui/HELP-CENSUS.md is missing, so there is nothing to measure the pages against",
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
