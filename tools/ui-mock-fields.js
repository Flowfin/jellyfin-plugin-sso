#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Reconciles docs/ui/mock/FIELDS.md against the inputs of the configuration
 * pages it declares a home for (#1526, widened to the five built pages by
 * #1527).
 *
 * WHY THE COUNT IS DERIVED AND NOT WRITTEN DOWN. Stage 0 asks that every field
 * of the old page reappears under a new home, and a table saying so is worth
 * only what checks it. A count typed into a document drifts against the page
 * the moment a field moves; a count read off the page cannot.
 *
 * WHAT #1527 ADDED. Until the pages existed, the table's "New tab" column was a
 * promise nothing could check: the tool read the single old page and could only
 * ask whether a control had SOME row. It now reads the five built pages and
 * asks the stronger question the stage-1 done-condition names - whether each
 * control is reachable on the page its row names - and three more questions the
 * split created, at the legs below: whether a controller reaches off its own
 * page, whether an id the core names is declared anywhere, and whether the tab
 * strip actually routes to the pages the plugin registers. The mock beside the
 * table is checked exactly as before.
 *
 * NO COUNT OF THE REFUSALS IS WRITTEN HERE. Each leg says what it refused when
 * it refuses, and a total in this header would drift against the legs the way
 * every hand count does. What each one is for is written at the leg.
 *
 * WHY COMMENTS ARE STRIPPED FIRST. The Providers page documents its own hidden
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

/*
 * The five pages, keyed by the tab name FIELDS.md writes in its "New tab"
 * column. The key is the join between the table and the tree, so a tab renamed
 * in one and not the other fails here rather than passing quietly.
 */
const PAGES = {
  Overview: path.join(root, "SSO-Auth", "Web", "configPage.html"),
  Providers: path.join(root, "SSO-Auth", "Web", "providersPage.html"),
  Accounts: path.join(root, "SSO-Auth", "Web", "accountsPage.html"),
  Policies: path.join(root, "SSO-Auth", "Web", "policiesPage.html"),
  Server: path.join(root, "SSO-Auth", "Web", "serverPage.html"),
};

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

/**
 * Index of the tag that closes the `tag` element opening at `start`.
 *
 * The tag is a parameter because a risk region is not always a `<div>`: #1666 made the Sensitive and
 * Insecure regions native `<details>` folds, and a walk counting `<div>` depth inside one returns at
 * the first inner `</div>` - which puts every control of those regions OUTSIDE the box the page draws
 * around it, and the marking this tool compares against FIELDS.md is exactly that box.
 */
function regionEnd(html, start, tag) {
  const re = new RegExp("<" + tag + "\\b[^>]*>|</" + tag + ">", "g");
  re.lastIndex = start;
  let depth = 0;
  let m;
  while ((m = re.exec(html)) !== null) {
    if (m[0] === "</" + tag + ">") {
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
    '<(div|details)\\b[^>]*class="[^"]*' + className + '[^"]*"[^>]*>',
    "g",
  );
  const out = [];
  let m;
  while ((m = re.exec(html)) !== null)
    out.push({ a: m.index, b: regionEnd(html, m.index, m[1]) });
  return out;
}

/** Every reachable form control of one page, in document order. */
function readOnePage(tab, file) {
  const html = withoutComments(fs.readFileSync(file, "utf8"));
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
      tab,
      file: path.basename(file),
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

/** Every reachable form control of all five pages, tab by tab in the declared order. */
function readPage() {
  return Object.entries(PAGES).flatMap(([tab, file]) => readOnePage(tab, file));
}

/**
 * The `Field`, `New tab` and `Marked` columns of every body row of the table in
 * FIELDS.md, as a map from id to `{ tab, marked }`.
 *
 * The tab is what #1527 made checkable; before the pages existed there was
 * nothing to check it against. The marking was always derivable and was never
 * compared: it is the page's OWN classification, read back out of the
 * `sso-danger-zone` and `sso-sensitive-region` boxes the markup draws, and a
 * move that carries a control out of its box leaves it saving exactly as before
 * while it stops being presented as dangerous. That is a silent loss the id
 * sets cannot see, and moving controls between files is what this change does.
 */
function readTable() {
  if (!fs.existsSync(TABLE)) return null;
  const rows = new Map();
  fs.readFileSync(TABLE, "utf8")
    .split(/\r?\n/)
    .filter((l) => /^\|\s*`/.test(l))
    .forEach((l) => {
      const cells = l.split("|");
      rows.set(cells[1].trim().replace(/`/g, ""), {
        tab: (cells[4] || "").trim(),
        marked: (cells[6] || "").trim(),
      });
    });
  return rows;
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

/*
 * THE SECOND LEG (#1527): does each page's controller only reach ids its own
 * page carries?
 *
 * WHY IT EXISTS. The five `initXPage` functions in sso-core.js register their
 * handlers with bare `view.querySelector("#id").addEventListener(...)` and not
 * one of those registrations is null-guarded. That is deliberate and it is not
 * free: the whole safety argument is that each function is reached only from
 * the page whose markup holds every id it touches, and a single id that moves
 * to another tab turns into a TypeError that stops the REST of that page's
 * wiring - a settings page whose controls are all present and half of them
 * inert. Guarding each site instead would hide exactly that mistake, so the
 * partition is checked here rather than defended there.
 *
 * WHAT IT READS. Every `"#..."` string literal inside each init function's
 * body, however it is written - a direct call, an entry in a list the function
 * loops over, a selector passed to a helper. A literal is what a selector is in
 * this file, and one built by concatenation at runtime is outside what any
 * reading of the source can resolve; the two id lists that ARE built that way
 * (`"#" + id` over a literal array) put their ids in literals in the same body,
 * so they are covered.
 */
const INIT_PAGES = {
  initOverviewPage: "Overview",
  initProvidersPage: "Providers",
  initAccountsPage: "Accounts",
  initPoliciesPage: "Policies",
  initServerPage: "Server",
};

/** The body of a top-level `function name(view) { ... }`, brace-matched. */
function functionBody(source, name) {
  const at = source.indexOf("function " + name + "(view) {");
  if (at === -1) return null;
  const open = source.indexOf("{", at);
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === "{") depth += 1;
    else if (source[i] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open, i + 1);
    }
  }
  return null;
}

/**
 * Every id the markup of one page declares, COMMENTS STRIPPED FIRST.
 *
 * The stripping is the whole point and it was missing. The control leg strips
 * comments and this one did not, so an element wrapped in an HTML comment
 * disappeared from the page while its id went on being "declared" here - and a
 * controller registering an unguarded handler against it passed both legs and
 * threw at the browser, killing the rest of that page's wiring. That is exactly
 * the failure the controller leg exists to prevent, walking through the check
 * that prevents it.
 */
function idsDeclaredBy(file) {
  return new Set(
    [
      ...withoutComments(fs.readFileSync(file, "utf8")).matchAll(
        /\sid="([^"]+)"/g,
      ),
    ].map((m) => m[1]),
  );
}

function controllerFaults() {
  const core = path.join(root, "SSO-Auth", "Web", "sso-core.js");
  if (!fs.existsSync(core)) {
    return [
      "SSO-Auth/Web/sso-core.js does not exist, so no controller is checked",
    ];
  }

  const source = fs.readFileSync(core, "utf8");
  const faults = [];
  for (const [fn, tab] of Object.entries(INIT_PAGES)) {
    const body = functionBody(source, fn);
    if (body === null) {
      faults.push(fn + " is not in sso-core.js, so its page has no controller");
      continue;
    }

    const declared = idsDeclaredBy(PAGES[tab]);
    const reached = [
      ...new Set([...body.matchAll(/"#([A-Za-z0-9_-]+)"/g)].map((m) => m[1])),
    ];
    const absent = reached.filter((id) => !declared.has(id));
    if (absent.length) {
      faults.push(
        fn +
          " reaches id(s) the " +
          tab +
          " page does not carry: " +
          absent.join(", "),
      );
    }
  }

  // The init functions are one call deep. Everything the shared renderers reach - the card lists, the
  // status regions, the result panels - is outside every init body and outside the field table too,
  // because those are containers rather than form controls. A renamed container is therefore invisible
  // to both legs above, so this asks the weaker question that still catches it: every id the core names
  // anywhere is declared by SOME page. It cannot say which page, which is what the leg above is for.
  const declaredAnywhere = new Set(
    Object.values(PAGES).flatMap((file) => [...idsDeclaredBy(file)]),
  );
  // A literal immediately followed by `+` is a PREFIX rather than an id - the SAML half queries
  // `"#saml-" + prop` - and asking whether the tree declares an id called `saml-` is a question about
  // this reader rather than about the tree. Concatenated selectors are outside what any reading of the
  // source resolves, which is the same bound the leg above carries and is stated in both places.
  const named = [
    ...new Set(
      [...source.matchAll(/"#([A-Za-z0-9_-]+)"(\s*\+)?/g)]
        .filter((m) => !m[2])
        .map((m) => m[1]),
    ),
  ];
  const nowhere = named.filter((id) => !declaredAnywhere.has(id));
  if (nowhere.length) {
    faults.push(
      "sso-core.js names id(s) no page declares: " + nowhere.join(", "),
    );
  }

  return faults;
}

/*
 * THE FOURTH LEG (#1527): does every link and every controller name a page the plugin registers?
 *
 * WHY IT EXISTS. The tab strip is static markup, and it is the ONLY route between the five pages. Its
 * hrefs, the `data-controller` on each page, and the core's registered name are three sets of strings
 * that have to agree with the `GetPages` table in SSOPlugin.cs, and until this leg nothing compared
 * them: the manifest test pins the table against itself, so a name renamed in BOTH the table and that
 * test passes CI green and ships an Overview page with four dead tabs and no route to the settings at
 * all. That is the worst outcome this change can produce and it was the least guarded.
 *
 * The table is read out of the C# rather than restated here, so this cannot drift from it.
 */
function registeredPageNames() {
  const plugin = path.join(root, "SSO-Auth", "SSOPlugin.cs");
  if (!fs.existsSync(plugin)) return null;

  const source = fs.readFileSync(plugin, "utf8");
  const id = source.match(/const string PageId = "([^"]+)"/);
  if (!id) return null;

  // Page(PageId, "..."), Page(PageId + "-providers", "..."), Page(PageId + ".js", "...")
  return new Set(
    [...source.matchAll(/Page\(PageId(?:\s*\+\s*"([^"]*)")?\s*,/g)].map(
      (m) => id[1] + (m[1] || ""),
    ),
  );
}

/**
 * The registered page name each tab must link to, derived rather than restated.
 *
 * Overview is the plugin's own page id, because that is the name the dashboard's
 * plugin list opens; the other four are that id and their tab in lower case,
 * which is the convention `SSOPlugin.GetPages` registers them under. Deriving it
 * is what lets the leg below ask the question it is actually for - does the
 * Accounts tab open Accounts - rather than the weaker one it asked first, which
 * was only whether an href names SOME registered page. A strip whose Policies
 * label pointed at Server passed that weaker question with five registered
 * hrefs and no route to the profile editor at all.
 */
function tabTargets(registered, tabs) {
  const id = [...registered].reduce((a, b) => (a.length <= b.length ? a : b));
  const out = {};
  tabs.forEach((tab, i) => {
    out[tab] = i === 0 ? id : id + "-" + tab.toLowerCase();
  });
  return out;
}

function linkFaults() {
  const registered = registeredPageNames();
  if (registered === null) {
    return [
      "SSO-Auth/SSOPlugin.cs does not declare a page table to check against",
    ];
  }

  const faults = [];
  const say = (what, name, where) => {
    if (!registered.has(name)) {
      faults.push(what + ' "' + name + '" in ' + where + " is not registered");
    }
  };

  // The tab each anchor is FOR, in strip order, so an href can be paired with its own label rather
  // than only checked for existing. Naming a registered page is the weaker question: an Accounts tab
  // pointing at Policies names a registered page and opens the wrong one, silently, and the first
  // draft of this leg passed it.
  const ORDER = Object.keys(PAGES);
  const PAGE_NAMES = tabTargets(registered, ORDER);

  for (const [tab, file] of Object.entries(PAGES)) {
    const html = withoutComments(fs.readFileSync(file, "utf8"));
    const where = path.basename(file);

    // One match per anchor, carrying its label class, its data-index and its href together, so the
    // three are compared against each other instead of each being read on its own.
    const anchors = [
      ...html.matchAll(
        /class="emby-tab-button SSOTAB_(\w+)([^"]*)"[^>]*?data-index="(\d+)"[^>]*?href="#\/configurationpage\?name=([^"]+)"/g,
      ),
    ].map((m) => ({
      key: m[1],
      active: m[2].includes("emby-tab-button-active"),
      index: Number(m[3]),
      href: m[4],
    }));

    if (anchors.length !== ORDER.length) {
      faults.push(
        where +
          " carries " +
          anchors.length +
          " tab link(s) of the expected shape; one per page is expected, so a tab is missing, duplicated or written differently",
      );
      continue;
    }

    anchors.forEach((a, position) => {
      say("tab link", a.href, where);

      const expectedKey = ORDER[position].toLowerCase();
      if (a.key !== expectedKey) {
        faults.push(
          where +
            " has the " +
            a.key +
            " tab where " +
            expectedKey +
            " belongs, so the strip is not in the declared order",
        );
      }

      // The href must be the page this anchor is labelled for. `emby-tabs` also drives its highlight
      // off data-index, so an index that is not the anchor's position paints the wrong tab white.
      const expectedHref = PAGE_NAMES[ORDER[position]];
      if (expectedHref && a.href !== expectedHref) {
        faults.push(
          where +
            ": the " +
            a.key +
            ' tab links to "' +
            a.href +
            '", not to "' +
            expectedHref +
            '"',
        );
      }

      if (a.index !== position) {
        faults.push(
          where +
            ": the " +
            a.key +
            " tab carries data-index " +
            a.index +
            " at position " +
            position,
        );
      }
    });

    const controller = html.match(/data-controller="__plugin\/([^"]+)"/);
    if (!controller) {
      faults.push(where + " declares no controller");
    } else {
      say("controller", controller[1], where);
    }

    // The page must also be the one the tab strip marks as current, or an administrator is told they
    // are somewhere they are not.
    const active = anchors.filter((a) => a.active);
    if (active.length !== 1) {
      faults.push(
        where + " marks " + active.length + " tabs as current; exactly one is",
      );
    } else if (active[0].key !== tab.toLowerCase()) {
      faults.push(
        where + " marks the " + active[0].key + " tab as current, not " + tab,
      );
    }
  }

  for (const file of [
    "overview",
    "providers",
    "accounts",
    "policies",
    "server",
  ]) {
    const js = path.join(root, "SSO-Auth", "Web", file + ".js");
    if (!fs.existsSync(js)) {
      faults.push("SSO-Auth/Web/" + file + ".js does not exist");
      continue;
    }

    const core = fs.readFileSync(js, "utf8").match(/SSO_CORE_PAGE = "([^"]+)"/);
    if (!core) {
      faults.push(file + ".js names no core module");
    } else {
      say("core module", core[1], file + ".js");
    }
  }

  return faults;
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
        " control(s) carry no id and cannot be keyed, at " +
        anonymous.map((f) => f.file + ":" + f.line).join(", "),
    );
  }

  // A control on two pages is refused rather than counted twice. Two pages both
  // holding one id is invalid HTML across the pair AND a save model with two
  // owners for one setting, which is the failure the split can produce that the
  // single page could not.
  const repeated = [
    ...new Set(pageIds.filter((id, i) => pageIds.indexOf(id) !== i)),
  ];
  if (repeated.length) {
    faults.push(
      "id(s) on more than one page: " +
        repeated
          .map(
            (id) =>
              id +
              " (" +
              fields
                .filter((f) => f.id === id)
                .map((f) => f.tab)
                .join(", ") +
              ")",
          )
          .join("; "),
    );
  }

  const data = readData();
  const against = (name, list) => {
    if (list === null) {
      faults.push(
        name + " does not exist, so nothing reconciles against the pages",
      );
      return;
    }
    const twice = [...new Set(list.filter((id, i) => list.indexOf(id) !== i))];
    if (twice.length) faults.push(name + " names twice: " + twice.join(", "));
    const unlisted = pageIds.filter((id) => !list.includes(id));
    const orphaned = list.filter((id) => !pageIds.includes(id));
    if (unlisted.length)
      faults.push("on a page and not in " + name + ": " + unlisted.join(", "));
    if (orphaned.length)
      faults.push(
        "in " + name + " and not on any page: " + orphaned.join(", "),
      );
  };
  against("FIELDS.md", rows === null ? null : [...rows.keys()]);
  against("fields.js", data);

  // The stage-1 done-condition (#1527): reachable on ITS page, not merely on
  // some page; and still inside the risk box the table says it is in. Only
  // reached once the id sets agree, because a mismatched set would otherwise
  // report every consequence of one missing row.
  if (rows !== null && faults.length === 0) {
    const misplaced = fields.filter((f) => rows.get(f.id).tab !== f.tab);
    if (misplaced.length) {
      faults.push(
        "on a page FIELDS.md does not name for it: " +
          misplaced
            .map(
              (f) =>
                f.id +
                " (table: " +
                rows.get(f.id).tab +
                ", tree: " +
                f.tab +
                ")",
            )
            .join(", "),
      );
    }

    const remarked = fields.filter(
      (f) => rows.get(f.id).marked !== (f.risk || "-"),
    );
    if (remarked.length) {
      faults.push(
        "no longer inside the risk region FIELDS.md declares: " +
          remarked
            .map(
              (f) =>
                f.id +
                " (table: " +
                rows.get(f.id).marked +
                ", tree: " +
                (f.risk || "-") +
                ")",
            )
            .join(", "),
      );
    }
  }

  for (const [tab, file] of Object.entries(PAGES)) {
    console.log(
      (path.basename(file) + ":").padEnd(19) +
        String(fields.filter((f) => f.tab === tab).length).padStart(3) +
        " form controls outside HTML comments",
    );
  }
  console.log(
    "the five pages:    ".padEnd(19) +
      String(fields.length).padStart(3) +
      " in total",
  );
  console.log(
    "FIELDS.md:".padEnd(19) +
      (rows === null ? "absent" : String(rows.size).padStart(3) + " rows"),
  );
  console.log(
    "fields.js:".padEnd(19) +
      (data === null ? "absent" : String(data.length).padStart(3) + " entries"),
  );
  // Every leg runs and every leg PRINTS that it ran, whatever the ones before
  // it found. A leg that is silently skipped reads exactly like a leg that
  // passed, which is the accounting mistake this whole check exists against.
  const controllers = controllerFaults();
  console.log(
    "controllers:".padEnd(19) +
      String(Object.keys(INIT_PAGES).length).padStart(3) +
      " page controllers checked against the ids their page declares",
  );

  const links = linkFaults();
  const registered = registeredPageNames();
  console.log(
    "page names:".padEnd(19) +
      String(registered === null ? 0 : registered.size).padStart(3) +
      " registered by SSOPlugin.GetPages, checked against every tab link, controller and core reference",
  );

  const all = faults.concat(controllers, links);
  if (all.length) {
    console.error("");
    for (const f of all) console.error("FAIL " + f);
    return 1;
  }
  console.log(
    "every field has one row, no row names a field the pages lost, every field is on the page and inside the risk region its row names, no controller reaches off its own page, and every link names a page the plugin registers",
  );

  return 0;
}

process.exit(main());
