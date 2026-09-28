#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Reconciles docs/ui/mock/FIELDS.md and the mock against the inputs of the five
 * configuration pages (#1526, #1527): each control must have one row, sit on the
 * page and inside the risk region its row names, and every controller and tab
 * link must stay on registered pages. HTML comments are stripped first and the
 * ids are compared as sets, so a deleted and an added field do not cancel out.
 */

"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");

// The five pages, keyed by the tab name FIELDS.md writes in its "New tab" column.
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
 * Returns the index of the tag closing the `tag` element opening at `start`.
 * The tag is a parameter because risk regions can be `<details>` folds (#1666).
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

/** Returns the start and end of every div or details region carrying a class. */
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
 * Reads the `Field`, `New tab` and `Marked` columns of FIELDS.md as a map from
 * id to `{ tab, marked }`. The marking is compared against the page's own risk
 * boxes, so a control moved out of its box fails even though it still saves.
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

/** Returns the ids of docs/ui/mock/fields.js, loaded as the mock page loads it. */
function readData() {
  if (!fs.existsSync(DATA)) return null;
  const shim = {};
  new Function("window", fs.readFileSync(DATA, "utf8"))(shim);
  return (shim.SSO_MOCK_FIELDS || []).map((f) => f.id);
}

/** Prints a FIELDS.md table row for every field, for `--emit`. */
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
 * The second leg (#1527): each page controller must only reach ids its own page
 * carries, since the init functions register handlers without null guards and
 * one moved id stops the rest of that page's wiring. It reads every `"#..."`
 * literal in each init body; selectors built at runtime are out of reach.
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
 * Returns every id one page declares, with HTML comments stripped first so a
 * commented-out element does not count as declared.
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

/** Returns the faults of the controller leg and of the any-page id check. */
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

  // Ids outside the init bodies, such as containers, must at least be declared by some page.
  const declaredAnywhere = new Set(
    Object.values(PAGES).flatMap((file) => [...idsDeclaredBy(file)]),
  );
  // A literal followed by `+` is a prefix such as `"#saml-" + prop`, not an id.
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
 * The fourth leg (#1527): every tab link and controller must name a page the
 * plugin registers, read from `GetPages` in SSOPlugin.cs so it cannot drift.
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
 * Maps each tab to the registered page name it must link to: Overview is the
 * plugin page id, the others are that id plus the lower-case tab name.
 */
function tabTargets(registered, tabs) {
  const id = [...registered].reduce((a, b) => (a.length <= b.length ? a : b));
  const out = {};
  tabs.forEach((tab, i) => {
    out[tab] = i === 0 ? id : id + "-" + tab.toLowerCase();
  });
  return out;
}

/** Returns the faults of the tab strip, page controllers and current-tab marks. */
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

  // The tab each anchor is for, in strip order, so an href is paired with its own label.
  const ORDER = Object.keys(PAGES);
  const PAGE_NAMES = tabTargets(registered, ORDER);

  for (const [tab, file] of Object.entries(PAGES)) {
    const html = withoutComments(fs.readFileSync(file, "utf8"));
    const where = path.basename(file);

    // One match per anchor with its label class, data-index and href together.
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

      // The href must be this anchor's page, and data-index its position in the strip.
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

    // The page must also be the one the tab strip marks as current.
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

/** Runs every leg, prints each one, and returns the exit code. */
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

  // A control on two pages means two save owners for one setting, so it is refused.
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

  // Reachable on its own page and inside its risk box (#1527), checked once the id sets agree.
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
  // Every leg runs and prints, so a skipped leg cannot read as a passed one.
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
