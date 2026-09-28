#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Reads the Sensitive and Insecure option folds on both protocol forms of the
 * Providers page and the count their summary carries (#1666).
 *
 * A wrong count over a closed fold is worse than none, so the static half checks the
 * markup is four collapsed folds with a count slot and the runtime half drives the
 * shipped recount over a tree built from that markup. The stub has no event
 * propagation, so dropping the capture flag on the delegated listener is not caught
 * here.
 */

const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const CORE = path.join(root, "SSO-Auth", "Web", "sso-core.js");
const PROVIDERS_PAGE = path.join(root, "SSO-Auth", "Web", "providersPage.html");
const ENGLISH = path.join(root, "SSO-Auth", "Localization", "en.json");

// The marker class the recount walks, and the two the count is derived from.
const FOLD = "sso-option-fold";
const COUNT = "sso-fold-count";
const BOXES = ["checkboxContainer", "inputContainer"];
// The two regions, by the class that says which one a fold is.
const REGIONS = ["sso-sensitive-region", "sso-danger-zone"];
// The ids sso-core.js expands when a loaded provider has an active insecure toggle (#689).
const EXPANDS = ["sso-insecure-options", "saml-insecure-options"];
// The count's catalogue row and the English fallback the runtime arms read with no catalogue loaded.
const COUNT_KEY = "config.option_fold_count";
const COUNT_EN = "{active} of {total} in use";

// The stub: only the members the code under test touches.

// A minimal classList over a set of names.
class Classes {
  constructor(names) {
    this.set = new Set(names || []);
  }
  add(name) {
    this.set.add(name);
  }
  remove(...names) {
    names.forEach((name) => this.set.delete(name));
  }
  contains(name) {
    return this.set.has(name);
  }
}

// A DOM element with a real tree, attributes and a classList.
class Element {
  constructor(tag, options) {
    const settings = options || {};
    this.tag = tag;
    this.id = settings.id || "";
    this.type = settings.type || tag;
    this.value = settings.value || "";
    this.checked = Boolean(settings.checked);
    this.open = Boolean(settings.open);
    this.hidden = false;
    this.textContent = "";
    this.children = [];
    this.classList = new Classes(settings.classes);
  }

  append(...children) {
    children.forEach((child) => this.children.push(child));
    return this;
  }

  /** Every descendant in document order, excluding the element itself. */
  descendants() {
    return this.children.flatMap((child) => [child, ...child.descendants()]);
  }

  matches(selector) {
    return selector.startsWith(".")
      ? this.classList.contains(selector.slice(1))
      : selector.startsWith("#")
        ? this.id === selector.slice(1)
        : this.tag === selector;
  }

  querySelectorAll(selector) {
    const wanted = selector.split(",").map((part) => part.trim());
    return this.descendants().filter((el) =>
      wanted.some((part) => el.matches(part)),
    );
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }
}

// The page root, which holds capture listeners and dispatches events to them.
class Page extends Element {
  constructor() {
    super("div", {});
    this.listeners = new Map();
  }

  addEventListener(name, handler, capture) {
    const key = name + (capture ? ":capture" : "");
    if (!this.listeners.has(key)) {
      this.listeners.set(key, []);
    }
    this.listeners.get(key).push(handler);
  }

  /**
   * Dispatches one event at `target` the way a browser delivers a captured one.
   * `isTrusted` is false because two dashboard controls dispatch synthetic events on real input.
   */
  dispatch(name, target) {
    (this.listeners.get(name + ":capture") || []).forEach((handler) =>
      handler({ isTrusted: false, target, type: name }),
    );
  }
}

// Reading the markup.

/** Replaces every HTML comment with spaces, so a documented fold is not a real one. */
function withoutComments(html) {
  return html.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, " "));
}

/** The value of `name="..."` where the name starts an attribute, as the sibling gates read it. */
function attr(tag, name) {
  const found = tag.match(new RegExp("(?<![-\\w])" + name + '="([^"]*)"'));
  return found ? found[1] : "";
}

/** The classes on an opening tag, as a set. */
function classesOf(tag) {
  return new Set(attr(tag, "class").split(/\s+/).filter(Boolean));
}

/**
 * The span of the element whose opening tag starts at `start`, as `{ tag, inner: [from, to] }`.
 * The tag name comes from the match because regions are `<details>` and boxes inside are `<div>`.
 */
function spanFrom(html, start) {
  const name = /^<([a-zA-Z][-\w]*)/.exec(html.slice(start));
  if (name === null) {
    throw new Error("no element opens at offset " + start);
  }
  const tag = name[1];
  const openEnd = html.indexOf(">", start);
  if (openEnd === -1) {
    throw new Error("the <" + tag + "> at offset " + start + " never closes");
  }
  const re = new RegExp("<" + tag + "\\b[^>]*>|</" + tag + ">", "g");
  re.lastIndex = start;
  let depth = 0;
  let m;
  while ((m = re.exec(html)) !== null) {
    if (m[0] === "</" + tag + ">") {
      depth -= 1;
      if (depth === 0) {
        return { tag, inner: [openEnd + 1, m.index] };
      }
    } else {
      depth += 1;
    }
  }
  throw new Error("the <" + tag + "> at offset " + start + " is never closed");
}

/**
 * Every option fold the markup holds, as `{ tag, classes, id, open, summary, boxes }`.
 * Nested folds are not admitted; the arms refuse that shape.
 */
function foldsOf(html) {
  const source = withoutComments(html);
  const opens = [...source.matchAll(/<([a-zA-Z][-\w]*)\b[^>]*>/g)].filter((m) =>
    classesOf(m[0]).has(FOLD),
  );
  return opens.map((m) => {
    const span = spanFrom(source, m.index);
    const inner = source.slice(span.inner[0], span.inner[1]);
    const summary = /<summary\b[^>]*>/.exec(inner);
    const boxes = [...inner.matchAll(/<([a-zA-Z][-\w]*)\b[^>]*>/g)]
      .filter((box) => BOXES.some((name) => classesOf(box[0]).has(name)))
      .map((box) => {
        const boxSpan = spanFrom(inner, box.index);
        const body = inner.slice(boxSpan.inner[0], boxSpan.inner[1]);
        const control = /<(input|select|textarea)\b[^>]*>/.exec(body);
        return {
          classes: classesOf(box[0]),
          control:
            control === null
              ? null
              : {
                  tag: control[1],
                  id: attr(control[0], "id"),
                  type: attr(control[0], "type") || control[1],
                },
        };
      });
    return {
      tag: span.tag,
      id: attr(m[0], "id"),
      classes: classesOf(m[0]),
      open: /\sopen[\s>]/.test(m[0]),
      boxes,
      // A summary names the fold only as its first child, so the offset is kept.
      summary:
        summary === null
          ? null
          : {
              at: summary.index,
              inner: inner.slice(...spanFrom(inner, summary.index).inner),
            },
      firstChild: /<([a-zA-Z][-\w]*)\b[^>]*>/.exec(inner),
      nested: [...inner.matchAll(/<([a-zA-Z][-\w]*)\b[^>]*>/g)].filter((el) =>
        classesOf(el[0]).has(FOLD),
      ).length,
    };
  });
}

/** A Page carrying the folds the markup holds, each with its summary, its count span and its boxes. */
function fixtureFrom(html) {
  const page = new Page();
  const folds = foldsOf(html);
  folds.forEach((read) => {
    const fold = new Element(read.tag, {
      id: read.id,
      classes: [...read.classes],
      open: read.open,
    });
    const summary = new Element("summary", {});
    summary.append(new Element("span", { classes: [COUNT] }));
    fold.append(summary);
    read.boxes.forEach((box) => {
      const wrapper = new Element("div", { classes: [...box.classes] });
      if (box.control !== null) {
        wrapper.append(
          new Element(box.control.tag, {
            id: box.control.id,
            type: box.control.type,
          }),
        );
      }
      fold.append(wrapper);
    });
    page.append(fold);
  });
  return { page, folds };
}

// The arms: named refusals over one page's markup and its tree, reused by the calibration.

/** The static arms: four collapsed folds, each opened by a summary with a count slot. */
function markupArms(html, refuse) {
  const folds = foldsOf(html);

  if (folds.length === 0) {
    refuse(
      "regions-are-folds",
      "no region on this page carries " +
        FOLD +
        ", so nothing here hides its options behind a fold at all",
    );
    return folds;
  }

  folds.forEach((fold, index) => {
    const named =
      fold.id ||
      [...fold.classes].find((name) => REGIONS.includes(name)) ||
      "#" + index;

    if (fold.tag !== "details") {
      refuse(
        "regions-are-folds",
        named +
          " is a <" +
          fold.tag +
          "> rather than a <details>, so its options are not behind a fold a browser collapses",
      );
    }

    if (fold.open) {
      refuse(
        "collapsed-by-default",
        named +
          " ships open, so the page opens with the region it is supposed to fold already unfolded",
      );
    }

    if (fold.summary === null || fold.firstChild === null) {
      refuse(
        "summary-names-the-region",
        named +
          " has no <summary>, so the fold has no name and no room for a count",
      );
      return;
    }

    if (fold.firstChild[1] !== "summary") {
      refuse(
        "summary-names-the-region",
        named +
          " opens with a <" +
          fold.firstChild[1] +
          "> rather than its <summary>, so a browser reads the name as ordinary content and draws its own",
      );
    }

    if (!new RegExp('class="[^"]*' + COUNT).test(fold.summary.inner)) {
      refuse(
        "summary-carries-the-count",
        named +
          " has a summary with no ." +
          COUNT +
          ", so the region names itself and says nothing about what it hides",
      );
    }

    if (fold.nested > 0) {
      refuse(
        "no-fold-inside-a-fold",
        named +
          " holds another option fold, so its boxes would be counted twice and its own summary would disagree with what it hides",
      );
    }

    if (fold.boxes.length === 0) {
      refuse(
        "a-fold-holds-options",
        named +
          ' holds no option box, so its count can only ever read "0 of 0" and the summary is a label with a number bolted on',
      );
    }

    fold.boxes.forEach((box) => {
      if (box.control === null) {
        refuse(
          "every-box-holds-a-control",
          named +
            " holds a " +
            [...box.classes].join(" ") +
            " with no control in it, so the total counts a box an administrator cannot set",
        );
      }
    });
  });

  REGIONS.forEach((region) => {
    if (!folds.some((fold) => fold.classes.has(region))) {
      refuse(
        "both-regions-are-folded",
        "no fold on this page is a " +
          region +
          ", so that region is either gone or no longer folded",
      );
    }
  });

  return folds;
}

/** The expander ids, read from the markup, since a moved id leaves the expand doing nothing. */
function expanderArms(html, refuse) {
  const folds = foldsOf(html);
  EXPANDS.forEach((id) => {
    if (!folds.some((fold) => fold.id === id)) {
      refuse(
        "the-expander-finds-its-fold",
        "no option fold carries id " +
          id +
          ", which sso-core.js opens when a loaded provider has an active insecure toggle",
      );
    }
  });
}

/** What the summary of each fold says, after a recount. */
function countsOf(page) {
  return page.querySelectorAll("." + FOLD).map((fold) => {
    const count = fold.querySelector("." + COUNT);
    return count === null ? null : count.textContent;
  });
}

/** The English count sentence for the given numbers. */
function expected(active, total) {
  return COUNT_EN.replace("{active}", String(active)).replace(
    "{total}",
    String(total),
  );
}

/**
 * The runtime arms: the shipped recount driven over the tree the markup built.
 * Every expected number is derived from the same markup, never typed into this file.
 */
function runtimeArms(core, html, refuse) {
  const { page, folds } = fixtureFrom(html);
  const totals = folds.map((fold) => fold.boxes.length);

  core.bindOptionFoldCounts(page);
  core.refreshOptionFoldCounts(page);
  countsOf(page).forEach((said, index) => {
    const want = expected(0, totals[index]);
    if (said !== want) {
      if (said === null || said === "") {
        refuse(
          "the-count-is-filled-in",
          "fold " +
            index +
            " has an empty count after a recount, so its summary names the region and hides the state",
        );
        return;
      }
      refuse(
        "the-count-is-right-on-load",
        "fold " +
          index +
          " says " +
          JSON.stringify(said) +
          " over a form where nothing is in use, and its boxes are " +
          JSON.stringify(want),
      );
    }
  });

  // One ticked checkbox, and no other fold's number may move.
  const withCheckbox = page.querySelectorAll("." + FOLD).findIndex(
    (fold) =>
      fold
        .querySelectorAll(BOXES.map((name) => "." + name).join(", "))
        .map((box) => box.querySelector("input, select, textarea"))
        .filter((control) => control && control.type === "checkbox").length > 0,
  );
  if (withCheckbox === -1) {
    refuse(
      "a-ticked-box-is-counted",
      "no fold on this page holds a checkbox, so the direction this arm drives is reached by nothing",
    );
  } else {
    const fold = page.querySelectorAll("." + FOLD)[withCheckbox];
    const box = fold
      .querySelectorAll(BOXES.map((name) => "." + name).join(", "))
      .map((one) => one.querySelector("input, select, textarea"))
      .find((control) => control && control.type === "checkbox");
    box.checked = true;
    page.dispatch("change", box);
    countsOf(page).forEach((said, index) => {
      const want = expected(index === withCheckbox ? 1 : 0, totals[index]);
      if (said !== want) {
        refuse(
          index === withCheckbox
            ? "a-ticked-box-is-counted"
            : "a-tick-moves-one-summary",
          "fold " +
            index +
            " says " +
            JSON.stringify(said) +
            " after " +
            box.id +
            " was ticked, and it should say " +
            JSON.stringify(want),
        );
      }
    });
    // And back, because a count that only grows misreports an emptied region.
    box.checked = false;
    page.dispatch("change", box);
    countsOf(page).forEach((said, index) => {
      const want = expected(0, totals[index]);
      if (said !== want) {
        refuse(
          "a-box-turned-back-off-is-counted",
          "fold " +
            index +
            " says " +
            JSON.stringify(said) +
            " after " +
            box.id +
            " was turned back off, and it should say " +
            JSON.stringify(want),
        );
      }
    });
  }

  // A value, not a tick: the SAML sensitive region holds the secondary signing certificate.
  const valued = page
    .querySelectorAll("." + FOLD)
    .map((fold, index) => ({
      index,
      control: fold
        .querySelectorAll(BOXES.map((name) => "." + name).join(", "))
        .map((box) => box.querySelector("input, select, textarea"))
        .find((control) => control && control.type !== "checkbox"),
    }))
    .find((entry) => entry.control !== undefined);
  if (valued === undefined) {
    refuse(
      "a-filled-field-is-counted",
      "no fold on this page holds a field with a value, so the direction this arm drives is reached by nothing",
    );
  } else {
    valued.control.value = "a certificate";
    page.dispatch("input", valued.control);
    const said = countsOf(page)[valued.index];
    const want = expected(1, totals[valued.index]);
    if (said !== want) {
      refuse(
        "a-filled-field-is-counted",
        "fold " +
          valued.index +
          " says " +
          JSON.stringify(said) +
          " after " +
          valued.control.id +
          " was filled in, and it should say " +
          JSON.stringify(want),
      );
    }
    // Whitespace is not a value.
    valued.control.value = "   ";
    page.dispatch("input", valued.control);
    if (countsOf(page)[valued.index] !== expected(0, totals[valued.index])) {
      refuse(
        "whitespace-is-not-a-value",
        "fold " +
          valued.index +
          " counts " +
          valued.control.id +
          " as in use while it holds nothing but whitespace",
      );
    }
    valued.control.value = "";
  }

  // The expanders, driven: an insecure fold that code cannot open undoes #689.
  EXPANDS.forEach((id) => {
    const fold = page.querySelector("#" + id);
    if (fold === null) {
      return;
    }
    const open = id.startsWith("saml-")
      ? core.setSamlInsecureOptionsExpanded
      : core.setInsecureOptionsExpanded;
    open(page, true);
    if (fold.open !== true) {
      refuse(
        "the-expander-opens-the-fold",
        id +
          " stays closed after the code that surfaces an active downgrade opened it",
      );
    }
    open(page, false);
    if (fold.open !== false) {
      refuse(
        "the-expander-closes-the-fold",
        id +
          " stays open after a fresh editor collapsed it, so the last provider's state bleeds into the next",
      );
    }
  });
}

/** The catalogue row the count is rendered from, and the English the script falls back to. */
function catalogueArms(refuse) {
  const catalogue = JSON.parse(fs.readFileSync(ENGLISH, "utf8"));
  if (catalogue[COUNT_KEY] !== COUNT_EN) {
    refuse(
      "the-count-has-a-catalogue-row",
      "en.json answers " +
        JSON.stringify(catalogue[COUNT_KEY]) +
        " for " +
        COUNT_KEY +
        " and the summary is rendered from " +
        JSON.stringify(COUNT_EN),
    );
  }
  const core = fs.readFileSync(CORE, "utf8");
  if (!core.includes(JSON.stringify(COUNT_EN))) {
    refuse(
      "the-count-has-a-catalogue-row",
      "sso-core.js does not carry " +
        JSON.stringify(COUNT_EN) +
        " as its built-in English, so a page whose catalogue never arrived shows something else",
    );
  }

  /*
   * The arms drive bindOptionFoldCounts themselves, so the call from initSharedPage
   * is read out of the source.
   */
  const shared = core.slice(core.indexOf("function initSharedPage("));
  const body = shared.slice(0, shared.indexOf("\n}"));
  ["bindOptionFoldCounts(view)", "refreshOptionFoldCounts(view)"].forEach(
    (call) => {
      if (!body.includes(call)) {
        refuse(
          "the-page-binds-the-recount",
          "initSharedPage does not call " +
            call +
            ", so the summaries are filled by nothing when the page is wired",
        );
      }
    },
  );

  /*
   * Loading a provider ticks boxes without dispatching, so both re-sync functions
   * must recount, each read within its own body.
   */
  ["syncDependentFields:", "syncSamlDependentFields:"].forEach((entry) => {
    const at = core.indexOf(entry);
    if (at === -1) {
      refuse(
        "a-load-recounts",
        "sso-core.js has no " +
          entry +
          ", so nothing recounts after a provider is loaded",
      );
      return;
    }
    const method = core.slice(at, core.indexOf("\n  },", at));
    if (!method.includes("refreshOptionFoldCounts(page)")) {
      refuse(
        "a-load-recounts",
        entry.replace(":", "") +
          " does not recount, so a loaded provider's ticked options are not in the summary until something else is changed",
      );
    }
  });
}

// The calibration, run before the real page is opened.

/**
 * A hand page with one checkbox fold and one value-field fold, deliberately not a
 * copy of the shipped page.
 */
function handPage(mutate) {
  const page = [
    '<details id="sso-insecure-options" class="sso-security-block sso-danger-zone sso-option-fold">',
    '  <summary class="sso-subgroup-title sso-fold-summary">',
    '    <span>Insecure options</span><span class="sso-fold-count"></span>',
    "  </summary>",
    '  <div class="checkboxContainer"><label><input id="One" type="checkbox" /><span>One</span></label></div>',
    '  <div class="checkboxContainer"><label><input id="Two" type="checkbox" /><span>Two</span></label></div>',
    "</details>",
    '<details id="saml-insecure-options" class="sso-security-block sso-danger-zone sso-option-fold">',
    '  <summary class="sso-fold-summary">',
    '    <span>Insecure options</span><span class="sso-fold-count"></span>',
    "  </summary>",
    '  <div class="checkboxContainer"><label><input id="saml-Three" type="checkbox" /><span>Three</span></label></div>',
    "</details>",
    '<details class="sso-security-block sso-sensitive-region sso-option-fold">',
    '  <summary class="sso-fold-summary">',
    '    <span>Rotation</span><span class="sso-fold-count"></span>',
    "  </summary>",
    '  <div class="inputContainer"><label for="Cert">Certificate</label><textarea id="Cert"></textarea></div>',
    "</details>",
  ].join("\n");
  return mutate ? mutate(page) : page;
}

const MUTATIONS = [
  [
    "a region that is no longer a fold",
    "regions-are-folds",
    (html) =>
      html
        .replace(
          '<details id="sso-insecure-options"',
          '<div id="sso-insecure-options"',
        )
        .replace(
          '</details>\n<details id="saml-',
          '</div>\n<details id="saml-',
        ),
  ],
  [
    "a fold that ships open",
    "collapsed-by-default",
    (html) =>
      html.replace(
        '<details id="sso-insecure-options"',
        '<details open id="sso-insecure-options"',
      ),
  ],
  [
    "a fold whose summary is not its first child",
    "summary-names-the-region",
    (html) =>
      html.replace(
        '<details id="saml-insecure-options" class="sso-security-block sso-danger-zone sso-option-fold">\n',
        '<details id="saml-insecure-options" class="sso-security-block sso-danger-zone sso-option-fold">\n  <p>Read this first</p>\n',
      ),
  ],
  [
    "a summary with nowhere to put the count",
    "summary-carries-the-count",
    (html) => html.replace('<span class="sso-fold-count"></span>', ""),
  ],
  [
    "an option fold inside an option fold",
    "no-fold-inside-a-fold",
    (html) =>
      html
        .replace(
          '<div class="checkboxContainer"><label><input id="saml-Three"',
          '<details class="sso-option-fold"><summary><span class="sso-fold-count"></span></summary><div class="checkboxContainer"><label><input id="saml-Three"',
        )
        .replace(
          "<span>Three</span></label></div>\n</details>",
          "<span>Three</span></label></div></details>\n</details>",
        ),
  ],
  [
    "a fold holding no option at all",
    "a-fold-holds-options",
    (html) =>
      html.replace(
        '<div class="checkboxContainer"><label><input id="saml-Three" type="checkbox" /><span>Three</span></label></div>\n',
        "",
      ),
  ],
  [
    "an option box with no control in it",
    "every-box-holds-a-control",
    (html) =>
      html.replace(
        '<div class="inputContainer"><label for="Cert">Certificate</label><textarea id="Cert"></textarea></div>',
        '<div class="inputContainer"><label for="Cert">Certificate</label></div><div class="inputContainer"><textarea id="Cert"></textarea></div>',
      ),
  ],
  [
    "a page that folds only one of the two regions",
    "both-regions-are-folded",
    (html) => html.replace("sso-sensitive-region ", ""),
  ],
  [
    "an expander whose fold was renamed",
    "the-expander-finds-its-fold",
    (html) =>
      html.replace('id="saml-insecure-options"', 'id="saml-insecure-list"'),
  ],
];

/** Runs the markup arms over the hand page and over one mutation per arm, which each must refuse. */
function calibrate() {
  const results = [];

  const clean = [];
  markupArms(handPage(null), (name, detail) => clean.push([name, detail]));
  expanderArms(handPage(null), (name, detail) => clean.push([name, detail]));
  if (clean.length !== 0) {
    throw new Error(
      "the calibration's own page is refused by " +
        clean.map(([name, detail]) => name + ": " + detail).join("; "),
    );
  }
  results.push(true);

  MUTATIONS.forEach(([why, arm, mutate]) => {
    const refused = [];
    const collect = (name, detail) => refused.push([name, detail]);
    const html = handPage(mutate);
    markupArms(html, collect);
    expanderArms(html, collect);
    if (!refused.some(([name]) => name === arm)) {
      throw new Error(
        "the calibration's " +
          JSON.stringify(why) +
          " was not refused by " +
          arm +
          "; it was refused by " +
          (refused.length === 0
            ? "nothing"
            : refused.map(([name]) => name).join(", ")),
      );
    }
    results.push(false);
  });

  return (
    "calibration:        " +
    results.length +
    " arms, 1 that must pass and " +
    (results.length - 1) +
    " that must be refused, all as expected"
  );
}

// The run.

// Imports the shipped sso-core.js as a data URL module.
async function loadCore() {
  const source = fs.readFileSync(CORE, "utf8");
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64");
  return (await import(url)).default;
}

// Runs the calibration, then every arm over the shipped page, and exits non-zero on a refusal.
async function run() {
  console.log(calibrate());

  const refusals = [];
  const refuse = (name, detail) => refusals.push([name, detail]);

  const html = fs.readFileSync(PROVIDERS_PAGE, "utf8");
  const folds = markupArms(html, refuse);
  expanderArms(html, refuse);
  catalogueArms(refuse);
  runtimeArms(await loadCore(), html, refuse);

  folds.forEach((fold) => {
    console.log(
      (
        fold.id || [...fold.classes].find((name) => REGIONS.includes(name))
      ).padEnd(24) +
        String(fold.boxes.length).padStart(3) +
        " option(s) behind a <" +
        fold.tag +
        "> that ships " +
        (fold.open ? "open" : "closed"),
    );
  });
  console.log(
    "providersPage.html: " +
      folds.length +
      " option fold(s), " +
      folds.reduce((sum, fold) => sum + fold.boxes.length, 0) +
      " option(s) behind them in total",
  );

  refusals.forEach(([name, detail]) =>
    console.error("REFUSED  " + name + ": " + detail),
  );
  if (refusals.length > 0) {
    console.error(refusals.length + " refusal(s) in the option folds (#1666)");
    return 1;
  }

  console.log(
    "every Sensitive and Insecure region is a collapsed fold whose summary counts the options in use inside it, on load and after a change",
  );
  return 0;
}

run().then(
  (code) => process.exit(code),
  (error) => {
    console.error("the option-fold gate could not run: " + error.stack);
    process.exit(1);
  },
);
