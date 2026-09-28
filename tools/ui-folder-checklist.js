#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Runs the shipped library checklist builder of the provider page against both
 * client shapes and refuses the two known failures by name (#1607).
 * Jellyfin 12 throws on the createElement `is` option, which only running the
 * builder can show; the DOM stub below is the smallest one the code touches.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORE = path.join(HERE, "..", "SSO-Auth", "Web", "sso-core.js");

const FOLDERS = {
  Items: [
    { Id: "7a2175bccb1f1a94152cbd2b2bae8f6d", Name: "Filme" },
    { Id: "8a05b0252259a1dbd62df97522638439", Name: "Musik" },
    { Id: "9c3186ccd370b2ece73ef08633749540", Name: "Serien" },
  ],
};

/** The stub class list of one element. */
class Classes {
  constructor(owner) {
    this.owner = owner;
    this.set = new Set();
  }
  add(...names) {
    names.forEach((name) => this.set.add(name));
  }
  remove(...names) {
    names.forEach((name) => this.set.delete(name));
  }
  contains(name) {
    return this.set.has(name);
  }
}

/** The stub DOM element; its members mirror the DOM methods of the same name. */
class Element {
  constructor(tag) {
    this.tag = tag;
    this.type = "";
    this.checked = false;
    this.textContent = "";
    this.dataset = {};
    this.attributes = {};
    this.children = [];
    this.parent = null;
    this.classList = new Classes(this);
  }

  setAttribute(name, value) {
    this.attributes[name] = value;
  }

  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }

  append(...nodes) {
    nodes.forEach((node) => this.appendChild(node));
  }

  appendChild(node) {
    node.parent = this;
    this.children.push(node);
    return node;
  }

  remove() {
    if (!this.parent) {
      return;
    }
    const at = this.parent.children.indexOf(this);
    if (at >= 0) {
      this.parent.children.splice(at, 1);
    }
    this.parent = null;
  }

  /** Every descendant, this node excluded, in document order. */
  descendants() {
    return this.children.flatMap((child) => [child, ...child.descendants()]);
  }

  querySelectorAll(selector) {
    if (!selector.startsWith(".")) {
      throw new Error("the stub resolves class selectors only: " + selector);
    }
    const wanted = selector.slice(1);
    return this.descendants().filter((node) => node.classList.contains(wanted));
  }
}

/**
 * Returns a stub `document` in one of the two client shapes.
 * `refusesTheIsOption` is Jellyfin 12, whose createElement throws on any second
 * argument with the message used below.
 */
function documentFor(refusesTheIsOption) {
  let optionsSeen = 0;
  return {
    optionsAccepted: () => optionsSeen,
    createElement(tag, options) {
      if (options !== undefined) {
        if (refusesTheIsOption) {
          throw new TypeError("t.toLowerCase is not a function");
        }
        optionsSeen += 1;
      }
      return new Element(tag);
    },
  };
}

/** Imports the shipped sso-core.js as a module. */
async function loadCore() {
  const source = fs.readFileSync(CORE, "utf8");
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64");
  return (await import(url)).default;
}

/** Returns the checkbox rows drawn into a container. */
function rowsOf(container) {
  return container.querySelectorAll(".folder-checkbox");
}

/** Runs every leg and exits non-zero on a refusal. */
async function main() {
  const core = await loadCore();
  const faults = [];
  const refuse = (leg, detail) => faults.push(leg + ": " + detail);

  // ---- The two client shapes draw the same three rows ----
  for (const [name, refuses] of [
    ["jellyfin-12", true],
    ["jellyfin-10.11", false],
  ]) {
    const doc = documentFor(refuses);
    globalThis.document = doc;
    const container = new Element("div");

    try {
      core._populateFolders(container, FOLDERS);
    } catch (error) {
      refuse(
        name,
        "building the checklist threw, so the list stays empty on a server that has libraries: " +
          String((error && error.message) || error),
      );
      continue;
    }

    const rows = rowsOf(container);
    if (rows.length !== FOLDERS.Items.length) {
      refuse(
        name,
        `the checklist drew ${rows.length} rows for ${FOLDERS.Items.length} libraries`,
      );
      continue;
    }

    const unmarked = rows.filter(
      (row) => row.getAttribute("is") !== "emby-checkbox",
    );
    if (unmarked.length > 0) {
      refuse(
        name,
        `${unmarked.length} rows carry no is="emby-checkbox", so the client cannot style or upgrade them`,
      );
    }

    const ids = rows.map((row) => row.dataset.id);
    if (ids.join(",") !== FOLDERS.Items.map((f) => f.Id).join(",")) {
      refuse(
        name,
        "the rows do not carry the library ids they were built from",
      );
    }

    if (!refuses && doc.optionsAccepted() === 0) {
      refuse(
        name,
        "the upgrading form was never tried on a client that accepts it, so 10.11 loses the upgrade",
      );
    }
  }

  // The legs below need a builder that returns rows; stopping here keeps the refusal readable.
  if (faults.length > 0) {
    faults.forEach((fault) => console.error("REFUSED  " + fault));
    process.exit(1);
  }

  // ---- A second fill replaces the rows rather than doubling them ----
  {
    globalThis.document = documentFor(true);
    const container = new Element("div");
    core._populateFolders(container, FOLDERS);
    core._populateFolders(container, FOLDERS);

    if (rowsOf(container).length !== FOLDERS.Items.length) {
      refuse(
        "refill",
        `a second fill left ${rowsOf(container).length} rows for ${FOLDERS.Items.length} libraries, so ids are duplicated`,
      );
    }
  }

  // ---- No rows is not an empty selection ----
  {
    globalThis.document = documentFor(true);

    const empty = new Element("div");
    if (core.serializeEnabledFolders(empty) !== null) {
      refuse(
        "never-drew",
        "a checklist that never drew serialized as a library set, which is the write that " +
          "clears a provider's folder restriction and costs its users their access at the next sign-in",
      );
    }

    const drawn = new Element("div");
    core._populateFolders(drawn, FOLDERS);
    const none = core.serializeEnabledFolders(drawn);
    if (none === null || none.length !== 0) {
      refuse(
        "cleared",
        "a drawn checklist with nothing ticked did not serialize as an empty set, so an " +
          "administrator cannot clear a restriction: " +
          JSON.stringify(none),
      );
    }

    rowsOf(drawn)[1].checked = true;
    const one = core.serializeEnabledFolders(drawn);
    if (!Array.isArray(one) || one.join(",") !== FOLDERS.Items[1].Id) {
      refuse(
        "ticked",
        "a ticked row did not serialize as its library id: " +
          JSON.stringify(one),
      );
    }
  }

  delete globalThis.document;

  if (faults.length > 0) {
    faults.forEach((fault) => console.error("REFUSED  " + fault));
    process.exit(1);
  }

  console.log("The library checklist holds on both client shapes.");
  console.log(
    "  jellyfin-12      a client that refuses the createElement `is` option still gets its rows",
  );
  console.log(
    "  jellyfin-10.11   a client that accepts it is still handed the upgrading form",
  );
  console.log(
    "  refill           a second fill replaces the rows rather than doubling the ids",
  );
  console.log(
    "  never-drew       a checklist that never drew is not serialized as an empty library set",
  );
  console.log(
    "  cleared/ticked   a drawn checklist still says what the administrator ticked",
  );
}

main().catch((error) => {
  console.error(String((error && error.stack) || error));
  process.exit(1);
});
