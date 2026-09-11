#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Drives the REAL parts applier of the shipped i18n.js and refuses each way it
 * can be wrong (#1529).
 *
 * WHY A RUNNING PROOF AND NOT A CONFORMANCE RULE. The C# rules beside this one
 * read the TEXT of the markup and the catalogs: they can say that a parts value
 * names the same slots the element has children, and they do. What they cannot
 * say is what happens when it does not - and that is the whole safety of this
 * mechanism. `applyParts` must leave the English sentence standing rather than
 * assemble a partial one, because a sentence missing a `<code>` sample in the
 * middle of instructions for recovering from a lockout is worse than a sentence
 * in the wrong language. Whether it does is a property of the code, and the
 * inverted condition reads exactly like the correct one.
 *
 * A LIVE WALK COULD NOT ANSWER IT EITHER, which is why this file exists rather
 * than a note in a pull request. On a real server the catalog comes from the
 * server, so the refusal cases cannot be reached without shipping a broken
 * catalog to reach them. The first attempt to check this in a browser drove
 * four different bad values through a key the catalog did not carry, so the
 * applier was never entered and all four "passed" for the same empty reason.
 *
 * WHAT THE STUB CAN AND CANNOT SAY. The DOM below is the smallest one the
 * applier touches: createTextNode, children, replaceChildren, getAttribute and a
 * selector lookup for exactly the two marker forms. It is not a browser. It
 * cannot say anything about layout, about the order the page runs its own
 * scripts in, or about a client whose createElement behaves differently - the
 * folder-checklist gate beside it exists for that last one. What keeps it from
 * being a proof about itself is that the code under test is the shipped
 * i18n.js, loaded whole through a data URL, and that the catalog reaches it
 * through its own loadCatalog and its own fetch rather than by assignment.
 *
 * Node is preinstalled on the runner and this tool has no dependencies, in the
 * same terms as tools/ui-mock-fields.js and tools/ui-untranslated.js.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APPLIER = path.join(HERE, "..", "SSO-Auth", "Web", "i18n.js");

// ---------------------------------------------------------------------------
// The stub.
// ---------------------------------------------------------------------------

class TextNode {
  constructor(text) {
    this.text = text;
  }
  get rendered() {
    return this.text;
  }
}

class Element {
  constructor(tag, attributes = {}, nodes = []) {
    this.tag = tag;
    this.attributes = attributes;
    this.nodes = nodes;
  }

  get children() {
    return this.nodes.filter((node) => node instanceof Element);
  }

  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }

  setAttribute(name, value) {
    this.attributes[name] = value;
  }

  replaceChildren(...nodes) {
    this.nodes = nodes;
  }

  set textContent(value) {
    this.nodes = [new TextNode(value)];
  }

  get rendered() {
    return this.nodes.map((node) => node.rendered).join("");
  }

  // The shape a reader can compare: text as text, an element as <tag>content</tag>.
  get shape() {
    return this.nodes
      .map((node) =>
        node instanceof Element
          ? `<${node.tag}>${node.rendered}</${node.tag}>`
          : node.text,
      )
      .join("");
  }
}

function documentWith(elements) {
  return {
    createTextNode: (text) => new TextNode(text),
    querySelectorAll: (selector) => {
      const attribute = selector.slice(1, -1);
      return elements.filter((el) => el.getAttribute(attribute) !== null);
    },
  };
}

// ---------------------------------------------------------------------------
// The legs.
// ---------------------------------------------------------------------------

async function applierWith(catalog, elements) {
  // The catalog reaches the module the way it does on a server: through its own
  // loadCatalog, over a fetch. Assigning it directly would test a module this
  // tree does not ship.
  globalThis.ApiClient = {
    getUrl: (route) => "https://example.invalid/" + route,
  };
  globalThis.fetch = () =>
    Promise.resolve({ ok: true, json: () => Promise.resolve(catalog) });
  globalThis.document = documentWith(elements);

  const source = fs.readFileSync(APPLIER, "utf8");
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64") +
    "#" +
    Math.random();
  const module = await import(url);
  await module.loadCatalog();
  return module;
}

/** The sentence the shipped Overview page carries, in miniature. */
function sentence() {
  return new Element("li", { "data-i18n-parts": "probe.sentence" }, [
    new Element("strong", {}, [new TextNode("Recovery works from disk.")]),
    new TextNode(" Edit the plugin's "),
    new Element("code", {}, [new TextNode("config.xml")]),
    new TextNode(", set "),
    new Element("code", {}, [new TextNode("Flag")]),
    new TextNode(" back."),
  ]);
}

const faults = [];
const refuse = (leg, detail) => faults.push(leg + ": " + detail);

// ---- Arm: a value naming every child exactly once assembles, and may reorder ----
{
  const el = sentence();
  const before = el.shape;
  const kept = el.children;
  const module = await applierWith(
    { "probe.sentence": "{0} Setze {2} zurueck, in {1} des Plugins." },
    [el],
  );
  module.applyTo();

  const expected =
    "<strong>Recovery works from disk.</strong> Setze <code>Flag</code> zurueck, in <code>config.xml</code> des Plugins.";
  if (el.shape !== expected) {
    refuse(
      "assemble",
      `the sentence came out as "${el.shape}" rather than "${expected}", so a translation cannot move a slot`,
    );
  }
  if (before === el.shape) {
    refuse(
      "assemble",
      "nothing happened at all, so every arm below proves nothing",
    );
  }

  // The children must be the SAME nodes. A clone would drop a listener and, on a
  // page where a child is a link or a button, would quietly disconnect it.
  const now = el.children;
  if (
    now.length !== kept.length ||
    now.some((child) => !kept.includes(child))
  ) {
    refuse(
      "assemble",
      "the children are not the element's own nodes any more, so the catalog created markup instead of moving it",
    );
  }
}

// ---- Arms: every value that does not describe the element leaves it alone ----
for (const [leg, value] of [
  ["too-few", "Only {0} named."],
  ["too-many", "{0} {1} {2} {3} named."],
  ["repeated", "{0} and {0} again, with {1}."],
  ["out-of-range", "{0} {1} {9}."],
]) {
  const el = sentence();
  const before = el.shape;
  const module = await applierWith({ "probe.sentence": value }, [el]);
  module.applyTo();
  if (el.shape !== before) {
    refuse(
      leg,
      `a value of "${value}" was applied to an element with 3 children and gave "${el.shape}", where the English sentence had to stay whole`,
    );
  }
}

// ---- Arm: a key the catalog does not carry leaves the English standing ----
{
  const el = sentence();
  const before = el.shape;
  const module = await applierWith({ "some.other.key": "{0}" }, [el]);
  module.applyTo();
  if (el.shape !== before) {
    refuse(
      "absent-key",
      "an element whose key is not in the catalog was rewritten anyway",
    );
  }
}

// ---- Arm: a catalog value is TEXT and never becomes markup ----
{
  const el = sentence();
  const module = await applierWith(
    { "probe.sentence": "{0}<b>bold</b>{1} & {2}" },
    [el],
  );
  module.applyTo();
  const text = el.nodes
    .filter((node) => node instanceof TextNode)
    .map((node) => node.text);
  if (!text.some((piece) => piece.includes("<b>bold</b>"))) {
    refuse(
      "text-only",
      "the angle brackets in a catalog value did not survive as text, which means something parsed them",
    );
  }
  if (el.children.some((child) => child.tag === "b")) {
    refuse(
      "text-only",
      "a catalog value created an element, which is the one thing this mechanism must never do",
    );
  }
}

// ---- Arm: the text marker still works, and runs BEFORE the parts pass ----
{
  // The <strong> inside a parts element carries its own text marker, because the
  // parts pass moves nodes and never looks inside one. It only translates if the
  // text pass has already run when the node is moved.
  const el = sentence();
  el.children[0].setAttribute("data-i18n", "probe.title");
  const module = await applierWith(
    {
      "probe.title": "Wiederherstellung von der Platte.",
      "probe.sentence": "{0} Ein Satz mit {1} und {2}.",
    },
    [el, ...el.children],
  );
  module.applyTo();
  if (
    !el.shape.includes("<strong>Wiederherstellung von der Platte.</strong>")
  ) {
    refuse(
      "order",
      `a marked child inside a parts element kept its English: "${el.shape}"`,
    );
  }
}

if (faults.length) {
  faults.forEach((fault) => console.error(fault));
  console.error(
    faults.length + " refusal(s) in the sentence-parts applier (#1529)",
  );
  process.exit(1);
}

console.log(
  "sentence parts:    seven arms run against the shipped i18n.js and its own loadCatalog",
);
console.log(
  "  assemble         a value naming every child once is written, may reorder, and moves the nodes rather than copying them",
);
console.log(
  "  too-few / too-many / repeated / out-of-range   a value that does not describe the element leaves the English sentence whole",
);
console.log(
  "  absent-key       a key the catalog does not carry changes nothing",
);
console.log(
  "  text-only        angle brackets in a catalog value stay text and never become an element",
);
console.log(
  "  order            a marked child is translated before the sentence around it is rebuilt",
);
