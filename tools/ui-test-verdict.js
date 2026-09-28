#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Drives the shipped sso-core.js Test Connection renderer against both catalogues
 * and refuses a verdict that reaches the page in the wrong language or not at all
 * (#1728). Keys are read from ProviderTestKeys.cs and sentences from the catalogues.
 * Run with `node tools/ui-test-verdict.js`; no dependencies.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.join(HERE, "..", "SSO-Auth", "Web");
const LOCALIZATION = path.join(HERE, "..", "SSO-Auth", "Localization");
const KEYS_SOURCE = path.join(
  HERE,
  "..",
  "SSO-Auth",
  "Api",
  "Provider",
  "ProviderTestKeys.cs",
);

function read(file) {
  return fs.readFileSync(file, "utf8");
}

function catalogue(name) {
  return JSON.parse(read(path.join(LOCALIZATION, `${name}.json`)));
}

const faults = [];
const refuse = (leg, detail) => faults.push(leg + ": " + detail);

// The vocabulary: `internal const string Name = "test.name";` in the C# file, read as name -> key.
const KEYS = Object.fromEntries(
  [
    ...read(KEYS_SOURCE).matchAll(/const string (\w+) = "(test\.[a-z0-9_]+)"/g),
  ].map((m) => [m[1], m[2]]),
);
for (const name of [
  "OidcDiscoveryRead",
  "Issuer",
  "UserInfoEndpoint",
  "JwksReachable",
  "PkceAdvertised",
  "SamlCertificateUnparsable",
  "NotAdvertised",
]) {
  if (!KEYS[name]) {
    refuse("vocabulary", `ProviderTestKeys.cs declares no ${name}`);
  }
}
if (faults.length) {
  console.error("REFUSED " + faults.join("\n        "));
  process.exit(1);
}

// The stub.

class Element {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.classes = new Set();
    this.text = "";
    this.classList = {
      add: (...names) => names.forEach((name) => this.classes.add(name)),
      contains: (name) => this.classes.has(name),
    };
  }

  set textContent(value) {
    this.text = String(value);
    this.children = [];
  }

  get textContent() {
    return this.children.length
      ? this.children.map((child) => child.textContent).join(" ")
      : this.text;
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  replaceChildren(...nodes) {
    this.children = nodes;
  }

  querySelector() {
    return null;
  }

  querySelectorAll() {
    return [];
  }
}

globalThis.document = {
  createElement: (tag) => new Element(tag),
  querySelector: () => null,
  querySelectorAll: () => [],
};

// ApiClient.getUrl hands back the shipped i18n.js; the catalogue it fetches is the arm's.
const culture = { values: {} };
globalThis.ApiClient = {
  getUrl: (route) =>
    route === "SSOViews/i18n.js"
      ? pathToFileURL(path.join(WEB, "i18n.js")).href
      : "/" + route,
};
globalThis.fetch = () =>
  Promise.resolve({ ok: true, json: () => Promise.resolve(culture.values) });

async function loadCore() {
  const source = read(path.join(WEB, "sso-core.js"));
  const url =
    "data:text/javascript;base64," +
    Buffer.from(source, "utf8").toString("base64");
  return (await import(url)).default;
}

const core = await loadCore();

/** Loads one catalogue through the page's own localize() and waits until a lookup answers from it. */
async function localizeTo(name) {
  culture.values = catalogue(name);
  core.localize(new Element("div"));
  const probe = culture.values[KEYS.NotAdvertised];
  for (let turn = 0; turn < 50; turn += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
    if (core.testText(KEYS.NotAdvertised) === probe) {
      return culture.values;
    }
  }
  refuse(
    name,
    "the page's localize() never loaded the catalogue, so nothing below is a reading of it",
  );
  return culture.values;
}

/** Substitutes the row's {value} slot by function, the way i18n.js does, so a value lands verbatim. */
const filled = (row, value) => row.replace(/\{value\}/g, () => value);

function render(result) {
  const container = new Element("div");
  core.renderTestResult(container, result);
  const heading = container.children[0]
    ? container.children[0].textContent
    : null;
  const list = container.children.find((child) => child.tag === "ul");
  const items = list ? list.children.map((item) => item.textContent) : [];
  return { heading, items, listPresent: Boolean(list) };
}

const ISSUER = "https://idp.example.test";
const success = {
  Ok: true,
  Key: KEYS.OidcDiscoveryRead,
  Facts: [
    { Key: KEYS.Issuer, Value: ISSUER },
    { Key: KEYS.UserInfoEndpoint, Value: null },
    { Key: KEYS.JwksReachable, Value: "2" },
    { Key: KEYS.PkceAdvertised, Value: null },
  ],
};
const failure = { Ok: false, Key: KEYS.SamlCertificateUnparsable, Facts: [] };

const seen = {};

for (const name of ["en", "de"]) {
  const rows = await localizeTo(name);

  // ---- Arm: the verdict and every fact are the catalogue's rows, in this language ----
  const { heading, items } = render(success);
  const expectedHeading = "✅ " + rows[KEYS.OidcDiscoveryRead];
  if (heading !== expectedHeading) {
    refuse(
      name + " verdict",
      `the heading reads "${heading}" where the ${name} row is "${expectedHeading}"`,
    );
  }
  const expectedItems = [
    filled(rows[KEYS.Issuer], ISSUER),
    filled(rows[KEYS.UserInfoEndpoint], rows[KEYS.NotAdvertised]),
    filled(rows[KEYS.JwksReachable], "2"),
    rows[KEYS.PkceAdvertised],
  ];
  expectedItems.forEach((expected, index) => {
    if (items[index] !== expected) {
      refuse(
        name + " fact " + index,
        `the row reads "${items[index]}" where the ${name} catalogue gives "${expected}"`,
      );
    }
  });
  if (items.length !== expectedItems.length) {
    refuse(
      name + " facts",
      `${items.length} rows rendered where the result carries ${expectedItems.length} facts`,
    );
  }

  // ---- Arm: a failure is the catalogue's row too, and carries no list ----
  const failed = render(failure);
  if (failed.heading !== "⚠ " + rows[KEYS.SamlCertificateUnparsable]) {
    refuse(
      name + " failure",
      `the heading reads "${failed.heading}" where the ${name} row is "⚠ ${rows[KEYS.SamlCertificateUnparsable]}"`,
    );
  }
  if (failed.listPresent) {
    refuse(name + " failure", "a verdict with no facts rendered a list");
  }

  seen[name] = { heading, items };
}

// ---- Arm: the German is not the English wearing a German catalogue ----
if (seen.en.heading === seen.de.heading) {
  refuse(
    "de differs",
    `the German heading is the English one, "${seen.de.heading}", so the page is not reading the catalogue it was handed`,
  );
}
seen.en.items.forEach((item, index) => {
  if (item === seen.de.items[index]) {
    refuse(
      "de differs",
      `fact ${index} reads "${item}" in both languages, so the row is not the catalogue's`,
    );
  }
});

// ---- Arm: a key this catalogue does not carry renders as itself, never as a blank ----
{
  const { heading } = render({
    Ok: true,
    Key: "test.nobody_declared_this",
    Facts: [],
  });
  if (heading !== "✅ test.nobody_declared_this") {
    refuse(
      "unknown key",
      `an undeclared key rendered as "${heading}" rather than as itself; a missing row must stay visible`,
    );
  }
}

// ---- Arm: a provider value lands verbatim, whatever it contains ----
{
  const rows = culture.values;
  const value = "$& {value} $1 <b>x</b>";
  const { items } = render({
    Ok: true,
    Key: KEYS.OidcDiscoveryRead,
    Facts: [{ Key: KEYS.Issuer, Value: value }],
  });
  const expected = filled(rows[KEYS.Issuer], value);
  if (items[0] !== expected) {
    refuse(
      "verbatim value",
      `a value carrying replacement patterns rendered as "${items[0]}" where it must land as "${expected}"`,
    );
  }
}

if (faults.length) {
  console.error("REFUSED " + faults.join("\n        "));
  process.exit(1);
}

console.log(
  [
    "test verdict:      the shipped renderer run against both catalogues",
    "  en, de           the verdict and every fact are the catalogue's rows, with the value in its slot",
    "  not advertised   a fact without a value reads as the not-advertised row, in that language",
    "  failure          a failed verdict is its row and carries no list",
    "  de differs       every German line differs from its English one",
    "  unknown key      an undeclared key renders as itself, never blank",
    "  verbatim         a provider value lands as sent, replacement patterns included",
  ].join("\n"),
);
