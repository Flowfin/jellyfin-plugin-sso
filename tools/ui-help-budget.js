#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 iderex

/*
 * Holds every label, help text and error text of both catalogues to the word
 * budgets of the Coding-Standards wiki page (#1901). Hard caps refuse, soft
 * caps report; calibration fixtures run first and stop the run on a mismatch.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CATALOGUES = path.join(HERE, "..", "SSO-Auth", "Localization");

const LABEL_WORDS = 5;
const SHORT_SOFT = 25;
const SHORT_HARD = 40;
const FULL_SOFT = 100;
const FULL_HARD = 120;
const SENTENCE_WORDS = 25;
const ERROR_WORDS = 25;
const RATIO_MIN = 0.8;
const RATIO_MAX = 1.6;
const RATIO_FLOOR = 10;

const LABEL = /_label$/;
const HELP = /_help$/;
const ERROR = /^error\.|_failed$|_refused$/;

// The sentence rule of SSO-Auth/Web/i18n.js, kept identical so the lead
// measured here is the lead the page shows; initials such as `e.g.` do not end one.
const SENTENCE_END = /[.!?](?=\s)/g;
const INITIALS = /^(?:\p{L}\.)*\p{L}$/u;
const WORD_TAIL = /([\p{L}.]*)$/u;

// Splits a text into its sentences by the page's rule.
function sentences(text) {
  const out = [];
  let start = 0;
  SENTENCE_END.lastIndex = 0;
  let match;
  while ((match = SENTENCE_END.exec(text)) !== null) {
    const token = WORD_TAIL.exec(text.slice(0, match.index))[1];
    if (INITIALS.test(token)) {
      continue;
    }
    out.push(text.slice(start, match.index + 1).trim());
    start = match.index + 1;
  }
  const rest = text.slice(start).trim();
  if (rest !== "") {
    out.push(rest);
  }
  return out;
}

// Counts the tokens holding a letter or digit, placeholders excluded.
function words(text) {
  return String(text)
    .replace(/\{\d+\}/g, " ")
    .split(/\s+/)
    .filter((token) => /[\p{L}\p{N}]/u.test(token)).length;
}

// Lowercases a text and drops placeholders, extra spaces and trailing punctuation.
function normalise(text) {
  return String(text)
    .replace(/\{\d+\}/g, " ")
    .replace(/[\s:.]+$/u, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

// Returns the hard and soft findings for one pair of catalogues.
function judge(english, german) {
  const hard = [];
  const soft = [];
  const cultures = [
    ["en", english],
    ["de", german],
  ];
  for (const key of Object.keys(english)) {
    for (const [culture, catalogue] of cultures) {
      const text = catalogue[key];
      if (typeof text !== "string") {
        continue;
      }
      const at = `${culture} ${key}`;
      if (LABEL.test(key) && words(text) > LABEL_WORDS) {
        hard.push(`label ${at}: ${words(text)} words, at most ${LABEL_WORDS}`);
      }
      if (ERROR.test(key) && words(text) > ERROR_WORDS) {
        hard.push(`error ${at}: ${words(text)} words, at most ${ERROR_WORDS}`);
      }
      if (!HELP.test(key)) {
        continue;
      }
      const parts = sentences(text);
      const lead = parts[0] || "";
      const full = words(parts.slice(1).join(" "));
      if (words(lead) > SHORT_HARD) {
        hard.push(`short ${at}: ${words(lead)} words, at most ${SHORT_HARD}`);
      } else if (words(lead) > SHORT_SOFT) {
        soft.push(`short ${at}: ${words(lead)} words, ${SHORT_SOFT} wanted`);
      }
      if (full > FULL_HARD) {
        hard.push(`full ${at}: ${full} words, at most ${FULL_HARD}`);
      } else if (full > FULL_SOFT) {
        soft.push(`full ${at}: ${full} words, ${FULL_SOFT} wanted`);
      }
      parts.forEach((sentence, index) => {
        if (words(sentence) > SENTENCE_WORDS) {
          hard.push(
            `sentence ${at} #${index + 1}: ${words(sentence)} words, at most ${SENTENCE_WORDS}`,
          );
        }
      });
      if (/https?:\/\/|<a\s/iu.test(lead)) {
        hard.push(`link ${at}: the short help carries a link`);
      }
      const label = normalise(catalogue[key.replace(HELP, "_label")] || "");
      if (label.split(" ").length > 1 && normalise(lead).startsWith(label)) {
        hard.push(`repeat ${at}: the short help repeats the label`);
      }
    }
    if (HELP.test(key) && typeof german[key] === "string") {
      const en = words(english[key]);
      const ratio = words(german[key]) / en;
      if (en >= RATIO_FLOOR && (ratio < RATIO_MIN || ratio > RATIO_MAX)) {
        hard.push(
          `ratio ${key}: German is ${ratio.toFixed(2)} of the English, ${RATIO_MIN} to ${RATIO_MAX} allowed`,
        );
      }
    }
  }
  return { hard, soft };
}

// Fixtures with known answers: each arm names the refusal it must produce, or
// `null` where the pair must pass.
const many = (n, word = "word") =>
  Array.from({ length: n }, () => word).join(" ");
const PASSING_EN = {
  "config.a_label": "Follow renames",
  "config.a_help": `Renames the account when the provider does. ${many(20)}. ${many(20)}.`,
  "config.a_failed":
    "Could not save the provider. Reload the page and try again.",
};
const PASSING_DE = {
  "config.a_label": "Umbenennungen nachziehen",
  "config.a_help": `Benennt das Konto um, wenn der Anbieter es tut. ${many(20, "Wort")}. ${many(20, "Wort")}.`,
  "config.a_failed":
    "Der Anbieter konnte nicht gespeichert werden. Laden Sie die Seite neu.",
};
const ARMS = [
  ["passes", null, {}, {}],
  ["label", "label en", { "config.a_label": many(6) }, {}],
  ["error", "error de", {}, { "config.a_failed": many(26) + "." }],
  [
    "short",
    "short en",
    { "config.a_help": many(41) + ". Then more." },
    { "config.a_help": many(41, "Wort") + ". Dann mehr." },
  ],
  [
    "full",
    "full en",
    { "config.a_help": "Lead. " + many(121) + "." },
    { "config.a_help": "Kurz. " + many(121, "Wort") + "." },
  ],
  [
    "sentence",
    "sentence de",
    { "config.a_help": "Lead. " + many(26) + "." },
    { "config.a_help": "Kurz. " + many(26, "Wort") + "." },
  ],
  [
    "link",
    "link en",
    { "config.a_help": "See https://x.example first. Then more." },
    {},
  ],
  [
    "repeat",
    "repeat en",
    { "config.a_help": "Follow renames at the provider. More." },
    {},
  ],
  ["ratio", "ratio", {}, { "config.a_help": "Kurz." }],
  [
    "initials",
    null,
    {
      "config.a_help": `Sends acr values, e.g. an MFA reference. ${many(20)}.`,
    },
    {
      "config.a_help": `Sendet acr-Werte, z. B. einen MFA-Verweis. ${many(20, "Wort")}.`,
    },
  ],
];

// Runs every fixture arm and returns the disagreements.
function calibrate() {
  const faults = [];
  for (const [arm, expected, en, de] of ARMS) {
    const verdict = judge({ ...PASSING_EN, ...en }, { ...PASSING_DE, ...de });
    const found = verdict.hard.filter((line) =>
      line.startsWith(expected + " "),
    );
    if (expected === null && verdict.hard.length > 0) {
      faults.push(
        `${arm}: must pass and was refused: ${verdict.hard.join("; ")}`,
      );
    } else if (expected !== null && found.length !== 1) {
      faults.push(
        `${arm}: expected one refusal '${expected}', got: ${verdict.hard.join("; ") || "none"}`,
      );
    }
  }
  return faults;
}

// Parses one catalogue from the Localization folder.
function read(name) {
  return JSON.parse(fs.readFileSync(path.join(CATALOGUES, name), "utf8"));
}

// Calibrates, then measures both catalogues and exits non-zero on a hard cap.
function main() {
  const faults = calibrate();
  if (faults.length > 0) {
    console.error("ui-help-budget.js disagrees with its own fixtures:");
    faults.forEach((fault) => console.error("  " + fault));
    process.exit(1);
  }
  const negatives = ARMS.filter(([, expected]) => expected !== null).length;
  console.log(
    `calibration:  ${ARMS.length} arms, ${ARMS.length - negatives} that must pass and ${negatives} that must be refused, all as expected`,
  );

  const english = read("en.json");
  const german = read("de.json");
  const keys = Object.keys(english);
  const count = (re) => keys.filter((key) => re.test(key)).length;
  const verdict = judge(english, german);
  console.log(
    `budgets:      ${count(LABEL)} label(s) at most ${LABEL_WORDS} words, ${count(HELP)} help text(s) with a lead of at most ${SHORT_HARD} words, a full text of at most ${FULL_HARD} and sentences of at most ${SENTENCE_WORDS}, ${count(ERROR)} error text(s) at most ${ERROR_WORDS}, German ${RATIO_MIN} to ${RATIO_MAX} of the English from ${RATIO_FLOOR} words`,
  );
  console.log(
    `over the soft caps (${SHORT_SOFT} lead, ${FULL_SOFT} full): ${verdict.soft.length}`,
  );
  verdict.soft.forEach((line) => console.log("  " + line));
  if (verdict.hard.length > 0) {
    console.error(`over a hard cap: ${verdict.hard.length}`);
    verdict.hard.forEach((line) => console.error("  " + line));
    process.exit(1);
  }
  console.log("every key of both catalogues is within its hard cap");
}

main();
