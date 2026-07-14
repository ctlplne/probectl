#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { readFile } from "node:fs/promises";

const JOURNEYS = ["J1", "J2", "J3", "J4", "J5", "J6"];
const PRODUCTS = [
  "Kentik",
  "ThousandEyes",
  "Datadog NPM",
  "Grafana",
  "Auvik",
  "probectl today",
];
const DIMS = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);

const [mode, path] = process.argv.slice(2);
if (!["--structure", "--final"].includes(mode) || !path) {
  fail("usage: check-ux-rubric.mjs {--structure|--final} <markdown>");
}

const markdown = await readFile(path, "utf8");
const rubric = parseRubric(markdown);
validateStructure(rubric);

if (mode === "--final") validateFinalTarget(rubric);

const suffix = mode === "--final" ? " and final target" : "";
console.log(
  `ux-rubric: structure${suffix} OK (6 journeys x 6 products x 10 dimensions)`,
);

function parseRubric(source) {
  const matches = [...source.matchAll(/^###\s+(J[1-6])\b.*$/gm)];
  const result = new Map();
  for (let index = 0; index < matches.length; index += 1) {
    const match = matches[index];
    const id = match[1];
    if (result.has(id)) fail(`duplicate journey heading ${id}`);
    const start = match.index + match[0].length;
    const end =
      index + 1 < matches.length ? matches[index + 1].index : source.length;
    const section = source.slice(start, end);
    result.set(id, parseJourneyTable(id, section));
  }
  return result;
}

function parseJourneyTable(id, section) {
  const lines = section.split(/\r?\n/);
  const headerIndex = lines.findIndex((line) =>
    /^\|\s*Product\s*\|\s*D1\s*\|/.test(line),
  );
  if (headerIndex < 0) fail(`${id}: missing Product/D1-D10 score table`);
  const header = cells(lines[headerIndex]);
  const expectedHeader = ["Product", ...DIMS, "/50"];
  if (JSON.stringify(header) !== JSON.stringify(expectedHeader)) {
    fail(
      `${id}: expected header ${expectedHeader.join(", ")}, got ${header.join(", ")}`,
    );
  }
  const rows = new Map();
  for (const line of lines.slice(headerIndex + 2)) {
    if (!line.trim().startsWith("|")) break;
    const row = cells(line).map(cleanMarkdown);
    if (row.length !== 12)
      fail(`${id}: score row must have product + 10 dimensions + total`);
    const [product, ...values] = row;
    if (rows.has(product)) fail(`${id}: duplicate product ${product}`);
    const scores = values.slice(0, 10).map((value, scoreIndex) => {
      const score = parseInteger(value, `${id}/${product}/${DIMS[scoreIndex]}`);
      if (score < 1 || score > 5)
        fail(
          `${id}/${product}/${DIMS[scoreIndex]}: score ${score} outside 1..5`,
        );
      return score;
    });
    const total = parseInteger(values[10], `${id}/${product}/total`);
    const computed = scores.reduce((sum, value) => sum + value, 0);
    if (total !== computed)
      fail(`${id}/${product}: total ${total} != computed ${computed}`);
    rows.set(product, { scores, total });
  }
  return rows;
}

function validateStructure(rubric) {
  for (const id of JOURNEYS) {
    const rows = rubric.get(id);
    if (!rows) fail(`missing journey ${id}`);
    if (rows.size !== PRODUCTS.length)
      fail(`${id}: expected ${PRODUCTS.length} product rows`);
    for (const product of PRODUCTS) {
      if (!rows.has(product)) fail(`${id}: missing product ${product}`);
    }
    for (const product of rows.keys()) {
      if (!PRODUCTS.includes(product))
        fail(`${id}: unexpected product ${product}`);
    }
  }
  if (rubric.size !== JOURNEYS.length)
    fail(`expected ${JOURNEYS.length} journey tables`);
}

function validateFinalTarget(rubric) {
  let atMax = 0;
  const failures = [];
  for (const id of JOURNEYS) {
    const rows = rubric.get(id);
    const probectl = rows.get("probectl today").total;
    const competitors = PRODUCTS.filter(
      (product) => product !== "probectl today",
    ).map((product) => rows.get(product).total);
    const maximum = Math.max(...competitors);
    const median = [...competitors].sort((a, b) => a - b)[2];
    if (probectl >= maximum) atMax += 1;
    if (probectl < median)
      failures.push(
        `${id}: probectl ${probectl} < competitor median ${median}`,
      );
  }
  if (atMax < 4)
    failures.push(
      `probectl meets competitor maximum on ${atMax}/6 journeys; need >=4`,
    );
  if (failures.length > 0)
    fail(`final target failed:\n- ${failures.join("\n- ")}`);
}

function cells(line) {
  const trimmed = line.trim();
  if (!trimmed.startsWith("|") || !trimmed.endsWith("|")) return [];
  return trimmed
    .slice(1, -1)
    .split("|")
    .map((cell) => cell.trim());
}

function cleanMarkdown(value) {
  return value.replaceAll("**", "").replaceAll("`", "").trim();
}

function parseInteger(value, label) {
  if (!/^\d+$/.test(value))
    fail(`${label}: expected integer, got ${JSON.stringify(value)}`);
  return Number(value);
}

function fail(message) {
  console.error(`ux-rubric: ${message}`);
  process.exit(1);
}
