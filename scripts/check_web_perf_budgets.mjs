#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const receiptPath = join(
  repoRoot,
  "receipts",
  "web-ux",
  "web-performance.json",
);
const expectedJourneys = [
  ["J1", "/onboarding"],
  ["J2", "/incidents"],
  ["J3", "/explore"],
  ["J4", "/path"],
  ["J5", "/admin"],
  ["J6", "/provider"],
];
const RUNS_PER_ROUTE = 5;
const LCP_BUDGET_MS = 2_500;
const INP_BUDGET_MS = 200;

function percentile75(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.ceil(sorted.length * 0.75) - 1];
}

let receipt;
try {
  receipt = JSON.parse(await readFile(receiptPath, "utf8"));
} catch (error) {
  console.error(
    `web performance: cannot read ${receiptPath}; run "npm --prefix web run a11y:browser" first`,
  );
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}

const failures = [...(Array.isArray(receipt.failures) ? receipt.failures : [])];
const fail = (message) => {
  failures.push(message);
  console.error(`web performance: ${message}`);
};

if (receipt.schema !== "probectl.web-performance/v1") {
  fail(`unexpected receipt schema ${JSON.stringify(receipt.schema)}`);
}
if (receipt.profile?.runs_per_route !== RUNS_PER_ROUTE) {
  fail(
    `reference profile must declare ${RUNS_PER_ROUTE} runs, got ${JSON.stringify(receipt.profile?.runs_per_route)}`,
  );
}
const viewport = receipt.profile?.viewport;
if (
  viewport?.name !== "desktop" ||
  viewport?.width !== 1366 ||
  viewport?.height !== 900 ||
  receipt.profile?.theme !== "dark" ||
  receipt.profile?.cache !== "fresh context per run" ||
  receipt.profile?.api !== "local deterministic fixtures"
) {
  fail(
    "reference profile must be desktop 1366x900, dark, fresh-context, and local-fixture",
  );
}

const records = Array.isArray(receipt.journeys) ? receipt.journeys : [];
if (records.length !== expectedJourneys.length) {
  fail(
    `expected exactly ${expectedJourneys.length} J1-J6 route records, found ${records.length}`,
  );
}

for (const [journey, route] of expectedJourneys) {
  const matches = records.filter(
    (record) => record.journey === journey && record.route === route,
  );
  if (matches.length !== 1) {
    fail(
      `${journey} ${route}: expected exactly one record, found ${matches.length}`,
    );
    continue;
  }
  const record = matches[0];
  if (!Array.isArray(record.runs) || record.runs.length !== RUNS_PER_ROUTE) {
    fail(
      `${journey} ${route}: expected ${RUNS_PER_ROUTE} runs, found ${record.runs?.length ?? 0}`,
    );
    continue;
  }

  const runNumbers = new Set(record.runs.map((run) => run.run));
  if (
    runNumbers.size !== RUNS_PER_ROUTE ||
    ![1, 2, 3, 4, 5].every((run) => runNumbers.has(run))
  ) {
    fail(`${journey} ${route}: run identifiers must be exactly 1..5`);
    continue;
  }

  const lcp = record.runs.map((run) => run.lcp_ms);
  const inp = record.runs.map((run) => run.inp_ms);
  if (record.runs.some((run) => run.lcp_supported !== true)) {
    fail(`${journey} ${route}: Chromium LCP observer support is missing`);
  }
  if (record.runs.some((run) => run.event_timing_supported !== true)) {
    fail(`${journey} ${route}: Chromium Event Timing support is missing`);
  }
  if (lcp.some((value) => !Number.isFinite(value) || value <= 0)) {
    fail(
      `${journey} ${route}: all five LCP samples must be finite and positive`,
    );
    continue;
  }
  if (inp.some((value) => !Number.isFinite(value) || value < 0)) {
    fail(
      `${journey} ${route}: all five INP samples must be finite and non-negative`,
    );
    continue;
  }

  record.p75_lcp_ms = percentile75(lcp);
  record.p75_inp_ms = percentile75(inp);
  console.log(
    `${journey} ${route.padEnd(12)} LCP p75 ${record.p75_lcp_ms.toFixed(1).padStart(7)} ms / <${LCP_BUDGET_MS} ms  INP p75 ${record.p75_inp_ms.toFixed(1).padStart(6)} ms / <${INP_BUDGET_MS} ms`,
  );
  if (record.p75_lcp_ms >= LCP_BUDGET_MS) {
    fail(
      `${journey} ${route}: LCP p75 ${record.p75_lcp_ms.toFixed(1)} ms must be <${LCP_BUDGET_MS} ms`,
    );
  }
  if (record.p75_inp_ms >= INP_BUDGET_MS) {
    fail(
      `${journey} ${route}: INP p75 ${record.p75_inp_ms.toFixed(1)} ms must be <${INP_BUDGET_MS} ms`,
    );
  }
}

receipt.budgets = { lcp_p75_ms: LCP_BUDGET_MS, inp_p75_ms: INP_BUDGET_MS };
receipt.failures = [...new Set(failures)];
receipt.status = receipt.failures.length === 0 ? "pass" : "fail";
await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
console.log(`web performance receipt: ${receiptPath}`);

if (receipt.failures.length > 0) process.exit(1);
console.log("web performance: PASS (J1-J6, five deterministic runs each)");
