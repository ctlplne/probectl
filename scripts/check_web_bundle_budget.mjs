#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const distRoot = join(repoRoot, "web", "dist");
const manifestPath = join(distRoot, ".vite", "manifest.json");
const receiptPath = join(repoRoot, "receipts", "web-ux", "bundle-budget.json");

// X16 canonical ceilings. A receipt cannot raise these values: changing a
// ceiling requires changing this reviewed enforcement code and its docs.
const MAIN_BUDGET_BYTES = 250 * 1024;
const ROUTE_BUDGET_BYTES = 150 * 1024;

const receipt = {
  schema: "probectl.web-bundle-budget/v1",
  generated_at: new Date().toISOString(),
  manifest: "web/dist/.vite/manifest.json",
  budgets: {
    initial_gzip_bytes: MAIN_BUDGET_BYTES,
    lazy_route_gzip_bytes: ROUTE_BUDGET_BYTES,
  },
  initial: [],
  lazy_routes: [],
  failures: [],
};

function fail(message) {
  receipt.failures.push(message);
  console.error(`bundle budget: ${message}`);
}

async function measure(records, destination, budget, label) {
  for (const [source, item] of records) {
    const bytes = await readFile(join(distRoot, item.file));
    const gzipBytes = gzipSync(bytes, { level: 9 }).byteLength;
    const record = { source, file: item.file, gzip_bytes: gzipBytes };
    destination.push(record);
    console.log(
      `${label.padEnd(5)} ${(gzipBytes / 1024).toFixed(1).padStart(7)} KiB gz / ${budget / 1024} KiB  ${source}`,
    );
    if (gzipBytes > budget) {
      fail(
        `${source} is ${(gzipBytes / 1024).toFixed(1)} KiB gzip; ceiling is ${budget / 1024} KiB`,
      );
    }
  }
}

try {
  let manifest;
  try {
    manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  } catch (error) {
    throw new Error(
      `cannot read ${manifestPath}; run "npm --prefix web run build" first: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const entries = Object.entries(manifest).filter(([, item]) =>
    item.file?.endsWith(".js"),
  );
  const initial = entries.filter(([, item]) => item.isEntry);
  const lazyRoutes = entries.filter(([, item]) => item.isDynamicEntry);

  if (initial.length !== 1) {
    fail(`expected exactly one JavaScript app entry, found ${initial.length}`);
  }
  if (lazyRoutes.length === 0) {
    fail(
      "found no dynamic route entries; route-level code splitting regressed",
    );
  }

  await measure(initial, receipt.initial, MAIN_BUDGET_BYTES, "main");
  await measure(lazyRoutes, receipt.lazy_routes, ROUTE_BUDGET_BYTES, "route");
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
} finally {
  receipt.status = receipt.failures.length === 0 ? "pass" : "fail";
  await mkdir(dirname(receiptPath), { recursive: true });
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(`bundle budget receipt: ${receiptPath}`);
}

if (receipt.failures.length > 0) process.exit(1);
console.log(
  `bundle budget: PASS (${receipt.initial.length} initial, ${receipt.lazy_routes.length} lazy routes)`,
);
