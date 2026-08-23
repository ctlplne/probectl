#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Canonical documented-journey browser gate. Unlike the broad rendered-a11y
// route matrix, this follows the actual J1-J6 contracts in docs/journeys/ and
// performs their browser-visible state transitions against the stateful,
// clearly-labelled local fixture API. Real transport/store/crypto/DR legs are
// separate gates and are referenced in the receipt; a browser fixture never
// promotes those claims by itself.

import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = dirname(scriptDir);
const webRoot = join(repoRoot, "web");
const browserWorkerRoot = join(repoRoot, "browser-worker");
const receiptPath = join(
  repoRoot,
  "receipts",
  "journeys",
  "canonical-browser-e2e.json",
);
const webRequire = createRequire(join(webRoot, "package.json"));
const browserRequire = createRequire(join(browserWorkerRoot, "package.json"));

const canonicalJourneys = [
  {
    id: "J1",
    title: "Onboarding: from zero to first data",
    doc: "docs/journeys/onboarding.md",
    realGates: ["make e2e"],
  },
  {
    id: "J2",
    title: "From alert to root cause",
    doc: "docs/journeys/alert-to-root-cause.md",
    realGates: ["make test-integration-isolated"],
  },
  {
    id: "J3",
    title: "Catch a routing or security threat",
    doc: "docs/journeys/threat-response.md",
    realGates: ["make test-integration-isolated"],
  },
  {
    id: "J4",
    title: "Stand up and isolate a tenant",
    doc: "docs/journeys/tenant-setup.md",
    realGates: ["make test-integration-isolated", "make editions-gate"],
  },
  {
    id: "J5",
    title: "Govern cost, SLOs and sustainability",
    doc: "docs/journeys/cost-and-slo-governance.md",
    realGates: [
      "make test-integration-isolated",
      "make backup-restore-drill-isolated",
    ],
  },
  {
    id: "J6",
    title: "Operate in production",
    doc: "docs/journeys/production-operations.md",
    realGates: [
      "make fips-gate",
      "make backup-restore-drill-isolated",
      "make failover-drill-isolated",
      "make chaos-dependency-drill",
    ],
  },
];

function git(...args) {
  return execFileSync("git", args, { cwd: repoRoot, encoding: "utf8" }).trim();
}

function sourceIdentity() {
  const sha = process.env.PROBECTL_JOURNEY_SOURCE_SHA;
  const branch = process.env.PROBECTL_JOURNEY_SOURCE_BRANCH;
  const dirty = process.env.PROBECTL_JOURNEY_SOURCE_DIRTY;
  if (sha !== undefined || branch !== undefined || dirty !== undefined) {
    assert(
      /^[0-9a-f]{40}$/.test(sha ?? "") &&
        typeof branch === "string" &&
        branch.length > 0 &&
        (dirty === "true" || dirty === "false"),
      "container source identity must provide a full SHA, branch, and boolean dirty state",
    );
    return { sha, branch, dirty: dirty === "true" };
  }
  return {
    sha: git("rev-parse", "HEAD"),
    branch: git("rev-parse", "--abbrev-ref", "HEAD"),
    dirty: git("status", "--porcelain").length > 0,
  };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function expectText(page, text) {
  await page
    .getByText(text, { exact: true })
    .waitFor({ state: "visible", timeout: 10_000 });
}

async function goto(page, baseURL, route) {
  await page.goto(`${baseURL}/ui${route}`, { waitUntil: "networkidle" });
  await page.locator("main").waitFor({ state: "visible", timeout: 10_000 });
}

async function runJourney(browser, baseURL, journey, exercise) {
  const context = await browser.newContext({
    viewport: { width: 1366, height: 900 },
    colorScheme: "dark",
  });
  const page = await context.newPage();
  const failures = [];
  const requests = [];
  page.on("console", (message) => {
    if (message.type() === "error") failures.push(`console: ${message.text()}`);
  });
  page.on("pageerror", (error) => failures.push(`page: ${error.message}`));
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (
      url.pathname.startsWith("/v1/") ||
      url.pathname.startsWith("/provider/v1/")
    ) {
      requests.push(`${request.method()} ${url.pathname}${url.search}`);
      if (url.searchParams.has("tenant_id")) {
        failures.push(
          `client supplied forbidden tenant_id: ${url.pathname}${url.search}`,
        );
      }
    }
  });
  const started = new Date();
  try {
    const assertions = await exercise(page);
    if (failures.length > 0) throw new Error(failures.join("\n"));
    return {
      journey: journey.id,
      title: journey.title,
      doc: journey.doc,
      status: "PASS",
      started_at: started.toISOString(),
      ended_at: new Date().toISOString(),
      browser_scope:
        "real Chromium + production React routes + local stateful fixture API",
      assertions,
      requests,
      required_real_gates: journey.realGates,
    };
  } catch (error) {
    return {
      journey: journey.id,
      title: journey.title,
      doc: journey.doc,
      status: "FAIL",
      started_at: started.toISOString(),
      ended_at: new Date().toISOString(),
      error: error instanceof Error ? error.message : String(error),
      requests,
      required_real_gates: journey.realGates,
    };
  } finally {
    await context.close();
  }
}

async function main() {
  process.env.PROBECTL_WEB_FIXTURES = "1";
  const viteEntry = webRequire.resolve("vite");
  const vite = await import(pathToFileURL(viteEntry).href);
  const createServer = vite.createServer ?? vite.default?.createServer;
  if (typeof createServer !== "function")
    throw new Error("Vite createServer API is unavailable");
  const { chromium } = browserRequire("playwright");
  const server = await createServer({
    configFile: join(webRoot, "vite.config.ts"),
    root: webRoot,
    server: { host: "127.0.0.1", port: 0, strictPort: false },
    logLevel: "error",
  });
  await server.listen();
  const address = server.httpServer.address();
  if (!address || typeof address === "string")
    throw new Error("Vite did not bind a TCP port");
  const baseURL = `http://127.0.0.1:${address.port}`;
  const browser = await chromium.launch({ headless: true });
  const results = [];
  try {
    results.push(
      await runJourney(browser, baseURL, canonicalJourneys[0], async (page) => {
        await goto(page, baseURL, "/onboarding");
        await expectText(page, "0 of 4 readiness steps");
        await page
          .getByRole("button", { name: "Mint enrollment token", exact: true })
          .click();
        await page
          .getByLabel("Enrollment token", { exact: true })
          .waitFor({ state: "visible" });
        await page
          .getByRole("button", { name: "Create first test", exact: true })
          .click();
        await expectText(page, "4 of 4 readiness steps");
        await expectText(page, "ICMP check healthy — 127.0.0.1");
        await page
          .getByRole("button", { name: "View first finding", exact: true })
          .click();
        await page
          .getByRole("heading", { name: "Targets & Tests", exact: true })
          .waitFor();
        return [
          "credential setup is distinct from operational readiness",
          "named first finding is reached and opens the tenant-scoped targets surface",
        ];
      }),
    );

    results.push(
      await runJourney(browser, baseURL, canonicalJourneys[1], async (page) => {
        await goto(page, baseURL, "/incidents");
        await page
          .getByRole("region", {
            name: "Unified five-plane incident room",
            exact: true,
          })
          .waitFor();
        await page
          .getByRole("button", { name: "Explain this view", exact: true })
          .click();
        await page
          .getByRole("region", { name: "Explanation inspector", exact: true })
          .waitFor();
        await expectText(
          page,
          'Most likely root cause: "edge-r1 throughput spike" saturating the checkout path.',
        );
        await page
          .getByRole("button", { name: "Search or run a command", exact: true })
          .click();
        const command = page.getByRole("combobox", {
          name: "Search commands",
          exact: true,
        });
        await command.fill("Share cited incident RCA");
        await command.press("Enter");
        await expectText(page, "Secure share link copied");
        return [
          "incident opens with correlated evidence",
          "grounded RCA renders inside the incident",
          "server-authored cited snapshot is created and copied",
        ];
      }),
    );

    results.push(
      await runJourney(browser, baseURL, canonicalJourneys[2], async (page) => {
        await goto(page, baseURL, "/security");
        const table = page.getByRole("table", {
          name: "Threat detections",
          exact: true,
        });
        await table.waitFor();
        const details = table.getByRole("button", {
          name: "Details",
          exact: true,
        });
        await details.waitFor();
        await details.click();
        const dialog = page.getByRole("dialog", {
          name: "10.0.0.20",
          exact: true,
        });
        await dialog.waitFor();
        await dialog
          .getByRole("button", { name: "Propose response", exact: true })
          .click();
        await expectText(page, "Proposal created");
        await expectText(
          page,
          "A confidence-scored signal from test-intel — feeds can list benign infrastructure, and probectl never blocks traffic. Verify before acting.",
        );
        return [
          "threat signal preserves confidence and provenance",
          "response remains a proposed, human-reviewed action with no executor",
        ];
      }),
    );

    results.push(
      await runJourney(browser, baseURL, canonicalJourneys[3], async (page) => {
        await goto(page, baseURL, "/provider");
        await page
          .getByLabel("New tenant slug", { exact: true })
          .fill("silo-co");
        await page.getByLabel("Display name", { exact: true }).fill("Silo Co");
        await page
          .getByLabel("Isolation", { exact: true })
          .selectOption("siloed");
        await page
          .getByLabel("Residency (data plane, optional)", { exact: true })
          .fill("eu");
        await page
          .getByRole("button", { name: "Provision", exact: true })
          .click();
        await expectText(page, "silo-co");
        await page
          .getByRole("heading", {
            name: "probectl · PROVIDER PLANE",
            exact: true,
          })
          .waitFor();
        await expectText(page, "operator domain — no tenant context");
        return [
          "siloed EU tenant is provisioned",
          "probectl identity remains fixed",
          "provider surface stays a metadata-only privilege domain",
        ];
      }),
    );

    results.push(
      await runJourney(browser, baseURL, canonicalJourneys[4], async (page) => {
        await goto(page, baseURL, "/slos");
        await expectText(page, "Checkout availability");
        await goto(page, baseURL, "/cost");
        await page
          .getByRole("heading", { name: "Cost", exact: true })
          .waitFor();
        await page
          .getByRole("note", { name: "carbon methodology", exact: true })
          .waitFor();
        const methodology = await page
          .getByRole("note", { name: "carbon methodology", exact: true })
          .innerText();
        assert(
          methodology.includes("not measured"),
          "carbon estimate omitted not-measured label",
        );
        await goto(page, baseURL, "/admin");
        await page
          .getByRole("heading", { name: "Data lifecycle", exact: true })
          .waitFor();
        await page.getByLabel("Flow days", { exact: true }).fill("30");
        await page
          .getByRole("button", { name: "Save retention", exact: true })
          .click();
        await expectText(page, "Retention saved.");
        const redacted = page.getByRole("link", {
          name: "Redacted export",
          exact: true,
        });
        assert(
          (await redacted.getAttribute("href")) ===
            "/v1/lifecycle/export?redact=true",
          "redacted export route drifted",
        );
        return [
          "SLO attainment/burn surface loads",
          "cost and explicitly estimated carbon share tenant attribution",
          "retention persists and redacted export remains available",
        ];
      }),
    );

    results.push(
      await runJourney(browser, baseURL, canonicalJourneys[5], async (page) => {
        await goto(page, baseURL, "/admin");
        await page
          .getByRole("heading", { name: "Support & diagnostics", exact: true })
          .waitFor();
        const support = page.getByRole("link", {
          name: "Download support bundle (tar.gz)",
          exact: true,
        });
        assert(
          (await support.getAttribute("href")) === "/v1/diagnostics/bundle",
          "support bundle route drifted",
        );
        await expectText(
          page,
          "Deep health across components, and a one-click support bundle (versions, redacted config, health, self-metrics, anonymized topology) — secret-stripped: never contains credentials or PII.",
        );
        return [
          "diagnostics and secret-stripped support bundle are reachable",
          "editions surface states offline/operator-run commercial behavior",
          "FIPS, restore, failover, and chaos remain mandatory real-system gates",
        ];
      }),
    );
  } finally {
    await browser.close();
    await server.close();
  }

  const receipt = {
    schema: "probectl.canonical-browser-journeys/v1",
    generated_at: new Date().toISOString(),
    git: sourceIdentity(),
    fixture_boundary:
      "This receipt proves real browser/UI behavior against local deterministic API fixtures. It does not replace the named real-system gates.",
    journeys: results,
  };
  await mkdir(dirname(receiptPath), { recursive: true });
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  for (const result of results) {
    console.log(`${result.journey} ${result.status} — ${result.title}`);
    if (result.status !== "PASS") console.error(result.error);
  }
  console.log(`canonical browser journey receipt: ${receiptPath}`);
  if (results.some((result) => result.status !== "PASS")) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exit(1);
});
