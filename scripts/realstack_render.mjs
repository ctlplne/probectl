#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Renders one page of a LIVE control plane in a real Chromium for the
// real-stack integration receipts (the rendered-UI legs of capabilities.yaml
// real_stack_proof cells). Unlike scripts/web_rendered_a11y.mjs, which renders
// the bundle against fixtures, this drives the real single-page app the control
// plane serves at /ui/ against its real API, as a signed-in user.
//
// Input (stdin, JSON):
//   { "url": "http://127.0.0.1:PORT/ui/...",
//     "cookies": [{"name": "probectl_session", "value": "..."}],
//     "expect": ["text that must render", ...],
//     "absent": ["text that must NOT render", ...],
//     "steps": [{"click": "accessible name", "role": "button",
//                "expect": ["text that must render after the click"],
//                "gone": true}],
//     "timeoutMs": 30000 }
// A step clicks the ONE element with that role and exact accessible name — an
// ambiguous or missing control fails the step rather than clicking a guess —
// then waits for its expected text and, with "gone", for that control to leave
// the page — the UI re-rendered from the server's answer, so the action took
// effect. The absent texts are checked on the first render and again after the
// last step.
// Output (stdout, JSON): { missing, present, title, url, errors, text }.
// The Go side (internal/testsupport.RenderUI) asserts on it.
//
// Playwright comes from browser-worker's pinned dependency, as in the a11y
// gate. PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH selects a local Chromium when the
// pinned browser is not installed (CI installs it).

import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const bwRequire = createRequire(join(repoRoot, "browser-worker", "package.json"));

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

async function main() {
  const spec = JSON.parse(await readStdin());
  const timeout = spec.timeoutMs ?? 30000;
  const { chromium } = bwRequire("playwright");
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined,
  });
  const result = { missing: [], present: [], title: "", url: "", errors: [], text: "" };
  try {
    const context = await browser.newContext();
    const origin = new URL(spec.url).origin;
    await context.addCookies((spec.cookies ?? []).map((c) => ({ name: c.name, value: c.value, url: origin })));
    const page = await context.newPage();
    page.on("pageerror", (err) => result.errors.push(String(err)));
    await page.goto(spec.url, { waitUntil: "domcontentloaded", timeout });
    const deadline = Date.now() + timeout;
    const remaining = () => Math.max(1000, deadline - Date.now());
    const awaitTexts = async (texts) => {
      for (const want of texts ?? []) {
        try {
          await page.getByText(want, { exact: false }).first().waitFor({ state: "visible", timeout: remaining() });
        } catch {
          result.missing.push(want);
        }
      }
    };
    const absentNow = async () => {
      const text = await page.locator("body").innerText();
      for (const t of spec.absent ?? []) {
        if (text.includes(t) && !result.present.includes(t)) result.present.push(t);
      }
      return text;
    };
    await awaitTexts(spec.expect);
    let body = await absentNow();
    for (const step of spec.steps ?? []) {
      if (result.missing.length > 0) break;
      const control = page.getByRole(step.role ?? "button", { name: step.click, exact: true });
      try {
        await control.click({ timeout: remaining() });
      } catch (err) {
        result.missing.push(`click ${step.role ?? "button"} "${step.click}": ${String(err).split("\n")[0]}`);
        break;
      }
      await awaitTexts(step.expect);
      if (step.gone) {
        try {
          await control.waitFor({ state: "detached", timeout: remaining() });
        } catch {
          result.missing.push(`"${step.click}" was still offered after the click`);
        }
      }
    }
    if ((spec.steps ?? []).length > 0) body = await absentNow();
    result.title = await page.title();
    result.url = page.url();
    result.text = body.slice(0, 6000);
  } finally {
    await browser.close();
  }
  process.stdout.write(JSON.stringify(result));
}

main().catch((err) => {
  process.stderr.write(String(err?.stack ?? err));
  process.exit(2);
});
