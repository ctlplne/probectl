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
//                "gone": true, "vanish": "another control's name"},
//               {"fill": "#css-selector", "value": "typed text"},
//               {"select": "css-selector of a <select>", "value": "option value"}],
//     "controls": [{"role": "button", "name": "accessible name"}],
//     "trustCertFiles": ["/path/to/server-leaf.pem"],
//     "timeoutMs": 30000 }
// A step clicks the ONE element with that role and exact accessible name — an
// ambiguous or missing control fails the step rather than clicking a guess —
// then waits for its expected text and, with "gone", for that control to leave
// the page — the UI re-rendered from the server's answer, so the action took
// effect; "vanish" waits the same way for another control (say, the row
// action a confirm dialog completes). A "fill" step types into the ONE
// element its CSS selector matches (a
// third-party form such as an IdP login page); a "select" step chooses the
// option with that value in the ONE <select> its selector matches. "controls" must be visible by
// role and exact accessible name after the last step. The absent texts are
// checked on the first render and again after the last step.
// "trustCertFiles" are the leaf certificates of HTTPS servers under a
// throwaway test CA (an HTTPS control plane, an IdP): the browser trusts their
// public keys outright (--ignore-certificate-errors-spki-list), so every
// handshake verifies on its first attempt. (Ignoring certificate errors
// instead makes Chromium fail and retry each new connection, which under load
// ends in ERR_TOO_MANY_RETRIES.) It never changes what the control plane
// itself verifies.
// Output (stdout, JSON): { missing, present, title, url, errors, text, cookies }.
// The Go side (internal/testsupport.RenderUI) asserts on it.
//
// Playwright comes from browser-worker's pinned dependency, as in the a11y
// gate. PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH selects a local Chromium when the
// pinned browser is not installed (CI installs it).

import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
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
  const pinned = (spec.trustCertFiles ?? []).map((file) =>
    createHash("sha256")
      .update(new X509Certificate(readFileSync(file)).publicKey.export({ type: "spki", format: "der" }))
      .digest("base64"),
  );
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined,
    args: pinned.length > 0 ? [`--ignore-certificate-errors-spki-list=${pinned.join(",")}`] : [],
  });
  const result = { missing: [], present: [], title: "", url: "", errors: [], text: "", cookies: [] };
  try {
    const context = await browser.newContext();
    const origin = new URL(spec.url).origin;
    await context.addCookies((spec.cookies ?? []).map((c) => ({ name: c.name, value: c.value, url: origin })));
    const page = await context.newPage();
    page.on("pageerror", (err) => result.errors.push(String(err)));
    page.on("requestfailed", (req) => result.errors.push(`request failed: ${req.url()} ${req.failure()?.errorText ?? ""}`));
    page.on("response", (resp) => {
      if (resp.status() >= 400) result.errors.push(`HTTP ${resp.status()}: ${resp.url()}`);
    });
    await page.goto(spec.url, { waitUntil: "domcontentloaded", timeout });
    const deadline = Date.now() + timeout;
    const remaining = () => Math.max(1000, deadline - Date.now());
    const awaitTexts = async (texts) => {
      for (const want of texts ?? []) {
        try {
          // Any visible match counts: the first in DOM order may be hidden
          // (a closed <select>'s option), which is not a missing text.
          await page.getByText(want, { exact: false }).filter({ visible: true }).first()
            .waitFor({ state: "visible", timeout: remaining() });
        } catch {
          result.missing.push(want);
        }
      }
    };
    // A login lands through redirects and client-side routing, so a read can
    // race a navigation ("execution context was destroyed"): retry it briefly.
    // A read that still fails is recorded and yields the fallback, so the
    // result (and why it failed) is always reported.
    const settled = async (read, fallback) => {
      for (let attempt = 0; ; attempt++) {
        try {
          return await read();
        } catch (err) {
          if (attempt >= 10 || page.isClosed()) {
            result.errors.push(`page read failed: ${String(err).split("\n")[0]}`);
            return fallback;
          }
          await new Promise((resolve) => setTimeout(resolve, 250));
        }
      }
    };
    const absentNow = async () => {
      const text = await settled(() => page.locator("body").innerText({ timeout: remaining() }), "");
      for (const t of spec.absent ?? []) {
        if (text.includes(t) && !result.present.includes(t)) result.present.push(t);
      }
      return text;
    };
    await awaitTexts(spec.expect);
    let body = await absentNow();
    for (const step of spec.steps ?? []) {
      if (result.missing.length > 0) break;
      if (step.fill) {
        try {
          await page.locator(step.fill).fill(step.value ?? "", { timeout: remaining() });
        } catch (err) {
          result.missing.push(`fill "${step.fill}": ${String(err).split("\n")[0]}`);
          break;
        }
        continue;
      }
      if (step.select) {
        try {
          await page.locator(step.select).selectOption(step.value ?? "", { timeout: remaining() });
        } catch (err) {
          result.missing.push(`select "${step.select}": ${String(err).split("\n")[0]}`);
          break;
        }
        continue;
      }
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
      if (step.vanish) {
        try {
          await page
            .getByRole(step.role ?? "button", { name: step.vanish, exact: true })
            .waitFor({ state: "detached", timeout: remaining() });
        } catch {
          result.missing.push(`"${step.vanish}" was still offered after clicking "${step.click}"`);
        }
      }
    }
    for (const c of spec.controls ?? []) {
      if (result.missing.length > 0) break;
      try {
        await page.getByRole(c.role, { name: c.name, exact: true }).first().waitFor({ state: "visible", timeout: remaining() });
      } catch {
        result.missing.push(`${c.role} "${c.name}"`);
      }
    }
    if ((spec.steps ?? []).length > 0 || (spec.controls ?? []).length > 0) body = await absentNow();
    result.title = await settled(() => page.title(), "");
    result.url = page.url();
    result.text = body.slice(0, 6000);
    result.cookies = (await settled(() => context.cookies(), [])).map(({ name, value, domain, path }) => ({ name, value, domain, path }));
  } finally {
    await browser.close();
  }
  process.stdout.write(JSON.stringify(result));
}

main().catch((err) => {
  process.stderr.write(String(err?.stack ?? err));
  process.exit(2);
});
