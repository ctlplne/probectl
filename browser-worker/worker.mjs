// probectl browser-worker (S36, F15): a Playwright worker that runs one transaction
// Script in headless Chromium and emits a JSON Result on stdout matching
// internal/browser's model. The Go ExecDriver invokes this (one process per run);
// the Fleet owns concurrency, isolation (it kills the process on timeout), and
// recycling. Full browser rendering: real DOM/paint timings, a resource waterfall
// from Playwright request timings, and a PNG screenshot on failure.
//
// Input  (stdin): the Script JSON (see internal/browser/script.go).
// Output (stdout): the Result JSON (see toWorkerResult in execdriver.go).
import { chromium } from "playwright";

const STEP_TIMEOUT_MS = Number(process.env.PROBECTL_BROWSER_STEP_TIMEOUT_MS || 15000);

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

function targetFor(step, current) {
  return step.url && step.url !== "" ? step.url : current;
}

async function run(script) {
  const started = Date.now();
  const steps = [];
  const waterfall = [];
  let success = true;
  let error = "";

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: false });
  const page = await context.newPage();

  // Resource waterfall from Playwright request timings.
  page.on("response", (resp) => {
    try {
      const req = resp.request();
      const t = req.timing();
      waterfall.push({
        url: resp.url(),
        method: req.method(),
        status: resp.status(),
        start_ms: Math.max(0, Math.round(t.startTime - (started - performance.timeOrigin))),
        dns_ms: ms(t.domainLookupStart, t.domainLookupEnd),
        connect_ms: ms(t.connectStart, t.connectEnd),
        tls_ms: ms(t.secureConnectionStart, t.connectEnd),
        ttfb_ms: ms(t.requestStart, t.responseStart),
        total_ms: ms(t.startTime, t.responseEnd),
        size_bytes: 0,
      });
    } catch {
      /* a response without timing (cached/data:) — skip it */
    }
  });

  let current = script.start_url || "";
  let lastStatus = 0;

  for (const step of script.steps) {
    const t0 = Date.now();
    let ok = true;
    let detail = "";
    try {
      switch (step.action) {
        case "goto": {
          current = targetFor(step, current);
          const resp = await page.goto(current, { timeout: STEP_TIMEOUT_MS, waitUntil: "load" });
          lastStatus = resp ? resp.status() : 0;
          detail = String(lastStatus);
          break;
        }
        case "fill":
          await page.fill(selectorFor(step), step.value || "", { timeout: STEP_TIMEOUT_MS });
          detail = "filled";
          break;
        case "click":
        case "submit":
          if (step.selector) {
            await Promise.all([
              page.waitForLoadState("load").catch(() => {}),
              page.click(step.selector, { timeout: STEP_TIMEOUT_MS }),
            ]);
          } else {
            await page.keyboard.press("Enter");
            await page.waitForLoadState("load").catch(() => {});
          }
          detail = "submitted";
          break;
        case "assert_text":
        case "wait_text": {
          await page.getByText(step.value, { exact: false }).first().waitFor({ timeout: STEP_TIMEOUT_MS });
          detail = "found";
          break;
        }
        case "assert_status":
          ok = lastStatus === step.status;
          detail = `status ${lastStatus} (want ${step.status})`;
          break;
        case "screenshot":
          detail = "captured";
          break;
        default:
          ok = false;
          detail = `unknown action ${step.action}`;
      }
    } catch (e) {
      ok = false;
      detail = String(e && e.message ? e.message : e);
    }

    steps.push({ name: step.name || "", action: step.action, success: ok, duration_ms: Date.now() - t0, detail });
    if (!ok && !step.optional) {
      success = false;
      error = `step "${step.name || step.action}" (${step.action}): ${detail}`;
      break;
    }
  }

  const dom = await readDOMTimings(page).catch(() => ({}));

  let screenshotB64 = "";
  if (!success) {
    try {
      const png = await page.screenshot({ fullPage: true });
      screenshotB64 = png.toString("base64");
    } catch {
      /* page may be gone */
    }
  }

  await browser.close();

  return {
    success,
    error,
    total_ms: Date.now() - started,
    steps,
    waterfall,
    dom,
    screenshot_b64: screenshotB64,
    screenshot_content_type: screenshotB64 ? "image/png" : "",
  };
}

function selectorFor(step) {
  if (step.selector && step.selector !== "") return step.selector;
  return `[name="${step.field}"]`;
}

function ms(start, end) {
  if (!start || !end || end < start) return 0;
  return Math.round(end - start);
}

async function readDOMTimings(page) {
  return page.evaluate(() => {
    const nav = performance.getEntriesByType("navigation")[0] || {};
    const paints = {};
    for (const p of performance.getEntriesByType("paint")) paints[p.name] = Math.round(p.startTime);
    return {
      dom_content_loaded_ms: Math.round(nav.domContentLoadedEventEnd || 0),
      load_ms: Math.round(nav.loadEventEnd || 0),
      first_paint_ms: paints["first-paint"] || 0,
      first_contentful_paint_ms: paints["first-contentful-paint"] || 0,
    };
  });
}

(async () => {
  try {
    const input = await readStdin();
    const script = JSON.parse(input);
    const result = await run(script);
    process.stdout.write(JSON.stringify(result));
  } catch (e) {
    process.stdout.write(JSON.stringify({ success: false, error: String(e && e.message ? e.message : e), steps: [], waterfall: [] }));
    process.exitCode = 1;
  }
})();
