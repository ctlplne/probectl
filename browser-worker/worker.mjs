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
import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { BlockList, isIP } from "node:net";

const STEP_TIMEOUT_MS = Number(process.env.PROBECTL_BROWSER_STEP_TIMEOUT_MS || 15000);
const ALLOW_PRIVATE_TARGETS = process.env.PROBECTL_BROWSER_ALLOW_PRIVATE_TARGETS === "true";
const MAX_RESOURCE_BYTES = 16 * 1024 * 1024;

const deniedIPv4 = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
  ["224.0.0.0", 4],
]) deniedIPv4.addSubnet(network, prefix);
deniedIPv4.addAddress("255.255.255.255");

const deniedIPv6 = new BlockList();
deniedIPv6.addAddress("::", "ipv6");
deniedIPv6.addAddress("::1", "ipv6");
deniedIPv6.addSubnet("fc00::", 7, "ipv6");
deniedIPv6.addSubnet("fe80::", 10, "ipv6");
deniedIPv6.addSubnet("ff00::", 8, "ipv6");

function mappedIPv4(address) {
  const lower = address.toLowerCase();
  if (!lower.startsWith("::ffff:")) return "";
  const tail = lower.slice("::ffff:".length);
  if (isIP(tail) === 4) return tail;
  const words = tail.split(":");
  if (words.length !== 2) return "";
  const hi = Number.parseInt(words[0], 16);
  const lo = Number.parseInt(words[1], 16);
  if (!Number.isInteger(hi) || !Number.isInteger(lo) || hi < 0 || hi > 0xffff || lo < 0 || lo > 0xffff) return "";
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

function targetDenied(address, family) {
  if (ALLOW_PRIVATE_TARGETS) return false;
  const unzoned = address.split("%")[0];
  const mapped = mappedIPv4(unzoned);
  if (mapped) return deniedIPv4.check(mapped, "ipv4");
  return family === 6
    ? deniedIPv6.check(unzoned, "ipv6")
    : deniedIPv4.check(unzoned, "ipv4");
}

async function checkedAddresses(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "");
  const literalFamily = isIP(host);
  const addresses = literalFamily
    ? [{ address: host, family: literalFamily }]
    : await lookup(host, { all: true, verbatim: true });
  if (addresses.length === 0) throw new Error(`SSRF guard: ${host} resolved to no addresses`);
  for (const item of addresses) {
    if (targetDenied(item.address, item.family)) {
      throw new Error(`SSRF guard denied ${host} -> ${item.address}`);
    }
  }
  return addresses;
}

function fixedLookup(addresses) {
  return (_hostname, options, callback) => {
    if (typeof options === "object" && options.all) {
      callback(null, addresses);
      return;
    }
    callback(null, addresses[0].address, addresses[0].family);
  };
}

function responseHeaders(headers) {
  const out = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value == null || ["connection", "content-length", "transfer-encoding"].includes(name)) continue;
    out[name] = Array.isArray(value) ? value.join(name === "set-cookie" ? "\n" : ", ") : String(value);
  }
  return out;
}

async function fetchGuarded(route) {
  const request = route.request();
  const target = new URL(request.url());
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    await route.abort("blockedbyclient");
    return;
  }
  const addresses = await checkedAddresses(target.hostname);
  const transport = target.protocol === "https:" ? https : http;
  const headers = { ...request.headers(), host: target.host };
  delete headers.connection;
  delete headers["proxy-connection"];

  const response = await new Promise((resolve, reject) => {
    const upstream = transport.request(target, {
      method: request.method(),
      headers,
      lookup: fixedLookup(addresses),
      ...(target.protocol === "https:" ? { servername: target.hostname.replace(/^\[|\]$/g, "") } : {}),
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_RESOURCE_BYTES) {
          res.destroy(new Error(`browser resource exceeds ${MAX_RESOURCE_BYTES} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => resolve({
        status: res.statusCode || 502,
        headers: responseHeaders(res.headers),
        body: Buffer.concat(chunks),
      }));
      res.on("error", reject);
    });
    upstream.on("error", reject);
    const body = request.postDataBuffer();
    if (body) upstream.write(body);
    upstream.end();
  });
  await route.fulfill(response);
}

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
  const context = await browser.newContext({ ignoreHTTPSErrors: false, serviceWorkers: "block" });
  const page = await context.newPage();
  await page.route("**/*", async (route) => {
    try {
      await fetchGuarded(route);
    } catch (err) {
      process.stderr.write(`browser target blocked: ${String(err && err.message ? err.message : err)}\n`);
      await route.abort("blockedbyclient").catch(() => {});
    }
  });
  if (typeof page.routeWebSocket === "function") {
    await page.routeWebSocket("**/*", (socket) => socket.close());
  }

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
