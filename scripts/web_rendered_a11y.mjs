#!/usr/bin/env node
// Real-browser frontend a11y gate (PRODUCT-001).
//
// This deliberately reuses the already-pinned browser-worker Playwright
// dependency instead of adding a second browser stack to web/. The check runs
// the real Vite app in Chromium, injects local API responses, then verifies:
// axe WCAG tags (including browser-computed color contrast), no positive
// tabindex, minimum interactive target size, visible keyboard focus, and
// focus-not-obscured for each native surface route under each shipped theme.

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = dirname(scriptDir);
const webRoot = join(repoRoot, "web");
const browserWorkerRoot = join(repoRoot, "browser-worker");
const themes = ["dark", "aurora"];
const viewport = { width: 1366, height: 900 };

const bwRequire = createRequire(join(browserWorkerRoot, "package.json"));
const webRequire = createRequire(join(webRoot, "package.json"));

function requireExistingPlaywright() {
  try {
    return bwRequire("playwright");
  } catch (err) {
    throw new Error(
      `browser-worker Playwright dependency is not installed. Run: npm --prefix ${browserWorkerRoot} ci --no-audit --no-fund\n${err}`,
    );
  }
}

async function loadVite() {
  const vitePackage = webRequire.resolve("vite/package.json");
  return import(
    pathToFileURL(join(dirname(vitePackage), "dist/node/index.js")).href
  );
}

async function loadReactPlugin() {
  const pluginPath = webRequire.resolve("@vitejs/plugin-react");
  const mod = await import(pathToFileURL(pluginPath).href);
  return mod.default;
}

async function nativeRoutes() {
  const src = await readFile(join(webRoot, "src/surfaces.ts"), "utf8");
  const routes = new Set();
  for (const match of src.matchAll(/\{[\s\S]*?\n  \}/g)) {
    const block = match[0];
    if (!/kind:\s*'native'/.test(block)) continue;
    const route = block.match(/route:\s*'([^']+)'/);
    if (route) routes.add(route[1]);
  }
  if (routes.size === 0)
    throw new Error("no native routes found in web/src/surfaces.ts");
  return [...routes].sort();
}

function json(body, status = 200) {
  return { status, body };
}

function apiPayload(path, method) {
  const operator = {
    id: "op_1",
    email: "root@msp.example",
    name: "Root",
    role: "admin",
    status: "active",
    enrolled: true,
  };
  const tenants = [
    {
      id: "tn_1",
      slug: "acme",
      name: "Acme Industries",
      status: "active",
      isolation_model: "pooled",
      created_at: "2026-06-01T00:00:00Z",
    },
    {
      id: "tn_2",
      slug: "globex",
      name: "Globex",
      status: "suspended",
      isolation_model: "siloed",
      residency: "eu",
      created_at: "2026-06-02T00:00:00Z",
    },
  ];
  const sampleTests = [
    {
      id: "t1",
      name: "edge-dns",
      type: "dns",
      target: "1.1.1.1",
      interval_seconds: 30,
      timeout_seconds: 3,
      params: {},
      enabled: true,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    },
  ];
  const sampleAgents = [
    {
      id: "a1",
      name: "agent-1",
      hostname: "host-a",
      agent_version: "0.1.0",
      status: "online",
      capabilities: ["icmp", "tcp"],
    },
  ];

  if (path === "/v1/me")
    return json({
      tenant_id: "00000000-0000-0000-0000-000000000001",
      user_id: "u_test",
      email: "operator@probectl.test",
      display_name: "Test Operator",
      mfa_satisfied: true,
      permissions: [],
    });
  if (path === "/v1/tests") return json({ items: sampleTests });
  if (path === "/v1/agents") return json({ items: sampleAgents });
  if (path === "/v1/ai/discover") return json({ proposals: [] });
  if (path === "/v1/alerts") return json({ items: [] });
  if (path === "/v1/alerts/active")
    return json({ items: [], evaluator_running: true });
  if (path === "/v1/tls/posture")
    return json({ items: [], collector_running: true });
  if (path === "/v1/threat/detections")
    return json({ items: [], detections_running: true });
  if (path === "/v1/endpoints")
    return json({ items: [], collector_running: true });
  if (path === "/v1/results/latest")
    return json({ items: [], collector_running: true });
  if (path === "/v1/topology")
    return json({
      topology_running: true,
      at: "2026-06-04T12:00:00Z",
      nodes: [],
      edges: [],
      coverage: {
        path_edges: 0,
        flow_edges: 0,
        routing_edges: 0,
        device_edges: 0,
      },
    });
  if (path === "/v1/cost/summary")
    return json({
      cost_running: true,
      summary: {
        priced: true,
        zones_mapped: true,
        pricing_source: "test",
        pricing_as_of: "2026-06-01",
        total_bytes: 0,
        total_usd: 0,
        by_class: {},
        by_service: {},
        by_team: {},
        chatty_pairs: [],
        trend: [],
        budgets: [],
      },
    });
  if (path === "/v1/slos") return json({ slo_running: true, items: [] });
  if (path === "/v1/compliance")
    return json({
      compliance_running: true,
      items: [],
      coverage: {
        flow_observed: false,
        ebpf_observed: false,
        observations: 0,
        zones_seen: 0,
        zones_total: 0,
        notes: [],
      },
    });
  if (path === "/v1/outages")
    return json({
      outage_running: true,
      feeds_enabled: false,
      scope_resolution: false,
      events: [],
      vantage_events: [],
      coverage_notes: [
        "coverage = your vantage points + public open-data feeds -- probectl does not operate a global probe fleet",
      ],
    });
  if (path === "/v1/rum") return json({ rum_running: false });
  if (path === "/v1/carbon") return json({ carbon_running: false });
  if (path === "/v1/secrets/health")
    return json({
      resolver_running: true,
      backends: [
        {
          scheme: "env",
          configured: true,
          resolves: 0,
          failures: 0,
          cached_leases: 0,
        },
      ],
    });
  if (path === "/v1/directory/scim-tokens") return json({ items: [] });
  if (path === "/v1/abac/policies") return json({ items: [] });
  if (path === "/v1/diagnostics")
    return json({
      status: "degraded",
      checked_at: "2026-06-06T00:00:00Z",
      checks: [{ name: "database", status: "ok" }],
    });
  if (path === "/branding") return json({ product_name: "probectl" });
  if (path === "/v1/security/keys")
    return json({ error: { message: "not found" } }, 404);
  if (path === "/v1/lifecycle/retention")
    return json({ flow_retention_days: null, isolation_model: "pooled" });
  if (path === "/v1/editions")
    return json({
      tier: "community",
      state: "community",
      features: [
        { name: "fips", tier: "enterprise", licensed: false, mode: "off" },
        { name: "byok", tier: "enterprise", licensed: false, mode: "off" },
        {
          name: "governance",
          tier: "enterprise",
          licensed: false,
          mode: "off",
        },
        {
          name: "remediation",
          tier: "enterprise",
          licensed: false,
          mode: "off",
        },
        {
          name: "provider_plane",
          tier: "provider",
          licensed: false,
          mode: "off",
        },
      ],
    });

  if (path === "/provider/v1/me") return json({ operator });
  if (path === "/provider/v1/license")
    return json({
      tier: "provider",
      state: "active",
      customer: "MSP Test GmbH",
      tenant_band: 25,
    });
  if (path === "/provider/v1/tenants" && method === "GET")
    return json({ items: tenants });
  if (path === "/provider/v1/fleet")
    return json({
      items: [
        {
          tenant_id: "tn_1",
          tenant_slug: "acme",
          tenant_name: "Acme Industries",
          tenant_status: "active",
          agents_total: 3,
          agents_online: 2,
          agents_stale: 1,
          versions: { "0.3.0": 3 },
        },
      ],
    });
  if (path === "/provider/v1/breakglass")
    return json({
      items: [
        {
          id: "bg_1",
          operator_email: "root@msp.example",
          tenant_id: "tn_1",
          reason: "incident #42",
          scope: "read",
          expires_at: "2026-06-05T12:00:00Z",
          use_count: 2,
          state: "active",
        },
      ],
    });
  if (path === "/provider/v1/operators") return json({ items: [operator] });
  if (path === "/provider/v1/fairness")
    return json({
      items: [
        {
          tenant_id: "tn_1",
          policy: {
            results_per_sec: 100,
            queries_per_min: 60,
            burst_seconds: 10,
          },
          ingest: {},
          queries: {
            allowed: 50,
            rejected_concurrency: 0,
            rejected_budget: 13,
            in_flight: 1,
          },
        },
      ],
      overrides: {},
    });
  if (path.includes("/provider/v1/usage"))
    return json({
      items: [
        {
          tenant_id: "tn_1",
          tenant_slug: "acme",
          meter: "results_ingested",
          kind: "counter",
          period_start: "2026-06-05T00:00:00Z",
          period_end: "2026-06-06T00:00:00Z",
          value: 1042,
          unit: "count",
        },
      ],
      meters: [
        "agents",
        "tests",
        "results_ingested",
        "ingest_bytes",
        "flow_events",
        "ai_calls",
      ],
    });
  if (path.includes("/provider/v1/tenants/tn_1/governance"))
    return json({
      classifications: {
        ip_address: "pii",
        hostname: "internal",
        credential: "restricted",
        email: "pii",
        asn: "public",
      },
      redact_from: "pii",
      redact_export: false,
      residency: "eu",
      isolation_model: "siloed",
      retention_days: 30,
      byok: "byok",
    });
  if (path === "/provider/v1/branding") return json({ product_name: "" });
  return json({ error: { code: "not_found", message: "not found" } }, 404);
}

function fetchStubSource(theme) {
  return `(() => {
    const theme = ${JSON.stringify(theme)};
    localStorage.setItem('probectl.theme', theme);
    const json = (body, status = 200) => ({ status, body });
    const payloads = ${apiPayload.toString()};
    const respond = ({ status, body }) => new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
    window.fetch = async (input, init = {}) => {
      const method = String(init.method || 'GET').toUpperCase();
      const url = new URL(String(input), location.origin);
      if (url.pathname.includes('/v1/v1')) throw new Error('double /v1 prefix: ' + url.pathname);
      return respond(payloads(url.pathname, method));
    };
  })();`;
}

async function startVite() {
  const { createServer } = await loadVite();
  const react = await loadReactPlugin();
  const server = await createServer({
    configFile: false,
    root: webRoot,
    plugins: [react()],
    resolve: { alias: { "@ee": join(repoRoot, "ee/web") } },
    server: { host: "127.0.0.1", port: 0, strictPort: false, proxy: {} },
    logLevel: "error",
  });
  await server.listen();
  const baseURL = server.resolvedUrls?.local?.[0];
  if (!baseURL) throw new Error("vite did not report a local URL");
  return { server, baseURL: baseURL.replace(/\/$/, "") };
}

async function runAxe(page, axeSource) {
  await page.addScriptTag({ content: axeSource });
  return page.evaluate(async () => {
    return await globalThis.axe.run(document, {
      runOnly: {
        type: "tag",
        values: [
          "wcag2a",
          "wcag2aa",
          "wcag21a",
          "wcag21aa",
          "wcag22aa",
          "best-practice",
        ],
      },
    });
  });
}

function formatAxe(violations) {
  return violations
    .map((v) => {
      const nodes = v.nodes
        .slice(0, 4)
        .map(
          (n) =>
            `      ${n.target.join(", ")} :: ${n.failureSummary?.trim() ?? v.help}`,
        )
        .join("\n");
      return `  ${v.id}: ${v.help}\n${nodes}`;
    })
    .join("\n");
}

function blockingAxeResults(result) {
  return [
    ...result.violations,
    ...result.incomplete.filter((v) => v.id === "color-contrast"),
  ];
}

async function targetAndTabChecks(page) {
  return page.evaluate(() => {
    const selector = [
      "a[href]",
      "button:not([disabled])",
      "input:not([disabled])",
      "select:not([disabled])",
      "textarea:not([disabled])",
      '[tabindex]:not([tabindex="-1"])',
    ].join(",");
    const isVisible = (el) => {
      const r = el.getBoundingClientRect();
      const style = getComputedStyle(el);
      return (
        r.width > 0 &&
        r.height > 0 &&
        style.visibility !== "hidden" &&
        style.display !== "none"
      );
    };
    const label = (el) =>
      [
        el.tagName.toLowerCase(),
        el.id ? `#${el.id}` : "",
        el.getAttribute("aria-label")
          ? `[aria-label="${el.getAttribute("aria-label")}"]`
          : "",
        el.textContent?.trim()
          ? ` "${el.textContent.trim().slice(0, 48)}"`
          : "",
      ].join("");
    const focusVisible = (el) => {
      const style = getComputedStyle(el);
      const outline =
        Number.parseFloat(style.outlineWidth || "0") > 0 &&
        style.outlineStyle !== "none";
      return outline || style.boxShadow !== "none";
    };
    const unobscured = (el) => {
      const r = el.getBoundingClientRect();
      const x = Math.min(
        Math.max(r.left + r.width / 2, 0),
        window.innerWidth - 1,
      );
      const y = Math.min(
        Math.max(r.top + r.height / 2, 0),
        window.innerHeight - 1,
      );
      const top = document.elementFromPoint(x, y);
      return !top || top === el || el.contains(top) || top.contains(el);
    };

    const problems = [];
    const elements = [...document.querySelectorAll(selector)].filter(isVisible);
    for (const el of elements) {
      const tabIndex = Number(el.getAttribute("tabindex") || "0");
      if (tabIndex > 0)
        problems.push(`${label(el)} uses positive tabindex=${tabIndex}`);
      const r = el.getBoundingClientRect();
      if (r.width < 24 || r.height < 24) {
        problems.push(
          `${label(el)} target is ${Math.round(r.width)}x${Math.round(r.height)}px`,
        );
      }
      el.focus({ preventScroll: false });
      if (
        document.activeElement !== el &&
        !el.contains(document.activeElement)
      ) {
        problems.push(`${label(el)} cannot receive focus`);
        continue;
      }
      if (!focusVisible(el))
        problems.push(`${label(el)} has no visible focus indicator`);
      if (!unobscured(el))
        problems.push(
          `${label(el)} focus target is obscured at its center point`,
        );
    }
    return problems;
  });
}

async function selfCheck(browser, axeSource) {
  const page = await browser.newPage({ viewport });
  await page.setContent(`
    <main>
      <button style="color:#777;background:#777;border:0">Bad contrast</button>
      <button id="tiny" style="width:10px;height:10px;padding:0">T</button>
    </main>
  `);
  const axe = await runAxe(page, axeSource);
  if (!blockingAxeResults(axe).some((v) => v.id === "color-contrast")) {
    throw new Error(
      "self-check failed: axe did not catch a deliberate color-contrast failure",
    );
  }
  const custom = await targetAndTabChecks(page);
  if (!custom.some((p) => p.includes("target is"))) {
    throw new Error(
      "self-check failed: target-size check did not catch a deliberate tiny control",
    );
  }
  await page.close();
}

async function main() {
  const axePath = join(webRoot, "node_modules/axe-core/axe.min.js");
  if (!existsSync(axePath)) {
    throw new Error(
      `axe-core is not installed at ${axePath}; run npm ci in web/ first`,
    );
  }
  const axeSource = await readFile(axePath, "utf8");
  const { chromium } = requireExistingPlaywright();
  const browser = await chromium.launch({ headless: true });
  const routes = await nativeRoutes();
  const { server, baseURL } = await startVite();
  const failures = [];

  try {
    await selfCheck(browser, axeSource);
    for (const theme of themes) {
      const context = await browser.newContext({
        viewport,
        colorScheme: theme === "aurora" ? "light" : "dark",
      });
      await context.addInitScript(fetchStubSource(theme));
      for (const route of routes) {
        const page = await context.newPage();
        page.on("console", (msg) => {
          if (msg.type() === "error")
            failures.push(`${theme} ${route}: console error: ${msg.text()}`);
        });
        await page.goto(`${baseURL}${route}`, { waitUntil: "networkidle" });
        await page.waitForSelector("main", { timeout: 10_000 });
        await page.addStyleTag({
          content: `*, *::before, *::after { transition-duration: 0s !important; animation-duration: 0s !important; }`,
        });
        const axe = await runAxe(page, axeSource);
        const axeFailures = blockingAxeResults(axe);
        if (axeFailures.length > 0) {
          failures.push(
            `${theme} ${route}: axe violations\n${formatAxe(axeFailures)}`,
          );
        }
        const custom = await targetAndTabChecks(page);
        if (custom.length > 0) {
          failures.push(
            `${theme} ${route}: focus/target violations\n  ${custom.join("\n  ")}`,
          );
        }
        await page.close();
      }
      await context.close();
    }
  } finally {
    await server.close();
    await browser.close();
  }

  if (failures.length > 0) {
    console.error(
      `rendered browser a11y failed (${failures.length} finding groups):`,
    );
    console.error(failures.join("\n\n"));
    process.exit(1);
  }
  console.log(
    `rendered browser a11y OK (${routes.length} native routes x ${themes.length} themes)`,
  );
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
