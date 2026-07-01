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
const dashboardCaptions = [
  "Active tests dashboard",
  "BGP routing dashboard",
  "Top flow contributors dashboard",
  "Device inventory dashboard",
  "eBPF evidence dashboard",
  "Cost budget dashboard",
  "Threat signal dashboard",
  "Tenant health dashboard",
];

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

function localChromiumExecutable() {
  const candidates = [
    process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
  ].filter(Boolean);
  return candidates.find((candidate) => existsSync(candidate));
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

function apiPayload(path, method, pagePath = "") {
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
      capabilities: ["icmp", "tcp", "flow", "device", "ebpf", "endpoint"],
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
  if (path === "/v1/incidents")
    return json({
      items: [
        {
          id: "inc-dashboard",
          tenant_id: "00000000-0000-0000-0000-000000000001",
          status: "open",
          severity: "warning",
          title: "checkout latency burn",
          target: "https://checkout.probectl.test",
          started_at: "2026-06-04T11:45:00Z",
          last_seen_at: "2026-06-04T12:00:00Z",
          signal_count: 3,
          signals: [],
        },
      ],
    });
  if (path === "/v1/alerts") return json({ items: [] });
  if (path === "/v1/alerts/active")
    return json({
      items: [
        {
          fingerprint: "fp-dashboard",
          rule_id: "r-dashboard",
          rule_name: "checkout latency burn",
          severity: "warning",
          metric: "probectl_result_duration_ms",
          labels: { target: "checkout", service: "checkout" },
          value: 184,
          reason: "p95 latency above objective",
          since: "2026-06-04T11:45:00Z",
          last_seen_at: "2026-06-04T12:00:00Z",
        },
      ],
      evaluator_running: true,
    });
  if (path === "/v1/tls/posture")
    return json({ items: [], collector_running: true });
  if (path === "/v1/threat/detections")
    return json({
      items: [
        {
          id: "det-dashboard",
          kind: "ioc_match",
          plane: "threat",
          severity: "warning",
          confidence: 0.82,
          source: "test-intel",
          category: "scanner",
          indicator: "10.0.0.20",
          entity: "10.0.0.20",
          title: "Known scanner contact",
          summary:
            "Flow evidence matched a locally cached threat-intel indicator.",
          observed_at: "2026-06-04T12:00:00Z",
        },
      ],
      detections_running: true,
    });
  if (path === "/v1/endpoints")
    return json({ items: [], collector_running: true });
  if (path === "/v1/results/latest")
    return json({
      items: [
        {
          agent_id: "a1",
          type: "dns",
          target: "1.1.1.1",
          success: true,
          duration_ms: 21,
          metrics: { "dns.query.ms": 21 },
          observed_at: "2026-06-04T12:00:00Z",
        },
        {
          agent_id: "a1",
          type: "http",
          target: "https://checkout.probectl.test",
          success: true,
          duration_ms: 184,
          metrics: { "http.total.ms": 184, "http.status": 200 },
          observed_at: "2026-06-04T12:00:00Z",
        },
      ],
      collector_running: true,
    });
  if (path === "/v1/topology" && pagePath !== "/dashboards")
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
  if (path === "/v1/topology")
    return json({
      topology_running: true,
      at: "2026-06-04T12:00:00Z",
      nodes: [
        { id: "as:64500", kind: "as", label: "AS64500" },
        {
          id: "prefix:203.0.113.0/24",
          kind: "prefix",
          label: "203.0.113.0/24",
        },
        { id: "service:checkout", kind: "service", label: "checkout" },
        { id: "service:payments", kind: "service", label: "payments" },
        { id: "device:10.0.0.1", kind: "device", label: "edge-r1" },
        { id: "hop:10.0.0.1", kind: "hop", label: "10.0.0.1" },
      ],
      edges: [
        { from: "as:64500", to: "prefix:203.0.113.0/24", kind: "routing" },
        {
          from: "service:checkout",
          to: "service:payments",
          kind: "flow",
          label: "http",
        },
        { from: "device:10.0.0.1", to: "hop:10.0.0.1", kind: "device" },
      ],
      coverage: {
        path_edges: 0,
        flow_edges: 1,
        routing_edges: 1,
        device_edges: 1,
      },
    });
  if (path === "/v1/flows/top")
    return json({
      items: [
        {
          key: "10.0.0.10",
          detail: "checkout",
          bytes: 524_288_000,
          packets: 120_000,
          flows: 42,
        },
      ],
      effective_limit: 8,
      window: "1h",
    });
  if (path === "/v1/flows/capacity")
    return json({
      items: [
        {
          ts: "2026-06-04T12:00:00Z",
          exporter: "edge-r1",
          iface: 1,
          bps: 85_000_000,
          pps: 12_000,
        },
      ],
    });
  if (path === "/v1/flows/anomalies")
    return json({
      items: [
        {
          exporter: "edge-r1",
          iface: 1,
          ts: "2026-06-04T12:00:00Z",
          current_bps: 85_000_000,
          baseline_bps: 35_000_000,
          stddev_bps: 8_000_000,
          sigma: 6.2,
          model: "local-zscore-v1",
        },
      ],
    });
  if (path === "/v1/cost/summary")
    return json({
      cost_running: true,
      summary: {
        priced: true,
        zones_mapped: true,
        pricing_source: "test",
        pricing_as_of: "2026-06-01",
        total_bytes: 17 * 2 ** 30,
        total_usd: 0.38,
        by_class: { inter_az: { bytes: 10 * 2 ** 30, usd: 0.1 } },
        by_service: { checkout: { bytes: 12 * 2 ** 30, usd: 0.38 } },
        by_team: { payments: { bytes: 12 * 2 ** 30, usd: 0.38 } },
        chatty_pairs: [],
        trend: [
          { hour: "2026-06-04T10:00:00Z", bytes: 4 * 2 ** 30, usd: 0.08 },
          { hour: "2026-06-04T11:00:00Z", bytes: 7 * 2 ** 30, usd: 0.16 },
          { hour: "2026-06-04T12:00:00Z", bytes: 17 * 2 ** 30, usd: 0.38 },
        ],
        budgets: [
          {
            kind: "team",
            name: "payments",
            monthly_usd: 500,
            spent_usd: 0.38,
            exceeded: false,
          },
        ],
      },
    });
  if (path === "/v1/slos")
    return json({
      slo_running: true,
      items: [
        {
          name: "checkout-availability",
          display_name: "Checkout availability",
          service: "checkout",
          team: "payments",
          objective: 0.99,
          window: "30d",
          attainment: 0.982,
          error_budget_remaining: 0.12,
          total_events: 300,
          cold_start: false,
          burn_rates: [
            {
              window: "fast",
              long: "1h0m0s",
              short: "5m0s",
              burn: 16.2,
              limit: 14.4,
              firing: true,
            },
          ],
        },
      ],
    });
  if (path === "/v1/compliance")
    return json({
      compliance_running: true,
      items: [
        {
          policy: "pci-east-west",
          rule_id: "deny-checkout-db",
          description: "Checkout must not talk directly to cardholder database",
          from: "checkout",
          to: "cardholder-db",
          ports: "5432",
          verdict: "violation",
          violations: 2,
          observed_pairs: 1,
        },
      ],
      coverage: {
        flow_observed: true,
        ebpf_observed: true,
        observations: 3,
        zones_seen: 2,
        zones_total: 2,
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
  if (path === "/v1/remediation/proposals")
    return json({ items: [], approvals_enabled: false });
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
    return json({
      items: [
        {
          version: 1,
          mode: "managed",
          state: "active",
          created_at: "2026-06-04T12:00:00Z",
        },
      ],
    });
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
      if (url.searchParams.has('tenant_id')) throw new Error('browser sent tenant_id query param: ' + url.pathname);
      window.__probectlFetches = window.__probectlFetches || [];
      window.__probectlFetches.push(url.pathname + url.search);
      return respond(payloads(url.pathname, method, location.pathname));
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
    return await globalThis.axe.run(
      {
        include: [["body"]],
        exclude: [["svg[aria-hidden='true']"]],
      },
      {
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
      },
    );
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

async function dashboardChecks(page) {
  return page.evaluate((expectedCaptions) => {
    const problems = [];
    const normalize = (value) =>
      String(value || "")
        .replace(/\s+/g, " ")
        .trim();
    const tables = [...document.querySelectorAll("table")];

    for (const caption of expectedCaptions) {
      const table = tables.find(
        (candidate) => normalize(candidate.caption?.textContent) === caption,
      );
      if (!table) {
        problems.push(`missing table caption: ${caption}`);
        continue;
      }
      const bodyText = normalize(table.tBodies[0]?.textContent);
      if (!table.tBodies[0]?.querySelector("tr")) {
        problems.push(`${caption}: no body rows rendered`);
      }
      if (/^No\s|No data/i.test(bodyText)) {
        problems.push(
          `${caption}: rendered an empty/default state (${bodyText})`,
        );
      }
    }

    const requests = globalThis.__probectlFetches || [];
    const tenantSpoof = requests.find((raw) =>
      new URL(raw, location.origin).searchParams.has("tenant_id"),
    );
    if (tenantSpoof)
      problems.push(`browser request carried tenant_id: ${tenantSpoof}`);

    const requiredPaths = [
      "/v1/me",
      "/v1/tests",
      "/v1/agents",
      "/v1/results/latest",
      "/v1/topology",
      "/v1/flows/top",
      "/v1/flows/capacity",
      "/v1/flows/anomalies",
      "/v1/cost/summary",
      "/v1/threat/detections",
    ];
    for (const requiredPath of requiredPaths) {
      if (
        !requests.some(
          (raw) => new URL(raw, location.origin).pathname === requiredPath,
        )
      ) {
        problems.push(`missing tenant-scoped fetch: ${requiredPath}`);
      }
    }
    return problems;
  }, dashboardCaptions);
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
  const executablePath = localChromiumExecutable();
  const browser = await chromium.launch({
    headless: true,
    ...(executablePath ? { executablePath } : {}),
  });
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
          if (msg.type() === "error") {
            const loc = msg.location();
            if (
              loc.url.endsWith("/favicon.ico") &&
              msg.text().includes("Failed to load resource")
            ) {
              return;
            }
            failures.push(
              `${theme} ${route}: console error: ${msg.text()} (${loc.url || "unknown"}:${loc.lineNumber})`,
            );
          }
        });
        page.on("response", (resp) => {
          if (resp.status() >= 400) {
            const url = new URL(resp.url());
            failures.push(
              `${theme} ${route}: HTTP ${resp.status()} ${url.pathname}`,
            );
          }
        });
        try {
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
          if (route === "/dashboards") {
            const dashboard = await dashboardChecks(page);
            if (dashboard.length > 0) {
              failures.push(
                `${theme} ${route}: dashboard coverage violations\n  ${dashboard.join("\n  ")}`,
              );
            }
          }
        } catch (err) {
          failures.push(
            `${theme} ${route}: route check failed: ${err.message}`,
          );
        } finally {
          await page.close();
        }
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
