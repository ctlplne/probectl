#!/usr/bin/env node
// Real-browser frontend a11y and interaction-performance gate (X16).
//
// This deliberately reuses the already-pinned browser-worker Playwright
// dependency instead of adding a second browser stack to web/. The check runs
// the production Vite build in Chromium, injects local API responses, then
// verifies axe WCAG tags (including browser-computed color contrast), no
// positive tabindex, minimum interactive target size, visible keyboard focus,
// and focus-not-obscured for each native route under each shipped theme and
// reference viewport. It also records raw LCP/INP samples for J1-J6; the
// separate checker owns and enforces the canonical p75 budgets.

import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = dirname(scriptDir);
const webRoot = join(repoRoot, "web");
const browserWorkerRoot = join(repoRoot, "browser-worker");
const appBasePath = "/ui";
// Theme matrix. Default stays the CI pair; PROBECTL_A11Y_THEMES widens or
// narrows a run without a code change (e.g. =dark,aurora,ember locally, or in
// a scheduled workflow) — only themes the token contract defines are accepted.
const KNOWN_THEMES = ["dark", "aurora", "ember"];
const themes = (process.env.PROBECTL_A11Y_THEMES ?? "dark,aurora")
  .split(",")
  .map((t) => t.trim())
  .filter(Boolean);
{
  const unknown = themes.filter((t) => !KNOWN_THEMES.includes(t));
  if (themes.length === 0 || unknown.length > 0) {
    console.error(
      `PROBECTL_A11Y_THEMES invalid: [${unknown.join(", ")}] — known: ${KNOWN_THEMES.join(", ")}`,
    );
    process.exit(1);
  }
}
const viewports = [
  { name: "desktop", width: 1366, height: 900 },
  { name: "mobile", width: 390, height: 844 },
];
const journeyRoutes = [
  { journey: "J1", route: "/onboarding" },
  { journey: "J2", route: "/incidents" },
  { journey: "J3", route: "/explore" },
  { journey: "J4", route: "/path" },
  { journey: "J5", route: "/admin" },
  { journey: "J6", route: "/provider" },
];
const performanceRuns = 5;
const receiptRoot = join(repoRoot, "receipts", "web-ux");
const a11yReceiptPath = join(receiptRoot, "rendered-a11y.json");
const performanceReceiptPath = join(receiptRoot, "web-performance.json");
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
const explorerTemplates = [
  {
    id: "top-talkers-site",
    question: "Show top talkers by site",
    source: "flow",
    dimensions: ["site", "interface"],
    groupings: ["site"],
    measures: ["bps", "pps"],
    visualization: "bar",
    evidence_path: "/planes/flow",
  },
  {
    id: "asn-before-incident",
    question: "Which ASN change preceded this incident?",
    source: "changes",
    dimensions: ["source", "prefix", "target"],
    groupings: ["source"],
    measures: ["events"],
    visualization: "timeline",
    evidence_path: "/incidents",
  },
  {
    id: "loss-by-hop",
    question: "Show loss by hop for this test",
    source: "path",
    dimensions: ["target", "hop", "node"],
    groupings: ["hop"],
    measures: ["loss_ratio", "rtt_avg_ms"],
    visualization: "line",
    evidence_path: "/path",
  },
  {
    id: "service-dependencies",
    question: "Show service dependencies",
    source: "topology",
    dimensions: ["from", "to", "kind"],
    groupings: ["kind"],
    measures: ["edges"],
    visualization: "topology",
    evidence_path: "/topology",
  },
  {
    id: "saturated-interface",
    question: "Which device interface is saturated?",
    source: "flow",
    dimensions: ["site", "interface"],
    groupings: ["site", "interface"],
    measures: ["bps", "pps"],
    visualization: "line",
    evidence_path: "/planes/device",
  },
  {
    id: "outage-endpoints",
    question: "Which endpoints are affected by this outage?",
    source: "endpoints",
    dimensions: ["endpoint", "cause", "summary"],
    groupings: ["cause"],
    measures: ["affected_endpoints"],
    visualization: "table",
    evidence_path: "/endpoints",
  },
  {
    id: "certificates-expiring",
    question: "Which certificates expire in the next 30 days?",
    source: "tls",
    dimensions: ["target", "subject", "issuer"],
    groupings: ["issuer"],
    measures: ["days_remaining"],
    visualization: "table",
    evidence_path: "/security",
  },
  {
    id: "cross-az-cost",
    question: "Show cross-AZ network cost",
    source: "cost",
    dimensions: ["from_zone", "to_zone", "service"],
    groupings: ["from_zone", "to_zone"],
    measures: ["bytes", "usd"],
    visualization: "bar",
    evidence_path: "/cost",
  },
  {
    id: "slo-budget-burn",
    question: "Which SLO error budgets are burning?",
    source: "slo",
    dimensions: ["slo", "service", "team"],
    groupings: ["service"],
    measures: ["burn_rate", "budget_remaining"],
    visualization: "bar",
    evidence_path: "/slos",
  },
  {
    id: "deployments-before-incident",
    question: "Which deployments immediately preceded this incident?",
    source: "changes",
    dimensions: ["source", "actor", "target"],
    groupings: ["source"],
    measures: ["events"],
    visualization: "timeline",
    evidence_path: "/incidents",
  },
];

function appURL(baseURL, route) {
  if (!route.startsWith("/")) {
    throw new Error(`rendered browser route must start with "/": ${route}`);
  }
  return new URL(`${appBasePath}${route}`, `${baseURL}/`).href;
}

function appRoute(pathname, basePath) {
  if (pathname === basePath) return "/";
  if (pathname.startsWith(`${basePath}/`)) {
    return pathname.slice(basePath.length);
  }
  return pathname;
}

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
      tenant_name: "Acme Industries",
      tenant_slug: "acme-industries",
      user_id: "u_test",
      email: "operator@probectl.test",
      display_name: "Test Operator",
      mfa_satisfied: true,
      permissions: [
        "incident.read",
        "incident.write",
        "ai.query",
        "metrics.read",
        "metrics.write",
      ],
    });
  if (path === "/v1/tests") return json({ items: sampleTests });
  if (path === "/v1/agents")
    return json({
      items: sampleAgents,
      control_version: "0.2.0",
      rollouts_available: true,
    });
  if (path === "/v1/rollouts")
    return json({
      items: [
        {
          id: "rollout-a11y",
          target: "0.2.0",
          digest: "sha256:a11yfixture",
          halted: false,
          halt_reason: "",
          done: false,
          progress:
            "rollout to 0.2.0: canary[1]=applying early[4]=pending main[16]=pending",
          waves: [
            { cohort: "canary", agents: 1, status: "applying" },
            { cohort: "early", agents: 4, status: "pending" },
            { cohort: "main", agents: 16, status: "pending" },
          ],
        },
      ],
    });
  if (path === "/v1/dashboards") return json({ items: [] });
  if (path === "/v1/dashboard-report-schedules")
    return json({
      items: [],
      destinations: [
        {
          id: "tenant-report-inbox",
          name: "Tenant report inbox",
          kind: "local",
          outbound: false,
          ready: true,
        },
      ],
      outbound_default: false,
    });
  if (path === "/v1/dashboard-report-artifacts") return json({ items: [] });
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
  if (path === "/v1/incidents/inc-dashboard")
    return json({
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
    });
  if (path === "/v1/incidents/inc-dashboard/changes")
    return json({ items: [] });
  if (path === "/v1/incidents/inc-dashboard/journal")
    return json({ items: [], truncated: false, limit: 200 });
  if (path === "/v1/alerts") return json({ items: [] });
  if (path === "/v1/explorer/schema")
    return json({
      templates: explorerTemplates,
      visualizations: ["table", "bar", "line", "timeline", "topology"],
      comparison_sources: ["flow", "changes", "topology", "endpoints", "tls"],
      max_rows: 500,
    });
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
  if (
    path === "/v1/topology" &&
    pagePath !== "/dashboards" &&
    pagePath !== "/topology"
  )
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
  return json({ error: { code: "not_found", message: "not found" } }, 404);
}

function fetchStubSource(theme) {
  return `(() => {
    const theme = ${JSON.stringify(theme)};
    const appBasePath = ${JSON.stringify(appBasePath)};
    const appRoute = ${appRoute.toString()};
    const explorerTemplates = ${JSON.stringify(explorerTemplates)};
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
      return respond(payloads(url.pathname, method, appRoute(location.pathname, appBasePath)));
    };
  })();`;
}

function performanceObserverSource() {
  return `(() => {
    const state = {
      lcp_ms: null,
      interactions: {},
      lcp_supported: typeof PerformanceObserver !== 'undefined' &&
        PerformanceObserver.supportedEntryTypes?.includes('largest-contentful-paint'),
      event_timing_supported: typeof PerformanceObserver !== 'undefined' &&
        PerformanceObserver.supportedEntryTypes?.includes('event'),
    };
    window.__probectlPerformance = state;
    if (state.lcp_supported) {
      new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) state.lcp_ms = entry.startTime;
      }).observe({ type: 'largest-contentful-paint', buffered: true });
    }
    if (state.event_timing_supported) {
      new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (!entry.interactionId) continue;
          const key = String(entry.interactionId);
          state.interactions[key] = Math.max(state.interactions[key] || 0, entry.duration);
        }
      }).observe({ type: 'event', buffered: true, durationThreshold: 0 });
    }
  })();`;
}

async function writeReceipt(path, receipt) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(receipt, null, 2)}\n`);
}

async function settleTwoFrames(page) {
  await page.evaluate(
    () =>
      new Promise((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(resolve)),
      ),
  );
}

async function exerciseJourneyInteraction(page, route) {
  if (route === "/provider") {
    await page.locator('a[href="#provider-tenants"]').first().click();
    return;
  }
  await page.getByRole("button", { name: "Search or run a command" }).click();
}

async function runPerformanceProfile(browser, baseURL) {
  const receipt = {
    schema: "probectl.web-performance/v1",
    generated_at: new Date().toISOString(),
    profile: {
      browser: "pinned Chromium",
      viewport: viewports[0],
      theme: "dark",
      cache: "fresh context per run",
      api: "local deterministic fixtures",
      runs_per_route: performanceRuns,
      interaction:
        "open command palette (J1-J5); provider tenant-lifecycle anchor (J6)",
      lcp: "Largest Contentful Paint PerformanceObserver",
      inp: "maximum Event Timing duration for the exercised interaction",
    },
    journeys: [],
    failures: [],
  };

  for (const { journey, route } of journeyRoutes) {
    const record = { journey, route, runs: [] };
    receipt.journeys.push(record);
    for (let run = 1; run <= performanceRuns; run += 1) {
      const context = await browser.newContext({
        viewport: viewports[0],
        colorScheme: "dark",
      });
      await context.addInitScript(fetchStubSource("dark"));
      await context.addInitScript(performanceObserverSource());
      const page = await context.newPage();
      try {
        await page.goto(appURL(baseURL, route), { waitUntil: "networkidle" });
        await page.waitForSelector("main", { timeout: 10_000 });
        await settleTwoFrames(page);
        await exerciseJourneyInteraction(page, route);
        await settleTwoFrames(page);
        const measured = await page.evaluate(() => {
          const state = globalThis.__probectlPerformance;
          const interactionDurations = Object.values(
            state?.interactions || {},
          ).filter((value) => Number.isFinite(value));
          return {
            lcp_ms: state?.lcp_ms ?? null,
            // Chromium only reports Event Timing entries at or above its
            // reporting floor. A supported observer with no entry therefore
            // means the exercised interaction completed below that floor.
            inp_ms:
              interactionDurations.length > 0
                ? Math.max(...interactionDurations)
                : state?.event_timing_supported
                  ? 0
                  : null,
            lcp_supported: Boolean(state?.lcp_supported),
            event_timing_supported: Boolean(state?.event_timing_supported),
          };
        });
        record.runs.push({ run, ...measured });
      } catch (error) {
        const message = `${journey} ${route} run ${run}: ${error instanceof Error ? error.message : String(error)}`;
        receipt.failures.push(message);
        record.runs.push({ run, error: message });
      } finally {
        await context.close();
      }
    }
  }

  return receipt;
}

async function startVite() {
  const { preview } = await loadVite();
  const server = await preview({
    // Load the shipping config so preview serves the same /ui/ asset base as
    // the embedded control-plane UI. B-409bafc5: configFile:false served a
    // root-relative build while BrowserRouter required basename="/ui", so the
    // gate waited on pages that could never mount.
    configFile: join(webRoot, "vite.config.ts"),
    root: webRoot,
    preview: { host: "127.0.0.1", port: 0, strictPort: false },
    logLevel: "error",
  });
  const address = server.httpServer.address();
  if (!address || typeof address === "string") {
    throw new Error("vite preview did not report a TCP address");
  }
  return { server, baseURL: `http://127.0.0.1:${address.port}` };
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
  // "incomplete" means axe could not decide and requests human review; it is
  // not a violation. Actual color-contrast failures remain in violations and
  // are proven live by selfCheck() before the route matrix runs.
  return result.violations;
}

// A route must never widen the document beyond the viewport: horizontal page
// scroll on mobile means clipped chrome (tenant indicator, primary actions)
// that axe cannot see. Scrollable WIDGETS (tables, charts) are fine — this
// measures only document-level overflow. Identifies the widest offenders so
// a regression names its culprit.
async function horizontalOverflowCheck(page) {
  return page.evaluate(() => {
    const doc = document.documentElement;
    const overflow = doc.scrollWidth - doc.clientWidth;
    if (overflow <= 1) return [];
    const viewport = doc.clientWidth;
    const insideScrollContainer = (el) => {
      for (
        let a = el.parentElement;
        a && a !== document.body;
        a = a.parentElement
      ) {
        const ox = getComputedStyle(a).overflowX;
        if (
          ox === "auto" ||
          ox === "scroll" ||
          ox === "hidden" ||
          ox === "clip"
        )
          return true;
      }
      return false;
    };
    const offenders = [];
    document.querySelectorAll("body *").forEach((el) => {
      const rect = el.getBoundingClientRect();
      if (rect.right - viewport > 1 && !insideScrollContainer(el)) {
        offenders.push(
          `${el.tagName.toLowerCase()}${el.className ? `.${String(el.className).split(" ")[0]}` : ""} right=${Math.round(rect.right)}`,
        );
      }
    });
    return [
      `document scrolls horizontally: scrollWidth ${doc.scrollWidth} > viewport ${viewport} (+${overflow}px)` +
        (offenders.length > 0
          ? `; widest: ${offenders.slice(0, 4).join(", ")}`
          : ""),
    ];
  });
}

// Card actions are allowed to wrap, but never to steal the heading's readable
// measure or disappear behind Card's intentional overflow clipping. The data
// markers are a stable component contract; CSS-module class hashes are not.
async function mobileCardHeaderCheck(page) {
  return page.evaluate(() => {
    if (window.innerWidth > 640) return [];
    const problems = [];
    const px = (value) => Number.parseFloat(value || "0") || 0;
    for (const header of document.querySelectorAll("[data-card-header]")) {
      const heading = header.querySelector("[data-card-heading]");
      const actions = header.querySelector("[data-card-actions]");
      if (!heading || !actions) continue;

      const title =
        heading.querySelector("h2")?.textContent?.trim() || "untitled card";
      const headerRect = header.getBoundingClientRect();
      const headingRect = heading.getBoundingClientRect();
      const actionsRect = actions.getBoundingClientRect();
      const style = getComputedStyle(header);
      const innerLeft = headerRect.left + px(style.paddingLeft);
      const innerRight = headerRect.right - px(style.paddingRight);
      const innerWidth = innerRight - innerLeft;

      if (actionsRect.top < headingRect.bottom - 1) {
        problems.push(`${title}: mobile actions do not stack below heading`);
      }
      if (headingRect.width < innerWidth - 1) {
        problems.push(
          `${title}: mobile heading width ${Math.round(headingRect.width)}px is narrower than ${Math.round(innerWidth)}px card content`,
        );
      }
      if (
        header.scrollWidth - header.clientWidth > 1 ||
        actions.scrollWidth - actions.clientWidth > 1
      ) {
        problems.push(`${title}: card header content is overflow-clipped`);
      }
      for (const control of actions.querySelectorAll(
        "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled])",
      )) {
        const rect = control.getBoundingClientRect();
        if (rect.left < innerLeft - 1 || rect.right > innerRight + 1) {
          problems.push(
            `${title}: action "${control.textContent?.trim().slice(0, 48) || control.tagName.toLowerCase()}" is clipped by card`,
          );
        }
      }
    }
    return problems;
  });
}

// Targets is an operational inventory first and an optional authoring aid
// second. Keep that hierarchy measurable in a real layout: DOM-order tests
// cannot prove that the inventory reaches the first desktop viewport.
async function targetsHierarchyCheck(page, viewportName) {
  return page.evaluate((currentViewport) => {
    const problems = [];
    const inventory = document.querySelector("[data-targets-inventory]");
    const authoring = document.querySelector("[data-targets-authoring]");
    if (!inventory) problems.push("missing Tests inventory marker");
    if (!authoring) problems.push("missing AI authoring marker");
    if (!inventory || !authoring) return problems;

    const inventoryRect = inventory.getBoundingClientRect();
    const authoringRect = authoring.getBoundingClientRect();
    if (inventoryRect.top >= authoringRect.top) {
      problems.push("AI authoring precedes the Tests inventory");
    }

    if (currentViewport === "desktop") {
      if (inventoryRect.top >= window.innerHeight) {
        problems.push("Tests inventory begins below the desktop viewport");
      }
      if (!inventory.querySelector("tbody tr")) {
        problems.push("populated Tests inventory has no rendered row");
      }
    }
    return problems;
  }, viewportName);
}

// The graph is Topology's hero artifact. The complete history/filter stack is
// kept in a native disclosure so it stays keyboard-reachable without consuming
// the first viewport in the default live state.
async function topologyHierarchyCheck(page) {
  return page.evaluate(() => {
    const problems = [];
    const controls = document.querySelector("[data-topology-controls]");
    const graphCard = document.querySelector("[data-topology-graph]");
    const graph = graphCard?.querySelector('[aria-label="Topology graph"]');
    const instruction = graphCard?.querySelector("[data-card-heading] p");
    if (!controls) problems.push("missing history/filter disclosure marker");
    if (!graphCard) problems.push("missing dependency graph marker");
    if (!graph) problems.push("missing rendered dependency graph");
    if (!instruction)
      problems.push("missing primary node-selection instruction");
    if (!controls || !graphCard || !graph || !instruction) return problems;

    if (controls.open) {
      problems.push(
        "history/filter stack is expanded in the default live state",
      );
    }
    if (
      controls.getBoundingClientRect().top >=
      graphCard.getBoundingClientRect().top
    ) {
      problems.push(
        "dependency graph does not follow the compact scope control",
      );
    }
    if (graph.getBoundingClientRect().top >= window.innerHeight) {
      problems.push("dependency graph content begins below the viewport");
    }
    if (instruction.getBoundingClientRect().bottom >= window.innerHeight) {
      problems.push(
        "primary node-selection instruction falls below the viewport",
      );
    }
    return problems;
  });
}

// Explorer's working query must lead its teaching chrome. On mobile, canonical
// recipes are one horizontally scrollable row whose labels wrap inside each
// button; they must not form a full-screen wall or clip their question text.
async function explorerHierarchyCheck(page, viewportName) {
  return page.evaluate((currentViewport) => {
    const problems = [];
    const workspace = document.querySelector("[data-explorer-workspace]");
    const recipes = document.querySelector("[data-explorer-recipes]");
    const builder = document.querySelector("[data-explorer-builder]");
    const heading = workspace?.querySelector("[data-card-heading] h2");
    if (!workspace) problems.push("missing Explorer workspace marker");
    if (!recipes) problems.push("missing canonical recipe-strip marker");
    if (!builder) problems.push("missing query-builder marker");
    if (!heading || heading.textContent?.trim() !== "Query builder") {
      problems.push("Query builder does not title the working surface");
    }
    if (!workspace || !recipes || !builder) return problems;

    if (!workspace.contains(recipes) || !workspace.contains(builder)) {
      problems.push("recipes and builder do not share the working surface");
    }
    if (
      !(
        recipes.compareDocumentPosition(builder) &
        Node.DOCUMENT_POSITION_FOLLOWING
      )
    ) {
      problems.push("query fields do not follow the compact recipe strip");
    }

    const recipeButtons = [...recipes.querySelectorAll("button")];
    if (recipeButtons.length === 0) {
      problems.push("canonical recipe strip has no buttons");
    }
    for (const button of recipeButtons) {
      if (
        button.scrollWidth > button.clientWidth + 1 ||
        button.scrollHeight > button.clientHeight + 1
      ) {
        problems.push(
          `recipe label is clipped: ${button.textContent?.trim().slice(0, 64) || "unnamed recipe"}`,
        );
      }
    }

    if (builder.getBoundingClientRect().top >= window.innerHeight) {
      problems.push("query builder begins below the viewport");
    }
    if (currentViewport === "mobile") {
      const recipeStyle = getComputedStyle(recipes);
      if (recipeStyle.flexWrap !== "nowrap") {
        problems.push("mobile recipes wrap into a vertical wall");
      }
      if (recipes.getBoundingClientRect().height > window.innerHeight / 3) {
        problems.push(
          "mobile recipe strip consumes more than one-third viewport",
        );
      }
    }
    return problems;
  }, viewportName);
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
      const closedDetails = el.closest("details:not([open])");
      if (closedDetails) {
        const summary = closedDetails.querySelector(":scope > summary");
        if (!summary?.contains(el)) return false;
      }
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
      "/v1/dashboards",
      "/v1/dashboard-report-schedules",
      "/v1/dashboard-report-artifacts",
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
    const body = normalize(document.body.textContent);
    for (const requiredText of [
      "Acme Industries",
      "00000000-0000-0000-0000-000000000001",
      "Absolute time · UTC",
      "1 hour coordinated",
      "Coverage, provenance, and redaction details",
      "Operator",
      "Executive",
      "Tenant report inbox",
      "no outbound default",
    ]) {
      if (!body.includes(requiredText))
        problems.push(
          `missing dashboard scope/reporting text: ${requiredText}`,
        );
    }
    return problems;
  }, dashboardCaptions);
}

async function selfCheck(browser, axeSource) {
  const page = await browser.newPage({ viewport: viewports[0] });
  await page.setContent(`
    <main>
      <p style="color:#aaa;background-color:#fff;font-size:16px">Bad contrast</p>
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
  await page.setContent(`
    <style>
      .shell { display: grid; grid-template-columns: 1fr; width: 100vw; }
      .topbar { min-width: calc(100vw + 9px); }
    </style>
    <div class="shell"><header class="topbar">Planted shell-width regression</header></div>
  `);
  const overflow = await horizontalOverflowCheck(page);
  if (
    !overflow.some((problem) =>
      problem.includes("document scrolls horizontally"),
    )
  ) {
    throw new Error(
      "self-check failed: horizontal-overflow check did not catch a deliberate shell-width regression",
    );
  }
  await page.setViewportSize(viewports[1]);
  await page.setContent(`
    <style>
      .bad-card { width: 350px; overflow: hidden; }
      .bad-header { display: flex; align-items: flex-start; gap: 16px; padding: 16px; }
      .bad-heading { min-width: 0; }
      .bad-actions { display: flex; flex-shrink: 0; gap: 8px; }
      .bad-actions button { white-space: nowrap; }
    </style>
    <section class="bad-card">
      <header class="bad-header" data-card-header>
        <div class="bad-heading" data-card-heading>
          <h2>Planted card regression</h2>
          <p>Copy squeezed beside actions.</p>
        </div>
        <div class="bad-actions" data-card-actions>
          <button>Register collector</button>
          <button>Enroll agent</button>
        </div>
      </header>
    </section>
  `);
  const cardHeader = await mobileCardHeaderCheck(page);
  if (
    !cardHeader.some(
      (problem) =>
        problem.includes("do not stack") ||
        problem.includes("narrower") ||
        problem.includes("clipped"),
    )
  ) {
    throw new Error(
      "self-check failed: mobile CardHeader check did not catch a deliberate non-wrapping regression",
    );
  }
  await page.setViewportSize(viewports[0]);
  await page.setContent(`
    <section data-targets-authoring>Author with AI</section>
    <section data-targets-inventory style="margin-top:1000px">
      <table><tbody><tr><td>Planted test</td></tr></tbody></table>
    </section>
  `);
  const targetsHierarchy = await targetsHierarchyCheck(page, viewports[0].name);
  if (
    !targetsHierarchy.some((problem) =>
      problem.includes("AI authoring precedes"),
    ) ||
    !targetsHierarchy.some((problem) =>
      problem.includes("inventory begins below the desktop viewport"),
    )
  ) {
    throw new Error(
      "self-check failed: Targets hierarchy check did not catch the planted authoring-first regression",
    );
  }
  await page.setViewportSize(viewports[1]);
  await page.setContent(`
    <details data-topology-controls open>
      <summary>History &amp; filters</summary>
      <div style="height:1000px">Planted expanded controls</div>
    </details>
    <section data-topology-graph>
      <header data-card-heading><p>Click a node to inspect it.</p></header>
      <svg aria-label="Topology graph"></svg>
    </section>
  `);
  const topologyHierarchy = await topologyHierarchyCheck(page);
  if (
    !topologyHierarchy.some((problem) =>
      problem.includes("expanded in the default live state"),
    ) ||
    !topologyHierarchy.some((problem) =>
      problem.includes("graph content begins below"),
    )
  ) {
    throw new Error(
      "self-check failed: Topology hierarchy check did not catch the planted expanded-controls regression",
    );
  }
  await page.setContent(`
    <section data-explorer-workspace>
      <header data-card-heading><h2>Query builder</h2></header>
      <div data-explorer-recipes style="display:flex;flex-wrap:wrap;width:350px">
        <button style="width:120px;height:32px;white-space:nowrap;overflow:hidden">Which certificates expire in the next 30 days?</button>
        <button style="width:350px;height:400px">Recipe two</button>
        <button style="width:350px;height:400px">Recipe three</button>
      </div>
      <form data-explorer-builder><input aria-label="Ask in natural language"></form>
    </section>
  `);
  const explorerHierarchy = await explorerHierarchyCheck(
    page,
    viewports[1].name,
  );
  if (
    !explorerHierarchy.some((problem) =>
      problem.includes("recipe label is clipped"),
    ) ||
    !explorerHierarchy.some((problem) =>
      problem.includes("wrap into a vertical wall"),
    ) ||
    !explorerHierarchy.some((problem) =>
      problem.includes("query builder begins below"),
    )
  ) {
    throw new Error(
      "self-check failed: Explorer hierarchy check did not catch the planted clipped recipe wall",
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
  const a11yReceipt = {
    schema: "probectl.web-rendered-a11y/v1",
    generated_at: new Date().toISOString(),
    source: "web/src/surfaces.ts native routes",
    themes,
    viewports,
    routes,
    checks: [],
    failures,
  };
  let performanceReceipt = {
    schema: "probectl.web-performance/v1",
    generated_at: new Date().toISOString(),
    journeys: [],
    failures: ["performance profile did not run"],
  };

  try {
    await selfCheck(browser, axeSource);
    for (const viewport of viewports) {
      for (const theme of themes) {
        const context = await browser.newContext({
          viewport,
          colorScheme: theme === "aurora" ? "light" : "dark",
        });
        await context.addInitScript(fetchStubSource(theme));
        for (const route of routes) {
          const record = {
            route,
            theme,
            viewport: viewport.name,
            axe: [],
            custom: [],
            overflow: [],
            cardHeader: [],
            dashboard: [],
            targets: [],
            topology: [],
            explorer: [],
            runtime: [],
          };
          a11yReceipt.checks.push(record);
          const page = await context.newPage();
          page.on("console", (msg) => {
            if (msg.type() !== "error") return;
            const loc = msg.location();
            if (
              loc.url.endsWith("/favicon.ico") &&
              msg.text().includes("Failed to load resource")
            ) {
              return;
            }
            record.runtime.push(
              `console error: ${msg.text()} (${loc.url || "unknown"}:${loc.lineNumber})`,
            );
          });
          page.on("response", (resp) => {
            if (resp.status() < 400) return;
            const url = new URL(resp.url());
            record.runtime.push(`HTTP ${resp.status()} ${url.pathname}`);
          });
          try {
            await page.goto(appURL(baseURL, route), {
              waitUntil: "networkidle",
            });
            await page.waitForSelector("main", { timeout: 10_000 });
            if (route === "/explore") {
              await page.waitForSelector("[data-explorer-workspace]", {
                timeout: 10_000,
              });
            }
            await page.addStyleTag({
              content: `*, *::before, *::after { transition-duration: 0s !important; animation-duration: 0s !important; }`,
            });
            const axe = await runAxe(page, axeSource);
            const axeFailures = blockingAxeResults(axe);
            record.axe = axeFailures.map((violation) => ({
              id: violation.id,
              impact: violation.impact,
              help: violation.help,
              targets: violation.nodes.map((node) => node.target),
            }));
            if (axeFailures.length > 0) {
              failures.push(
                `${viewport.name} ${theme} ${route}: axe violations\n${formatAxe(axeFailures)}`,
              );
            }
            record.custom = await targetAndTabChecks(page);
            if (record.custom.length > 0) {
              failures.push(
                `${viewport.name} ${theme} ${route}: focus/target violations\n  ${record.custom.join("\n  ")}`,
              );
            }
            record.overflow = await horizontalOverflowCheck(page);
            if (record.overflow.length > 0) {
              failures.push(
                `${viewport.name} ${theme} ${route}: horizontal overflow\n  ${record.overflow.join("\n  ")}`,
              );
            }
            record.cardHeader = await mobileCardHeaderCheck(page);
            if (record.cardHeader.length > 0) {
              failures.push(
                `${viewport.name} ${theme} ${route}: CardHeader layout violations\n  ${record.cardHeader.join("\n  ")}`,
              );
            }
            if (route === "/dashboards") {
              record.dashboard = await dashboardChecks(page);
              if (record.dashboard.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: dashboard coverage violations\n  ${record.dashboard.join("\n  ")}`,
                );
              }
            }
            if (route === "/targets") {
              record.targets = await targetsHierarchyCheck(page, viewport.name);
              if (record.targets.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: Targets hierarchy violations\n  ${record.targets.join("\n  ")}`,
                );
              }
            }
            if (route === "/topology") {
              record.topology = await topologyHierarchyCheck(page);
              if (record.topology.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: Topology hierarchy violations\n  ${record.topology.join("\n  ")}`,
                );
              }
            }
            if (route === "/explore") {
              record.explorer = await explorerHierarchyCheck(
                page,
                viewport.name,
              );
              if (record.explorer.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: Explorer hierarchy violations\n  ${record.explorer.join("\n  ")}`,
                );
              }
            }
          } catch (err) {
            record.runtime.push(
              `route check failed: ${err instanceof Error ? err.message : String(err)}`,
            );
          } finally {
            await page.close();
          }
          if (record.runtime.length > 0) {
            failures.push(
              `${viewport.name} ${theme} ${route}: runtime violations\n  ${record.runtime.join("\n  ")}`,
            );
          }
          record.status =
            record.axe.length === 0 &&
            record.custom.length === 0 &&
            record.overflow.length === 0 &&
            record.cardHeader.length === 0 &&
            record.dashboard.length === 0 &&
            record.targets.length === 0 &&
            record.topology.length === 0 &&
            record.explorer.length === 0 &&
            record.runtime.length === 0
              ? "pass"
              : "fail";
        }
        await context.close();
      }
    }
    const expectedChecks = routes.length * themes.length * viewports.length;
    if (a11yReceipt.checks.length !== expectedChecks) {
      failures.push(
        `route matrix incomplete: expected ${expectedChecks}, recorded ${a11yReceipt.checks.length}`,
      );
    }
    for (const route of routes) {
      for (const theme of themes) {
        for (const viewport of viewports) {
          const matches = a11yReceipt.checks.filter(
            (record) =>
              record.route === route &&
              record.theme === theme &&
              record.viewport === viewport.name,
          );
          if (matches.length !== 1) {
            failures.push(
              `route matrix ${viewport.name} ${theme} ${route}: expected one record, found ${matches.length}`,
            );
          }
        }
      }
    }
    performanceReceipt = await runPerformanceProfile(browser, baseURL);
  } catch (error) {
    failures.push(
      `browser gate aborted: ${error instanceof Error ? error.message : String(error)}`,
    );
  } finally {
    a11yReceipt.status = failures.length === 0 ? "pass" : "fail";
    await writeReceipt(a11yReceiptPath, a11yReceipt);
    await writeReceipt(performanceReceiptPath, performanceReceipt);
    await new Promise((resolve, reject) => {
      server.httpServer.close((error) => (error ? reject(error) : resolve()));
    });
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
    `rendered browser a11y OK (${routes.length} native routes x ${themes.length} themes x ${viewports.length} viewports)`,
  );
  console.log(`rendered a11y receipt: ${a11yReceiptPath}`);
  console.log(`web performance receipt: ${performanceReceiptPath}`);
}

function assertSchemaValue(value, schema, path) {
  if (!schema || typeof schema !== "object") {
    throw new Error(`self-check failed: OpenAPI schema missing at ${path}`);
  }
  const types = Array.isArray(schema.type) ? schema.type : [schema.type];
  const matches = types.some((type) => {
    if (type === "object")
      return (
        value !== null && typeof value === "object" && !Array.isArray(value)
      );
    if (type === "array") return Array.isArray(value);
    if (type === "integer") return Number.isInteger(value);
    if (type === "number")
      return typeof value === "number" && Number.isFinite(value);
    if (type === "null") return value === null;
    return typeof value === type;
  });
  if (!matches) {
    throw new Error(
      `self-check failed: ${path} does not match OpenAPI type ${types.join("|")}`,
    );
  }
  if (schema.enum && !schema.enum.includes(value)) {
    throw new Error(`self-check failed: ${path} is outside its OpenAPI enum`);
  }
  if (
    schema.type === "string" &&
    schema.format === "date-time" &&
    Number.isNaN(Date.parse(value))
  ) {
    throw new Error(
      `self-check failed: ${path} is not an OpenAPI date-time string`,
    );
  }
  if (schema.type === "array") {
    value.forEach((item, index) =>
      assertSchemaValue(item, schema.items, `${path}[${index}]`),
    );
  }
  if (schema.type === "object") {
    for (const required of schema.required ?? []) {
      if (!(required in value)) {
        throw new Error(
          `self-check failed: ${path} lacks required property ${required}`,
        );
      }
    }
    for (const [key, propertySchema] of Object.entries(
      schema.properties ?? {},
    )) {
      if (key in value) {
        assertSchemaValue(value[key], propertySchema, `${path}.${key}`);
      }
    }
  }
}

async function selfTest() {
  const example = appURL("http://127.0.0.1:4173", "/onboarding");
  if (example !== "http://127.0.0.1:4173/ui/onboarding") {
    throw new Error(`self-check failed: shipping route resolved to ${example}`);
  }
  const dashboardRoute = appRoute("/ui/dashboards", appBasePath);
  if (dashboardRoute !== "/dashboards") {
    throw new Error(
      `self-check failed: dashboard route resolved to ${dashboardRoute}`,
    );
  }
  const [viteConfig, appSource, scriptSource, openapiSource] =
    await Promise.all([
      readFile(join(webRoot, "vite.config.ts"), "utf8"),
      readFile(join(webRoot, "src/App.tsx"), "utf8"),
      readFile(fileURLToPath(import.meta.url), "utf8"),
      readFile(join(repoRoot, "internal/control/openapi.json"), "utf8"),
    ]);
  if (!viteConfig.includes(`base: '${appBasePath}/'`)) {
    throw new Error(
      `self-check failed: vite.config.ts does not use base ${appBasePath}/`,
    );
  }
  if (!appSource.includes(`BrowserRouter basename="${appBasePath}"`)) {
    throw new Error(
      `self-check failed: BrowserRouter does not use basename ${appBasePath}`,
    );
  }
  const routedNavigations = scriptSource.match(
    /page\.goto\(appURL\(baseURL, route\)/g,
  );
  if (routedNavigations?.length !== 2) {
    throw new Error(
      "self-check failed: every route matrix must navigate through appURL",
    );
  }
  const topologyFixture = apiPayload(
    "/v1/topology",
    "GET",
    dashboardRoute,
  ).body;
  const openapi = JSON.parse(openapiSource);
  const topologySchema =
    openapi.paths?.["/v1/topology"]?.get?.responses?.["200"]?.content?.[
      "application/json"
    ]?.schema;
  assertSchemaValue(topologyFixture, topologySchema, "topology fixture");
  const nodeKinds = new Set(topologyFixture.nodes.map((node) => node.kind));
  const edgeKinds = new Set(topologyFixture.edges.map((edge) => edge.kind));
  for (const kind of ["as", "prefix", "device"]) {
    if (!nodeKinds.has(kind)) {
      throw new Error(`self-check failed: topology fixture lacks ${kind} node`);
    }
  }
  for (const kind of ["routing", "device"]) {
    if (!edgeKinds.has(kind)) {
      throw new Error(`self-check failed: topology fixture lacks ${kind} edge`);
    }
  }
  console.log(
    `rendered browser route contract OK (${example}; shipping Vite config + BrowserRouter agree; dashboard fixture matches OpenAPI and covers BGP/device)`,
  );
}

const run = process.argv.includes("--selftest") ? selfTest : main;
run().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
