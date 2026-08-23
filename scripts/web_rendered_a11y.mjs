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
const targetsLaptopViewport = {
  name: "targets-laptop",
  width: 1280,
  height: 720,
};
const dashboardLaptopViewport = {
  name: "dashboard-laptop",
  width: 1280,
  height: 720,
};
const topologyLaptopViewport = {
  name: "topology-laptop",
  width: 1280,
  height: 720,
};
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

const renderedPath = {
  target: "1.1.1.1",
  target_ip: "1.1.1.1",
  mode: "icmp",
  max_hops: 30,
  trace_count: 3,
  destination_reached: true,
  measurement_fidelity: {
    version: 1,
    probe_transport: "icmp",
    acquisition_mode: "raw_icmp",
    timing_source: "application_monotonic",
    hop_visibility: "full",
    kernel_timestamping: false,
    hardware_timestamping: false,
  },
  hops: [
    {
      ttl: 1,
      nodes: [
        {
          ip: "10.0.0.1",
          sent: 3,
          received: 3,
          loss_ratio: 0,
          rtt_min_ms: 1,
          rtt_avg_ms: 1.2,
          rtt_max_ms: 2,
        },
      ],
    },
    {
      ttl: 2,
      nodes: [
        {
          ip: "10.0.0.2",
          sent: 3,
          received: 2,
          loss_ratio: 0.33,
          rtt_min_ms: 8,
          rtt_avg_ms: 9,
          rtt_max_ms: 10,
        },
      ],
    },
    {
      ttl: 3,
      nodes: [
        {
          ip: "1.1.1.1",
          sent: 3,
          received: 3,
          loss_ratio: 0,
          rtt_min_ms: 14,
          rtt_avg_ms: 15,
          rtt_max_ms: 16,
        },
      ],
    },
  ],
  links: [
    { ttl: 1, from: "10.0.0.1", to: "10.0.0.2" },
    { ttl: 2, from: "10.0.0.2", to: "1.1.1.1" },
  ],
};

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
      name: "edge-icmp",
      type: "icmp",
      target: "1.1.1.1",
      interval_seconds: 30,
      timeout_seconds: 3,
      params: {},
      enabled: true,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    },
    {
      id: "t2",
      name: "edge-icmp-secondary",
      type: "icmp",
      target: "9.9.9.9",
      interval_seconds: 60,
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
  if (path === "/v1/tests/t1") return json(sampleTests[0]);
  if (path === "/v1/coverage/vantages")
    return json({
      items: [
        {
          test_id: "t1",
          test_name: "edge-icmp",
          region: "us-east",
          site: "iad-1",
          agent_readiness: "ready",
          agent_count: 1,
          ready_agent_count: 1,
          probe_family: "icmp",
          target: "1.1.1.1",
          last_evidence_at: "2026-07-28T06:29:00Z",
          independent_vantage_count: 1,
          stale_after_seconds: 300,
          status: "non_redundant",
          execution_cadence: {
            state: "gaps_observed",
            reason: "missed_rounds",
            attribution: "exact_test_id",
            configured_interval_seconds: 30,
            window_seconds: 180,
            expected_rounds: 6,
            observed_rounds: 4,
            missed_rounds: 2,
            max_gap_seconds: 90,
            observed_agent_count: 1,
            history_complete: true,
            current_assignment_verified: false,
          },
          next_action: {
            kind: "author_test",
            label: "Author another test",
            href: "/targets?create=test",
          },
        },
        {
          test_id: "t2",
          test_name: "edge-icmp-secondary",
          region: "us-west",
          site: "sjc-1",
          agent_readiness: "unavailable",
          agent_count: 0,
          ready_agent_count: 0,
          probe_family: "icmp",
          target: "9.9.9.9",
          independent_vantage_count: 0,
          stale_after_seconds: 300,
          status: "uncovered",
          execution_cadence: {
            state: "never_observed",
            reason: "no_exact_test_evidence",
            attribution: "none",
            configured_interval_seconds: 60,
            window_seconds: 360,
            expected_rounds: 0,
            observed_rounds: 0,
            missed_rounds: 0,
            max_gap_seconds: 0,
            observed_agent_count: 0,
            history_complete: true,
            current_assignment_verified: false,
          },
          next_action: {
            kind: "enroll_vantage",
            label: "Enroll or restore a vantage",
            href: "/admin",
          },
        },
      ],
      as_of: "2026-07-28T06:30:00Z",
      evidence_running: true,
      candidate_limit: 5000,
      truncated: false,
    });
  if (path === "/v1/tests/t1/path") return json(renderedPath);
  if (path === "/v1/tests/t1/path/history")
    return json({
      items: [
        {
          id: "round-rendered",
          observed_at: "2026-07-28T06:30:00Z",
          path: renderedPath,
        },
      ],
    });
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
    return json({
      items: [
        {
          event: {
            id: "device-config:config-2",
            source: "probectl-device-config",
            kind: "config",
            title: "Config drift detected on edge-r1",
            summary: "Redacted device config changed from version 1 to 2.",
            target: "edge-r1",
            ref: "config-2",
            config: {
              current_id: "config-2",
              current_version: 2,
              current_hash: "0123456789abcdef",
              previous_id: "config-1",
              previous_version: 1,
              previous_hash: "abcdef0123456789",
            },
            occurred_at: "2026-06-04T11:59:00Z",
          },
          score: 0.98,
          reason: "same target edge-r1",
        },
      ],
    });
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
  if (path === "/v1/flows/ingest-quality" && method === "GET")
    return json({
      contract_version: "probectl.flow-ingest-quality/v1",
      items: [
        {
          agent_id:
            "flow-agent-at-a-deliberately-long-sovereign-site-name-that-must-wrap",
          exporter_address: "2001:db8:100:200::1234",
          protocol: "ipfix",
          window_started_at: "2026-06-04T11:59:00Z",
          window_ended_at: "2026-06-04T12:00:00Z",
          last_packet_at: "2026-06-04T11:59:58Z",
          last_valid_record_at: "2026-06-04T11:59:58Z",
          packets_received: 128,
          records_decoded: 2048,
          decode_error_packets: 0,
          template_misses: 0,
          queue_dropped_records: 0,
          emit_dropped_records: 0,
          template_state: "ready",
          sampling_state: "sampled",
          state: "healthy",
          reason: "receiving_valid_records",
          next_action: "continue_monitoring",
        },
      ],
      ingest_running: true,
      effective_limit: 100,
      truncated: false,
      as_of: "2026-06-04T12:00:00Z",
      stale_after_seconds: 180,
      retention: { max_per_tenant: 4096, retention_days: 30 },
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
  if (path === "/v1/device/collection-outcomes" && method === "GET")
    return json({
      contract_version: "probectl.device-collection-outcomes/v1",
      items: [
        {
          agent_id:
            "device-agent-with-a-deliberately-long-offline-safe-identifier",
          configured_target:
            "edge-router-with-a-deliberately-long-name.internal.example",
          protocol: "lldp",
          last_attempt_at: "2026-06-04T12:00:00Z",
          last_success_at: "2026-06-04T11:55:00Z",
          state: "failed",
          reason: "poll_failed",
          row_count: 0,
          next_action: "verify_configured_target_access",
        },
        {
          agent_id: "device-agent-1",
          configured_target: "edge-r1.internal",
          protocol: "cdp",
          last_attempt_at: "2026-06-04T12:00:00Z",
          last_success_at: "2026-06-04T12:00:00Z",
          state: "healthy_empty",
          reason: "no_rows_observed",
          row_count: 0,
          next_action: "review_target_neighbor_configuration",
        },
      ],
      collection_running: true,
      effective_limit: 100,
      truncated: false,
      as_of: "2026-06-04T12:00:00Z",
      retention: { max_per_tenant: 4096, retention_days: 30 },
    });
  if (path === "/v1/device/syslog" && method === "GET")
    return json({
      items: [
        {
          id: "syslog-1",
          device: "edge-r1",
          severity_text: "warning",
          message: "Interface Gi0/1 down",
          observed_at: "2026-06-04T12:00:00Z",
        },
      ],
      syslog_running: true,
    });
  if (path === "/v1/device/configs" && method === "GET")
    return json({
      items: [
        {
          id: "config-2",
          device: "edge-r1",
          version: 2,
          content_hash: "0123456789abcdef",
          previous_hash: "abcdef0123456789",
          drifted: true,
          archived_at: "2026-06-04T12:00:00Z",
          content:
            "hostname edge-r1\ninterface Gi0/1\n description payments uplink\n no shutdown\nsnmp-server community [REDACTED]",
        },
        {
          id: "config-1",
          device: "edge-r1",
          version: 1,
          content_hash: "abcdef0123456789",
          drifted: false,
          archived_at: "2026-06-03T12:00:00Z",
          content:
            "hostname edge-r1\ninterface Gi0/1\n description checkout uplink\n shutdown\nsnmp-server community [REDACTED]",
        },
      ],
      archive_running: true,
    });
  return json({ error: { code: "not_found", message: "not found" } }, 404);
}

function fetchStubSource(theme) {
  return `(() => {
    const theme = ${JSON.stringify(theme)};
    const appBasePath = ${JSON.stringify(appBasePath)};
    const appRoute = ${appRoute.toString()};
    const explorerTemplates = ${JSON.stringify(explorerTemplates)};
    const renderedPath = ${JSON.stringify(renderedPath)};
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

// A hidden-overflow component can clip a control without widening the
// document. The control remains in the accessibility tree, so axe and the
// document-level overflow check both stay green even though a user cannot see
// or reach its full hit target. Deliberate local scroll viewports are exempt:
// their controls remain reachable by scrolling that widget.
async function interactiveClippingCheck(page) {
  return page.evaluate(() => {
    const problems = [];
    const controls = document.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [role="button"]',
    );
    for (const control of controls) {
      const rect = control.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) continue;

      let hasLocalHorizontalScroll = false;
      for (
        let ancestor = control.parentElement;
        ancestor && ancestor !== document.body;
        ancestor = ancestor.parentElement
      ) {
        const style = getComputedStyle(ancestor);
        if (
          (style.overflowX === "auto" || style.overflowX === "scroll") &&
          ancestor.scrollWidth > ancestor.clientWidth + 1
        ) {
          hasLocalHorizontalScroll = true;
        }
        if (
          (style.overflowX === "hidden" || style.overflowX === "clip") &&
          !hasLocalHorizontalScroll
        ) {
          const clip = ancestor.getBoundingClientRect();
          if (rect.left < clip.left - 1 || rect.right > clip.right + 1) {
            const name =
              control.getAttribute("aria-label")?.trim() ||
              control.textContent?.trim().replace(/\s+/g, " ").slice(0, 64) ||
              control.getAttribute("name") ||
              control.tagName.toLowerCase();
            problems.push(
              `"${name}" is clipped by hidden-overflow ${ancestor.tagName.toLowerCase()}: ` +
                `control ${Math.round(rect.left)}..${Math.round(rect.right)}, ` +
                `container ${Math.round(clip.left)}..${Math.round(clip.right)}`,
            );
            break;
          }
        }
      }
    }
    return problems;
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
    const toolbar = inventory?.querySelector("[data-targets-filter-toolbar]");
    if (!inventory) problems.push("missing Tests inventory marker");
    if (!authoring) problems.push("missing AI authoring marker");
    if (!inventory || !authoring) return problems;
    if (!toolbar) problems.push("missing full-width Targets filter toolbar");

    const inventoryRect = inventory.getBoundingClientRect();
    const authoringRect = authoring.getBoundingClientRect();
    if (inventoryRect.top >= authoringRect.top) {
      problems.push("AI authoring precedes the Tests inventory");
    }

    if (currentViewport === "targets-laptop") {
      const mobileList = inventory.querySelector("[data-targets-mobile-list]");
      const header = inventory.querySelector("[data-card-header]");
      const tableHead = inventory.querySelector("thead");
      const firstRow = inventory.querySelector("tbody tr");
      const composer = inventory.querySelector("[data-saved-view-composer]");
      if (inventoryRect.top >= window.innerHeight) {
        problems.push("Tests inventory begins below the 1280x720 viewport");
      }
      if (!header) problems.push("missing compact Tests heading");
      if (!tableHead)
        problems.push("populated Tests inventory has no table header");
      if (!firstRow) {
        problems.push("populated Tests inventory has no rendered row");
      }
      if (mobileList?.getClientRects().length) {
        problems.push("mobile Tests list remains visible at desktop width");
      }
      if (header && toolbar) {
        const headerRect = header.getBoundingClientRect();
        const toolbarRect = toolbar.getBoundingClientRect();
        if (toolbarRect.top < headerRect.bottom - 1) {
          problems.push(
            "Targets filter toolbar does not follow the compact heading",
          );
        }
        if (toolbarRect.width < inventoryRect.width * 0.9) {
          problems.push("Targets filter toolbar leaves a blank heading column");
        }
      }
      if (
        tableHead &&
        tableHead.getBoundingClientRect().bottom > window.innerHeight
      ) {
        problems.push("Tests table header falls below the 1280x720 fold");
      }
      if (
        firstRow &&
        firstRow.getBoundingClientRect().bottom > window.innerHeight
      ) {
        problems.push(
          "first populated Tests row falls below the 1280x720 fold",
        );
      }
      if (!composer) {
        problems.push("Targets is missing the saved-view composer group");
      } else if (toolbar) {
        const nameInput = composer.querySelector("input");
        const saveButton = Array.from(composer.querySelectorAll("button")).find(
          (button) => button.textContent?.trim() === "Save view",
        );
        if (!nameInput || !saveButton) {
          problems.push("saved-view composer is missing its name or action");
        } else {
          const composerRect = composer.getBoundingClientRect();
          const inputRect = nameInput.getBoundingClientRect();
          const buttonRect = saveButton.getBoundingClientRect();
          const verticalOverlap =
            Math.min(inputRect.bottom, buttonRect.bottom) -
            Math.max(inputRect.top, buttonRect.top);
          if (verticalOverlap <= 0 || buttonRect.left < inputRect.right - 1) {
            problems.push(
              "saved-view input and action detach from their shared row",
            );
          }
          if (
            inputRect.left < composerRect.left - 1 ||
            buttonRect.right > composerRect.right + 1 ||
            composer.scrollWidth - composer.clientWidth > 1
          ) {
            problems.push(
              "saved-view input or action escapes its semantic composer",
            );
          }
        }
      }
      const coverageTable = document.querySelector(
        "[data-targets-coverage] table",
      );
      if (!coverageTable || coverageTable.getClientRects().length === 0) {
        problems.push("desktop coverage receipt is not a semantic table");
      }
    }

    if (currentViewport === "mobile" && toolbar) {
      const desktopList = inventory.querySelector(
        "[data-targets-desktop-list]",
      );
      const mobileList = inventory.querySelector("[data-targets-mobile-list]");
      const mobileTests = Array.from(
        mobileList?.querySelectorAll("[data-targets-mobile-record]") ?? [],
      );
      if (desktopList?.getClientRects().length) {
        problems.push("desktop Tests table remains visible at 390px");
      }
      if (!mobileList?.getClientRects().length) {
        problems.push("mobile Tests list is not visible at 390px");
      }
      if (mobileTests.length < 2) {
        problems.push(
          "mobile Tests inventory needs at least two records to prove row association",
        );
      }
      for (const [index, record] of mobileTests.entries()) {
        const testName = record.getAttribute("data-test-name") ?? "";
        const recordBox = record.getBoundingClientRect();
        // Row association must include permission-aware disabled mutations: a
        // read-only user still needs to see which action exists and why it is
        // unavailable. Target/focus checks already exclude disabled controls.
        const controls = Array.from(record.querySelectorAll("button"));
        const labels = controls.map(
          (control) => control.getAttribute("aria-label") ?? "",
        );
        const expected = [
          `Results for ${testName}`,
          `View YAML for ${testName}`,
          `Delete ${testName}`,
        ];
        if (!testName || expected.some((label) => !labels.includes(label))) {
          problems.push(
            `mobile Tests record ${index + 1} does not expose all row actions`,
          );
        }
        for (const control of controls) {
          const box = control.getBoundingClientRect();
          if (
            box.left < recordBox.left - 1 ||
            box.right > recordBox.right + 1 ||
            box.left < -1 ||
            box.right > window.innerWidth + 1
          ) {
            problems.push(
              `mobile Tests action "${control.textContent?.trim() || control.tagName.toLowerCase()}" is clipped`,
            );
          }
        }
        if (record.scrollWidth - record.clientWidth > 1) {
          problems.push(
            `mobile Tests record ${index + 1} requires horizontal scrolling`,
          );
        }
      }

      const form = toolbar.querySelector("form");
      if (!form) {
        problems.push("missing Targets filter form");
      } else {
        const items = Array.from(form.children);
        const rowTops = new Set(
          items.map((item) => Math.round(item.getBoundingClientRect().top)),
        );
        if (items.length > 1 && rowTops.size !== items.length) {
          problems.push("Targets mobile filters are not a one-column stack");
        }
        if (form.scrollWidth - form.clientWidth > 1) {
          problems.push("Targets mobile filters overflow their toolbar");
        }
      }

      const coverage = document.querySelector("[data-targets-coverage]");
      const records = Array.from(
        coverage?.querySelectorAll("[data-coverage-mobile-record]") ?? [],
      );
      const desktopTable = coverage?.querySelector("table");
      if (desktopTable?.getClientRects().length) {
        problems.push("desktop coverage table remains visible at 390px");
      }
      if (records.length < 2) {
        problems.push(
          "mobile coverage needs at least two receipts to prove row association",
        );
      }
      const seenTestIDs = new Set();
      for (const [index, record] of records.entries()) {
        const testID = record.getAttribute("data-test-id") ?? "";
        const expectedText = [
          record.getAttribute("data-test-name"),
          record.getAttribute("data-probe-family"),
          record.getAttribute("data-target"),
        ].filter(Boolean);
        const coverageState = record.getAttribute("data-coverage-status") ?? "";
        const receipt = record.querySelector("[data-cadence-receipt]");
        const evidence = record.querySelector("[data-coverage-evidence]");
        const recordBox = record.getBoundingClientRect();
        const coverageBox = coverage?.getBoundingClientRect();

        if (!testID || seenTestIDs.has(testID)) {
          problems.push(
            `mobile coverage receipt ${index + 1} has an ambiguous test ID`,
          );
        }
        seenTestIDs.add(testID);
        if (
          expectedText.some(
            (value) => !record.textContent?.includes(String(value)),
          ) ||
          !coverageState ||
          !evidence ||
          !evidence.textContent?.trim() ||
          !record.textContent
            ?.toLowerCase()
            .includes(coverageState.replaceAll("_", "-"))
        ) {
          problems.push(
            `mobile coverage receipt ${index + 1} does not visibly group test, probe, target, and coverage state`,
          );
        }
        if (
          !receipt ||
          receipt.getAttribute("data-test-id") !== testID ||
          receipt.closest("[data-coverage-mobile-record]") !== record
        ) {
          problems.push(
            `mobile coverage receipt ${index + 1} associates cadence with the wrong test`,
          );
        }
        if (
          record.scrollWidth - record.clientWidth > 1 ||
          (coverageBox &&
            (recordBox.left < coverageBox.left - 1 ||
              recordBox.right > coverageBox.right + 1))
        ) {
          problems.push(
            `mobile coverage receipt ${index + 1} overflows its card`,
          );
        }
      }
    }
    return problems;
  }, viewportName);
}

// The graph is Topology's hero artifact. The complete history/filter stack is
// kept in a native disclosure so it stays keyboard-reachable without consuming
// the first viewport in the default live state.
async function topologyHierarchyCheck(page, viewportName) {
  return page.evaluate(async (currentViewport) => {
    const problems = [];
    // Earlier generic focus checks visit every control and may leave the page
    // scrolled. Hero hierarchy is an initial-frame contract, so measure it from
    // the same origin a user gets on a fresh navigation.
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    await new Promise((resolve) =>
      requestAnimationFrame(() => requestAnimationFrame(resolve)),
    );
    const controls = document.querySelector("[data-topology-controls]");
    const graphCard = document.querySelector("[data-topology-graph]");
    const graph = graphCard?.querySelector('[aria-label="Topology graph"]');
    const instruction = graphCard?.querySelector("[data-card-heading] p");
    const viewport = graphCard?.querySelector("[data-topology-viewport]");
    const navigation = graphCard?.querySelector("[data-topology-navigation]");
    const position = navigation?.querySelector("[data-topology-position]");
    const topologyTable = Array.from(document.querySelectorAll("table")).find(
      (table) =>
        table.querySelector("caption")?.textContent?.trim() ===
        "Topology nodes",
    );
    if (!controls) problems.push("missing history/filter disclosure marker");
    if (!graphCard) problems.push("missing dependency graph marker");
    if (!graph) problems.push("missing rendered dependency graph");
    if (!instruction)
      problems.push("missing primary node-selection instruction");
    if (!viewport) problems.push("missing topology graph viewport");
    if (!navigation) problems.push("missing graph exploration controls");
    if (!position) problems.push("missing graph column-position status");
    if (!topologyTable)
      problems.push("missing exact Topology nodes table alternative");
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
    if (!viewport || !navigation || !position) return problems;

    // The generic focus audit runs first and correctly scrolls off-screen SVG
    // buttons into view. Restore the product's true initial frame before
    // checking its mobile exploration affordance.
    if (currentViewport === "mobile") {
      viewport.scrollTo({ left: 0, behavior: "auto" });
      await new Promise((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(resolve)),
      );
    }

    const positionText = position.textContent?.trim() ?? "";
    if (
      !/^All \d+ columns visible(?:\s*·|$)|^Columns? \d+(?:–\d+)? of \d+(?:\s*·|$)/.test(
        positionText,
      )
    ) {
      problems.push(
        "graph navigation does not expose its current column position",
      );
    }

    if (currentViewport === "topology-laptop") {
      if (viewport.scrollWidth - viewport.clientWidth > 1) {
        problems.push(
          "topology laptop overview still requires horizontal scrolling",
        );
      }

      const viewportRect = viewport.getBoundingClientRect();
      const nodes = Array.from(graph.querySelectorAll('[role="button"]'));
      const partiallyClipped = nodes.filter((node) => {
        const rect = node.getBoundingClientRect();
        const overlaps =
          rect.right > viewportRect.left &&
          rect.left < viewportRect.right &&
          rect.bottom > viewportRect.top &&
          rect.top < viewportRect.bottom;
        const fullyVisible =
          rect.left >= viewportRect.left - 1 &&
          rect.right <= viewportRect.right + 1 &&
          rect.top >= viewportRect.top - 1 &&
          rect.bottom <= viewportRect.bottom + 1;
        return overlaps && !fullyVisible;
      });
      if (partiallyClipped.length > 0) {
        problems.push(
          `${partiallyClipped.length} focusable topology node(s) are partially clipped`,
        );
      }

      for (const kind of ["hop", "device", "service"]) {
        const node = nodes.find((candidate) =>
          candidate.getAttribute("aria-label")?.startsWith(`${kind} `),
        );
        if (!node) {
          problems.push(`missing ${kind} node in the laptop dependency chain`);
          continue;
        }
        const rect = node.getBoundingClientRect();
        if (
          rect.left < viewportRect.left - 1 ||
          rect.right > viewportRect.right + 1 ||
          rect.top < viewportRect.top - 1 ||
          rect.bottom > viewportRect.bottom + 1
        ) {
          problems.push(
            `${kind} node is not fully visible in the laptop overview`,
          );
        }
        if (rect.width < 110) {
          problems.push(
            `${kind} node is too small to read in the laptop overview`,
          );
        }
      }
    }

    if (
      currentViewport === "mobile" &&
      viewport.scrollWidth > viewport.clientWidth + 1
    ) {
      const next = navigation.querySelector("button:last-of-type");
      if (!next || next.disabled) {
        problems.push(
          "mobile graph overflow has no enabled forward exploration control",
        );
      } else {
        const beforeScroll = viewport.scrollLeft;
        const beforePosition = position.textContent?.trim();
        next.click();
        await new Promise((resolve) =>
          requestAnimationFrame(() => requestAnimationFrame(resolve)),
        );
        if (viewport.scrollLeft <= beforeScroll + 1) {
          problems.push("mobile graph Next control does not move the viewport");
        }
        if (position.textContent?.trim() === beforePosition) {
          problems.push(
            "mobile graph position does not update after navigation",
          );
        }
      }
    }
    return problems;
  }, viewportName);
}

// Path's topology SVG deliberately keeps its full hop-by-hop width inside a
// local viewport. This rendered check protects the mobile contract that DOM
// tests cannot measure: real overflow, visible guidance, and focus-driven
// scrolling that leaves both the first and destination hops fully visible.
async function pathGraphMobileCheck(page, viewportName) {
  if (viewportName !== "mobile") return [];
  return page.evaluate(async () => {
    const problems = [];
    const viewport = document.querySelector("[data-path-graph-scroll]");
    const graph = viewport?.querySelector("[data-path-graph]");
    const hint = document.querySelector("[data-path-graph-scroll-hint]");
    if (!viewport) problems.push("missing local path graph scroll viewport");
    if (!graph) problems.push("missing rendered path graph");
    if (!hint) problems.push("missing visible path graph scroll guidance");
    if (!viewport || !graph || !hint) return problems;

    const hintStyle = getComputedStyle(hint);
    if (
      !hint.textContent?.trim() ||
      hintStyle.display === "none" ||
      hintStyle.visibility === "hidden"
    ) {
      problems.push("path graph scroll guidance is not visibly rendered");
    }

    const declaredWidth = Number(graph.getAttribute("width"));
    const renderedWidth = graph.getBoundingClientRect().width;
    if (
      !Number.isFinite(declaredWidth) ||
      declaredWidth <= viewport.clientWidth ||
      renderedWidth < declaredWidth - 1
    ) {
      problems.push(
        `path graph lost its intrinsic width: declared ${declaredWidth}, rendered ${Math.round(renderedWidth)}, viewport ${viewport.clientWidth}`,
      );
    }
    if (viewport.scrollWidth <= viewport.clientWidth + 1) {
      problems.push("mobile path graph has no local horizontal overflow");
    }

    const hops = Array.from(graph.querySelectorAll('[role="button"]'));
    const first = hops[0];
    const destination =
      hops.find((hop) =>
        hop.getAttribute("aria-label")?.includes("(destination)"),
      ) ?? hops.at(-1);
    if (!first) problems.push("path graph has no focusable first hop");
    if (!destination) problems.push("path graph has no focusable destination");
    if (!first || !destination) return problems;

    const fullyVisible = (hop) => {
      const viewportRect = viewport.getBoundingClientRect();
      const hopRect = hop.getBoundingClientRect();
      return (
        hopRect.left >= viewportRect.left - 1 &&
        hopRect.right <= viewportRect.right + 1 &&
        hopRect.top >= viewportRect.top - 1 &&
        hopRect.bottom <= viewportRect.bottom + 1
      );
    };
    const settle = () =>
      new Promise((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(resolve)),
      );

    viewport.scrollTo({ left: 0, behavior: "auto" });
    first.focus();
    await settle();
    if (document.activeElement !== first || !fullyVisible(first)) {
      problems.push("keyboard focus does not reveal the first path hop");
    }

    const beforeDestination = viewport.scrollLeft;
    destination.focus();
    await settle();
    if (document.activeElement !== destination || !fullyVisible(destination)) {
      problems.push("keyboard focus does not reveal the destination path hop");
    }
    if (viewport.scrollLeft <= beforeDestination + 1) {
      problems.push("destination focus does not advance the path viewport");
    }
    const focusStyle = getComputedStyle(destination);
    if (
      focusStyle.outlineStyle === "none" ||
      Number.parseFloat(focusStyle.outlineWidth || "0") <= 0
    ) {
      problems.push("focused destination path hop has no visible outline");
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
    for (const scopedPath of [
      "/v1/flows/top",
      "/v1/flows/capacity",
      "/v1/flows/anomalies",
      "/v1/results/history",
    ]) {
      if (
        !requests.some((raw) => {
          const url = new URL(raw, location.origin);
          return (
            url.pathname === scopedPath &&
            url.searchParams.get("window") === "1h"
          );
        })
      ) {
        problems.push(`dashboard scope did not reach ${scopedPath}`);
      }
    }
    const body = normalize(document.body.textContent);
    for (const requiredText of [
      "Acme Industries",
      "00000000-0000-0000-0000-000000000001",
      "Absolute time · UTC",
      "Relative time scope",
      "Last 1 hour coordinated",
      "Latest state",
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

async function dashboardScopeGeometryChecks(page, viewportName) {
  return page.evaluate((name) => {
    const problems = [];
    const scope = document.querySelector(
      '[aria-label="Dashboard scope and preset"]',
    );
    const context = scope?.querySelector("[data-dashboard-scope-context]");
    const tenantID = scope?.querySelector("[data-dashboard-tenant-id]");
    const timeRange = scope?.querySelector("[data-dashboard-time-range]");
    const timeScope = scope?.querySelector("select");
    if (!scope || !context || !tenantID || !timeRange || !timeScope) {
      return ["missing grouped dashboard tenant/time scope"];
    }
    if (timeScope.value !== "1h") {
      problems.push(`dashboard time scope is ${timeScope.value}, expected 1h`);
    }
    if (
      String(tenantID.textContent || "").trim() !==
      "00000000-0000-0000-0000-000000000001"
    ) {
      problems.push("full immutable tenant ID is not visibly rendered");
    }
    const scopeBox = scope.getBoundingClientRect();
    for (const [label, element] of [
      ["scope context", context],
      ["tenant ID", tenantID],
      ["absolute UTC range", timeRange],
    ]) {
      const box = element.getBoundingClientRect();
      if (
        box.left < scopeBox.left - 1 ||
        box.right > scopeBox.right + 1 ||
        box.width < 1 ||
        box.height < 1
      ) {
        problems.push(
          `${label} escapes or disappears from the scope strip ` +
            `(item ${box.left.toFixed(1)}–${box.right.toFixed(1)}, ` +
            `scope ${scopeBox.left.toFixed(1)}–${scopeBox.right.toFixed(1)})`,
        );
      }
    }
    if (
      tenantID.scrollWidth > tenantID.clientWidth + 1 ||
      timeRange.scrollWidth > timeRange.clientWidth + 1
    ) {
      problems.push("dashboard tenant/time scope clips horizontal content");
    }
    if (name === "dashboard-laptop") {
      const tenantLineHeight = Number.parseFloat(
        getComputedStyle(tenantID).lineHeight,
      );
      const timeLineHeight = Number.parseFloat(
        getComputedStyle(timeRange).lineHeight,
      );
      if (
        Number.isFinite(tenantLineHeight) &&
        tenantID.getBoundingClientRect().height > tenantLineHeight * 1.5
      ) {
        problems.push("tenant ID fragments across lines at 1280x720");
      }
      if (
        Number.isFinite(timeLineHeight) &&
        timeRange.getBoundingClientRect().height > timeLineHeight * 1.5
      ) {
        problems.push("absolute UTC range fragments across lines at 1280x720");
      }
    }
    return problems;
  }, viewportName);
}

async function deviceCollectionReceiptChecks(page) {
  return page.evaluate(() => {
    const problems = [];
    const normalize = (value) =>
      String(value || "")
        .replace(/\s+/g, " ")
        .trim();
    const list = document.querySelector(
      '[aria-label="Per-target device collection outcome receipts"]',
    );
    if (!list) return ["missing responsive device collection receipt list"];
    if (list.tagName !== "UL") {
      problems.push(
        `device collection receipts use ${list.tagName.toLowerCase()}, want a semantic list`,
      );
    }
    if (list.querySelector("table")) {
      problems.push("device collection receipts still contain a wide table");
    }
    if (list.scrollWidth > list.clientWidth + 1) {
      problems.push(
        `device collection receipt list scrolls horizontally: ${list.scrollWidth}px > ${list.clientWidth}px`,
      );
    }

    const listBox = list.getBoundingClientRect();
    const receipts = [...list.querySelectorAll(":scope > li")];
    if (receipts.length === 0) {
      problems.push("device collection receipt list has no populated receipts");
    }
    for (const [index, receipt] of receipts.entries()) {
      const receiptBox = receipt.getBoundingClientRect();
      if (
        receipt.scrollWidth > receipt.clientWidth + 1 ||
        receiptBox.left < listBox.left - 1 ||
        receiptBox.right > listBox.right + 1
      ) {
        problems.push(
          `device collection receipt ${index + 1} escapes its list`,
        );
      }
      const labels = new Map(
        [...receipt.querySelectorAll("dt")].map((term) => [
          normalize(term.textContent),
          term.parentElement,
        ]),
      );
      for (const required of [
        "Outcome / reason",
        "Rows",
        "Last attempt",
        "Last success",
        "Safe next action",
      ]) {
        if (!labels.has(required)) {
          problems.push(
            `device collection receipt ${index + 1} is missing ${required}`,
          );
        }
      }
      const safeAction = labels.get("Safe next action");
      const actionText = normalize(
        safeAction?.querySelector("dd")?.textContent,
      );
      if (!actionText) {
        problems.push(
          `device collection receipt ${index + 1} has no visible safe next action`,
        );
      }
      if (safeAction) {
        const actionBox = safeAction.getBoundingClientRect();
        if (
          actionBox.width < 1 ||
          actionBox.height < 1 ||
          actionBox.left < receiptBox.left - 1 ||
          actionBox.right > receiptBox.right + 1
        ) {
          problems.push(
            `device collection receipt ${index + 1} hides its safe next action`,
          );
        }
      }
    }
    return problems;
  });
}

async function flowIngestQualityReceiptChecks(page) {
  return page.evaluate(() => {
    const problems = [];
    const normalize = (value) =>
      String(value || "")
        .replace(/\s+/g, " ")
        .trim();
    const list = document.querySelector(
      '[aria-label="Per-exporter flow ingest quality receipts"]',
    );
    if (!list) return ["missing responsive flow ingest quality receipt list"];
    if (list.tagName !== "UL") {
      problems.push(
        `flow ingest receipts use ${list.tagName.toLowerCase()}, want a semantic list`,
      );
    }
    if (list.querySelector("table")) {
      problems.push("flow ingest receipts contain a wide table");
    }
    if (list.scrollWidth > list.clientWidth + 1) {
      problems.push(
        `flow ingest receipt list scrolls horizontally: ${list.scrollWidth}px > ${list.clientWidth}px`,
      );
    }
    const listBox = list.getBoundingClientRect();
    const receipts = [...list.querySelectorAll(":scope > li")];
    if (receipts.length === 0) {
      problems.push("flow ingest receipt list has no populated receipts");
    }
    for (const [index, receipt] of receipts.entries()) {
      const receiptBox = receipt.getBoundingClientRect();
      if (
        receipt.scrollWidth > receipt.clientWidth + 1 ||
        receiptBox.left < listBox.left - 1 ||
        receiptBox.right > listBox.right + 1
      ) {
        problems.push(`flow ingest receipt ${index + 1} escapes its list`);
      }
      const labels = new Map(
        [...receipt.querySelectorAll("dt")].map((term) => [
          normalize(term.textContent),
          term.parentElement,
        ]),
      );
      for (const required of [
        "Health / reason",
        "Packets",
        "Valid records",
        "Last packet",
        "Safe next action",
      ]) {
        if (!labels.has(required)) {
          problems.push(
            `flow ingest receipt ${index + 1} is missing ${required}`,
          );
        }
      }
      const safeAction = labels.get("Safe next action");
      const actionText = normalize(
        safeAction?.querySelector("dd")?.textContent,
      );
      if (!actionText) {
        problems.push(
          `flow ingest receipt ${index + 1} has no visible safe next action`,
        );
      }
      if (safeAction) {
        const actionBox = safeAction.getBoundingClientRect();
        if (
          actionBox.width < 1 ||
          actionBox.height < 1 ||
          actionBox.left < receiptBox.left - 1 ||
          actionBox.right > receiptBox.right + 1
        ) {
          problems.push(
            `flow ingest receipt ${index + 1} hides its safe next action`,
          );
        }
      }
    }
    return problems;
  });
}

async function flowTopTalkerChecks(page, viewportName) {
  return page.evaluate((name) => {
    const problems = [];
    const desktop = document.querySelector("[data-flow-top-desktop]");
    const mobile = document.querySelector("[data-flow-top-mobile]");
    const visible = (element) => {
      if (!element) return false;
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return (
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        rect.width > 0 &&
        rect.height > 0
      );
    };
    const checkContributorAction = (evidence, bounds, label) => {
      const known = evidence?.dataset.flowKnownObservers === "true";
      const action = evidence?.querySelector("[data-flow-exporter-action]");
      if (known && !action) {
        problems.push(`${label} is missing its contributor action`);
        return;
      }
      if (!known && action) {
        problems.push(`${label} invents a contributor action without identity`);
        return;
      }
      if (!action) return;
      const actionBox = action.getBoundingClientRect();
      if (
        !visible(action) ||
        actionBox.left < bounds.left - 1 ||
        actionBox.right > bounds.right + 1
      ) {
        problems.push(`${label} hides its contributor action`);
      }
    };

    if (!desktop)
      problems.push("missing desktop Flow top-talkers presentation");
    if (!mobile) problems.push("missing mobile Flow top-talkers presentation");
    if (!desktop || !mobile) return problems;

    if (name === "mobile") {
      if (visible(desktop)) {
        problems.push(
          "desktop Flow top-talkers table remains visible at 390px",
        );
      }
      if (!visible(mobile)) {
        problems.push(
          "mobile Flow top-talkers records are not visible at 390px",
        );
        return problems;
      }
      if (mobile.tagName !== "UL") {
        problems.push(
          `mobile Flow top talkers use ${mobile.tagName.toLowerCase()}, want a semantic list`,
        );
      }
      if (mobile.querySelector("table")) {
        problems.push("mobile Flow top talkers still contain a wide table");
      }
      if (mobile.scrollWidth > mobile.clientWidth + 1) {
        problems.push(
          `mobile Flow top-talkers list scrolls horizontally: ${mobile.scrollWidth}px > ${mobile.clientWidth}px`,
        );
      }

      const listBox = mobile.getBoundingClientRect();
      const records = [...mobile.querySelectorAll(":scope > li")];
      if (records.length === 0) {
        problems.push("mobile Flow top-talkers list has no populated records");
      }
      for (const [index, record] of records.entries()) {
        const recordBox = record.getBoundingClientRect();
        if (
          record.scrollWidth > record.clientWidth + 1 ||
          recordBox.left < listBox.left - 1 ||
          recordBox.right > listBox.right + 1
        ) {
          problems.push(
            `mobile Flow top-talker record ${index + 1} escapes its list`,
          );
        }
        for (const field of [
          "contributor",
          "bytes",
          "packets",
          "flows",
          "observation",
        ]) {
          const evidence = record.querySelector(
            `[data-flow-top-field="${field}"]`,
          );
          if (!evidence) {
            problems.push(
              `mobile Flow top-talker record ${index + 1} is missing ${field}`,
            );
            continue;
          }
          const evidenceBox = evidence.getBoundingClientRect();
          if (
            !visible(evidence) ||
            evidenceBox.left < recordBox.left - 1 ||
            evidenceBox.right > recordBox.right + 1
          ) {
            problems.push(
              `mobile Flow top-talker record ${index + 1} hides ${field}`,
            );
          }
        }
        const observation = record.querySelector(
          "[data-flow-observation-evidence]",
        );
        if (!observation) {
          problems.push(
            `mobile Flow top-talker record ${index + 1} is missing observation evidence`,
          );
        } else {
          checkContributorAction(
            observation,
            recordBox,
            `mobile Flow top-talker record ${index + 1}`,
          );
        }
      }
    } else {
      if (!visible(desktop)) {
        problems.push("desktop Flow top-talkers table is not visible");
      }
      if (visible(mobile)) {
        problems.push(
          "mobile Flow top-talkers records remain visible on desktop",
        );
      }
      if (!desktop.querySelector("table")) {
        problems.push("desktop Flow top talkers are not a semantic table");
      }
      const observations = [
        ...desktop.querySelectorAll("[data-flow-observation-evidence]"),
      ];
      if (observations.length === 0) {
        problems.push("desktop Flow top talkers have no observation evidence");
      }
      for (const [index, observation] of observations.entries()) {
        checkContributorAction(
          observation,
          desktop.getBoundingClientRect(),
          `desktop Flow top-talker row ${index + 1}`,
        );
      }
    }
    return problems;
  }, viewportName);
}

async function deviceConfigDiffChecks(page, viewportName, axeSource) {
  const problems = await page.evaluate((name) => {
    const issues = [];
    const desktop = document.querySelector("[data-config-versions-desktop]");
    const mobile = document.querySelector("[data-config-versions-mobile]");
    const visible = (element) => {
      if (!element) return false;
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return (
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        rect.width > 0 &&
        rect.height > 0
      );
    };

    if (!desktop) issues.push("missing desktop config-version presentation");
    if (!mobile) issues.push("missing mobile config-version presentation");
    if (!desktop || !mobile) return issues;

    if (name === "mobile") {
      if (visible(desktop))
        issues.push("desktop config-version table remains visible at 390px");
      if (!visible(mobile))
        issues.push("mobile config-version records are not visible at 390px");
      if (mobile.tagName !== "UL")
        issues.push("mobile config versions are not a semantic list");
      if (mobile.querySelector("table"))
        issues.push("mobile config versions still contain a wide table");
      if (mobile.scrollWidth > mobile.clientWidth + 1)
        issues.push("mobile config-version records scroll horizontally");
    } else {
      if (!visible(desktop))
        issues.push("desktop config-version table is not visible");
      if (visible(mobile))
        issues.push("mobile config-version records remain visible on desktop");
      if (!desktop.querySelector("table"))
        issues.push("desktop config versions are not a semantic table");
      if (desktop.scrollWidth > desktop.clientWidth + 1)
        issues.push(
          "desktop config-version evidence requires horizontal discovery",
        );
    }
    return issues;
  }, viewportName);
  if (problems.length > 0) return problems;

  const scope =
    viewportName === "mobile"
      ? "[data-config-versions-mobile]"
      : "[data-config-versions-desktop]";
  const action = page
    .locator(`${scope} button[aria-haspopup="dialog"]`)
    .first();
  if ((await action.count()) !== 1) {
    return [...problems, `${viewportName} config comparison action is missing`];
  }

  await action.click();
  const dialog = page.locator('[role="dialog"]');
  await dialog.waitFor({ state: "visible" });

  const dialogAxe = blockingAxeResults(await runAxe(page, axeSource));
  for (const violation of dialogAxe) {
    problems.push(`config comparison axe ${violation.id}: ${violation.help}`);
  }

  problems.push(
    ...(await page.evaluate(() => {
      const issues = [];
      const dialog = document.querySelector('[role="dialog"]');
      const viewport = document.querySelector(
        '[aria-label="Scrollable redacted config comparison"]',
      );
      if (!dialog) return ["config comparison dialog did not open"];
      const dialogBox = dialog.getBoundingClientRect();
      if (
        dialogBox.left < -1 ||
        dialogBox.top < -1 ||
        dialogBox.right > innerWidth + 1 ||
        dialogBox.bottom > innerHeight + 1
      ) {
        issues.push(
          `config comparison escapes viewport: ${Math.round(dialogBox.left)},${Math.round(dialogBox.top)} ${Math.round(dialogBox.right)},${Math.round(dialogBox.bottom)} within ${innerWidth}x${innerHeight}`,
        );
      }
      if (document.documentElement.scrollWidth > innerWidth + 1) {
        issues.push("config comparison widens the document");
      }
      if (!dialog.contains(document.activeElement)) {
        issues.push("config comparison does not receive focus");
      }
      if (!viewport) {
        issues.push("config comparison has no local evidence viewport");
      } else {
        const style = getComputedStyle(viewport);
        if (viewport.getAttribute("dir") !== "ltr")
          issues.push("config evidence is not isolated as LTR");
        if (style.overflowX !== "auto" || style.overflowY !== "auto")
          issues.push("config evidence is not locally scrollable");
      }
      const codes = [...dialog.querySelectorAll("code")].map((node) =>
        node.textContent?.trim(),
      );
      for (const hash of ["abcdef0123456789", "0123456789abcdef"]) {
        if (!codes.includes(hash))
          issues.push(`config comparison omits full hash ${hash}`);
      }
      for (const status of ["added", "removed", "unchanged"]) {
        if (!dialog.querySelector(`[data-config-diff-row="${status}"]`))
          issues.push(`config comparison omits ${status} line evidence`);
      }
      if (!codes.some((text) => text?.includes("[REDACTED]")))
        issues.push("config comparison omits redacted-content evidence");
      return issues;
    })),
  );

  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden" });
  if (
    !(await action.evaluate((element) => document.activeElement === element))
  ) {
    problems.push("config comparison does not restore trigger focus");
  }
  return problems;
}

async function configCorrelationPivotChecks(page, axeSource) {
  const problems = [];
  const change = page
    .getByRole("button", {
      name: "Config drift detected on edge-r1",
      exact: true,
    })
    .last();
  if ((await change.count()) !== 1) {
    return ["incident config-drift candidate is missing"];
  }
  await change.click();

  const pivot = page.getByRole("link", {
    name: "Review redacted change",
    exact: true,
  });
  // React Router updates the address bar before React commits the selected
  // evidence inspector. Locator.count() does not auto-wait, so checking it
  // immediately races that commit (most visibly in the mobile viewport).
  try {
    await pivot.first().waitFor({ state: "visible", timeout: 10_000 });
  } catch {
    return ["incident config-drift pivot is missing"];
  }
  const pivotCount = await pivot.count();
  if (pivotCount !== 1) {
    return [
      `incident config-drift pivot is not unique: expected 1, found ${pivotCount}`,
    ];
  }
  const href = await pivot.getAttribute("href");
  const target = href ? new URL(href, page.url()) : undefined;
  if (
    !target ||
    !target.pathname.endsWith("/planes/device") ||
    target.searchParams.get("config") !== "config-2" ||
    target.searchParams.get("previous_config") !== "config-1" ||
    target.searchParams.get("ctx_incident") !== "inc-dashboard"
  ) {
    problems.push(`incident config-drift pivot lost exact context: ${href}`);
  }

  await pivot.click();
  const dialog = page.getByRole("dialog", {
    name: "edge-r1: version 1 → 2",
    exact: true,
  });
  await dialog.waitFor({ state: "visible" });
  for (const expected of [
    "description checkout uplink",
    "description payments uplink",
  ]) {
    if ((await dialog.getByText(expected, { exact: true }).count()) !== 1) {
      problems.push(`incident config pivot omits exact diff line: ${expected}`);
    }
  }
  const dialogAxe = blockingAxeResults(await runAxe(page, axeSource));
  for (const violation of dialogAxe) {
    problems.push(
      `incident config pivot axe ${violation.id}: ${violation.help}`,
    );
  }

  const back = dialog.getByRole("link", {
    name: "Return to incident",
    exact: true,
  });
  if ((await back.count()) !== 1) {
    problems.push("config comparison omits incident return action");
    return problems;
  }
  await back.click();
  await page.waitForURL((url) => {
    return (
      url.pathname.endsWith("/incidents") &&
      url.searchParams.get("incident") === "inc-dashboard"
    );
  });
  const incidentRoom = page.getByRole("region", {
    name: "Unified five-plane incident room",
    exact: true,
  });
  // A URL transition completes before the destination query and route commit.
  // Wait for the user-visible room, then still reject duplicates explicitly.
  try {
    await incidentRoom.first().waitFor({ state: "visible", timeout: 10_000 });
  } catch {
    problems.push(
      "config comparison did not return to the originating incident",
    );
    return problems;
  }
  const incidentRoomCount = await incidentRoom.count();
  if (incidentRoomCount !== 1) {
    problems.push(
      `originating incident room is not unique: expected 1, found ${incidentRoomCount}`,
    );
  }
  return problems;
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
  await page.setContent(`
    <section style="width:160px;overflow:hidden">
      <div style="display:flex;width:260px">
        <button style="flex:0 0 120px">Visible control</button>
        <button style="flex:0 0 140px">Planted clipped control</button>
      </div>
    </section>
  `);
  const clippedControls = await interactiveClippingCheck(page);
  if (
    !clippedControls.some((problem) =>
      problem.includes("Planted clipped control"),
    )
  ) {
    throw new Error(
      "self-check failed: interactive-clipping check did not catch a control beyond a hidden-overflow ancestor",
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
  await page.setContent(`
    <ul
      aria-label="Per-target device collection outcome receipts"
      style="width:160px;overflow:hidden"
    >
      <li style="width:300px">
        <dl>
          <div><dt>Outcome / reason</dt><dd>Failed because the protocol read failed.</dd></div>
          <div><dt>Rows</dt><dd>0</dd></div>
          <div><dt>Last attempt</dt><dd>Now</dd></div>
          <div><dt>Last success</dt><dd>Never</dd></div>
          <div><dt>Safe next action</dt><dd>Verify local access.</dd></div>
        </dl>
      </li>
    </ul>
  `);
  const deviceReceipt = await deviceCollectionReceiptChecks(page);
  if (
    !deviceReceipt.some(
      (problem) =>
        problem.includes("scrolls horizontally") ||
        problem.includes("escapes its list"),
    )
  ) {
    throw new Error(
      "self-check failed: device receipt check did not catch planted horizontal clipping",
    );
  }
  await page.setContent(`
    <ul
      aria-label="Per-exporter flow ingest quality receipts"
      style="width:160px;overflow:hidden"
    >
      <li style="width:320px">
        <dl>
          <div><dt>Health / reason</dt><dd>Degraded because templates are missing.</dd></div>
          <div><dt>Packets</dt><dd>9</dd></div>
          <div><dt>Valid records</dt><dd>0</dd></div>
          <div><dt>Last packet</dt><dd>Now</dd></div>
          <div><dt>Safe next action</dt><dd>Verify exporter templates.</dd></div>
        </dl>
      </li>
    </ul>
  `);
  const flowReceipt = await flowIngestQualityReceiptChecks(page);
  if (
    !flowReceipt.some(
      (problem) =>
        problem.includes("scrolls horizontally") ||
        problem.includes("escapes its list"),
    )
  ) {
    throw new Error(
      "self-check failed: flow receipt check did not catch planted horizontal clipping",
    );
  }
  await page.setViewportSize(
    viewports.find((viewport) => viewport.name === "mobile"),
  );
  await page.setContent(`
    <div data-flow-top-desktop style="display:none">
      <table><tbody><tr><td>Desktop row</td></tr></tbody></table>
    </div>
    <ul data-flow-top-mobile style="display:block;width:160px;overflow:hidden">
      <li style="width:320px">
        <button data-flow-top-field="contributor">10.0.0.1</button>
        <dl>
          <div data-flow-top-field="bytes"><dt>Bytes</dt><dd>1 kB</dd></div>
          <div data-flow-top-field="packets"><dt>Packets</dt><dd>1</dd></div>
          <div data-flow-top-field="flows"><dt>Flows</dt><dd>1</dd></div>
        </dl>
        <span data-flow-top-field="observation">
          <span data-flow-observation-evidence data-flow-known-observers="true">
            Observed by 2 exporters
          </span>
        </span>
      </li>
    </ul>
  `);
  const flowTopTalkers = await flowTopTalkerChecks(page, "mobile");
  if (
    !flowTopTalkers.some((problem) =>
      problem.includes("missing its contributor action"),
    )
  ) {
    throw new Error(
      "self-check failed: Flow top-talker check did not catch a planted missing contributor action",
    );
  }
  await page.setViewportSize(dashboardLaptopViewport);
  await page.setContent(`
    <section aria-label="Dashboard scope and preset" style="width:900px">
      <div data-dashboard-scope-context>
        <label>
          Relative time scope
          <select>
            <option value="1h" selected>Last 1 hour</option>
          </select>
        </label>
        <code
          data-dashboard-tenant-id
          style="display:block;width:90px;line-height:16px;overflow-wrap:anywhere"
        >00000000-0000-0000-0000-000000000001</code>
        <strong
          data-dashboard-time-range
          style="display:block;width:140px;line-height:20px;white-space:normal"
        >Jul 27, 2026, 06:47:28 UTC – Jul 27, 2026, 07:47:28 UTC</strong>
      </div>
    </section>
  `);
  const dashboardScope = await dashboardScopeGeometryChecks(
    page,
    dashboardLaptopViewport.name,
  );
  if (
    !dashboardScope.some((problem) =>
      problem.includes("tenant ID fragments across lines"),
    ) ||
    !dashboardScope.some((problem) =>
      problem.includes("absolute UTC range fragments across lines"),
    )
  ) {
    throw new Error(
      "self-check failed: dashboard scope check did not catch planted tenant/time fragmentation",
    );
  }
  await page.setViewportSize(targetsLaptopViewport);
  await page.setContent(`
    <section data-targets-authoring>Author with AI</section>
    <section data-targets-inventory style="margin-top:1000px">
      <div data-targets-filter-toolbar>
        <form>
          <input aria-label="Find">
          <div data-saved-view-composer style="width:300px">
            <input aria-label="View name">
            <button style="transform:translate(-300px, 60px)">Save view</button>
          </div>
        </form>
      </div>
      <table><tbody><tr><td>Planted test</td></tr></tbody></table>
    </section>
  `);
  const targetsHierarchy = await targetsHierarchyCheck(
    page,
    targetsLaptopViewport.name,
  );
  if (
    !targetsHierarchy.some((problem) =>
      problem.includes("AI authoring precedes"),
    ) ||
    !targetsHierarchy.some((problem) =>
      problem.includes("inventory begins below the 1280x720 viewport"),
    ) ||
    !targetsHierarchy.some((problem) =>
      problem.includes("first populated Tests row falls below"),
    ) ||
    !targetsHierarchy.some((problem) =>
      problem.includes("saved-view input and action detach"),
    )
  ) {
    throw new Error(
      "self-check failed: Targets hierarchy check did not catch the planted authoring-first regression",
    );
  }
  await page.setViewportSize(viewports[1]);
  await page.setContent(`
    <section data-targets-inventory>
      <div data-targets-filter-toolbar><form><label>Find<input></label></form></div>
      <div data-targets-desktop-list><table><tbody><tr><td>Desktop test</td></tr></tbody></table></div>
      <ul data-targets-mobile-list>
        <li data-targets-mobile-record data-test-id="test-1" data-test-name="edge-one">
          edge-one
        </li>
      </ul>
    </section>
    <section data-targets-coverage>
      <table><tbody><tr><td>Planted desktop table</td></tr></tbody></table>
      <ul>
        <li
          data-coverage-mobile-record
          data-test-id="t1"
          data-test-name="edge-one"
          data-probe-family="icmp"
          data-target="1.1.1.1"
          data-coverage-status="uncovered"
        >
          edge-one icmp 1.1.1.1 uncovered
          <span data-cadence-receipt data-test-id="t2">wrong receipt</span>
        </li>
        <li
          data-coverage-mobile-record
          data-test-id="t2"
          data-test-name="edge-two"
          data-probe-family="dns"
          data-target="9.9.9.9"
          data-coverage-status="stale"
        >
          <span data-cadence-receipt data-test-id="t2">missing identity</span>
        </li>
      </ul>
    </section>
    <section data-targets-authoring>Author with AI</section>
  `);
  const targetsMobileReceipt = await targetsHierarchyCheck(page, "mobile");
  if (
    !targetsMobileReceipt.some((problem) =>
      problem.includes("does not expose all row actions"),
    ) ||
    !targetsMobileReceipt.some((problem) =>
      problem.includes("desktop coverage table remains visible"),
    ) ||
    !targetsMobileReceipt.some((problem) =>
      problem.includes("associates cadence with the wrong test"),
    ) ||
    !targetsMobileReceipt.some((problem) =>
      problem.includes("does not visibly group"),
    )
  ) {
    throw new Error(
      "self-check failed: Targets mobile receipt check did not catch planted row-association regressions",
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
  const topologyHierarchy = await topologyHierarchyCheck(page, "mobile");
  if (
    !topologyHierarchy.some((problem) =>
      problem.includes("expanded in the default live state"),
    ) ||
    !topologyHierarchy.some((problem) =>
      problem.includes("graph content begins below"),
    ) ||
    !topologyHierarchy.some((problem) =>
      problem.includes("missing graph exploration controls"),
    )
  ) {
    throw new Error(
      "self-check failed: Topology hierarchy check did not catch the planted expanded-controls regression",
    );
  }
  await page.setContent(`
    <p data-path-graph-scroll-hint style="display:none">Scroll horizontally</p>
    <div data-path-graph-scroll style="width:300px;overflow:auto">
      <svg data-path-graph width="100" height="80">
        <g role="button" tabindex="0" aria-label="Hop 1">
          <rect width="40" height="40"></rect>
        </g>
        <g role="button" tabindex="0" aria-label="Hop 2 (destination)" transform="translate(50 0)">
          <rect width="40" height="40"></rect>
        </g>
      </svg>
    </div>
  `);
  const pathGraph = await pathGraphMobileCheck(page, "mobile");
  if (
    !pathGraph.some((problem) =>
      problem.includes("guidance is not visibly rendered"),
    ) ||
    !pathGraph.some((problem) =>
      problem.includes("no local horizontal overflow"),
    )
  ) {
    throw new Error(
      "self-check failed: Path graph check did not catch planted collapsed-width guidance regression",
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
            clippedControls: [],
            cardHeader: [],
            dashboard: [],
            targets: [],
            topology: [],
            pathGraph: [],
            explorer: [],
            deviceReceipt: [],
            flowReceipt: [],
            flowTopTalkers: [],
            deviceConfigDiff: [],
            configCorrelationPivot: [],
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
            record.clippedControls = await interactiveClippingCheck(page);
            if (record.clippedControls.length > 0) {
              failures.push(
                `${viewport.name} ${theme} ${route}: clipped interactive controls\n  ${record.clippedControls.join("\n  ")}`,
              );
            }
            record.cardHeader = await mobileCardHeaderCheck(page);
            if (record.cardHeader.length > 0) {
              failures.push(
                `${viewport.name} ${theme} ${route}: CardHeader layout violations\n  ${record.cardHeader.join("\n  ")}`,
              );
            }
            if (route === "/dashboards") {
              if (viewport.name === "desktop") {
                await page.setViewportSize(dashboardLaptopViewport);
              }
              record.dashboard = [
                ...(await dashboardChecks(page)),
                ...(await dashboardScopeGeometryChecks(
                  page,
                  viewport.name === "desktop"
                    ? dashboardLaptopViewport.name
                    : viewport.name,
                )),
              ];
              if (record.dashboard.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: dashboard coverage violations\n  ${record.dashboard.join("\n  ")}`,
                );
              }
            }
            if (route === "/planes/device" || route === "/admin") {
              record.deviceReceipt = await deviceCollectionReceiptChecks(page);
              if (record.deviceReceipt.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: device receipt layout violations\n  ${record.deviceReceipt.join("\n  ")}`,
                );
              }
            }
            if (route === "/planes/flow" || route === "/admin") {
              record.flowReceipt = await flowIngestQualityReceiptChecks(page);
              if (record.flowReceipt.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: flow receipt layout violations\n  ${record.flowReceipt.join("\n  ")}`,
                );
              }
            }
            if (route === "/planes/flow") {
              record.flowTopTalkers = await flowTopTalkerChecks(
                page,
                viewport.name,
              );
              if (record.flowTopTalkers.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: Flow top-talker layout violations\n  ${record.flowTopTalkers.join("\n  ")}`,
                );
              }
            }
            if (route === "/planes/device") {
              record.deviceConfigDiff = await deviceConfigDiffChecks(
                page,
                viewport.name,
                axeSource,
              );
              if (record.deviceConfigDiff.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: device config comparison violations\n  ${record.deviceConfigDiff.join("\n  ")}`,
                );
              }
            }
            if (route === "/incidents") {
              record.configCorrelationPivot =
                await configCorrelationPivotChecks(page, axeSource);
              if (record.configCorrelationPivot.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: config correlation pivot violations\n  ${record.configCorrelationPivot.join("\n  ")}`,
                );
              }
            }
            if (route === "/targets") {
              if (viewport.name === "desktop") {
                await page.setViewportSize(targetsLaptopViewport);
              }
              record.targets = await targetsHierarchyCheck(
                page,
                viewport.name === "desktop"
                  ? targetsLaptopViewport.name
                  : viewport.name,
              );
              if (record.targets.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: Targets hierarchy violations\n  ${record.targets.join("\n  ")}`,
                );
              }
            }
            if (route === "/topology") {
              if (viewport.name === "desktop") {
                await page.setViewportSize(topologyLaptopViewport);
              }
              record.topology = await topologyHierarchyCheck(
                page,
                viewport.name === "desktop"
                  ? topologyLaptopViewport.name
                  : viewport.name,
              );
              if (record.topology.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: Topology hierarchy violations\n  ${record.topology.join("\n  ")}`,
                );
              }
            }
            if (route === "/path") {
              record.pathGraph = await pathGraphMobileCheck(
                page,
                viewport.name,
              );
              if (record.pathGraph.length > 0) {
                failures.push(
                  `${viewport.name} ${theme} ${route}: Path graph layout violations\n  ${record.pathGraph.join("\n  ")}`,
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
            record.clippedControls.length === 0 &&
            record.cardHeader.length === 0 &&
            record.dashboard.length === 0 &&
            record.targets.length === 0 &&
            record.topology.length === 0 &&
            record.pathGraph.length === 0 &&
            record.explorer.length === 0 &&
            record.deviceReceipt.length === 0 &&
            record.flowReceipt.length === 0 &&
            record.flowTopTalkers.length === 0 &&
            record.deviceConfigDiff.length === 0 &&
            record.configCorrelationPivot.length === 0 &&
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
