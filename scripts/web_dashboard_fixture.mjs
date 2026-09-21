#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

/**
 * Loopback-only visual fixture for the dense dashboard/reporting surface.
 *
 * Vite serves the production React application on upstreamPort. This proxy
 * supplies deterministic same-origin tenant API responses so a 1440x900
 * browser review exercises the real UI without credentials, a database, or
 * outbound traffic.
 */

import http from "node:http";

const port = Number.parseInt(process.env.PORT ?? "4175", 10);
const upstreamPort = Number.parseInt(process.env.VITE_PORT ?? "4174", 10);

function json(response, status, body) {
  const encoded = JSON.stringify(body);
  response.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(encoded),
    "Cache-Control": "no-store",
  });
  response.end(encoded);
}

function api(request, response, pathname) {
  if (pathname === "/v1/me") {
    json(response, 200, {
      tenant_id: "14ac5d56-0fd4-46a2-a926-ec21a53511e6",
      tenant_name: "Acme Industries",
      tenant_slug: "acme-industries",
      user_id: "dashboard-reviewer",
      email: "operator@acme.example",
      display_name: "Acme Operator",
      mfa_satisfied: true,
      permissions: ["metrics.read", "metrics.write"],
    });
    return true;
  }
  if (pathname === "/v1/tests") {
    json(response, 200, {
      items: [
        {
          id: "test-dns",
          name: "Edge DNS",
          type: "dns",
          target: "1.1.1.1",
          interval_seconds: 30,
          timeout_seconds: 3,
          params: {},
          enabled: true,
          created_at: "2026-07-14T12:00:00Z",
          updated_at: "2026-07-14T12:00:00Z",
        },
        {
          id: "test-checkout",
          name: "Checkout HTTPS",
          type: "http",
          target: "https://checkout.acme.example",
          interval_seconds: 60,
          timeout_seconds: 5,
          params: {},
          enabled: true,
          created_at: "2026-07-14T12:00:00Z",
          updated_at: "2026-07-14T12:00:00Z",
        },
      ],
    });
    return true;
  }
  if (pathname === "/v1/agents") {
    json(response, 200, {
      items: [
        {
          id: "agent-iad-1",
          name: "iad-edge-1",
          hostname: "iad-edge-01",
          agent_version: "1.4.0",
          status: "online",
          capabilities: ["icmp", "tcp", "flow", "device", "ebpf", "endpoint"],
          heartbeat_age_seconds: 18,
          heartbeat_state: "ready",
          heartbeat_reason: "Authenticated heartbeat is fresh.",
          version_state: "current",
          version_reason: "Agent matches the control version.",
          readiness_state: "ready",
          readiness_reason: "All reported capabilities are ready.",
          rollout_halted: false,
          last_failure: "",
          next_safe_action: {
            kind: "inspect_evidence",
            label: "Inspect agent evidence",
            reason: "Review tenant-scoped registry evidence.",
            href: "/agents",
          },
        },
      ],
      control_version: "1.4.0",
      rollouts_available: true,
    });
    return true;
  }
  if (pathname === "/v1/incidents") {
    json(response, 200, {
      items: [
        {
          id: "incident-checkout",
          tenant_id: "14ac5d56-0fd4-46a2-a926-ec21a53511e6",
          status: "open",
          severity: "warning",
          title: "Checkout latency burn",
          target: "checkout.acme.example",
          started_at: "2026-07-14T15:40:00Z",
          last_seen_at: "2026-07-14T16:00:00Z",
          signal_count: 3,
          signals: [],
        },
      ],
    });
    return true;
  }
  if (pathname === "/v1/alerts/active") {
    json(response, 200, {
      items: [
        {
          fingerprint: "alert-checkout",
          rule_id: "slo-checkout",
          rule_name: "Checkout latency burn",
          severity: "warning",
          metric: "probectl_result_duration_ms",
          labels: { service: "checkout" },
          value: 184,
          reason: "p95 latency above objective",
          since: "2026-07-14T15:40:00Z",
          last_seen_at: "2026-07-14T16:00:00Z",
        },
      ],
      evaluator_running: true,
    });
    return true;
  }
  if (pathname === "/v1/results/latest") {
    json(response, 200, {
      items: [
        {
          agent_id: "agent-iad-1",
          type: "dns",
          target: "1.1.1.1",
          success: true,
          duration_ms: 21,
          metrics: { "dns.query.ms": 21 },
          observed_at: "2026-07-14T16:00:00Z",
        },
        {
          agent_id: "agent-iad-1",
          type: "http",
          target: "https://checkout.acme.example",
          success: true,
          duration_ms: 184,
          metrics: { "http.total.ms": 184, "http.status": 200 },
          observed_at: "2026-07-14T16:00:00Z",
        },
      ],
      collector_running: true,
    });
    return true;
  }
  if (pathname === "/v1/flows/top") {
    json(response, 200, {
      items: [
        {
          key: "10.0.0.10",
          detail: "checkout",
          bytes: 524288000,
          packets: 120000,
          flows: 42,
        },
        {
          key: "10.0.0.20",
          detail: "payments",
          bytes: 104857600,
          packets: 22400,
          flows: 18,
        },
      ],
      effective_limit: 5,
      window: "1h",
    });
    return true;
  }
  if (pathname === "/v1/flows/capacity") {
    json(response, 200, {
      items: [
        {
          ts: "2026-07-14T15:45:00Z",
          exporter: "iad-edge-01",
          iface: 1,
          bps: 35000000,
          pps: 6000,
        },
        {
          ts: "2026-07-14T15:50:00Z",
          exporter: "iad-edge-01",
          iface: 1,
          bps: 48000000,
          pps: 7800,
        },
        {
          ts: "2026-07-14T15:55:00Z",
          exporter: "iad-edge-01",
          iface: 1,
          bps: 69000000,
          pps: 10000,
        },
        {
          ts: "2026-07-14T16:00:00Z",
          exporter: "iad-edge-01",
          iface: 1,
          bps: 85000000,
          pps: 12000,
        },
      ],
    });
    return true;
  }
  if (pathname === "/v1/flows/anomalies") {
    json(response, 200, {
      items: [
        {
          exporter: "iad-edge-01",
          iface: 1,
          ts: "2026-07-14T16:00:00Z",
          current_bps: 85000000,
          baseline_bps: 35000000,
          stddev_bps: 8000000,
          sigma: 6.2,
          model: "local-zscore-v1",
          training_window: {
            start: "2026-07-14T15:15:00Z",
            end: "2026-07-14T15:55:00Z",
            samples: 9,
          },
          feature_citations: [],
          features: { "flow.bps": 85000000, "flow.pps": 12000 },
        },
      ],
    });
    return true;
  }
  if (pathname === "/v1/topology") {
    json(response, 200, {
      topology_running: true,
      at: "2026-07-14T16:00:00Z",
      nodes: [
        { id: "as:64500", kind: "as", label: "AS64500" },
        {
          id: "prefix:203.0.113.0/24",
          kind: "prefix",
          label: "203.0.113.0/24",
        },
        { id: "service:checkout", kind: "service", label: "checkout" },
        { id: "service:payments", kind: "service", label: "payments" },
        { id: "device:10.0.0.1", kind: "device", label: "iad-edge-01" },
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
    return true;
  }
  if (pathname === "/v1/cost/summary") {
    json(response, 200, {
      cost_running: true,
      summary: {
        priced: true,
        zones_mapped: true,
        pricing_source: "operator-configured price book",
        pricing_as_of: "2026-07-01",
        total_bytes: 18253611008,
        total_usd: 0.38,
        by_class: { inter_az: { bytes: 10737418240, usd: 0.1 } },
        by_service: { checkout: { bytes: 12884901888, usd: 0.38 } },
        by_team: { payments: { bytes: 12884901888, usd: 0.38 } },
        chatty_pairs: [],
        trend: [
          { hour: "2026-07-14T14:00:00Z", bytes: 4294967296, usd: 0.08 },
          { hour: "2026-07-14T15:00:00Z", bytes: 7516192768, usd: 0.16 },
          { hour: "2026-07-14T16:00:00Z", bytes: 18253611008, usd: 0.38 },
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
    return true;
  }
  if (pathname === "/v1/slos") {
    json(response, 200, {
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
    return true;
  }
  if (pathname === "/v1/compliance") {
    json(response, 200, {
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
    return true;
  }
  if (pathname === "/v1/threat/detections") {
    json(response, 200, {
      items: [
        {
          id: "detection-scanner",
          kind: "ioc_match",
          plane: "threat",
          severity: "warning",
          confidence: 0.82,
          source: "operator-configured-feed",
          category: "scanner",
          indicator: "10.0.0.20",
          entity: "10.0.0.20",
          title: "Known scanner contact",
          summary: "Flow evidence matched a locally cached indicator.",
          observed_at: "2026-07-14T16:00:00Z",
        },
      ],
      detections_running: true,
    });
    return true;
  }
  if (pathname === "/v1/dashboards") {
    json(response, 200, { items: [] });
    return true;
  }
  if (pathname === "/v1/dashboard-report-schedules") {
    json(response, 200, {
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
    return true;
  }
  if (pathname === "/v1/dashboard-report-artifacts") {
    json(response, 200, { items: [] });
    return true;
  }
  if (pathname === "/branding") {
    json(response, 200, { product_name: "probectl" });
    return true;
  }
  return false;
}

const server = http.createServer((request, response) => {
  const pathname = new URL(request.url ?? "/", `http://${request.headers.host}`)
    .pathname;
  if (request.method === "GET" && api(request, response, pathname)) return;

  const upstream = http.request(
    {
      hostname: "127.0.0.1",
      port: upstreamPort,
      path: request.url,
      method: request.method,
      headers: { ...request.headers, host: `127.0.0.1:${upstreamPort}` },
    },
    (upstreamResponse) => {
      response.writeHead(
        upstreamResponse.statusCode ?? 502,
        upstreamResponse.headers,
      );
      upstreamResponse.pipe(response);
    },
  );
  upstream.on("error", (error) =>
    json(response, 502, { error: { message: String(error) } }),
  );
  request.pipe(upstream);
});

server.listen(port, "127.0.0.1", () => {
  console.log(`dashboard visual fixture: http://127.0.0.1:${port}/dashboards`);
});
