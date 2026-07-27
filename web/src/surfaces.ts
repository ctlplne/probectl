// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * The capability→surface registry (S-FE6) — the contract the CI
 * frontend-coverage gate enforces so backend↔frontend coverage never silently
 * drifts again. Every user-facing capability declares its Surface:
 *
 *  - "native":      a first-class screen on the S8a shell. The gate renders
 *                   the route and fails if it is the placeholder (or breaks
 *                   the a11y bar).
 *  - "federated":   served through an interoperability surface by design
 *                   (Prometheus / OTLP / API / CLI). External clients are
 *                   optional and never substitute for a native product screen.
 *                   The gate verifies the declared EVIDENCE exists ("file:<repo-relative path>",
 *                   "openapi:<path>" in the control plane's OpenAPI spec, or
 *                   "cli:<probectl command>" in the terminal surface).
 *  - "none-by-design": deliberately no current surface. The gate requires a
 *                   reason, and the feature denominator test still counts it.
 *  - "dev-showcase": a routed development aid outside the product capability
 *                    denominator and tenant navigation.
 *
 * Adding a nav destination without registering it here fails the gate; so
 * does declaring a native surface that renders the placeholder. Adding a PRD
 * F-number or plane without mapping it here also fails. Coverage +
 * consistency, not polish (the S-FE6 'watch out for').
 */

export type SurfaceKind = 'native' | 'federated' | 'none-by-design' | 'dev-showcase'
export type SurfaceLiveReceiptStatus = 'live-green' | 'static-only' | 'non-live'

export interface SurfaceLiveReceipt {
  status: SurfaceLiveReceiptStatus
  /**
   * Live receipt proof uses the same repo-relative discipline as normal
   * surface evidence, plus:
   *
   *  - "ci:<repo-relative workflow>:<literal needle>"
   *  - "test:<repo-relative test file>:<literal test/function needle>"
   */
  evidence: string[]
  /** Why this row is not live-green yet, or what the live receipt proves. */
  note: string
}

const STATIC_NATIVE_RECEIPT: SurfaceLiveReceipt = {
  status: 'static-only',
  evidence: [
    'ci:.github/workflows/ci.yml:npm run coverage-gate',
    'test:web/src/test/surface-coverage.test.tsx:every native surface renders a real screen',
  ],
  note: 'Native route renders and passes the frontend coverage/a11y gate, but no live e2e or integration receipt is currently bound to this row.',
}

const FEDERATED_NON_LIVE_RECEIPT: SurfaceLiveReceipt = {
  status: 'non-live',
  evidence: [
    'ci:.github/workflows/ci.yml:npm run coverage-gate',
    'test:web/src/test/surface-coverage.test.tsx:every declared file, OpenAPI, and CLI evidence exists',
  ],
  note: 'Federated/API/CLI surface is verified by static contract evidence; it is not a native served-screen e2e row.',
}

const NONE_BY_DESIGN_RECEIPT: SurfaceLiveReceipt = {
  status: 'non-live',
  evidence: [
    'ci:.github/workflows/ci.yml:npm run coverage-gate',
    'test:web/src/test/surface-coverage.test.tsx:future/non-GA PRD features stay explicit none-by-design declarations',
  ],
  note: 'Deliberately no served surface in the current GA denominator; the gate preserves the explicit product exclusion.',
}

const FULL_STACK_TOPOLOGY_RECEIPT: SurfaceLiveReceipt = {
  status: 'live-green',
  evidence: ['ci:.github/workflows/nightly.yml:make e2e', 'test:test/e2e/e2e_test.go:TestE2E'],
  note: 'Black-box e2e boots compose plus real binaries, ingests tenant-separated eBPF fixture flows through Kafka, and reads the tenant-scoped /v1/topology API.',
}

const CROSS_PLANE_INCIDENT_RECEIPT: SurfaceLiveReceipt = {
  status: 'live-green',
  evidence: [
    'ci:.github/workflows/ci.yml:make test-integration',
    'test:internal/control/crossplane_e2e_integration_test.go:TestCrossPlaneCorrelationE2E',
  ],
  note: 'Integration CI drives real Kafka and Postgres/RLS; BGP plus threat signals coalesce into exactly one tenant-scoped incident with cross-plane evidence.',
}

const DEVICE_LIVE_RECEIPT: SurfaceLiveReceipt = {
  status: 'live-green',
  evidence: [
    'ci:.github/workflows/ci.yml:device-live',
    'test:internal/device/snmp_test.go:TestSNMPIntegration',
  ],
  note: 'The device-live CI job starts loopback snmpd and requires the real gosnmp wire path to return live metrics and inventory.',
}

const EBPF_LIVE_RECEIPT: SurfaceLiveReceipt = {
  status: 'live-green',
  evidence: [
    'ci:.github/workflows/ci.yml:ebpf-kernel-matrix',
    'test:internal/ebpf/live_smoke_ebpf_test.go:TestLiveLoadAttachL4Flow',
  ],
  note: 'The eBPF kernel matrix compiles the BPF objects with the pinned toolchain and loads/attaches the live programs on real LTS kernels.',
}

export interface SurfaceDecl {
  /** The user-facing capability, in product language. */
  capability: string
  /** PRD F-number(s) or plane IDs from featureCatalog.ts covered by this surface. */
  featureIds?: string[]
  /** The sprint that owns (or will own) the surface. */
  sprint: string
  kind: SurfaceKind
  /** The app route (native kind only). */
  route?: string
  /**
   * Served proof: "file:<repo-relative>" | "openapi:<api path>" |
   * "cli:<probectl command>". Required for federated surfaces; optional for
   * native surfaces when a PRD row needs API/CLI parity proof.
   */
  evidence?: string[]
  /** Required for none-by-design declarations. */
  noneReason?: string
  /**
   * Deliberately OUTSIDE the tenant nav (S-T1+): a native surface that must
   * not be discoverable from the tenant app — e.g. the provider/operator
   * console, a separate privilege domain (and hidden-unlicensed at the API).
   * The render + a11y gates still apply; only the nav-membership rule is
   * waived.
   */
  offNav?: boolean
  /** Latest served-path receipt state for the declared operator surface. */
  liveReceipt: SurfaceLiveReceipt
}

export const SURFACES: SurfaceDecl[] = [
  // --- native screens (S8a shell) ---
  {
    capability: 'Design-system developer gallery',
    sprint: 'W10',
    kind: 'dev-showcase',
    route: '/gallery',
    offNav: true,
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Scheduled agent-to-service synthetic test CRUD + per-type result detail',
    featureIds: ['PLANE_ACTIVE_SYNTHETIC', 'F1', 'F2', 'F4', 'F5', 'F15'],
    sprint: 'S9/S-FE5',
    kind: 'native',
    route: '/targets',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Owned-vantage coverage gaps from local agent labels and result recency',
    featureIds: ['PLANE_ACTIVE_SYNTHETIC', 'F1'],
    sprint: 'I-02506421',
    kind: 'native',
    route: '/targets',
    offNav: true,
    evidence: [
      'openapi:/v1/coverage/vantages',
      'cli:probectl coverage vantages',
      'file:web/src/routes/CoveragePanel.tsx',
      'file:docs/outside-in.md',
    ],
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'First-run tenant onboarding: enroll agent, create test, invite teammates',
    featureIds: ['F1', 'F2', 'F25'],
    sprint: 'JOURNEY-001',
    kind: 'native',
    route: '/onboarding',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Keyboard command API and pointer-free J1-J6 journey parity',
    featureIds: ['F1', 'F3', 'F9', 'F28', 'F51'],
    sprint: 'X15',
    kind: 'native',
    route: '/onboarding',
    offNav: true,
    evidence: [
      'file:web/src/shell/journeyCommands.ts',
      'file:docs/ux/keyboard-command-reference.md',
      'file:web/src/test/journeys/keyboard-only.test.tsx',
    ],
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Truthful six-state data surfaces and transport-isolated demo workspace',
    featureIds: ['F1', 'F3', 'F6', 'F8', 'F9', 'F11', 'F18'],
    sprint: 'X18',
    kind: 'native',
    route: '/targets',
    offNav: true,
    evidence: [
      'file:docs/ux/demo-mode.md',
      'file:web/src/components/HonestDataState.tsx',
      'file:web/src/data/surfaceTruth.ts',
      'file:web/src/demo/DemoMode.tsx',
      'file:web/src/test/empty-states.test.tsx',
      'file:web/src/test/demo-mode.test.tsx',
    ],
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'AI test authoring + auto-discovery',
    featureIds: ['F45'],
    sprint: 'S26',
    kind: 'native',
    route: '/targets',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Path / topology visualization',
    featureIds: ['F3'],
    sprint: 'S11',
    kind: 'native',
    route: '/path',
    liveReceipt: FULL_STACK_TOPOLOGY_RECEIPT,
  },
  {
    capability: 'Incidents list + cross-plane timeline',
    featureIds: ['F9'],
    sprint: 'S17',
    kind: 'native',
    route: '/incidents',
    evidence: [
      'openapi:/v1/incidents/{id}/journal',
      'cli:probectl incident journal',
      'cli:probectl incident journal-append',
    ],
    liveReceipt: CROSS_PLANE_INCIDENT_RECEIPT,
  },
  {
    capability: 'Alerting: active alerts, silence/ack, rule config',
    featureIds: ['F8', 'F27'],
    sprint: 'S-FE1',
    kind: 'native',
    route: '/alerts',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'TLS/cert posture inventory + trustctl handoff',
    featureIds: ['F36'],
    sprint: 'S-FE2',
    kind: 'native',
    route: '/security',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Threat-intel / IOC + NDR detection triage',
    featureIds: ['F37', 'F38'],
    sprint: 'S-FE3/S42',
    kind: 'native',
    route: '/security',
    liveReceipt: CROSS_PLANE_INCIDENT_RECEIPT,
  },
  {
    capability: 'Endpoint / last-mile / WiFi DEM fleet + attribution',
    featureIds: ['F16', 'F46'],
    sprint: 'S-FE4',
    kind: 'native',
    route: '/endpoints',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'AI assistant (NL query + RCA with citations)',
    featureIds: ['F13'],
    sprint: 'S24',
    kind: 'native',
    route: '/ask',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Structured and natural-language telemetry Explorer',
    featureIds: ['F13'],
    sprint: 'X7',
    kind: 'native',
    route: '/explore',
    evidence: [
      'openapi:/v1/explorer/query',
      'openapi:/v1/explorer/compare',
      'cli:probectl explorer query',
      'cli:probectl explorer compare',
    ],
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Curated dashboards + tenant-safe PDF/CSV reporting',
    featureIds: ['F9'],
    sprint: 'S45',
    kind: 'native',
    route: '/dashboards',
    evidence: [
      'openapi:/v1/dashboards',
      'openapi:/v1/dashboards/{id}/manifest',
      'openapi:/v1/dashboard-manifests/import',
      'openapi:/v1/dashboard-report-schedules',
      'openapi:/v1/dashboard-reports',
      'openapi:/v1/dashboard-report-artifacts',
      'cli:probectl dashboard export',
      'cli:probectl dashboard import',
    ],
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Agent fleet admin',
    featureIds: ['F1'],
    sprint: 'S9',
    kind: 'native',
    route: '/admin',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Topology dependency graph + what-if impact simulation',
    featureIds: ['F40'],
    sprint: 'S43',
    kind: 'native',
    route: '/topology',
    liveReceipt: FULL_STACK_TOPOLOGY_RECEIPT,
  },
  {
    capability: 'Network egress cost summary + budgets (FinOps showback)',
    featureIds: ['F41'],
    sprint: 'S44',
    kind: 'native',
    route: '/cost',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'SLOs, error budgets + multi-window burn rates (OpenSLO)',
    featureIds: ['F42'],
    sprint: 'S45',
    kind: 'native',
    route: '/slos',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Segmentation validation + audit evidence (PCI/NIST/zero-trust)',
    featureIds: ['F43'],
    sprint: 'S46',
    kind: 'native',
    route: '/compliance',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Collective internet-outage view (open data + your vantages)',
    featureIds: ['F7', 'F19'],
    sprint: 'S47a',
    kind: 'native',
    route: '/outages',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'RUM convergence: real-user impact joined with synthetic coverage',
    featureIds: ['F20'],
    sprint: 'S47b',
    kind: 'native',
    route: '/endpoints',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Voice/RTP quality tests: MOS (E-model), jitter, loss',
    featureIds: ['F21'],
    sprint: 'S47c',
    kind: 'native',
    route: '/targets',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Carbon/energy estimate (ESG view of network traffic)',
    featureIds: ['F48'],
    sprint: 'S48',
    kind: 'native',
    route: '/cost',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Secret-backend config + credential health',
    featureIds: ['F31'],
    sprint: 'S41',
    kind: 'native',
    route: '/admin',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Editions / license state (Admin → Editions)',
    featureIds: ['F32'],
    sprint: 'S-T0',
    kind: 'native',
    route: '/admin',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Tenant data lifecycle: export, retention, residency visibility',
    featureIds: ['F55'],
    sprint: 'S-T5',
    kind: 'native',
    route: '/admin',
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  // The provider/operator console (ee/) is deliberately OFF the tenant nav: a
  // separate privilege domain, hidden when unlicensed (the API 404s).
  {
    capability: 'Provider console: ranked MSP operations, lifecycle, showback, and break-glass',
    featureIds: ['F51', 'F53'],
    sprint: 'S-T1',
    kind: 'native',
    route: '/provider',
    offNav: true,
    evidence: [
      'file:ee/web/provider/ProviderConsole.tsx',
      'file:web/src/test/journeys/msp-ops.test.tsx',
    ],
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },

  // --- federated surfaces (by design) ---
  {
    capability: 'Broker-coordinated agent-to-agent session and mesh scheduling',
    featureIds: ['F2'],
    sprint: 'S8/W7',
    kind: 'federated',
    evidence: [
      'openapi:/v1/a2a/sessions',
      'openapi:/v1/a2a/mesh',
      'cli:probectl a2a create-session',
      'cli:probectl a2a start-mesh',
      'file:docs/adr/a2a-broker-coordination.md',
    ],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'Prometheus-compatible metrics query API for optional operator clients',
    featureIds: ['F30'],
    sprint: 'S40',
    kind: 'federated',
    evidence: ['openapi:/v1/grafana/api/v1/query'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'Prometheus federation + remote-write interop',
    featureIds: ['F30'],
    sprint: 'S40',
    kind: 'federated',
    evidence: ['openapi:/v1/prometheus/federate', 'openapi:/v1/prometheus/write'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'OTLP ingest/export (OpenTelemetry interop)',
    featureIds: ['F12'],
    sprint: 'S22',
    kind: 'federated',
    evidence: ['file:docs/otlp.md'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'CMDB CI correlation (incidents/agents → ServiceNow)',
    featureIds: ['F30'],
    sprint: 'S40',
    kind: 'federated',
    evidence: ['openapi:/v1/cmdb/lookup', 'openapi:/v1/incidents/{id}/cis'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'Tenant fleet health and safe-action review',
    featureIds: ['F28'],
    sprint: 'X12',
    kind: 'native',
    route: '/admin',
    evidence: [
      'openapi:/v1/agents',
      'file:web/src/routes/admin/AdminPage.tsx',
      'file:web/src/test/journeys/fleet-health.test.tsx',
    ],
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Staged fleet rollout controls',
    featureIds: ['F28'],
    sprint: 'E7',
    kind: 'native',
    route: '/admin',
    evidence: [
      'file:web/src/routes/admin/RolloutCard.tsx',
      'file:web/src/test/rollout-console.test.tsx',
      'file:docs/ops/fleet-rollout.md',
      'file:internal/cli/surfaces.go',
      'openapi:/v1/rollouts',
      'openapi:/v1/rollouts/{id}/verify',
    ],
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'BGP/routing monitoring events and analyzer output',
    featureIds: ['PLANE_BGP_ROUTING', 'F6'],
    sprint: 'S13',
    kind: 'native',
    route: '/planes/bgp',
    evidence: [
      'openapi:/v1/bgp/events',
      'cli:probectl bgp events',
      'cli:probectl bgp setup',
      'file:docs/bgp.md',
    ],
    liveReceipt: CROSS_PLANE_INCIDENT_RECEIPT,
  },
  {
    capability: 'Flow analytics APIs and ClickHouse-backed views',
    featureIds: ['PLANE_FLOW_ANALYTICS', 'F17'],
    sprint: 'S32',
    kind: 'native',
    route: '/planes/flow',
    liveReceipt: FULL_STACK_TOPOLOGY_RECEIPT,
  },
  {
    capability: 'Device telemetry collectors and topology attribution',
    featureIds: ['PLANE_DEVICE_TELEMETRY', 'F18'],
    sprint: 'S33',
    kind: 'native',
    route: '/planes/device',
    evidence: [
      'openapi:/v1/devices',
      'openapi:/v1/device/metrics',
      'openapi:/v1/device/syslog',
      'openapi:/v1/device/configs',
      'cli:probectl device list',
      'cli:probectl device metrics',
      'file:docs/features/telemetry-planes.md',
    ],
    liveReceipt: DEVICE_LIVE_RECEIPT,
  },
  {
    capability: 'eBPF host/L7 visibility and service map',
    featureIds: ['PLANE_EBPF_HOST_L7', 'F11'],
    sprint: 'S31',
    kind: 'native',
    route: '/planes/ebpf',
    evidence: [
      'openapi:/v1/ebpf/service-map',
      'cli:probectl ebpf service-map',
      'file:docs/features/telemetry-planes.md',
    ],
    liveReceipt: EBPF_LIVE_RECEIPT,
  },
  {
    capability: 'REST/gRPC API and CLI command surface',
    featureIds: ['F10'],
    sprint: 'DESIGN-002',
    kind: 'native',
    route: '/docs/api',
    evidence: ['openapi:/openapi.json', 'file:cmd/probectl', 'file:proto'],
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'MCP server tools and transport',
    featureIds: ['F14'],
    sprint: 'S25',
    kind: 'federated',
    evidence: ['file:docs/mcp.md', 'file:internal/ai/mcp'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'Identity, SCIM, ABAC, and delegated administration',
    featureIds: ['F22', 'F25'],
    sprint: 'S-T2',
    kind: 'native',
    route: '/admin',
    evidence: [
      'file:docs/auth/self-hosted-idp.md',
      'file:docs/scim-abac.md',
      'openapi:/v1/abac/policies',
      'openapi:/v1/directory/scim-tokens',
    ],
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Audit log and tamper-evident verification',
    featureIds: ['F23'],
    sprint: 'DESIGN-003',
    kind: 'native',
    route: '/audit',
    evidence: ['openapi:/v1/audit', 'openapi:/v1/audit/verify'],
    liveReceipt: STATIC_NATIVE_RECEIPT,
  },
  {
    capability: 'Tenant / org / team / project hierarchy',
    featureIds: ['F24'],
    sprint: 'S-T3',
    kind: 'federated',
    evidence: ['openapi:/v1/hierarchy', 'file:internal/cli/surfaces.go'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'SIEM export and tenant-routed forwarding',
    featureIds: ['F26'],
    sprint: 'S38',
    kind: 'federated',
    evidence: [
      'openapi:/v1/siem/status',
      'cli:probectl siem status',
      'file:docs/siem.md',
      'file:internal/siem',
    ],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'IaC and GitOps deployment surfaces',
    featureIds: ['F29'],
    sprint: 'S39',
    kind: 'federated',
    evidence: ['file:deploy/terraform/README.md', 'file:deploy/gitops/README.md'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'Multi-region / HA runbooks and reference deployment',
    featureIds: ['F33'],
    sprint: 'S50',
    kind: 'federated',
    evidence: ['file:docs/ha.md', 'file:cmd/probectl-control/ha_reference_coherence_test.go'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'Advanced governance: retention, erasure, redaction, policy',
    featureIds: ['F34'],
    sprint: 'S-T6',
    kind: 'federated',
    evidence: ['file:docs/governance.md', 'file:internal/govern'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'Supportability: diagnostics, bundles, health evidence',
    featureIds: ['F35'],
    sprint: 'S51',
    kind: 'federated',
    evidence: ['file:docs/supportability.md', 'openapi:/v1/diagnostics/bundle'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'Change intelligence ingestion and incident correlation',
    featureIds: ['F39'],
    sprint: 'S42',
    kind: 'federated',
    evidence: ['file:docs/change-intel.md', 'openapi:/v1/changes'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'Guarded remediation proposals and approvals',
    featureIds: ['F44'],
    sprint: 'S52',
    kind: 'federated',
    evidence: [
      'file:docs/remediation.md',
      'openapi:/v1/remediation/proposals',
      'openapi:/v1/remediation/proposals/{id}/approve',
    ],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'Network chaos experiments and dependency matrix',
    featureIds: ['F47'],
    sprint: 'S53',
    kind: 'none-by-design',
    noneReason:
      'Library/test-harness only: internal/chaos and cmd/probectl-chaos-dependency-drill can exercise local faults, but no REST, UI, MCP, probectl operator CLI, or agent-control surface serves chaos until a human-gated and audited operator workflow exists.',
    liveReceipt: NONE_BY_DESIGN_RECEIPT,
  },
  {
    capability: 'Tenant isolation model operations (pooled, siloed, hybrid)',
    featureIds: ['F50', 'F52'],
    sprint: 'S-T1/S-T7',
    kind: 'federated',
    evidence: [
      'openapi:/v1/isolation/status',
      'file:docs/security/tenant-isolation.md',
      'file:ee/silo',
    ],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'Per-tenant keys and BYOK administration',
    featureIds: ['F56'],
    sprint: 'S-T8',
    kind: 'federated',
    evidence: ['openapi:/v1/security/keys', 'file:ee/tenantkeys'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },
  {
    capability: 'Tenant fairness self-view and enforcement',
    featureIds: ['F57'],
    sprint: 'S-T9',
    kind: 'federated',
    evidence: ['file:docs/fairness.md', 'openapi:/v1/fairness'],
    liveReceipt: FEDERATED_NON_LIVE_RECEIPT,
  },

  // --- declared none-by-design surfaces (deliberate product exclusions) ---

  {
    capability: 'Per-tenant or provider-master product rebranding',
    featureIds: ['F54'],
    sprint: 'W11 owner decision',
    kind: 'none-by-design',
    noneReason:
      'Removed by design: MSPs resell under the probectl banner. Operators may set one deployment-wide allowlisted token theme, but no tenant can replace product identity, logos, domains, or email identity.',
    liveReceipt: NONE_BY_DESIGN_RECEIPT,
  },

  {
    capability: 'Plugin/detection marketplace',
    featureIds: ['F49'],
    sprint: 'Phase 4 future bet',
    kind: 'none-by-design',
    noneReason:
      'PRD v1.0 marks F49 as outside the GA completeness denominator and a deliberate Phase-4 future bet; the detection-as-code substrate exists, but no current GA surface is promised.',
    liveReceipt: NONE_BY_DESIGN_RECEIPT,
  },
]

/** RegistryViolation is one coverage/consistency failure (gate output). */
export interface RegistryViolation {
  capability: string
  problem: string
}

/** checkRegistryShape runs the pure (render-free) registry checks: every nav
 *  destination is registered, every routed declaration points at a nav
 *  destination or a child of one, and every declaration is well-formed. The render/a11y checks
 *  live in the gate test (they need the DOM). */
export function checkRegistryShape(
  navRoutes: string[],
  surfaces: SurfaceDecl[],
): RegistryViolation[] {
  const violations: RegistryViolation[] = []
  const routed = new Map<string, SurfaceDecl[]>()
  for (const s of surfaces) {
    if (s.kind !== 'dev-showcase' && (!s.featureIds || s.featureIds.length === 0)) {
      violations.push({
        capability: s.capability,
        problem: 'surface declares no PRD featureIds',
      })
    }
    if (s.kind === 'none-by-design') {
      if (!s.noneReason || s.noneReason.trim() === '') {
        violations.push({
          capability: s.capability,
          problem: 'none-by-design surface declares no reason',
        })
      }
      if (s.route) {
        violations.push({
          capability: s.capability,
          problem: 'none-by-design surface must not declare a route',
        })
      }
      if (s.evidence && s.evidence.length > 0) {
        violations.push({
          capability: s.capability,
          problem: 'none-by-design surface must not declare federated evidence',
        })
      }
      continue
    }
    if (s.kind === 'federated') {
      if (!s.evidence || s.evidence.length === 0) {
        violations.push({
          capability: s.capability,
          problem: 'federated surface declares no evidence',
        })
      }
      continue
    }
    if (!s.route) {
      violations.push({ capability: s.capability, problem: `${s.kind} surface declares no route` })
      continue
    }
    routed.set(s.route, [...(routed.get(s.route) ?? []), s])
  }
  for (const nav of navRoutes) {
    if (!routed.has(nav) && ![...routed.keys()].some((route) => isChildRoute(nav, route))) {
      violations.push({
        capability: `nav:${nav}`,
        problem: 'nav destination has no registered surface (register it native)',
      })
    }
  }
  for (const [route, decls] of routed) {
    if (
      !navRoutes.some((nav) => route === nav || isChildRoute(nav, route)) &&
      !decls.every((d) => d.offNav)
    ) {
      violations.push({
        capability: decls[0].capability,
        problem: `route ${route} is not a nav destination`,
      })
    }
    const kinds = new Set(decls.map((d) => d.kind))
    if (kinds.size > 1) {
      violations.push({
        capability: decls[0].capability,
        problem: `route ${route} is declared with conflicting surface kinds`,
      })
    }
  }
  return violations
}

function isChildRoute(parent: string, route: string): boolean {
  return route.startsWith(`${parent}/`)
}
