/**
 * The capability→surface registry (S-FE6) — the contract the CI
 * frontend-coverage gate enforces so backend↔frontend coverage never silently
 * drifts again. Every user-facing capability declares its Surface:
 *
 *  - "native":      a first-class screen on the S8a shell. The gate renders
 *                   the route and fails if it is the placeholder (or breaks
 *                   the a11y bar).
 *  - "federated":   served through an external surface by design (Grafana /
 *                   Prometheus / OTLP / API). The gate verifies the declared
 *                   EVIDENCE exists ("file:<repo-relative path>" or
 *                   "openapi:<path>" in the control plane's OpenAPI spec).
 *  - "none-by-design": deliberately no current surface. The gate requires a
 *                   reason, and the feature denominator test still counts it.
 *
 * Adding a nav destination without registering it here fails the gate; so
 * does declaring a native surface that renders the placeholder. Adding a PRD
 * F-number or plane without mapping it here also fails. Coverage +
 * consistency, not polish (the S-FE6 'watch out for').
 */

export type SurfaceKind = 'native' | 'federated' | 'none-by-design'

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
  /** Federated proof: "file:<repo-relative>" | "openapi:<api path>". */
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
}

export const SURFACES: SurfaceDecl[] = [
  // --- native screens (S8a shell) ---
  {
    capability: 'Synthetic tests CRUD + per-type result detail',
    featureIds: ['PLANE_ACTIVE_SYNTHETIC', 'F1', 'F2', 'F4', 'F5', 'F15'],
    sprint: 'S9/S-FE5',
    kind: 'native',
    route: '/targets',
  },
  {
    capability: 'First-run tenant onboarding: enroll agent, create test, invite teammates',
    featureIds: ['F1', 'F2', 'F25'],
    sprint: 'JOURNEY-001',
    kind: 'native',
    route: '/onboarding',
  },
  {
    capability: 'AI test authoring + auto-discovery',
    featureIds: ['F45'],
    sprint: 'S26',
    kind: 'native',
    route: '/targets',
  },
  {
    capability: 'Path / topology visualization',
    featureIds: ['F3'],
    sprint: 'S11',
    kind: 'native',
    route: '/path',
  },
  {
    capability: 'Incidents list + cross-plane timeline',
    featureIds: ['F9'],
    sprint: 'S17',
    kind: 'native',
    route: '/incidents',
  },
  {
    capability: 'Alerting: active alerts, silence/ack, rule config',
    featureIds: ['F8', 'F27'],
    sprint: 'S-FE1',
    kind: 'native',
    route: '/alerts',
  },
  {
    capability: 'TLS/cert posture inventory + trustctl handoff',
    featureIds: ['F36'],
    sprint: 'S-FE2',
    kind: 'native',
    route: '/security',
  },
  {
    capability: 'Threat-intel / IOC + NDR detection triage',
    featureIds: ['F37', 'F38'],
    sprint: 'S-FE3/S42',
    kind: 'native',
    route: '/security',
  },
  {
    capability: 'Endpoint / last-mile / WiFi DEM fleet + attribution',
    featureIds: ['F16', 'F46'],
    sprint: 'S-FE4',
    kind: 'native',
    route: '/endpoints',
  },
  {
    capability: 'AI assistant (NL query + RCA with citations)',
    featureIds: ['F13'],
    sprint: 'S24',
    kind: 'native',
    route: '/ask',
  },
  {
    capability: 'Curated in-app dashboards',
    featureIds: ['F9'],
    sprint: 'S45',
    kind: 'native',
    route: '/dashboards',
  },
  {
    capability: 'Agent fleet admin',
    featureIds: ['F1'],
    sprint: 'S9',
    kind: 'native',
    route: '/admin',
  },
  {
    capability: 'Topology dependency graph + what-if impact simulation',
    featureIds: ['F40'],
    sprint: 'S43',
    kind: 'native',
    route: '/topology',
  },
  {
    capability: 'Network egress cost summary + budgets (FinOps showback)',
    featureIds: ['F41'],
    sprint: 'S44',
    kind: 'native',
    route: '/cost',
  },
  {
    capability: 'SLOs, error budgets + multi-window burn rates (OpenSLO)',
    featureIds: ['F42'],
    sprint: 'S45',
    kind: 'native',
    route: '/slos',
  },
  {
    capability: 'Segmentation validation + audit evidence (PCI/NIST/zero-trust)',
    featureIds: ['F43'],
    sprint: 'S46',
    kind: 'native',
    route: '/compliance',
  },
  {
    capability: 'Collective internet-outage view (open data + your vantages)',
    featureIds: ['F7', 'F19'],
    sprint: 'S47a',
    kind: 'native',
    route: '/outages',
  },
  {
    capability: 'RUM convergence: real-user impact joined with synthetic coverage',
    featureIds: ['F20'],
    sprint: 'S47b',
    kind: 'native',
    route: '/endpoints',
  },
  {
    capability: 'Voice/RTP quality tests: MOS (E-model), jitter, loss',
    featureIds: ['F21'],
    sprint: 'S47c',
    kind: 'native',
    route: '/targets',
  },
  {
    capability: 'Carbon/energy estimate (ESG view of network traffic)',
    featureIds: ['F48'],
    sprint: 'S48',
    kind: 'native',
    route: '/cost',
  },
  {
    capability: 'Secret-backend config + credential health',
    featureIds: ['F31'],
    sprint: 'S41',
    kind: 'native',
    route: '/admin',
  },
  {
    capability: 'Editions / license state (Admin → Editions)',
    featureIds: ['F32'],
    sprint: 'S-T0',
    kind: 'native',
    route: '/admin',
  },
  {
    capability: 'Tenant data lifecycle: export, retention, residency visibility',
    featureIds: ['F55'],
    sprint: 'S-T5',
    kind: 'native',
    route: '/admin',
  },
  // The provider/operator console (ee/) is deliberately OFF the tenant nav: a
  // separate privilege domain, hidden when unlicensed (the API 404s).
  {
    capability: 'Provider console: tenant lifecycle, fleet, break-glass (operators)',
    featureIds: ['F51', 'F53', 'F54'],
    sprint: 'S-T1',
    kind: 'native',
    route: '/provider',
    offNav: true,
  },

  // --- federated surfaces (by design) ---
  {
    capability: 'Cost dashboards (Grafana via the probectl datasource)',
    featureIds: ['F41'],
    sprint: 'S44',
    kind: 'federated',
    evidence: ['openapi:/v1/cost/summary', 'openapi:/v1/grafana/api/v1/query'],
  },
  {
    capability: 'Metrics exploration + dashboards (Grafana datasource)',
    featureIds: ['F9', 'F30'],
    sprint: 'S40',
    kind: 'federated',
    evidence: [
      'file:deploy/grafana/provisioning/datasources/probectl.yml',
      'openapi:/v1/grafana/api/v1/query',
    ],
  },
  {
    capability: 'Prometheus federation + remote-write interop',
    featureIds: ['F30'],
    sprint: 'S40',
    kind: 'federated',
    evidence: ['openapi:/v1/prometheus/federate', 'openapi:/v1/prometheus/write'],
  },
  {
    capability: 'OTLP ingest/export (OpenTelemetry interop)',
    featureIds: ['F12'],
    sprint: 'S22',
    kind: 'federated',
    evidence: ['file:docs/otlp.md'],
  },
  {
    capability: 'CMDB CI correlation (incidents/agents → ServiceNow)',
    featureIds: ['F30'],
    sprint: 'S40',
    kind: 'federated',
    evidence: ['openapi:/v1/cmdb/lookup', 'openapi:/v1/incidents/{id}/cis'],
  },
  {
    capability: 'Staged fleet rollout controls (CLI + API + operator runbook)',
    featureIds: ['F28'],
    sprint: 'S49',
    kind: 'federated',
    evidence: [
      'file:docs/ops/fleet-rollout.md',
      'file:internal/cli/surfaces.go',
      'openapi:/v1/rollouts',
      'openapi:/v1/rollouts/{id}/verify',
    ],
  },
  {
    capability: 'BGP/routing monitoring events and analyzer output',
    featureIds: ['PLANE_BGP_ROUTING', 'F6'],
    sprint: 'S13',
    kind: 'native',
    route: '/planes',
  },
  {
    capability: 'Flow analytics APIs and ClickHouse-backed views',
    featureIds: ['PLANE_FLOW_ANALYTICS', 'F17'],
    sprint: 'S32',
    kind: 'native',
    route: '/planes',
  },
  {
    capability: 'Device telemetry collectors and topology attribution',
    featureIds: ['PLANE_DEVICE_TELEMETRY', 'F18'],
    sprint: 'S33',
    kind: 'native',
    route: '/planes',
  },
  {
    capability: 'eBPF host/L7 visibility and service map',
    featureIds: ['PLANE_EBPF_HOST_L7', 'F11'],
    sprint: 'S31',
    kind: 'native',
    route: '/planes',
  },
  {
    capability: 'REST/gRPC API and CLI/TUI command surface',
    featureIds: ['F10'],
    sprint: 'S12',
    kind: 'federated',
    evidence: ['openapi:/openapi.json', 'file:cmd/probectl', 'file:proto'],
  },
  {
    capability: 'MCP server tools and transport',
    featureIds: ['F14'],
    sprint: 'S25',
    kind: 'federated',
    evidence: ['file:docs/mcp.md', 'file:internal/ai/mcp'],
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
  },
  {
    capability: 'Audit log and tamper-evident verification',
    featureIds: ['F23'],
    sprint: 'S-T4',
    kind: 'federated',
    evidence: ['openapi:/v1/audit', 'openapi:/v1/audit/verify'],
  },
  {
    capability: 'Tenant / org / team / project hierarchy',
    featureIds: ['F24'],
    sprint: 'S-T3',
    kind: 'federated',
    evidence: ['file:internal/store/hierarchy.go'],
  },
  {
    capability: 'SIEM export and tenant-routed forwarding',
    featureIds: ['F26'],
    sprint: 'S38',
    kind: 'federated',
    evidence: ['file:docs/siem.md', 'file:internal/siem'],
  },
  {
    capability: 'IaC and GitOps deployment surfaces',
    featureIds: ['F29'],
    sprint: 'S39',
    kind: 'federated',
    evidence: ['file:deploy/terraform/README.md', 'file:deploy/gitops/README.md'],
  },
  {
    capability: 'Multi-region / HA runbooks and reference deployment',
    featureIds: ['F33'],
    sprint: 'S50',
    kind: 'federated',
    evidence: ['file:docs/ha.md', 'file:cmd/probectl-control/ha_reference_coherence_test.go'],
  },
  {
    capability: 'Advanced governance: retention, erasure, redaction, policy',
    featureIds: ['F34'],
    sprint: 'S-T6',
    kind: 'federated',
    evidence: ['file:docs/governance.md', 'file:internal/govern'],
  },
  {
    capability: 'Supportability: diagnostics, bundles, health evidence',
    featureIds: ['F35'],
    sprint: 'S51',
    kind: 'federated',
    evidence: ['file:docs/supportability.md', 'openapi:/v1/diagnostics/bundle'],
  },
  {
    capability: 'Change intelligence ingestion and incident correlation',
    featureIds: ['F39'],
    sprint: 'S42',
    kind: 'federated',
    evidence: ['file:docs/change-intel.md', 'openapi:/v1/changes'],
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
  },
  {
    capability: 'Network chaos experiments and dependency matrix',
    featureIds: ['F47'],
    sprint: 'S53',
    kind: 'federated',
    evidence: ['file:docs/chaos.md', 'file:internal/chaos'],
  },
  {
    capability: 'Tenant isolation model operations (pooled, siloed, hybrid)',
    featureIds: ['F50', 'F52'],
    sprint: 'S-T1/S-T7',
    kind: 'federated',
    evidence: ['file:docs/security/tenant-isolation.md', 'file:ee/silo'],
  },
  {
    capability: 'Per-tenant keys and BYOK administration',
    featureIds: ['F56'],
    sprint: 'S-T8',
    kind: 'federated',
    evidence: ['openapi:/v1/security/keys', 'file:ee/tenantkeys'],
  },
  {
    capability: 'Tenant fairness self-view and enforcement',
    featureIds: ['F57'],
    sprint: 'S-T9',
    kind: 'federated',
    evidence: ['file:docs/fairness.md', 'openapi:/v1/fairness'],
  },

  // --- declared none-by-design surfaces (deliberate product exclusions) ---

  {
    capability: 'Plugin/detection marketplace',
    featureIds: ['F49'],
    sprint: 'Phase 4 future bet',
    kind: 'none-by-design',
    noneReason:
      'PRD v1.0 marks F49 as outside the GA completeness denominator and a deliberate Phase-4 future bet; the detection-as-code substrate exists, but no current GA surface is promised.',
  },
]

/** RegistryViolation is one coverage/consistency failure (gate output). */
export interface RegistryViolation {
  capability: string
  problem: string
}

/** checkRegistryShape runs the pure (render-free) registry checks: every nav
 *  destination is registered, every routed declaration points at a nav
 *  destination, and every declaration is well-formed. The render/a11y checks
 *  live in the gate test (they need the DOM). */
export function checkRegistryShape(
  navRoutes: string[],
  surfaces: SurfaceDecl[],
): RegistryViolation[] {
  const violations: RegistryViolation[] = []
  const routed = new Map<string, SurfaceDecl[]>()
  for (const s of surfaces) {
    if (!s.featureIds || s.featureIds.length === 0) {
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
    if (!routed.has(nav)) {
      violations.push({
        capability: `nav:${nav}`,
        problem: 'nav destination has no registered surface (register it native)',
      })
    }
  }
  for (const [route, decls] of routed) {
    if (!navRoutes.includes(route) && !decls.every((d) => d.offNav)) {
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
