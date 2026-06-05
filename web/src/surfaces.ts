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
 *  - "placeholder": the engine itself is not built yet; the surface is due
 *                   with the named sprint. The gate asserts the placeholder
 *                   is STILL a placeholder — when the screen ships, the entry
 *                   must be re-declared native (keeps this registry truthful).
 *
 * Adding a nav destination without registering it here fails the gate; so
 * does declaring a native surface that renders the placeholder. Coverage +
 * consistency, not polish (the S-FE6 'watch out for').
 */

export type SurfaceKind = 'native' | 'federated' | 'placeholder'

export interface SurfaceDecl {
  /** The user-facing capability, in product language. */
  capability: string
  /** The sprint that owns (or will own) the surface. */
  sprint: string
  kind: SurfaceKind
  /** The app route (native + placeholder kinds). */
  route?: string
  /** Federated proof: "file:<repo-relative>" | "openapi:<api path>". */
  evidence?: string[]
}

export const SURFACES: SurfaceDecl[] = [
  // --- native screens (S8a shell) ---
  { capability: 'Synthetic tests CRUD + per-type result detail', sprint: 'S9/S-FE5', kind: 'native', route: '/targets' },
  { capability: 'AI test authoring + auto-discovery', sprint: 'S26', kind: 'native', route: '/targets' },
  { capability: 'Path / topology visualization', sprint: 'S11', kind: 'native', route: '/path' },
  { capability: 'Incidents list + cross-plane timeline', sprint: 'S17', kind: 'native', route: '/incidents' },
  { capability: 'Alerting: active alerts, silence/ack, rule config', sprint: 'S-FE1', kind: 'native', route: '/alerts' },
  { capability: 'TLS/cert posture inventory + trustctl handoff', sprint: 'S-FE2', kind: 'native', route: '/security' },
  { capability: 'Threat-intel / IOC + NDR detection triage', sprint: 'S-FE3/S42', kind: 'native', route: '/security' },
  { capability: 'Endpoint / last-mile / WiFi DEM fleet + attribution', sprint: 'S-FE4', kind: 'native', route: '/endpoints' },
  { capability: 'AI assistant (NL query + RCA with citations)', sprint: 'S24', kind: 'native', route: '/ask' },
  { capability: 'Agent fleet admin', sprint: 'S9', kind: 'native', route: '/admin' },
  { capability: 'Topology dependency graph + what-if impact simulation', sprint: 'S43', kind: 'native', route: '/topology' },
  { capability: 'Network egress cost summary + budgets (FinOps showback)', sprint: 'S44', kind: 'native', route: '/cost' },
  { capability: 'SLOs, error budgets + multi-window burn rates (OpenSLO)', sprint: 'S45', kind: 'native', route: '/slos' },
  { capability: 'Segmentation validation + audit evidence (PCI/NIST/zero-trust)', sprint: 'S46', kind: 'native', route: '/compliance' },
  { capability: 'Collective internet-outage view (open data + your vantages)', sprint: 'S47a', kind: 'native', route: '/outages' },
  { capability: 'RUM convergence: real-user impact joined with synthetic coverage', sprint: 'S47b', kind: 'native', route: '/endpoints' },
  { capability: 'Voice/RTP quality tests: MOS (E-model), jitter, loss', sprint: 'S47c', kind: 'native', route: '/targets' },
  { capability: 'Carbon/energy estimate (ESG view of network traffic)', sprint: 'S48', kind: 'native', route: '/cost' },
  { capability: 'Secret-backend config + credential health', sprint: 'S41', kind: 'native', route: '/admin' },
  { capability: 'Editions / license state (Admin → Editions)', sprint: 'S-T0', kind: 'native', route: '/admin' },

  // --- federated surfaces (by design) ---
  {
    capability: 'Cost dashboards (Grafana via the probectl datasource)',
    sprint: 'S44',
    kind: 'federated',
    evidence: ['openapi:/v1/cost/summary', 'openapi:/v1/grafana/api/v1/query'],
  },
  {
    capability: 'Metrics exploration + dashboards (Grafana datasource)',
    sprint: 'S40',
    kind: 'federated',
    evidence: ['file:deploy/grafana/provisioning/datasources/probectl.yml', 'openapi:/v1/grafana/api/v1/query'],
  },
  {
    capability: 'Prometheus federation + remote-write interop',
    sprint: 'S40',
    kind: 'federated',
    evidence: ['openapi:/v1/prometheus/federate', 'openapi:/v1/prometheus/write'],
  },
  {
    capability: 'OTLP ingest/export (OpenTelemetry interop)',
    sprint: 'S22',
    kind: 'federated',
    evidence: ['file:docs/otlp.md'],
  },
  {
    capability: 'CMDB CI correlation (incidents/agents → ServiceNow)',
    sprint: 'S40',
    kind: 'federated',
    evidence: ['openapi:/v1/cmdb/lookup', 'openapi:/v1/incidents/{id}/cis'],
  },

  // --- declared placeholders (engine lands with the named sprint) ---


  { capability: 'Curated in-app dashboards', sprint: 'S45 (Grafana covers it today via S40)', kind: 'placeholder', route: '/dashboards' },

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
export function checkRegistryShape(navRoutes: string[], surfaces: SurfaceDecl[]): RegistryViolation[] {
  const violations: RegistryViolation[] = []
  const routed = new Map<string, SurfaceDecl[]>()
  for (const s of surfaces) {
    if (s.kind === 'federated') {
      if (!s.evidence || s.evidence.length === 0) {
        violations.push({ capability: s.capability, problem: 'federated surface declares no evidence' })
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
      violations.push({ capability: `nav:${nav}`, problem: 'nav destination has no registered surface (register it native or placeholder)' })
    }
  }
  for (const [route, decls] of routed) {
    if (!navRoutes.includes(route)) {
      violations.push({ capability: decls[0].capability, problem: `route ${route} is not a nav destination` })
    }
    const kinds = new Set(decls.map((d) => d.kind))
    if (kinds.size > 1) {
      violations.push({ capability: decls[0].capability, problem: `route ${route} is declared both native and placeholder` })
    }
  }
  return violations
}
