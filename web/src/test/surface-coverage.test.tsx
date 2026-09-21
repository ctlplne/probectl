// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test } from 'vitest'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import {
  REQUIRED_FEATURES,
  type RequiredFeature,
  type RequiredFeatureStatus,
} from '../featureCatalog'
import { NAV } from '../nav/ia'
import {
  SURFACES,
  checkRegistryShape,
  type SurfaceDecl,
  type SurfaceLiveReceipt,
} from '../surfaces'
import {
  ALL_HONEST_DATA_STATES,
  NATIVE_DATA_SURFACE_TRUTH,
  NON_DATA_NATIVE_ROUTES,
} from '../data/surfaceTruth'

/**
 * The frontend-coverage gate (S-FE6). Backend↔frontend coverage is a verified,
 * standing property: every user-facing capability must have its DECLARED
 * surface — native (a real screen, not the placeholder, passing the WCAG 2.2
 * AA bar), federated (evidence exists), or none-by-design (with a rationale).
 * Plus the consistency pass: no orphaned route styles, no nav
 * drift. Coverage + consistency — not polish.
 */

const REPO_ROOT = resolve(__dirname, '../../..')
const PLACEHOLDER_MARKER = /lands in a later sprint/i

const openapi = readFileSync(join(REPO_ROOT, 'internal/control/openapi.json'), 'utf8')
const openapiPaths = Object.keys((JSON.parse(openapi) as { paths: Record<string, unknown> }).paths)
const cliSurfaceSource = readFileSync(join(REPO_ROOT, 'internal/cli/surfaces.go'), 'utf8')
const cliCommands = cliCommandsFromSurfaceSource(cliSurfaceSource)
const prd = readPRDv1()
const allowedSurfaceKinds = new Set<SurfaceDecl['kind']>([
  'native',
  'federated',
  'none-by-design',
  'dev-showcase',
])
const allowedLiveReceiptStatuses = new Set<SurfaceLiveReceipt['status']>([
  'live-green',
  'static-only',
  'non-live',
])
const TEST_SURFACE_RECEIPT = SURFACES[0].liveReceipt
const TELEMETRY_PLANE_ROUTES = [
  { route: '/planes/bgp', tab: /BGP/i },
  { route: '/planes/flow', tab: /Flow/i },
  { route: '/planes/device', tab: /Device/i },
  { route: '/planes/ebpf', tab: /eBPF/i },
]
const requiredFeatureIds = new Set(REQUIRED_FEATURES.map((f) => f.id))
const PRD_ROW_SURFACE_PARITY: Array<{
  id: string
  name: string
  kind: SurfaceDecl['kind']
  route?: string
  evidence?: string[]
  noneReason?: RegExp[]
}> = [
  {
    id: 'F6',
    name: 'BGP monitoring',
    kind: 'native',
    route: '/planes/bgp',
    evidence: ['openapi:/v1/bgp/events', 'cli:probectl bgp events', 'cli:probectl bgp setup'],
  },
  {
    id: 'F11',
    name: 'eBPF host/L7 agent',
    kind: 'native',
    route: '/planes/ebpf',
    evidence: ['openapi:/v1/ebpf/service-map', 'cli:probectl ebpf service-map'],
  },
  {
    id: 'F18',
    name: 'Device telemetry',
    kind: 'native',
    route: '/planes/device',
    evidence: ['openapi:/v1/devices', 'openapi:/v1/device/metrics', 'cli:probectl device metrics'],
  },
  {
    // DPR-254: F26 keeps its federated API/CLI surface AND now has the native
    // delivery-posture card, so the parity row requires both.
    id: 'F26',
    name: 'SIEM integration',
    kind: 'native',
    route: '/admin',
    evidence: ['openapi:/v1/siem/status', 'cli:probectl siem status'],
  },
  {
    id: 'F24',
    name: 'Tenant→Org→Team→Project',
    kind: 'native',
    route: '/admin',
    evidence: ['openapi:/v1/hierarchy', 'openapi:/v1/hierarchy/orgs'],
  },
  {
    id: 'F47',
    name: 'Network chaos',
    kind: 'none-by-design',
    noneReason: [/Library\/test-harness only/i, /no REST, UI, MCP, probectl operator CLI/i],
  },
]

function readPRDv1(): string {
  const candidates = [
    join(REPO_ROOT, 'probectl-PRD-v1.0.md'),
    join(REPO_ROOT, '../probectl-PRD-v1.0.md'),
    join(REPO_ROOT, '../../probectl-PRD-v1.0.md'),
  ]
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return readFileSync(candidate, 'utf8')
    }
  }
  throw new Error(`probectl-PRD-v1.0.md not found in ${candidates.join(' or ')}`)
}

function cliCommandsFromSurfaceSource(source: string): Set<string> {
  const commands = new Set<string>()
  const groups = source.matchAll(
    /\n\t"([^"]+)": \{Name: "([^"]+)", Summary: "[^"]+", Ops: map\[string\]apiOp\{([\s\S]*?)\n\t\}\},/g,
  )
  for (const group of groups) {
    const commandGroup = group[2]
    for (const op of group[3].matchAll(/\n\t\t"([^"]+)":\s+\{Method:/g)) {
      commands.add(`probectl ${commandGroup} ${op[1]}`)
    }
  }
  for (const command of source.matchAll(/Command:\s*"(probectl [^"]+)"/g)) {
    commands.add(command[1])
  }
  return commands
}

function uniqueRoutes(kind: SurfaceDecl['kind']): string[] {
  return [...new Set(SURFACES.filter((s) => s.kind === kind && s.route).map((s) => s.route!))]
}

function featureCoverageViolations(surfaces: SurfaceDecl[]): string[] {
  const covered = new Set<string>()
  const violations: string[] = []
  for (const s of surfaces) {
    for (const id of s.featureIds ?? []) {
      if (!requiredFeatureIds.has(id)) {
        violations.push(`${s.capability}: unknown feature id ${id}`)
      }
      if (!s.kind || !allowedSurfaceKinds.has(s.kind)) {
        violations.push(`${s.capability}: feature ${id} lacks a declared surface kind`)
        continue
      }
      covered.add(id)
    }
  }
  for (const feature of REQUIRED_FEATURES) {
    if (!covered.has(feature.id)) {
      violations.push(`${feature.id} ${feature.name}: missing surface declaration`)
    }
  }
  return violations
}

function hasServedEvidence(s: SurfaceDecl): boolean {
  if (s.kind === 'native') {
    return Boolean(s.route)
  }
  if (s.kind === 'federated') {
    return Boolean(s.evidence?.length)
  }
  return Boolean(s.noneReason?.trim())
}

function servedEvidenceViolations(features: RequiredFeature[], surfaces: SurfaceDecl[]): string[] {
  const violations: string[] = []
  for (const feature of features.filter((f) => f.status !== 'future')) {
    const decls = surfaces.filter((s) => s.featureIds?.includes(feature.id))
    if (!decls.some(hasServedEvidence)) {
      violations.push(
        `${feature.id} ${feature.name}: missing native, API/CLI, federated, or none-by-design evidence`,
      )
    }
  }
  return violations
}

function futureFeatureViolations(features: RequiredFeature[], surfaces: SurfaceDecl[]): string[] {
  const violations: string[] = []
  for (const feature of features.filter((f) => f.status === 'future')) {
    const decls = surfaces.filter((s) => s.featureIds?.includes(feature.id))
    if (decls.length !== 1) {
      violations.push(
        `${feature.id} ${feature.name}: future feature must have exactly one non-GA declaration`,
      )
      continue
    }
    if (decls[0].kind !== 'none-by-design') {
      violations.push(
        `${feature.id} ${feature.name}: future feature must be none-by-design, got ${decls[0].kind}`,
      )
    }
    if (!decls[0].noneReason || !/future|no current GA/i.test(decls[0].noneReason)) {
      violations.push(`${feature.id} ${feature.name}: future feature lacks a GA exclusion reason`)
    }
  }
  return violations
}

function evidenceViolations(surfaces: SurfaceDecl[]): string[] {
  const violations: string[] = []
  for (const s of surfaces) {
    for (const ev of s.evidence ?? []) {
      if (ev.startsWith('file:')) {
        const p = ev.slice('file:'.length)
        if (!existsSync(join(REPO_ROOT, p))) {
          violations.push(`${s.capability}: missing ${p}`)
        }
      } else if (ev.startsWith('openapi:')) {
        const path = ev.slice('openapi:'.length)
        if (path === '/openapi.json') {
          continue
        }
        if (!openapiPaths.includes(path)) {
          violations.push(`${s.capability}: ${path} not in openapi.json`)
        }
      } else if (ev.startsWith('cli:')) {
        const command = ev.slice('cli:'.length)
        if (!cliCommands.has(command)) {
          violations.push(`${s.capability}: ${command} not in internal/cli/surfaces.go`)
        }
      } else {
        violations.push(`${s.capability}: unknown evidence kind ${ev}`)
      }
    }
  }
  return violations
}

function liveReceiptViolations(surfaces: SurfaceDecl[]): string[] {
  const violations: string[] = []
  for (const s of surfaces) {
    const receipt = s.liveReceipt
    if (!receipt) {
      violations.push(`${s.capability}: missing live receipt status`)
      continue
    }
    if (!allowedLiveReceiptStatuses.has(receipt.status)) {
      violations.push(`${s.capability}: unknown live receipt status ${receipt.status}`)
      continue
    }
    if (!receipt.note.trim()) {
      violations.push(`${s.capability}: live receipt note is required`)
    }
    if (receipt.evidence.length === 0) {
      violations.push(`${s.capability}: live receipt evidence is required`)
    }
    if ((s.kind === 'native' || s.kind === 'dev-showcase') && receipt.status === 'non-live') {
      violations.push(`${s.capability}: native surface must be live-green or static-only`)
    }
    if (s.kind !== 'native' && s.kind !== 'dev-showcase' && receipt.status === 'static-only') {
      violations.push(
        `${s.capability}: only native or dev-showcase surfaces may use static-only receipt status`,
      )
    }
    const hasCI = receipt.evidence.some((ev) => ev.startsWith('ci:'))
    const hasTest = receipt.evidence.some((ev) => ev.startsWith('test:'))
    if (receipt.status === 'live-green' && (!hasCI || !hasTest)) {
      violations.push(`${s.capability}: live-green receipt requires ci: and test: evidence`)
    }
    if (
      receipt.status === 'live-green' &&
      receipt.evidence.some((ev) => ev.includes('surface-coverage.test.tsx'))
    ) {
      violations.push(
        `${s.capability}: live-green receipt must cite a live e2e/integration test, not the static frontend gate`,
      )
    }
    for (const ev of receipt.evidence) {
      const evidenceViolation = liveReceiptEvidenceViolation(s.capability, ev)
      if (evidenceViolation) {
        violations.push(evidenceViolation)
      }
    }
  }
  return violations
}

function liveReceiptEvidenceViolation(capability: string, ev: string): string | undefined {
  const parsed = parseLiveReceiptEvidence(ev)
  if (!parsed) {
    return `${capability}: unknown live receipt evidence kind ${ev}`
  }
  const [kind, relPath, needle] = parsed
  const path = join(REPO_ROOT, relPath)
  if (!existsSync(path)) {
    return `${capability}: missing ${kind} evidence file ${relPath}`
  }
  if (!needle.trim()) {
    return `${capability}: ${ev} has an empty evidence needle`
  }
  if (!readFileSync(path, 'utf8').includes(needle)) {
    return `${capability}: ${kind} evidence ${relPath} does not contain ${needle}`
  }
  return undefined
}

function parseLiveReceiptEvidence(ev: string): ['ci' | 'test', string, string] | undefined {
  const first = ev.indexOf(':')
  const second = ev.indexOf(':', first + 1)
  if (first <= 0 || second <= first + 1) {
    return undefined
  }
  const kind = ev.slice(0, first)
  if (kind !== 'ci' && kind !== 'test') {
    return undefined
  }
  return [kind, ev.slice(first + 1, second), ev.slice(second + 1)]
}

function prdCellsFor(id: string): string[] | undefined {
  for (const row of prd.split('\n')) {
    const cells = row
      .split('|')
      .map((cell) => cell.trim())
      .filter(Boolean)
    if (cells[0]?.split('/').includes(id)) {
      return cells
    }
  }
  return undefined
}

function prdRowFor(id: string): string | undefined {
  return prd.split('\n').find((row) => {
    const cells = row
      .split('|')
      .map((cell) => cell.trim())
      .filter(Boolean)
    return cells[0]?.split('/').includes(id)
  })
}

function prdStatusFor(id: string): RequiredFeatureStatus | undefined {
  const cells = prdCellsFor(id)
  if (!cells) {
    return undefined
  }
  const statusCell = cells[2] ?? ''
  if (statusCell.includes('✅')) {
    return 'delivered'
  }
  if (statusCell.includes('🚫')) {
    return 'removed'
  }
  if (statusCell.includes('⛔')) {
    return 'future'
  }
  if (statusCell.includes('🔶') || statusCell.includes('⏳')) {
    return 'partial'
  }
  return undefined
}

function prdCatalogStatusViolations(features: RequiredFeature[]): string[] {
  const violations: string[] = []
  for (const feature of features.filter((f) => f.source === 'prd-v1.0:3')) {
    const prdStatus = prdStatusFor(feature.id)
    if (!prdStatus) {
      violations.push(`${feature.id} ${feature.name}: missing PRD status`)
      continue
    }
    if (feature.status !== prdStatus) {
      violations.push(
        `${feature.id} ${feature.name}: catalog status ${feature.status} != PRD status ${prdStatus}`,
      )
    }
  }
  return violations
}

describe('frontend-coverage gate (S-FE6)', () => {
  test('every native data route declares all six server-truth states and their evidence fields', () => {
    const contractsByRoute = new Map(
      NATIVE_DATA_SURFACE_TRUTH.map((contract) => [contract.route, contract]),
    )
    const expectedRoutes = uniqueRoutes('native').filter(
      (route) => !NON_DATA_NATIVE_ROUTES.has(route),
    )

    expect([...contractsByRoute.keys()].sort()).toEqual(expectedRoutes.sort())
    for (const route of expectedRoutes) {
      const contract = contractsByRoute.get(route)
      expect(contract, `${route} lacks a truthful data-state contract`).toBeDefined()
      expect(contract?.states).toEqual(ALL_HONEST_DATA_STATES)
      expect(contract?.producer.trim()).toBeTruthy()
      expect(contract?.serverTruth.trim()).toBeTruthy()
      expect(contract?.lastSuccessfulIngest.trim()).toBeTruthy()
      expect(contract?.coverageLimitation.trim()).toBeTruthy()
      expect(contract?.authorizedNextAction.trim()).toBeTruthy()
    }
  })

  test('registry shape: every nav destination is registered; routed declarations sit on or under nav', () => {
    const violations = checkRegistryShape(
      NAV.map((n) => n.to),
      SURFACES,
    )
    expect(violations).toEqual([])
  })

  test('every PRD F-number and telemetry plane declares native, federated, or none-by-design status', () => {
    expect(REQUIRED_FEATURES).toHaveLength(62)
    expect(REQUIRED_FEATURES[0].id).toBe('PLANE_ACTIVE_SYNTHETIC')
    expect(REQUIRED_FEATURES.some((f) => f.id === 'F1')).toBe(true)
    expect(REQUIRED_FEATURES.some((f) => f.id === 'F57')).toBe(true)
    expect(prdCatalogStatusViolations(REQUIRED_FEATURES)).toEqual([])
    expect(featureCoverageViolations(SURFACES)).toEqual([])
    expect(servedEvidenceViolations(REQUIRED_FEATURES, SURFACES)).toEqual([])
  })

  test('audited PRD rows trace to first-class operator surfaces or explicit none-by-design reasons', () => {
    for (const row of PRD_ROW_SURFACE_PARITY) {
      expect(prdRowFor(row.id), `${row.id}: missing PRD row`).toContain(`| ${row.name} |`)
      const decls = SURFACES.filter((s) => s.featureIds?.includes(row.id))
      expect(decls.length, `${row.id}: no surface declaration`).toBeGreaterThan(0)
      expect(
        decls.some((s) => s.kind === row.kind),
        `${row.id}: missing ${row.kind} surface declaration`,
      ).toBe(true)
      if (row.route) {
        expect(
          decls.some((s) => s.kind === 'native' && s.route === row.route),
          `${row.id}: missing native route ${row.route}`,
        ).toBe(true)
      }
      const evidence = new Set(decls.flatMap((s) => s.evidence ?? []))
      for (const ev of row.evidence ?? []) {
        expect(evidence.has(ev), `${row.id}: missing served evidence ${ev}`).toBe(true)
      }
      const noneReasons = decls.map((s) => s.noneReason ?? '').join('\n')
      for (const reason of row.noneReason ?? []) {
        expect(noneReasons, `${row.id}: none-by-design reason missing ${reason}`).toMatch(reason)
      }
    }
  })

  test('future/non-GA PRD features stay explicit none-by-design declarations', () => {
    const futureFeatures = REQUIRED_FEATURES.filter((f) => f.status === 'future')
    expect(futureFeatures.map((f) => f.id)).toEqual(['F49'])
    expect(futureFeatureViolations(REQUIRED_FEATURES, SURFACES)).toEqual([])
    expect(SURFACES.find((s) => s.featureIds?.includes('F49'))?.noneReason).toContain(
      'outside the GA completeness denominator',
    )

    const bad: SurfaceDecl[] = SURFACES.map(
      (s): SurfaceDecl =>
        s.featureIds?.includes('F49')
          ? { ...s, kind: 'native', route: '/marketplace', noneReason: undefined }
          : s,
    )
    expect(futureFeatureViolations(REQUIRED_FEATURES, bad)).toContain(
      'F49 Plugin/detection marketplace: future feature must be none-by-design, got native',
    )
  })

  test('removed features remain explicit none-by-design decisions', () => {
    const removed = REQUIRED_FEATURES.filter((feature) => feature.status === 'removed')
    expect(removed.map((feature) => feature.id)).toEqual(['F54'])
    const declaration = SURFACES.find((surface) => surface.featureIds?.includes('F54'))
    expect(declaration?.kind).toBe('none-by-design')
    expect(declaration?.noneReason).toMatch(/removed by design/i)
    expect(declaration?.noneReason).toMatch(/probectl banner/i)
  })

  test('the gate itself fails on a capability with no surface', () => {
    // A nav destination nobody registered → violation.
    expect(
      checkRegistryShape(['/ghost'], SURFACES).some((v) => v.capability === 'nav:/ghost'),
    ).toBe(true)
    // A federated claim without evidence → violation.
    const bad: SurfaceDecl[] = [
      {
        capability: 'x',
        featureIds: ['F1'],
        sprint: 'Sx',
        kind: 'federated',
        liveReceipt: TEST_SURFACE_RECEIPT,
      },
    ]
    expect(checkRegistryShape([], bad)[0].problem).toMatch(/no evidence/)
    // A deliberate no-surface declaration must say why; otherwise "no UI"
    // can hide an accidental omission.
    const noReason: SurfaceDecl[] = [
      {
        capability: 'future x',
        featureIds: ['F49'],
        sprint: 'Sy',
        kind: 'none-by-design',
        liveReceipt: TEST_SURFACE_RECEIPT,
      },
    ]
    expect(checkRegistryShape([], noReason)[0].problem).toMatch(/no reason/)
    // A routed declaration outside the nav → violation.
    const offNav: SurfaceDecl[] = [
      {
        capability: 'y',
        featureIds: ['F1'],
        sprint: 'Sy',
        kind: 'native',
        route: '/nowhere',
        liveReceipt: TEST_SURFACE_RECEIPT,
      },
    ]
    expect(checkRegistryShape([], offNav)[0].problem).toMatch(/not a nav destination/)
    // …unless it is EXPLICITLY declared offNav (S-T1: the provider console —
    // deliberately undiscoverable from the tenant app).
    const declared: SurfaceDecl[] = [
      {
        capability: 'y',
        featureIds: ['F1'],
        sprint: 'Sy',
        kind: 'native',
        route: '/nowhere',
        offNav: true,
        liveReceipt: TEST_SURFACE_RECEIPT,
      },
    ]
    expect(checkRegistryShape([], declared)).toEqual([])

    const childRoute: SurfaceDecl[] = [
      {
        capability: 'plane child',
        featureIds: ['F1'],
        sprint: 'Sz',
        kind: 'native',
        route: '/planes/flow',
        liveReceipt: TEST_SURFACE_RECEIPT,
      },
    ]
    expect(checkRegistryShape(['/planes'], childRoute)).toEqual([])
  })

  test('the gate itself fails when a required PRD feature disappears or has no surface kind', () => {
    const removedF1 = SURFACES.map((s) => ({
      ...s,
      featureIds: (s.featureIds ?? []).filter((id) => id !== 'F1'),
    }))
    expect(featureCoverageViolations(removedF1)).toContain(
      'F1 Canary agent: missing surface declaration',
    )

    const missingKind = [
      {
        capability: 'broken feature status',
        featureIds: ['F1'],
        sprint: 'test',
      } as unknown as SurfaceDecl,
    ]
    expect(featureCoverageViolations(missingKind)).toContain(
      'broken feature status: feature F1 lacks a declared surface kind',
    )

    const legacyPlaceholder = [
      {
        capability: 'legacy placeholder taxonomy',
        featureIds: ['F1'],
        sprint: 'test',
        kind: 'placeholder',
      } as unknown as SurfaceDecl,
    ]
    expect(featureCoverageViolations(legacyPlaceholder)).toContain(
      'legacy placeholder taxonomy: feature F1 lacks a declared surface kind',
    )

    const staleCatalog = REQUIRED_FEATURES.map((feature): RequiredFeature => {
      if (feature.id !== 'F28') {
        return feature
      }
      return { ...feature, status: 'partial' }
    })
    expect(prdCatalogStatusViolations(staleCatalog)).toContain(
      'F28 Zero-downtime lifecycle and fleet rollout: catalog status partial != PRD status delivered',
    )
  })

  // DPR-238: one case PER ROUTE. Every native route is a full app mount plus a
  // lazy chunk resolving, and there are dozens of them; inside a single test they
  // shared one 15s budget and the loop timed out — on a slower runner first, and
  // the timeout then named the loop instead of the route that was slow. Worse, a
  // test that dies mid-loop never reaches its unmount(), so the NEXT test in this
  // file inherited a second mounted shell and failed on a duplicate banner
  // landmark, reporting an a11y violation that did not exist. Same reason
  // DPR-234 split the telemetry-plane case just above.
  test.each(uniqueRoutes('native'))(
    'native surface %s renders a real screen — never the placeholder',
    async (route) => {
      const { container, findByRole, unmount } = renderApp(route)
      // The shell mounts AFTER the session resolves (/v1/me, SEC-001), so await
      // the <main> landmark rather than asserting synchronously.
      expect(await findByRole('main'), `${route}: no main landmark`).toBeTruthy()
      // Native routes are lazy chunks. The heading is the stable signal that
      // the route module resolved; a fixed sleep made this gate runner-speed
      // dependent and could inspect the Suspense fallback instead.
      expect(await findByRole('heading', { level: 1 }), `${route}: no h1`).toBeTruthy()
      expect(
        container.textContent ?? '',
        `${route} is declared native but renders the placeholder`,
      ).not.toMatch(PLACEHOLDER_MARKER)
      unmount()
    },
  )

  // DPR-234: one case PER PLANE, not one case looping over four. Rendering the
  // app and running axe on a single route costs ~15s in this environment, so four
  // of them inside one test sat exactly on the shared 60s budget and timed out on
  // a loaded machine — and a timeout named the loop rather than the plane. Each
  // case now gets its own budget and its own name; the assertions are unchanged.
  test.each(TELEMETRY_PLANE_ROUTES)(
    'telemetry plane $route is deep-linkable, selects its tab, and passes axe',
    async (plane) => {
      const { container, findByRole, unmount } = renderApp(plane.route)
      expect(await findByRole('main'), `${plane.route}: no main landmark`).toBeTruthy()
      const activeTab = await findByRole('tab', { name: plane.tab })
      expect(activeTab, `${plane.route}: active tab`).toHaveAttribute('aria-selected', 'true')
      const results = await axe(container)
      expect(results, `${plane.route} fails the a11y bar`).toHaveNoViolations()
      unmount()
    },
    60_000,
  )

  test('every declared file, OpenAPI, and CLI evidence exists', () => {
    expect(evidenceViolations(SURFACES)).toEqual([])
    for (const s of SURFACES.filter((x) => x.kind === 'federated')) {
      expect(
        s.evidence?.length ?? 0,
        `${s.capability}: federated surface declares evidence`,
      ).toBeGreaterThan(0)
    }
  })

  test('live served-path receipt status is explicit and live-green claims cite live proof', () => {
    expect(liveReceiptViolations(SURFACES)).toEqual([])

    const staticAsLive: SurfaceDecl[] = SURFACES.map((s): SurfaceDecl => {
      if (s.capability !== 'Topology dependency graph + what-if impact simulation') {
        return s
      }
      return {
        ...s,
        liveReceipt: {
          status: 'live-green',
          evidence: [
            'ci:.github/workflows/ci.yml:npm run coverage-gate',
            'test:web/src/test/surface-coverage.test.tsx:every native surface renders a real screen',
          ],
          note: 'bad fixture',
        },
      }
    })
    expect(liveReceiptViolations(staticAsLive)).toContain(
      'Topology dependency graph + what-if impact simulation: live-green receipt must cite a live e2e/integration test, not the static frontend gate',
    )

    const noWorkflow: SurfaceDecl[] = SURFACES.map((s): SurfaceDecl => {
      if (s.capability !== 'Path / topology visualization') {
        return s
      }
      return {
        ...s,
        liveReceipt: {
          status: 'live-green',
          evidence: ['test:test/e2e/e2e_test.go:TestE2E'],
          note: 'bad fixture',
        },
      }
    })
    expect(liveReceiptViolations(noWorkflow)).toContain(
      'Path / topology visualization: live-green receipt requires ci: and test: evidence',
    )
  })

  test('consistency: no orphaned route styles (every routes/*.module.css is imported)', () => {
    const routesDir = resolve(__dirname, '../routes')
    const cssFiles = readdirSync(routesDir).filter((f) => f.endsWith('.module.css'))
    const sources = readdirSync(routesDir)
      .filter((f) => f.endsWith('.tsx') || f.endsWith('.ts'))
      .map((f) => readFileSync(join(routesDir, f), 'utf8'))
      .join('\n')
    for (const css of cssFiles) {
      expect(sources.includes(`./${css}`), `orphaned route stylesheet: ${css}`).toBe(true)
    }
  })

  test.each(uniqueRoutes('native'))(
    'a11y: native surface %s passes the WCAG 2.2 AA bar',
    async (route) => {
      const view = renderApp(route)
      try {
        await view.findAllByRole('heading')
        await new Promise((resolve) => setTimeout(resolve, 50)) // settle queries/empty states
        const results = await axe(view.container)
        expect(results, `${route} fails the a11y bar`).toHaveNoViolations()
      } finally {
        view.unmount()
      }
    },
    // DPR-168: this sweep renders a whole route and runs axe over it, and the
    // heaviest route (/docs/api, every documented operation) measures 2.9s alone
    // but 16.3s when the full suite is competing for the same cores — over the
    // 15s default, so the a11y gate failed for load, not for accessibility.
    // Timeout headroom belongs on the sweep; page weight is the performance
    // gate's job, not this one's.
    60_000,
  )
})
