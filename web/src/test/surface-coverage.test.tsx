import { describe, expect, test } from 'vitest'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { REQUIRED_FEATURES, type RequiredFeature } from '../featureCatalog'
import { NAV } from '../nav/ia'
import { SURFACES, checkRegistryShape, type SurfaceDecl } from '../surfaces'

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
const allowedSurfaceKinds = new Set<SurfaceDecl['kind']>(['native', 'federated', 'none-by-design'])
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
    evidence: ['openapi:/v1/bgp/events', 'cli:probectl bgp events'],
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
    evidence: [
      'openapi:/v1/devices',
      'openapi:/v1/device/metrics',
      'cli:probectl device metrics',
    ],
  },
  {
    id: 'F26',
    name: 'SIEM integration',
    kind: 'federated',
    evidence: ['openapi:/v1/siem/status', 'cli:probectl siem status'],
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

function prdRowFor(id: string): string | undefined {
  return prd.split('\n').find((line) => line.startsWith(`| ${id} |`))
}

describe('frontend-coverage gate (S-FE6)', () => {
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

  test('the gate itself fails on a capability with no surface', () => {
    // A nav destination nobody registered → violation.
    expect(
      checkRegistryShape(['/ghost'], SURFACES).some((v) => v.capability === 'nav:/ghost'),
    ).toBe(true)
    // A federated claim without evidence → violation.
    const bad: SurfaceDecl[] = [
      { capability: 'x', featureIds: ['F1'], sprint: 'Sx', kind: 'federated' },
    ]
    expect(checkRegistryShape([], bad)[0].problem).toMatch(/no evidence/)
    // A deliberate no-surface declaration must say why; otherwise "no UI"
    // can hide an accidental omission.
    const noReason: SurfaceDecl[] = [
      { capability: 'future x', featureIds: ['F49'], sprint: 'Sy', kind: 'none-by-design' },
    ]
    expect(checkRegistryShape([], noReason)[0].problem).toMatch(/no reason/)
    // A routed declaration outside the nav → violation.
    const offNav: SurfaceDecl[] = [
      { capability: 'y', featureIds: ['F1'], sprint: 'Sy', kind: 'native', route: '/nowhere' },
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
  })

  test('every native surface renders a real screen — never the placeholder', async () => {
    for (const route of uniqueRoutes('native')) {
      const { container, findByRole, unmount } = renderApp(route)
      // The shell mounts AFTER the session resolves (/v1/me, SEC-001), so await
      // the <main> landmark rather than asserting synchronously.
      expect(await findByRole('main'), `${route}: no main landmark`).toBeTruthy()
      await new Promise((r) => setTimeout(r, 30)) // let the page settle
      expect(
        container.textContent ?? '',
        `${route} is declared native but renders the placeholder`,
      ).not.toMatch(PLACEHOLDER_MARKER)
      expect(container.querySelector('h1'), `${route}: no h1`).toBeTruthy()
      unmount()
    }
  })

  test('each telemetry plane has a deep-linkable native route and passes axe', async () => {
    for (const plane of TELEMETRY_PLANE_ROUTES) {
      const { container, findByRole, unmount } = renderApp(plane.route)
      expect(await findByRole('main'), `${plane.route}: no main landmark`).toBeTruthy()
      const activeTab = await findByRole('tab', { name: plane.tab })
      expect(activeTab, `${plane.route}: active tab`).toHaveAttribute('aria-selected', 'true')
      const results = await axe(container)
      expect(results, `${plane.route} fails the a11y bar`).toHaveNoViolations()
      unmount()
    }
  }, 60_000)

  test('every declared file, OpenAPI, and CLI evidence exists', () => {
    expect(evidenceViolations(SURFACES)).toEqual([])
    for (const s of SURFACES.filter((x) => x.kind === 'federated')) {
      expect(s.evidence?.length ?? 0, `${s.capability}: federated surface declares evidence`).toBeGreaterThan(
        0,
      )
    }
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

  test('a11y: every native surface passes the WCAG 2.2 AA bar (axe)', async () => {
    for (const route of uniqueRoutes('native')) {
      const { container, findAllByRole, unmount } = renderApp(route)
      await findAllByRole('heading')
      await new Promise((r) => setTimeout(r, 50)) // settle queries/empty states
      const results = await axe(container)
      expect(results, `${route} fails the a11y bar`).toHaveNoViolations()
      unmount()
    }
  }, 60_000)
})
