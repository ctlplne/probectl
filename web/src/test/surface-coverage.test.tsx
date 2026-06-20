import { describe, expect, test } from 'vitest'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { REQUIRED_FEATURES } from '../featureCatalog'
import { NAV } from '../nav/ia'
import { SURFACES, checkRegistryShape, type SurfaceDecl } from '../surfaces'

/**
 * The frontend-coverage gate (S-FE6). Backend↔frontend coverage is a verified,
 * standing property: every user-facing capability must have its DECLARED
 * surface — native (a real screen, not the placeholder, passing the WCAG 2.2
 * AA bar), federated (evidence exists), or an explicitly registered
 * placeholder. Plus the consistency pass: no orphaned route styles, no nav
 * drift. Coverage + consistency — not polish.
 */

const REPO_ROOT = resolve(__dirname, '../../..')
const PLACEHOLDER_MARKER = /lands in a later sprint/i

const openapi = readFileSync(join(REPO_ROOT, 'internal/control/openapi.json'), 'utf8')
const openapiPaths = Object.keys((JSON.parse(openapi) as { paths: Record<string, unknown> }).paths)
const allowedSurfaceKinds = new Set<SurfaceDecl['kind']>([
  'native',
  'federated',
  'placeholder',
  'none-by-design',
])
const requiredFeatureIds = new Set(REQUIRED_FEATURES.map((f) => f.id))

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

describe('frontend-coverage gate (S-FE6)', () => {
  test('registry shape: every nav destination is registered; every routed declaration is a nav destination', () => {
    const violations = checkRegistryShape(
      NAV.map((n) => n.to),
      SURFACES,
    )
    expect(violations).toEqual([])
  })

  test('every PRD F-number and telemetry plane declares native, federated, placeholder, or none-by-design status', () => {
    expect(REQUIRED_FEATURES).toHaveLength(62)
    expect(REQUIRED_FEATURES[0].id).toBe('PLANE_ACTIVE_SYNTHETIC')
    expect(REQUIRED_FEATURES.some((f) => f.id === 'F1')).toBe(true)
    expect(REQUIRED_FEATURES.some((f) => f.id === 'F57')).toBe(true)
    expect(featureCoverageViolations(SURFACES)).toEqual([])
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

  test('every declared placeholder is STILL a placeholder (re-declare native when it ships)', async () => {
    for (const route of uniqueRoutes('placeholder')) {
      const { container, unmount } = renderApp(route)
      await new Promise((r) => setTimeout(r, 30))
      expect(
        container.textContent ?? '',
        `${route} no longer renders the placeholder — re-declare it native in surfaces.ts`,
      ).toMatch(PLACEHOLDER_MARKER)
      unmount()
    }
  })

  test('every federated surface has its declared evidence', () => {
    for (const s of SURFACES.filter((x) => x.kind === 'federated')) {
      for (const ev of s.evidence ?? []) {
        if (ev.startsWith('file:')) {
          const p = ev.slice('file:'.length)
          expect(existsSync(join(REPO_ROOT, p)), `${s.capability}: missing ${p}`).toBe(true)
        } else if (ev.startsWith('openapi:')) {
          const path = ev.slice('openapi:'.length)
          expect(openapiPaths, `${s.capability}: ${path} not in openapi.json`).toContain(path)
        } else {
          throw new Error(`${s.capability}: unknown evidence kind ${ev}`)
        }
      }
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
