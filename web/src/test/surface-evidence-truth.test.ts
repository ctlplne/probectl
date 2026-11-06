// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, test } from 'vitest'
import { SURFACES } from '../surfaces'

const REPO_ROOT = resolve(__dirname, '../../..')
const capabilityRegistry = readFileSync(resolve(REPO_ROOT, 'capabilities.yaml'), 'utf8')

function nativeRoutes(featureID: string): string[] {
  return SURFACES.filter(
    (surface) => surface.kind === 'native' && surface.featureIds?.includes(featureID),
  )
    .map((surface) => surface.route!)
    .sort()
}

function capabilityBlock(id: string): string {
  const marker = `  - id: ${id}\n`
  const start = capabilityRegistry.indexOf(marker)
  if (start < 0) throw new Error(`missing capability ${id}`)
  const end = capabilityRegistry.indexOf('\n  - id: ', start + marker.length)
  return capabilityRegistry.slice(start, end < 0 ? undefined : end)
}

describe('truthful native UI evidence', () => {
  const expectedNativeRoutes: Array<[string, string[]]> = [
    // DPR-254: F24 and F26 had API and CLI surfaces and no screen at all. Both
    // now render as admin cards, so they move from the gap list to here.
    ['F24', ['/admin']],
    ['F26', ['/admin']],
    ['F34', ['/admin', '/provider']],
    ['F39', ['/explore', '/incidents', '/path']],
    ['F44', ['/admin']],
    ['F50', ['/admin']],
    ['F52', ['/provider']],
    ['F56', ['/admin']],
    ['F57', ['/provider']],
    ['F58', ['/admin']],
  ]

  test.each(expectedNativeRoutes)(
    '%s is bound only to the routes that render its operator controls',
    (featureID, routes) => {
      expect(nativeRoutes(featureID)).toEqual(routes)
      const block = capabilityBlock(featureID)
      expect(block).toContain('ui: {refs: [')
      for (const route of routes) expect(block).toContain(`"ui:${featureID}@${route}"`)
    },
  )

  // Implemented controls do not close a still-unexecuted served proof. Keep
  // every new qualification gap explicit instead of crediting it as coverage.
  test('only the declared interface-role served UI qualification remains gapped', () => {
    const gapped = [...capabilityRegistry.matchAll(/^ {2}- id: (\S+)$/gm)]
      .map((match) => match[1])
      .filter((id) => capabilityBlock(id).includes('ui: {gap:'))
    expect(gapped).toEqual(['F18'])
    const f18 = capabilityBlock('F18')
    expect(nativeRoutes('F18')).toEqual(['/admin', '/planes/device', '/targets', '/topology'])
    expect(f18).toContain('evidence_status: partial')
    expect(f18).toContain('Complete paired-tenant, both-theme served interface-role')
    expect(f18).toContain('qualification remains unproven.')
    for (const root of [
      'TestInterfaceRoleFRRSameRouterKeepsThreeRolesFlowAndOverride',
      'TestInterfaceRoleExplanationServesOwnedSourcesAndCurrentAuthority',
      'TestDeviceTelemetryRealStack',
      'TestNMSVendorLiveImportTwoTenants',
      'TestNMSImportExportPreviewRoutesKeepVendorPagesInOneTenant',
    ]) expect(f18).toContain(`#${root}`)
  })

  /**
   * A closed UI cell must not quietly close the capability's OTHER gaps. F24's
   * ui cell was its only one, so it is now evidence-complete; F26 still has no
   * real-stack receipt and has to keep saying so.
   */
  test('closing the UI cell did not silently absorb the remaining gaps', () => {
    const f24 = capabilityBlock('F24')
    expect(f24).toContain('evidence_status: complete')
    expect(f24).not.toContain('{gap:')

    const f26 = capabilityBlock('F26')
    expect(f26).toContain('evidence_status: partial')
    expect(f26).toContain('real_stack_proof: {gap:')
  })

  test('the human-gated invariant reuses the guarded-remediation screen with a reason', () => {
    const block = capabilityBlock('CLM-HUMAN-GATED')
    expect(block).toContain('ui_aliases: {F44:')
    expect(block).toContain('ui: {refs: ["ui:F44@/admin"]}')
  })
})
