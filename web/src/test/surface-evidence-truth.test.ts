// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

  /**
   * DPR-254 closed the last two `ui` gaps in the registry, so there is no
   * feature left whose UI cell is an acknowledged gap. That is a claim worth
   * pinning: the moment a new one appears it must be declared here rather than
   * left to read as covered.
   */
  test('no capability claims a UI gap any more', () => {
    const gapped = [...capabilityRegistry.matchAll(/^ {2}- id: (\S+)$/gm)]
      .map((match) => match[1])
      .filter((id) => capabilityBlock(id).includes('ui: {gap:'))
    expect(gapped).toEqual([])
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
