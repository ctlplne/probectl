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

  test.each(['F24', 'F26'])('%s stays an explicit UI gap without a native screen', (featureID) => {
    expect(nativeRoutes(featureID)).toEqual([])
    expect(capabilityBlock(featureID)).toContain('ui: {gap:')
    expect(capabilityBlock(featureID)).toContain('evidence_status: partial')
  })

  test('the human-gated invariant reuses the guarded-remediation screen with a reason', () => {
    const block = capabilityBlock('CLM-HUMAN-GATED')
    expect(block).toContain('ui_aliases: {F44:')
    expect(block).toContain('ui: {refs: ["ui:F44@/admin"]}')
  })
})
