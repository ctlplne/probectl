// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test } from 'vitest'
import type { DeploymentProfile } from '../api/agents'
import { agentTestSyncYAML, handoutAllowsPrivateTargets } from './agentTestSync'

// D-57: only a single-tenant install hands out allow_private_targets: true.
describe('agent test_sync handout (D-57)', () => {
  test.each<[DeploymentProfile | undefined, boolean]>([
    ['single', true],
    ['multi-tenant', false],
    ['regulated', false],
    [undefined, false],
  ])('profile %s opts in: %s', (profile, want) => {
    expect(handoutAllowsPrivateTargets(profile)).toBe(want)
    const yaml = agentTestSyncYAML(profile, 'why this value')
    expect(yaml.split('\n')).toEqual([
      'test_sync:',
      '  # enabled: on by default once `probectl-agent enroll` wrote testsync.pub',
      '  # why this value',
      `  allow_private_targets: ${String(want)}`,
    ])
  })

  test('an unexpected profile string fails closed', () => {
    expect(handoutAllowsPrivateTargets('Single' as DeploymentProfile)).toBe(false)
    expect(handoutAllowsPrivateTargets('' as DeploymentProfile)).toBe(false)
  })

  test('the reason wraps into comment lines and never into the value line', () => {
    const reason = Array.from({ length: 40 }, (_, i) => `word${i}`).join(' ')
    const lines = agentTestSyncYAML('single', reason).split('\n')
    const comments = lines.slice(2, -1)
    expect(comments.length).toBeGreaterThan(1)
    for (const line of comments) {
      expect(line.startsWith('  # ')).toBe(true)
      expect(line.length).toBeLessThanOrEqual(78)
    }
    expect(comments.map((line) => line.slice(4)).join(' ')).toBe(reason)
    expect(lines.at(-1)).toBe('  allow_private_targets: true')
  })
})
