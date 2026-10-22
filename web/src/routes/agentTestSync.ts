// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { DeploymentProfile } from '../api/agents'

/**
 * Whether the agent config onboarding hands out opts in to private targets
 * (D-57). Only a single-tenant (sovereign) install, where the operator owns
 * both the control plane and the agent, says true. multi-tenant, regulated
 * and an unknown profile say false: there the agent-side guard is what stops
 * a hosted control plane from making a customer's agent probe that
 * customer's internal network. Fail closed on anything else.
 */
export function handoutAllowsPrivateTargets(profile: DeploymentProfile | undefined): boolean {
  return profile === 'single'
}

/** Wraps one comment sentence into `# `-prefixed YAML comment lines. */
function yamlComment(text: string, indent: string, width = 78): string[] {
  const lines: string[] = []
  let line = ''
  for (const word of text.split(/\s+/).filter(Boolean)) {
    if (line && indent.length + 2 + line.length + 1 + word.length > width) {
      lines.push(`${indent}# ${line}`)
      line = word
    } else {
      line = line ? `${line} ${word}` : word
    }
  }
  if (line) lines.push(`${indent}# ${line}`)
  return lines
}

/**
 * The agent `test_sync:` block onboarding shows for the first test. Central
 * tests reach enrolled agents on their own (G9); what the operator still owns
 * is the agent's bound on what a bundle may make it probe, so that is the
 * handout. `enabled` stays implicit: it is on once `probectl-agent enroll`
 * wrote testsync.pub, and an explicit true without the key refuses to start.
 * `reason` is the localized comment saying why the value is what it is.
 */
export function agentTestSyncYAML(profile: DeploymentProfile | undefined, reason: string): string {
  const allow = handoutAllowsPrivateTargets(profile)
  return [
    'test_sync:',
    '  # enabled: on by default once `probectl-agent enroll` wrote testsync.pub',
    ...yamlComment(reason, '  '),
    `  allow_private_targets: ${allow ? 'true' : 'false'}`,
  ].join('\n')
}
