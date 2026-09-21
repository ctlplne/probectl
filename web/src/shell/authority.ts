// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { BadgeTone } from '../components'

export interface AuthorityPosture {
  label: string
  /** Compressed label for narrow viewports; same posture, fewer characters. */
  short: string
  tone: BadgeTone
  detail: string
}

function isReadPermission(permission: string): boolean {
  return (
    permission.endsWith('.read') ||
    permission === 'audit.read' ||
    permission === 'diagnostics.read' ||
    permission === 'lifecycle.export'
  )
}

export function authorityPosture(permissions: string[]): AuthorityPosture {
  const sorted = [...permissions].sort()
  const joined = sorted.join(', ')
  if (sorted.some((permission) => /break[-_]?glass|breakglass/i.test(permission))) {
    return {
      label: 'Break-glass active',
      short: 'Break-glass',
      tone: 'danger',
      detail: `Time-bounded emergency access from server permissions: ${joined}`,
    }
  }
  if (sorted.some((permission) => /read[_-]?only|degraded|license_read_only/i.test(permission))) {
    return {
      label: 'Degraded read-only',
      short: 'Degraded',
      tone: 'warning',
      detail: `Read-only/degraded state from server permissions: ${joined}`,
    }
  }
  if (sorted.some((permission) => permission.startsWith('provider.'))) {
    return {
      label: 'Provider plane',
      short: 'Provider',
      tone: 'warning',
      detail: `Provider privilege domain from server permissions: ${joined}`,
    }
  }
  if (sorted.length === 0 || (sorted.length === 1 && sorted[0] === 'audit.read')) {
    return {
      label: 'Auditor read-only',
      short: 'Auditor',
      tone: 'info',
      detail:
        sorted.length === 0
          ? 'No write permissions returned by the server'
          : `Audit-only server permissions: ${joined}`,
    }
  }
  if (sorted.every(isReadPermission)) {
    return {
      label: 'Read-only',
      short: 'Read-only',
      tone: 'neutral',
      detail: `Read-only server permissions: ${joined}`,
    }
  }
  return {
    label: 'Operator',
    short: 'Operator',
    tone: 'success',
    detail: `Write-capable server permissions: ${joined}`,
  }
}
