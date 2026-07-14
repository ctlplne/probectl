// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import type { BadgeTone } from '../components'

export interface AuthorityPosture {
  label: string
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
      tone: 'danger',
      detail: `Time-bounded emergency access from server permissions: ${joined}`,
    }
  }
  if (sorted.some((permission) => /read[_-]?only|degraded|license_read_only/i.test(permission))) {
    return {
      label: 'Degraded read-only',
      tone: 'warning',
      detail: `Read-only/degraded state from server permissions: ${joined}`,
    }
  }
  if (sorted.some((permission) => permission.startsWith('provider.'))) {
    return {
      label: 'Provider plane',
      tone: 'warning',
      detail: `Provider privilege domain from server permissions: ${joined}`,
    }
  }
  if (sorted.length === 0 || (sorted.length === 1 && sorted[0] === 'audit.read')) {
    return {
      label: 'Auditor read-only',
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
      tone: 'neutral',
      detail: `Read-only server permissions: ${joined}`,
    }
  }
  return {
    label: 'Operator',
    tone: 'success',
    detail: `Write-capable server permissions: ${joined}`,
  }
}
