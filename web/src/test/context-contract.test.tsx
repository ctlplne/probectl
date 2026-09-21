// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import {
  REGISTERED_PLANE_PATHS,
  parsePivotContext,
  planePivotHref,
  serializePivotContext,
  type PivotContext,
} from '../routes/pivotContext'

const NOW = new Date('2026-07-14T12:00:00Z')

function completeContext(): PivotContext {
  return {
    incidentId: 'inc-42',
    from: '2026-07-14T10:00:00-02:00',
    to: '2026-07-14T12:05:00Z',
    filters: { severity: 'critical', site: 'edge' },
    selection: { kind: 'entity', id: 'hop:192.0.2.1' },
    returnTo: '/incidents?incident_status=open',
    expiresAt: '2026-07-14T12:30:00Z',
  }
}

describe('cross-plane URL context contract', () => {
  test('round-trips typed context without ever representing a tenant', () => {
    const encoded = serializePivotContext(completeContext(), NOW)
    const decoded = parsePivotContext(encoded, { now: NOW })

    expect(decoded.referencesValid).toBe(true)
    expect(decoded.context).toEqual({
      ...completeContext(),
      from: '2026-07-14T12:00:00.000Z',
      to: '2026-07-14T12:05:00.000Z',
      expiresAt: '2026-07-14T12:30:00.000Z',
    })
    expect(encoded.toString().toLowerCase()).not.toContain('tenant')
  })

  test('expired or malformed references fail closed while safe time and filters survive', () => {
    const encoded = serializePivotContext(completeContext(), NOW)
    encoded.set('ctx_expires', '2026-07-14T11:59:59Z')
    encoded.append('ctx_filter', 'tenant_id:other-tenant')
    encoded.set('ctx_return', 'https://attacker.invalid/steal')

    const decoded = parsePivotContext(encoded, { now: NOW })

    expect(decoded.referencesValid).toBe(false)
    expect(decoded.context.incidentId).toBeUndefined()
    expect(decoded.context.selection).toBeUndefined()
    expect(decoded.context.from).toBe('2026-07-14T12:00:00.000Z')
    expect(decoded.context.to).toBe('2026-07-14T12:05:00.000Z')
    expect(decoded.context.filters).toEqual({ severity: 'critical', site: 'edge' })
    expect(decoded.context.returnTo).toBeUndefined()
  })

  test('tenant-switch re-authorization invalidates IDs but retains harmless investigation context', () => {
    const encoded = serializePivotContext(completeContext(), NOW)
    const decoded = parsePivotContext(encoded, {
      now: NOW,
      // This models the destination checking IDs against its new, RLS-scoped
      // tenant response. Nothing from the old tenant is accepted.
      authorize: () => false,
    })

    expect(decoded.referencesValid).toBe(false)
    expect(decoded.context.incidentId).toBeUndefined()
    expect(decoded.context.selection).toBeUndefined()
    expect(decoded.context.filters).toEqual({ severity: 'critical', site: 'edge' })
    expect(decoded.context.from).toBeDefined()
    expect(decoded.context.to).toBeDefined()
  })

  test('saved-view filters replay through the URL and never touch browser storage', () => {
    const storageRead = vi.spyOn(Storage.prototype, 'getItem')
    const storageWrite = vi.spyOn(Storage.prototype, 'setItem')
    const savedViewFromServer = { severity: 'warning', plane: 'bgp' }

    const encoded = serializePivotContext(
      { filters: savedViewFromServer, from: '2026-07-14T11:00:00Z' },
      NOW,
    )
    const replayed = parsePivotContext(encoded, { now: NOW })

    expect(replayed.context.filters).toEqual(savedViewFromServer)
    expect(storageRead).not.toHaveBeenCalled()
    expect(storageWrite).not.toHaveBeenCalled()
  })

  test('every registered plane pivot uses the same serializer and parser', () => {
    for (const [plane, pathname] of Object.entries(REGISTERED_PLANE_PATHS)) {
      const href = planePivotHref(
        plane as keyof typeof REGISTERED_PLANE_PATHS,
        completeContext(),
        NOW,
      )
      const url = new URL(href, 'https://probectl.invalid')
      expect(url.pathname).toBe(pathname)
      expect(parsePivotContext(url.searchParams, { now: NOW }).context.incidentId).toBe('inc-42')
      expect(href.toLowerCase()).not.toContain('tenant')
    }
  })
})
