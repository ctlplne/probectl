// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

export const DASHBOARD_TIME_SCOPE_PARAM = 'range'
export const DEFAULT_DASHBOARD_TIME_SCOPE = '1h'

export type DashboardTimeScope = '15m' | '1h' | '6h' | '24h'

export interface DashboardTimeScopeDefinition {
  value: DashboardTimeScope
  durationMs: number
  bucket: string
  labelKey:
    | 'dashboard.scope.time.option.15m'
    | 'dashboard.scope.time.option.1h'
    | 'dashboard.scope.time.option.6h'
    | 'dashboard.scope.time.option.24h'
}

export const DASHBOARD_TIME_SCOPES: readonly DashboardTimeScopeDefinition[] = [
  {
    value: '15m',
    durationMs: 15 * 60 * 1000,
    bucket: '1m',
    labelKey: 'dashboard.scope.time.option.15m',
  },
  {
    value: '1h',
    durationMs: 60 * 60 * 1000,
    bucket: '5m',
    labelKey: 'dashboard.scope.time.option.1h',
  },
  {
    value: '6h',
    durationMs: 6 * 60 * 60 * 1000,
    bucket: '15m',
    labelKey: 'dashboard.scope.time.option.6h',
  },
  {
    value: '24h',
    durationMs: 24 * 60 * 60 * 1000,
    bucket: '1h',
    labelKey: 'dashboard.scope.time.option.24h',
  },
] as const

const dashboardTimeScopes = new Map(
  DASHBOARD_TIME_SCOPES.map((definition) => [definition.value, definition]),
)

function isTenantKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '')
  return normalized === 'tenant' || normalized === 'tenantid'
}

/**
 * Parses one bounded relative dashboard scope from untrusted URL state.
 *
 * Missing, repeated, oversized, and unknown values all fail closed to 1h.
 * Tenant identity is deliberately absent: the authenticated server session is
 * the only tenant authority.
 */
export function parseDashboardTimeScope(params: URLSearchParams): DashboardTimeScopeDefinition {
  const values = params.getAll(DASHBOARD_TIME_SCOPE_PARAM)
  if (values.length !== 1 || values[0].length > 8) {
    return dashboardTimeScopes.get(DEFAULT_DASHBOARD_TIME_SCOPE)!
  }
  return (
    dashboardTimeScopes.get(values[0] as DashboardTimeScope) ??
    dashboardTimeScopes.get(DEFAULT_DASHBOARD_TIME_SCOPE)!
  )
}

/**
 * Returns a canonical dashboard URL while preserving harmless route state
 * such as `view` and `demo`. It emits exactly one range and strips any
 * client-supplied tenant key because dashboard requests are session-scoped.
 */
export function canonicalDashboardSearchParams(
  params: URLSearchParams,
  scope: DashboardTimeScope,
): URLSearchParams {
  const next = new URLSearchParams(params)
  for (const key of Array.from(next.keys())) {
    if (isTenantKey(key)) next.delete(key)
  }
  next.delete(DASHBOARD_TIME_SCOPE_PARAM)
  next.set(DASHBOARD_TIME_SCOPE_PARAM, scope)
  return next
}
