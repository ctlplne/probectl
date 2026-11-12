// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { apiFetch } from './client'
import type {
  AlertDependencyPolicyInput,
  AlertDependencyPolicyState,
  EntityContextPage,
} from './sdk.gen'

export type {
  AlertDependencyPolicyInput,
  AlertDependencyPolicyState,
  EntityContext,
} from './sdk.gen'

export function getAlertDependencyPolicy(tenantID: string, ruleID: string, signal: AbortSignal) {
  return apiFetch<AlertDependencyPolicyState>(
    `/alerts/rules/${encodeURIComponent(ruleID)}/dependency-policy`,
    {
      signal,
      headers: { 'X-Probectl-Tenant': tenantID },
    },
  )
}

export function putAlertDependencyPolicy(
  tenantID: string,
  ruleID: string,
  input: AlertDependencyPolicyInput,
  signal: AbortSignal,
) {
  return apiFetch<AlertDependencyPolicyState>(
    `/alerts/rules/${encodeURIComponent(ruleID)}/dependency-policy`,
    {
      method: 'PUT',
      signal,
      headers: { 'X-Probectl-Tenant': tenantID, 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  )
}

export function clearAlertDependencyPolicy(tenantID: string, ruleID: string, signal: AbortSignal) {
  return apiFetch<AlertDependencyPolicyState>(
    `/alerts/rules/${encodeURIComponent(ruleID)}/dependency-policy`,
    {
      method: 'DELETE',
      signal,
      headers: { 'X-Probectl-Tenant': tenantID },
    },
  )
}

export function alertDependencyContexts(tenantID: string, cursor: string, signal: AbortSignal) {
  const query = new URLSearchParams({ limit: '100' })
  if (cursor) query.set('cursor', cursor)
  return apiFetch<EntityContextPage>(`/entity-contexts?${query.toString()}`, {
    signal,
    headers: { 'X-Probectl-Tenant': tenantID },
  })
}
