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

export function alertDependencyPolicy(
  tenantID: string,
  ruleID: string,
  method: 'GET' | 'PUT' | 'DELETE',
  signal: AbortSignal,
  input?: AlertDependencyPolicyInput,
) {
  const headers: Record<string, string> = { 'X-Probectl-Tenant': tenantID }
  if (input) headers['Content-Type'] = 'application/json'
  return apiFetch<AlertDependencyPolicyState>(
    `/alerts/rules/${encodeURIComponent(ruleID)}/dependency-policy`,
    {
      method,
      signal,
      headers,
      ...(input ? { body: JSON.stringify(input) } : {}),
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
