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
  AlertDependencyGraphInput,
} from './sdk.gen'

export type {
  AlertDependencyPolicyInput,
  AlertDependencyPolicyState,
  EntityContext,
  AlertDependencyGraphInput,
} from './sdk.gen'

// This is configuration shape validation only. Current source/tenant authority,
// graph completeness and cycles are checked by the authenticated server.
export function parseDependencyGraph(text: string): AlertDependencyGraphInput | undefined {
  if (!text.trim()) return undefined
  const graph: unknown = JSON.parse(text)
  const object = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value)
  const uuid = (value: unknown): value is string =>
    typeof value === 'string' && /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value)
  if (
    !object(graph) ||
    Object.keys(graph).some((key) => key !== 'nodes') ||
    !Array.isArray(graph.nodes) ||
    graph.nodes.length === 0 ||
    graph.nodes.some(
      (node: unknown) =>
        !object(node) ||
        Object.keys(node).some(
          (key) => !['entity_id', 'agent_id', 'test_id', 'parents'].includes(key),
        ) ||
        !uuid(node.entity_id) ||
        !uuid(node.agent_id) ||
        !uuid(node.test_id) ||
        !Array.isArray(node.parents) ||
        !node.parents.every(uuid),
    )
  )
    throw new Error(
      'Enter the complete graph with canonical device, agent and test IDs and parent arrays.',
    )
  return graph as unknown as AlertDependencyGraphInput
}

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
