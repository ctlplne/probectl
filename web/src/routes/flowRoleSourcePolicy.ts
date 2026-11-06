// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { FlowExplorerResult, FlowQueryFilterGroup } from '../api/flowExplorer'

const roleNames = ['transit', 'ix_peering', 'private_peering', 'customer', 'backbone', 'other']
const roleFields = ['in_if_role', 'out_if_role']
const sourceGrants = ['flow.read', 'ai.query', 'entities.read', 'metrics.read', 'events.read']

function hasRoleSelector(result: FlowExplorerResult) {
  if (
    [...(result.query.group_by ?? []), ...(result.query.matrix_with ?? [])].some((name) =>
      roleFields.includes(name),
    )
  )
    return true
  const pending: FlowQueryFilterGroup[] = result.query.filter ? [result.query.filter] : []
  while (pending.length) {
    const group = pending.pop()!
    if (group.conditions?.some((predicate) => roleFields.includes(predicate.field))) return true
    pending.push(...(group.groups ?? []))
  }
  return false
}

// Hide the entire role result, including its group values, synchronously when
// identity or grants change. A retained response is not current authority.
export function flowRoleResultReadable(
  result: FlowExplorerResult | undefined,
  tenant: string,
  permissions: readonly string[],
) {
  if (!result) return true
  if (
    !hasRoleSelector(result) &&
    result.role_digest === undefined &&
    result.role_tenant_id === undefined &&
    result.role_sources === undefined
  )
    return true
  if (
    result.role_tenant_id !== tenant ||
    !/^[a-f0-9]{64}$/.test(result.role_digest ?? '') ||
    !sourceGrants.every((permission) => permissions.includes(permission))
  )
    return false
  if (result.role_sources !== undefined && !Array.isArray(result.role_sources)) return false
  return (result.role_sources ?? []).every(
    (source) =>
      source !== null &&
      typeof source === 'object' &&
      source.tenant_id === tenant &&
      Boolean(source.context_id && source.router_id && source.interface_id) &&
      roleNames.includes(source.role) &&
      source.if_index > 0 &&
      source.obs_domain >= 0 &&
      source.obs_domain <= 4294967295 &&
      Boolean(source.reason) &&
      Array.isArray(source.sources) &&
      source.sources.length > 0 &&
      source.sources.every((reference) => typeof reference === 'string' && reference.length > 0),
  )
}
