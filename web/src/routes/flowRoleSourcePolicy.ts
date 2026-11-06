// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { FlowExplorerResult, FlowQueryFilterGroup } from '../api/flowExplorer'

const roleNames = ['transit', 'ix_peering', 'private_peering', 'customer', 'backbone', 'other']
const roleFields = ['in_if_role', 'out_if_role']
const sourceGrants = ['flow.read', 'ai.query', 'entities.read', 'metrics.read', 'events.read']

function querySelectors(result: FlowExplorerResult) {
  const names = [...(result.query.group_by ?? []), ...(result.query.matrix_with ?? [])]
  const pending: FlowQueryFilterGroup[] = result.query.filter ? [result.query.filter] : []
  while (pending.length) {
    const group = pending.pop()!
    names.push(...(group.conditions ?? []).map((predicate) => predicate.field))
    pending.push(...(group.groups ?? []))
  }
  return names
}

// Hide the entire role result, including its group values, synchronously when
// identity or grants change. A retained response is not current authority.
export function flowRoleResultReadable(
  result: FlowExplorerResult | undefined,
  tenant: string,
  permissions: readonly string[],
) {
  if (!result) return true
  const selectors = querySelectors(result)
  if (
    !selectors.some((name) => roleFields.includes(name)) &&
    result.role_digest === undefined &&
    result.role_tenant_id === undefined &&
    result.role_sources === undefined
  )
    return true
  const requiredGrants = new Set(sourceGrants)
  for (const selector of selectors) {
    if (!selector.startsWith('tag.')) continue
    if (result.tag_tenant_id !== tenant) return false
    requiredGrants.add('tags.read')
    if (selector.startsWith('tag.agent.')) requiredGrants.add('agent.read')
    if (
      selector.startsWith('tag.device.') ||
      selector.startsWith('tag.in_interface.') ||
      selector.startsWith('tag.out_interface.')
    )
      requiredGrants.add('metrics.read')
    if (selector.startsWith('tag.src_prefix.') || selector.startsWith('tag.dst_prefix.'))
      requiredGrants.add('entities.read')
  }
  const hasRequired = [...requiredGrants].every((permission) => permissions.includes(permission))
  if (
    result.role_tenant_id !== tenant ||
    !/^[a-f0-9]{64}$/.test(result.role_digest ?? '') ||
    !hasRequired
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
