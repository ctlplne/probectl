// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ExplorerComparisonResult, ExplorerResult } from '../api/explorer'
import type { FlowQueryFilterGroup } from '../api/flowExplorer'

export type NativeFlowResult = ExplorerResult | ExplorerComparisonResult
export type FlowDrillMode = 'include' | 'exclude'
export type FlowDrillAction = (group: Record<string, string>, mode?: FlowDrillMode) => void

export function isFlowComparison(result: NativeFlowResult): result is ExplorerComparisonResult {
  return 'contract_version' in result
}

export function flowGroupKey(group: Record<string, string>, other = false) {
  return JSON.stringify([
    other,
    Object.keys(other ? {} : group)
      .sort()
      .map((key) => [key, group[key]]),
  ])
}

export function flowGroupLabel(group: Record<string, string>, other = false) {
  if (other) return 'Other (unselected groups)'
  return (
    Object.entries(group)
      .map(([key, value]) => `${key}: ${value || '(unassigned)'}`)
      .join(' · ') || 'All flows'
  )
}

/** Add a complete tuple without changing an existing boolean expression or
 * silently adding a sixth level. The server still validates expanded refs. */
export function flowDrilldown(
  original: FlowQueryFilterGroup | undefined,
  group: Record<string, string>,
  maxDepth: number,
  maxEntries: number,
  mode: FlowDrillMode = 'include',
): FlowQueryFilterGroup {
  const conditions = Object.entries(group).map(([field, value]) => ({
    field,
    op: 'eq',
    values: [value],
  }))
  if (!conditions.length) return original ?? {}
  if (conditions.length > maxEntries) throw drillLimitError()
  const depth = (filter: FlowQueryFilterGroup): number =>
    1 + Math.max(0, ...(filter.groups ?? []).map(depth))
  if (mode === 'exclude') {
    // Exclude the entire tuple: NOT(a=A AND b=B), rather than incorrectly
    // excluding every flow that matches either individual dimension.
    const excluded: FlowQueryFilterGroup = { mode: 'exclude', match: 'all', conditions }
    if (!original) return excluded
    const all = original.mode !== 'exclude' && original.match !== 'any' && original.match !== 'or'
    if (maxDepth >= 2 && all) {
      const entries =
        (original.conditions?.length ?? 0) +
        (original.saved?.length ?? 0) +
        (original.groups?.length ?? 0)
      if (entries < maxEntries)
        return { ...original, groups: [...(original.groups ?? []), excluded] }
      if ((original.conditions?.length ?? 0) >= 2)
        return {
          ...original,
          conditions: [],
          groups: [
            ...(original.groups ?? []),
            { match: 'all', conditions: original.conditions },
            excluded,
          ],
        }
    }
    if (maxDepth >= 2 && depth(original) < maxDepth && maxEntries >= 2) {
      return { match: 'all', groups: [original, excluded] }
    }
    throw drillLimitError()
  }
  if (!original) return { match: 'all', conditions }
  const all = original.mode !== 'exclude' && original.match !== 'any' && original.match !== 'or'
  if (all) {
    const entries =
      (original.conditions?.length ?? 0) +
      (original.saved?.length ?? 0) +
      (original.groups?.length ?? 0)
    if (entries + conditions.length <= maxEntries)
      return { ...original, conditions: [...(original.conditions ?? []), ...conditions] }
    if (entries < maxEntries && maxDepth >= 2)
      return { ...original, groups: [...(original.groups ?? []), { match: 'all', conditions }] }
    // Flat conditions can be grouped at level two without deepening any of
    // the existing nested branches or saved references.
    if ((original.conditions?.length ?? 0) >= 2 && maxDepth >= 2)
      return {
        ...original,
        conditions: [],
        groups: [
          ...(original.groups ?? []),
          { match: 'all', conditions: original.conditions },
          { match: 'all', conditions },
        ],
      }
  }
  if (depth(original) < maxDepth) {
    if (conditions.length < maxEntries) return { match: 'all', groups: [original], conditions }
    if (maxEntries >= 2) return { match: 'all', groups: [original, { match: 'all', conditions }] }
  }
  throw drillLimitError()
}

function drillLimitError() {
  return new Error(
    'This drilldown exceeds the current filter group limits. Simplify a group before adding the tuple.',
  )
}
