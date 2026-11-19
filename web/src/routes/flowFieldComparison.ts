// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { SavedFlowQueryView } from '../api/flowViews'
import type { FlowFieldComparisonInput } from '../api/sdk.gen'

export interface FieldComparisonPlan {
  measure: string
  secondary: string[]
  groupedBySource: boolean
  period: number
}

export function fieldComparisonPlan(
  view: SavedFlowQueryView | undefined,
): FieldComparisonPlan | undefined {
  const plan = view?.definition.plan
  const time = view?.definition.time
  const primary = plan?.metrics?.find((metric) => metric.role === 'primary')
  const period = time?.lookback_seconds ?? 0
  if (
    !primary ||
    plan?.view !== 'table' ||
    !plan.group_by?.length ||
    time?.mode !== 'lookback' ||
    ![60, 120, 300, 604800].includes(period)
  )
    return
  return {
    measure: `${primary.measure}:${primary.calculation}`,
    secondary: (plan.metrics ?? [])
      .filter((metric) => metric.role === 'secondary')
      .slice(0, 2)
      .map((metric) => `${metric.measure}:${metric.calculation}`),
    groupedBySource: plan.group_by.includes('src_addr'),
    period,
  }
}

export function initialFieldComparison(
  version: string,
  plan: FieldComparisonPlan,
): FlowFieldComparisonInput {
  const completeWeek = plan.period === 604800
  return {
    version,
    measure: plan.measure,
    mode: 'rank',
    cadence: completeWeek ? 'complete_week' : 'previous_period',
    period_seconds: completeWeek ? undefined : plan.period,
    top_keys: 25,
    minimum_rank_change: 1,
    minimum_change: '1',
    secondary_thresholds: [],
  }
}
