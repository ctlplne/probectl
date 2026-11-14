// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ClientReportDefinition } from '../api/dashboardReporting'

export function emptyMonthlyReport(): ClientReportDefinition {
  return { period: 'completed_month', timezone: 'UTC', capacity_targets: [] }
}

export function validMonthlyReport(value: ClientReportDefinition): boolean {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
  const positive = (text: string) =>
    /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(text) && /[1-9]/.test(text)
  if (!value.timezone?.trim() || (value.month && !/^[0-9]{4}-(?:0[1-9]|1[0-2])$/.test(value.month)))
    return false
  return value.capacity_targets.every((item) => {
    const target = item.target
    const knownTarget =
      target.kind === 'interface'
        ? uuid.test(target.context_id ?? '') && uuid.test(target.interface_id ?? '')
        : uuid.test(target.tag_id ?? '') && Boolean(target.tag_value)
    const months = item.forecast_months ?? 1
    const members = new Set(
      item.physical_bounds.map((bound) => `${bound.context_id}/${bound.interface_id}`),
    )
    return (
      knownTarget &&
      positive(item.capacity_bps) &&
      Boolean(item.maximum_poll_gap.trim()) &&
      Number.isSafeInteger(months) &&
      months > 0 &&
      item.physical_bounds.length > 0 &&
      members.size === item.physical_bounds.length &&
      item.physical_bounds.every(
        (bound) =>
          uuid.test(bound.context_id) &&
          uuid.test(bound.interface_id) &&
          /^[1-9][0-9]*$/.test(bound.max_bps),
      )
    )
  })
}
