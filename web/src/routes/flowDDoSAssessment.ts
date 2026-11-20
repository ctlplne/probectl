// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { SavedFlowQueryView } from '../api/flowViews'
import type { FlowDDoSAssessmentInput } from '../api/sdk.gen'

export function ddosAssessmentPeriod(view?: SavedFlowQueryView) {
  const time = view?.definition.time
  const period = time?.lookback_seconds ?? 0
  if (time?.mode !== 'lookback' || period < 60) return undefined
  return [60, 120, 300].includes(period) ? period : 5
}

export function initialDDoSAssessment(revision: string, period: number): FlowDDoSAssessmentInput {
  return {
    version: revision,
    prefix: '',
    direction: 'ingress',
    period_seconds: period,
    bytes_floor: '',
    packets_floor: '',
    growth_basis_points: 5000,
    vector_share_basis_points: 6000,
    min_observed_records: 1,
    min_observed_addresses: 2,
  }
}
