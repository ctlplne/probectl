// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import {
  flowComplianceControls,
  type ComplianceFlowDefinition,
  type ComplianceFlowSource,
  type FlowComplianceControl,
} from '../api/dashboardReporting'

export interface FlowEvidenceDraft {
  control: FlowComplianceControl
  value: ComplianceFlowDefinition
}

export function emptyCompliancePoint(): ComplianceFlowSource {
  return { context_id: '', entity_id: '' }
}

export function emptyFlowEvidence(): FlowEvidenceDraft {
  return {
    control: flowComplianceControls[0].value,
    value: { lookback: '24h', sources: [emptyCompliancePoint()] },
  }
}

export function validCompliancePoint(source: ComplianceFlowSource | undefined) {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
  return !!source && uuid.test(source.context_id) && uuid.test(source.entity_id)
}

export function validFlowEvidence({ control, value }: FlowEvidenceDraft) {
  return (
    value.lookback.trim() &&
    value.sources.length > 0 &&
    value.sources.every(validCompliancePoint) &&
    new Set(value.sources.map(({ context_id, entity_id }) => context_id + entity_id)).size ===
      value.sources.length &&
    (control === 'SI.L2-3.14.6' || value.policy?.trim())
  )
}
