// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import {
  flowComplianceControls,
  needsCardholderZone,
  type ComplianceFlowSource,
  type FlowComplianceControl,
} from '../api/dashboardReporting'
import { Button, Field, Select, TextArea } from '../components'
import { emptyCompliancePoint, type FlowEvidenceDraft } from './complianceFlowReportModel'
import styles from './dashboards.module.css'

export function CompliancePointFields({
  label,
  source,
  onChange,
  disabled,
}: {
  label: string
  source: ComplianceFlowSource
  onChange: (value: ComplianceFlowSource) => void
  disabled: boolean
}) {
  return (
    <div className={styles.reportingControls}>
      <Field
        label={`${label} routing context ID`}
        disabled={disabled}
        required
        value={source.context_id}
        onChange={(event) => onChange({ ...source, context_id: event.target.value.trim() })}
      />
      <Field
        label={`${label} device or interface ID`}
        disabled={disabled}
        required
        value={source.entity_id}
        onChange={(event) => onChange({ ...source, entity_id: event.target.value.trim() })}
      />
    </div>
  )
}

export function ComplianceFlowReportEditor({
  draft,
  onChange,
  disabled,
}: {
  draft: FlowEvidenceDraft
  onChange: (value: FlowEvidenceDraft) => void
  disabled: boolean
}) {
  const { control, value } = draft
  return (
    <section aria-label="Flow control evidence configuration" className={styles.monthlyEditor}>
      <div className={styles.reportingControls}>
        <Select
          label="Flow evidence control"
          value={control}
          options={[...flowComplianceControls]}
          disabled={disabled}
          onChange={(event) =>
            onChange({ ...draft, control: event.target.value as FlowComplianceControl })
          }
        />
        <Field
          label="Observation lookback"
          hint="For example, 24h. Each report records its observation start and end."
          value={value.lookback}
          required
          disabled={disabled}
          onChange={(event) =>
            onChange({ control, value: { ...value, lookback: event.target.value } })
          }
        />
      </div>
      <p>Use canonical device or interface IDs from the selected routing contexts.</p>
      {value.sources.map((source, index) => (
        <div className={styles.monthlyTarget} key={index}>
          <CompliancePointFields
            label={`Measurement point ${index + 1}`}
            source={source}
            disabled={disabled}
            onChange={(next) =>
              onChange({
                control,
                value: {
                  ...value,
                  sources: value.sources.map((item, i) => (i === index ? next : item)),
                },
              })
            }
          />
          {value.sources.length > 1 && (
            <Button
              variant="secondary"
              disabled={disabled}
              onClick={() =>
                onChange({
                  control,
                  value: { ...value, sources: value.sources.filter((_, i) => i !== index) },
                })
              }
            >
              Remove measurement point {index + 1}
            </Button>
          )}
        </div>
      ))}
      <Button
        variant="secondary"
        disabled={disabled || value.sources.length >= 1024}
        onClick={() =>
          onChange({
            control,
            value: { ...value, sources: [...value.sources, emptyCompliancePoint()] },
          })
        }
      >
        Add measurement point
      </Button>
      {needsCardholderZone(control) && (
        <Field
          label="Cardholder-data zone"
          hint="Use the exact zone name from the segmentation policy."
          value={value.protected_zone ?? ''}
          required
          disabled={disabled}
          onChange={(event) =>
            onChange({ control, value: { ...value, protected_zone: event.target.value } })
          }
        />
      )}
      {control !== 'SI.L2-3.14.6' && (
        <TextArea
          label="Segmentation policy YAML"
          value={value.policy ?? ''}
          required
          disabled={disabled}
          spellCheck={false}
          onChange={(event) =>
            onChange({ control, value: { ...value, policy: event.target.value } })
          }
        />
      )}
    </section>
  )
}
