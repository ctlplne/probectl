// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { useFlowDDoSAssessment, type SavedFlowQueryView } from '../api/flowViews'
import type {
  FlowDDoSAssessmentInput,
  FlowDDoSDetection,
  FlowDDoSWindowEvidence,
} from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, ErrorState, Field, Select } from '../components'
import styles from './flowExplorer.module.css'

const labels: Record<FlowDDoSDetection['class'], string> = {
  tcp_syn_pressure: 'TCP SYN pressure',
  udp_reflection_suspected: 'Suspected UDP reflection',
  distributed_destination_pressure: 'Distributed destination pressure',
  volumetric_pressure: 'Volumetric pressure',
}

const directions = [
  { value: 'ingress', label: 'Ingress toward the prefix' },
  { value: 'egress', label: 'Egress from the prefix' },
]

const numericFields = [
  { key: 'growth_basis_points', label: 'Minimum growth (basis points)', min: 1, max: 1000000 },
  {
    key: 'vector_share_basis_points',
    label: 'Minimum vector share (basis points)',
    min: 1,
    max: 10000,
  },
  { key: 'min_observed_records', label: 'Minimum observed flow records', min: 1, max: undefined },
  {
    key: 'min_observed_addresses',
    label: 'Minimum destinations for spread',
    min: 2,
    max: undefined,
  },
] as const

function EvidenceWindow({ label, evidence }: { label: string; evidence: FlowDDoSWindowEvidence }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>
        <time dateTime={evidence.from}>{evidence.from}</time> –{' '}
        <time dateTime={evidence.to}>{evidence.to}</time>
      </dd>
      <dd>
        {evidence.bytes} bytes · {evidence.packets} packets
      </dd>
      <dd>
        {evidence.observed_records} observed records · {evidence.observed_addresses} protected
        addresses
      </dd>
      <dd>
        {evidence.sampled ? 'Sampling corrected' : 'Unsampled'} · {evidence.resolution_seconds}s
        resolution
      </dd>
      <dd>
        <details>
          <summary>Source reference</summary>
          <code>{evidence.citation}</code>
        </details>
      </dd>
    </div>
  )
}

export function FlowDDoSAssessmentCard({ view }: { view: SavedFlowQueryView }) {
  const period = view.definition.time?.lookback_seconds ?? 0
  if (view.definition.time?.mode !== 'lookback' || ![60, 120, 300].includes(period)) return null
  return <DDoSAssessmentForm id={view.id} revision={view.version} period={period} />
}

function DDoSAssessmentForm({
  id,
  revision,
  period,
}: {
  id: string
  revision: string
  period: number
}) {
  const [input, setInput] = useState<FlowDDoSAssessmentInput>(() => ({
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
  }))
  const assessment = useFlowDDoSAssessment()
  const update = (patch: Partial<FlowDDoSAssessmentInput>) =>
    setInput((previous) => ({ ...previous, ...patch }))
  const result = assessment.data
  const detection = result?.detection
  return (
    <Card>
      <CardHeader title="DDoS assessment" />
      <CardBody className={styles.stack}>
        <form
          className={styles.stack}
          onSubmit={(event) => {
            event.preventDefault()
            assessment.mutate({ id, input })
          }}
        >
          <fieldset className={styles.group} disabled={assessment.isPending}>
            <legend>Compare completed traffic windows</legend>
            <div className={styles.grid}>
              <Field
                label="Protected prefix"
                value={input.prefix}
                required
                maxLength={43}
                onChange={(event) => update({ prefix: event.target.value })}
              />
              <Select
                label="Observed direction"
                options={directions}
                value={input.direction}
                onChange={(event) =>
                  update({ direction: event.target.value as FlowDDoSAssessmentInput['direction'] })
                }
              />
              {(
                [
                  ['bytes_floor', 'Minimum bytes per window'],
                  ['packets_floor', 'Minimum packets per window'],
                ] as const
              ).map(([key, label]) => (
                <Field
                  key={key}
                  label={label}
                  value={input[key]}
                  required
                  inputMode="numeric"
                  pattern="[0-9]+"
                  maxLength={64}
                  onChange={(event) => update({ [key]: event.target.value })}
                />
              ))}
              {numericFields.map(({ key, label, min, max }) => (
                <Field
                  key={key}
                  label={label}
                  type="number"
                  min={min}
                  max={max}
                  required
                  value={Number.isNaN(input[key]) ? '' : input[key]}
                  onChange={(event) => update({ [key]: event.target.valueAsNumber })}
                />
              ))}
            </div>
            <div>
              <Button type="submit">Assess traffic</Button>
            </div>
          </fieldset>
        </form>
        {assessment.isPending && <p role="status">Assessing completed traffic windows…</p>}
        {assessment.isError && (
          <ErrorState
            title="Traffic assessment unavailable"
            description={assessment.error.message}
          />
        )}
        {result && (
          <>
            <p role="status">
              {result.prefix} · {result.direction} ·{' '}
              {detection ? labels[detection.class] : 'No detection met the thresholds'}
            </p>
            {detection && (
              <p>
                {detection.confidence === 'corroborated'
                  ? 'Corroborating measurements'
                  : 'Tentative evidence'}
                {detection.service && ` · ${detection.service}`}
                {detection.contributing_packets &&
                  ` · ${detection.contributing_packets} contributing packets`}
              </p>
            )}
            <dl className={styles.summary}>
              <EvidenceWindow label="Same time last week" evidence={result.before} />
              <EvidenceWindow label="Latest completed window" evidence={result.after} />
            </dl>
          </>
        )}
      </CardBody>
    </Card>
  )
}
