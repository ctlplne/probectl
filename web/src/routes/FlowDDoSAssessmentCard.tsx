// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { useFlowDDoSAssessment, type SavedFlowQueryView } from '../api/flowViews'
import type {
  FlowDDoSAssessment,
  FlowDDoSAssessmentInput,
  FlowDDoSDetection,
  FlowDDoSWindowEvidence,
} from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, ErrorState, Field, Select } from '../components'
import { ddosAssessmentPeriod, initialDDoSAssessment } from './flowDDoSAssessment'
import styles from './flowExplorer.module.css'

const labels: Record<FlowDDoSDetection['class'], string> = {
  tcp_syn_pressure: 'TCP SYN pressure',
  udp_reflection_suspected: 'Suspected UDP reflection',
  distributed_destination_pressure: 'Distributed destination pressure',
  volumetric_pressure: 'Volumetric pressure',
}

const applicationEvidenceLabels = {
  observed_application_demand: 'Successful requests did not increase with the flow pressure',
  application_health_degraded: 'HTTP response health degraded during flow pressure',
  traffic_growth_explained_by_healthy_application_demand:
    'Healthy application demand explains the spike',
  application_demand_does_not_explain_all_traffic:
    'Application demand leaves some flow growth unexplained',
  application_overload_inconclusive:
    'Completed requests rose with traffic during degraded service. Attack evidence is inconclusive.',
  traffic_outside_bound_application_exceeds_threshold:
    'Traffic outside the selected TCP service exceeded the configured floors',
  application_trace_sampling_incomparable:
    'Trace sampling differed or was incomplete across the observation windows',
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
        {evidence.bytes} bytes · {evidence.packets} packets in reports ending in this window
      </dd>
      <dd>
        {evidence.observed_records} observed records · {evidence.observed_addresses} protected
        addresses
      </dd>
      {evidence.observed_exporters ? (
        <dd>Required exporters observed · {evidence.observed_exporters}</dd>
      ) : null}
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
  const period = ddosAssessmentPeriod(view)
  if (!period) return null
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
  const [input, setInput] = useState(() => initialDDoSAssessment(revision, period))
  const assessment = useFlowDDoSAssessment()
  const result = assessment.data
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
            <DDoSAssessmentFields input={input} savedPeriod={period} onChange={setInput} />
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
        {result && <DDoSAssessmentEvidence result={result} />}
      </CardBody>
    </Card>
  )
}

export function DDoSAssessmentFields({
  input,
  savedPeriod,
  onChange,
}: {
  input: FlowDDoSAssessmentInput
  savedPeriod: number
  onChange: (input: FlowDDoSAssessmentInput) => void
}) {
  const update = (patch: Partial<FlowDDoSAssessmentInput>) => onChange({ ...input, ...patch })
  const application = input.application
  const exporterValue = input.required_exporters?.join(', ') ?? ''
  const [exporterDraft, setExporterDraft] = useState({ text: '', normalized: '' })
  return (
    <div className={styles.grid}>
      <Select
        label="Traffic reference"
        options={[
          { value: '', label: 'Same time last week' },
          { value: 'weekly_representative', label: 'Representative week from the last four' },
        ]}
        value={input.reference_mode ?? ''}
        onChange={(event) =>
          update({
            reference_mode:
              event.target.value === 'weekly_representative' ? 'weekly_representative' : undefined,
          })
        }
      />
      <Select
        label="Observation window"
        options={Array.from(new Set([5, 10, savedPeriod])).map((seconds) => ({
          value: String(seconds),
          label: `${seconds} seconds`,
        }))}
        value={String(input.period_seconds)}
        onChange={(event) => update({ period_seconds: Number(event.target.value) })}
      />
      <Field
        label="Protected prefix"
        value={input.prefix}
        required
        maxLength={43}
        onChange={(event) => update({ prefix: event.target.value })}
      />
      <Field
        label="Required exporter IPs"
        hint="Optional. List up to eight comma-separated IPs. Each needs an original observation in every compared window."
        value={exporterDraft.normalized === exporterValue ? exporterDraft.text : exporterValue}
        maxLength={350}
        onChange={(event) => {
          const text = event.target.value
          const exporters = text
            .split(',')
            .map((part) => part.trim())
            .filter(Boolean)
          setExporterDraft({ text, normalized: exporters.join(', ') })
          update({ required_exporters: exporters.length ? exporters : undefined })
        }}
      />
      <Select
        label="Observed direction"
        options={directions}
        value={input.direction}
        onChange={(event) =>
          update({
            direction: event.target.value as FlowDDoSAssessmentInput['direction'],
            application: event.target.value === 'ingress' ? input.application : undefined,
          })
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
      {input.direction === 'ingress' && (
        <Field
          label="HTTP service for demand comparison"
          hint="Optional. Use the telemetry service name for this exact host prefix."
          maxLength={128}
          value={input.application?.service ?? ''}
          onChange={(event) => {
            const service = event.target.value
            update({
              application: service ? { service, port: input.application?.port ?? 443 } : undefined,
            })
          }}
        />
      )}
      {application && (
        <Field
          label="HTTP server port"
          type="number"
          min={1}
          max={65535}
          required
          value={Number.isNaN(application.port) ? '' : application.port}
          onChange={(event) =>
            update({
              application: { service: application.service, port: event.target.valueAsNumber },
            })
          }
        />
      )}
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
  )
}

export function DDoSAssessmentEvidence({ result }: { result: FlowDDoSAssessment }) {
  const detection = result.detection
  const application = result.application
  return (
    <>
      <p role="status">
        {result.prefix} · {result.direction} ·{' '}
        {detection
          ? labels[detection.class]
          : application
            ? applicationEvidenceLabels[application.state]
            : 'No detection met the thresholds'}
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
      {application && (
        <div>
          {detection && <p>{applicationEvidenceLabels[application.state]}</p>}
          {application.state === 'application_overload_inconclusive' && (
            <p>
              Completed requests {application.reference.observed_requests} →{' '}
              {application.current.observed_requests}.
            </p>
          )}
          <p>
            Successful requests {application.reference.successful_requests} →{' '}
            {application.current.successful_requests}. Matching flow{' '}
            {application.reference.matching_flow_bytes} → {application.current.matching_flow_bytes}{' '}
            bytes and {application.reference.matching_flow_packets} →{' '}
            {application.current.matching_flow_packets} packets.
          </p>
        </div>
      )}
      <dl className={styles.summary}>
        <EvidenceWindow
          label={result.reference_mode ? 'Representative original window' : 'Same time last week'}
          evidence={result.before}
        />
        <EvidenceWindow label="Latest completed window" evidence={result.after} />
      </dl>
    </>
  )
}
