// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useId, useState } from 'react'
import { useFlowFieldComparison, type SavedFlowQueryView } from '../api/flowViews'
import type {
  FlowFieldChange,
  FlowFieldComparison,
  FlowFieldComparisonInput,
  FlowFieldComparisonSlice,
  FlowFieldObservation,
} from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, ErrorState, Field, Select } from '../components'
import {
  fieldComparisonPlan,
  initialFieldComparison,
  type FieldComparisonPlan,
} from './flowFieldComparison'
import styles from './flowExplorer.module.css'

const modeOptions = [
  { value: 'rank', label: 'Top keys and rank' },
  { value: 'amount', label: 'Traffic amount' },
  { value: 'share', label: 'Share of traffic' },
  { value: 'fanout', label: 'Destination fan-out' },
]

const changeLabels: Record<FlowFieldChange['kind'], string> = {
  entered_top_set: 'Entered top set',
  left_top_set: 'Left top set',
  rank_shift: 'Rank changed',
  amount_shift: 'Amount changed',
  share_shift: 'Traffic share changed',
  fanout_increase: 'Destination fan-out increased',
}

const additiveMeasures = new Set([
  'bytes:total',
  'packets:total',
  'flows:total',
  'bps:total',
  'pps:total',
  'fps:total',
  'bps:avg',
  'pps:avg',
  'fps:avg',
])
const decimalPattern = '[0-9]+(\\.[0-9]+)?'

function FieldWindow({ label, window }: { label: string; window: FlowFieldComparisonSlice }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>
        <time dateTime={window.from}>{window.from}</time> –{' '}
        <time dateTime={window.to}>{window.to}</time>
      </dd>
      <dd>
        {window.total_groups} groups · {window.source}, {window.resolution_seconds}s resolution
      </dd>
      {window.population_total !== undefined && <dd>Population total {window.population_total}</dd>}
      {window.last_included !== undefined && window.first_excluded !== undefined && (
        <>
          <dd>Last included amount {window.last_included}</dd>
          <dd>First excluded amount {window.first_excluded}</dd>
        </>
      )}
    </div>
  )
}

function FieldObservation({ item }: { item?: FlowFieldObservation }) {
  if (!item) return <>Outside top set</>
  return (
    <>
      <div>
        {item.value} · rank {item.rank}
      </div>
      {item.share !== undefined && <div>Share {item.share}</div>}
      {Object.entries(item.secondary ?? {}).map(([measure, value]) => (
        <div key={measure}>
          {measure} {value}
        </div>
      ))}
      <details>
        <summary>Source reference</summary>
        <code>{item.citation}</code>
      </details>
    </>
  )
}

export function FieldComparisonFields({
  plan,
  input,
  onChange,
}: {
  plan: FieldComparisonPlan
  input: FlowFieldComparisonInput
  onChange: (input: FlowFieldComparisonInput) => void
}) {
  const update = (patch: Partial<FlowFieldComparisonInput>) => onChange({ ...input, ...patch })
  const mode = input.mode
  const choices = modeOptions.filter((option) => {
    if (option.value === 'share') return additiveMeasures.has(input.measure)
    if (option.value === 'fanout')
      return plan.groupedBySource && input.measure === 'unique_dst:total'
    return true
  })
  const number = (value: string) => (value === '' ? undefined : Number(value))
  return (
    <>
      <div className={styles.grid}>
        <Select
          label="Change type"
          value={mode}
          options={choices}
          onChange={(event) => {
            const next = event.target.value as FlowFieldComparisonInput['mode']
            update({
              mode: next,
              minimum_change: next === 'share' ? undefined : '1',
              minimum_rank_change: next === 'rank' ? 1 : undefined,
              share_basis_points: next === 'share' ? 500 : undefined,
              secondary_thresholds: next === 'rank' ? [] : undefined,
            })
          }}
        />
        {plan.period !== 604800 && (
          <Select
            label="Reference window"
            value={input.cadence}
            options={[
              { value: 'previous_period', label: 'Previous period' },
              { value: 'previous_week', label: 'Same time last week' },
            ]}
            onChange={(event) =>
              update({ cadence: event.target.value as FlowFieldComparisonInput['cadence'] })
            }
          />
        )}
        <Field
          label="Top keys"
          type="number"
          min={1}
          max={300}
          required
          value={input.top_keys ?? ''}
          onChange={(event) => update({ top_keys: number(event.target.value) })}
        />
        {mode === 'rank' && (
          <Field
            label="Minimum rank change"
            type="number"
            min={1}
            max={input.top_keys}
            required
            value={input.minimum_rank_change ?? ''}
            onChange={(event) => update({ minimum_rank_change: number(event.target.value) })}
          />
        )}
        {mode === 'share' ? (
          <Field
            label="Minimum share change (basis points)"
            type="number"
            min={1}
            max={10000}
            required
            value={input.share_basis_points ?? ''}
            onChange={(event) => update({ share_basis_points: number(event.target.value) })}
          />
        ) : (
          <Field
            label={mode === 'rank' ? 'Minimum traffic amount' : 'Minimum amount change'}
            inputMode={mode === 'fanout' ? 'numeric' : 'decimal'}
            required
            value={input.minimum_change ?? ''}
            maxLength={256}
            pattern={mode === 'fanout' ? '[0-9]+' : decimalPattern}
            onChange={(event) => update({ minimum_change: event.target.value })}
          />
        )}
        {mode === 'rank' &&
          plan.secondary.map((key) => (
            <Field
              key={key}
              label={`Minimum ${key}`}
              value={
                input.secondary_thresholds?.find((item) => item.measure === key)?.minimum ?? ''
              }
              inputMode="decimal"
              pattern={decimalPattern}
              maxLength={256}
              onChange={(event) => {
                const minimum = event.target.value
                const thresholds = (input.secondary_thresholds ?? []).filter(
                  (item) => item.measure !== key,
                )
                if (minimum) thresholds.push({ measure: key, minimum })
                update({ secondary_thresholds: thresholds })
              }}
            />
          ))}
      </div>
      {plan.period === 604800 && (
        <p>Last seven complete days compared with the preceding seven days.</p>
      )}
    </>
  )
}

export function FieldComparisonResults({ result }: { result: FlowFieldComparison }) {
  const region = useId()
  return (
    <>
      <dl className={styles.summary}>
        <FieldWindow label="Before" window={result.before} />
        <FieldWindow label="After" window={result.after} />
      </dl>
      <p id={region} role="status">
        {result.changes.length
          ? `${result.changes.length} field changes`
          : 'No field changes met the comparison thresholds.'}
      </p>
      {result.changes.length > 0 && (
        <ol className={styles.chartGroupList} aria-labelledby={region}>
          {result.changes.map((change) => (
            <li key={change.key}>
              <strong>{changeLabels[change.kind]}</strong>
              <dl className={styles.summary}>
                {Object.entries(change.group).map(([field, value]) => (
                  <div key={field}>
                    <dt>{field}</dt>
                    <dd>{value}</dd>
                  </div>
                ))}
                <div>
                  <dt>Before</dt>
                  <dd>
                    <FieldObservation item={change.before} />
                  </dd>
                </div>
                <div>
                  <dt>After</dt>
                  <dd>
                    <FieldObservation item={change.after} />
                  </dd>
                </div>
                {change.delta !== undefined && (
                  <div>
                    <dt>Change</dt>
                    <dd>{change.delta}</dd>
                  </div>
                )}
              </dl>
            </li>
          ))}
        </ol>
      )}
    </>
  )
}

export function FlowFieldComparisonCard({ view }: { view: SavedFlowQueryView }) {
  const plan = fieldComparisonPlan(view)
  if (!plan) return null
  return <FieldComparisonForm view={view} plan={plan} />
}

function FieldComparisonForm({
  view,
  plan,
}: {
  view: SavedFlowQueryView
  plan: FieldComparisonPlan
}) {
  const [input, setInput] = useState(() => initialFieldComparison(view.version, plan))
  const comparison = useFlowFieldComparison()
  return (
    <Card>
      <CardHeader
        title="Field changes"
        description={`Saved revision ${view.version} · ${plan.measure}`}
      />
      <CardBody className={styles.stack}>
        <form
          className={styles.stack}
          onSubmit={(event) => {
            event.preventDefault()
            comparison.mutate({ id: view.id, input })
          }}
        >
          <fieldset className={styles.group} disabled={comparison.isPending}>
            <legend>Compare completed UTC windows</legend>
            <FieldComparisonFields plan={plan} input={input} onChange={setInput} />
            <div>
              <Button type="submit">Compare fields</Button>
            </div>
          </fieldset>
        </form>
        {comparison.isPending && <p role="status">Comparing saved flow windows…</p>}
        {comparison.isError && (
          <ErrorState title="Field comparison unavailable" description={comparison.error.message} />
        )}
        {comparison.data && <FieldComparisonResults result={comparison.data} />}
      </CardBody>
    </Card>
  )
}
