// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useId, useState } from 'react'
import { useFlowFieldComparison, type SavedFlowQueryView } from '../api/flowViews'
import type {
  FlowFieldChange,
  FlowFieldComparisonInput,
  FlowFieldComparisonSlice,
  FlowFieldObservation,
} from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, ErrorState, Field, Select } from '../components'
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

export function FlowFieldComparisonCard({ view }: { view: SavedFlowQueryView }) {
  const { plan, time } = view.definition
  const measure = plan?.metrics?.find((metric) => metric.role === 'primary')
  const period = time?.lookback_seconds ?? 0
  if (
    !measure ||
    plan?.view !== 'table' ||
    !plan.group_by?.length ||
    time?.mode !== 'lookback' ||
    ![60, 120, 300, 604800].includes(period)
  )
    return null

  return (
    <FieldComparisonForm
      id={view.id}
      version={view.version}
      measure={`${measure.measure}:${measure.calculation}`}
      secondary={
        plan.metrics
          ?.filter((metric) => metric.role === 'secondary')
          .slice(0, 2)
          .map((metric) => `${metric.measure}:${metric.calculation}`) ?? []
      }
      groupedBySource={plan.group_by.includes('src_addr')}
      period={period}
    />
  )
}

function FieldComparisonForm({
  id,
  version,
  measure,
  secondary,
  groupedBySource,
  period,
}: {
  id: string
  version: string
  measure: string
  secondary: string[]
  groupedBySource: boolean
  period: number
}) {
  const region = useId()
  const [mode, setMode] = useState<FlowFieldComparisonInput['mode']>('rank')
  const [priorWeek, setPriorWeek] = useState(false)
  const [topKeys, setTopKeys] = useState('25')
  const [rankStep, setRankStep] = useState('1')
  const [minimum, setMinimum] = useState('1')
  const [basisPoints, setBasisPoints] = useState('500')
  const [floors, setFloors] = useState<Record<string, string>>({})
  const comparison = useFlowFieldComparison()
  const completeWeek = period === 604800
  const choices = modeOptions.filter((option) => {
    if (option.value === 'share') return additiveMeasures.has(measure)
    if (option.value === 'fanout') return groupedBySource && measure === 'unique_dst:total'
    return true
  })
  const result = comparison.data

  return (
    <Card>
      <CardHeader title="Field changes" description={`Saved revision ${version} · ${measure}`} />
      <CardBody className={styles.stack}>
        <form
          className={styles.stack}
          onSubmit={(event) => {
            event.preventDefault()
            comparison.mutate({
              id,
              input: {
                version,
                measure,
                mode,
                top_keys: Number(topKeys),
                cadence: completeWeek
                  ? 'complete_week'
                  : priorWeek
                    ? 'previous_week'
                    : 'previous_period',
                period_seconds: completeWeek ? undefined : period,
                minimum_change: mode === 'share' ? undefined : minimum,
                minimum_rank_change: mode === 'rank' ? Number(rankStep) : undefined,
                share_basis_points: mode === 'share' ? Number(basisPoints) : undefined,
                secondary_thresholds:
                  mode === 'rank'
                    ? secondary
                        .filter((key) => floors[key])
                        .map((key) => ({ measure: key, minimum: floors[key] }))
                    : undefined,
              },
            })
          }}
        >
          <fieldset className={styles.group} disabled={comparison.isPending}>
            <legend>Compare completed UTC windows</legend>
            <div className={styles.grid}>
              <Select
                label="Change type"
                value={mode}
                options={choices}
                onChange={(event) =>
                  setMode(event.target.value as FlowFieldComparisonInput['mode'])
                }
              />
              {!completeWeek && (
                <Select
                  label="Reference window"
                  value={priorWeek ? 'week' : 'period'}
                  options={[
                    { value: 'period', label: 'Previous period' },
                    { value: 'week', label: 'Same time last week' },
                  ]}
                  onChange={(event) => setPriorWeek(event.target.value === 'week')}
                />
              )}
              <Field
                label="Top keys"
                type="number"
                min={1}
                max={300}
                required
                value={topKeys}
                onChange={(event) => setTopKeys(event.target.value)}
              />
              {mode === 'rank' && (
                <Field
                  label="Minimum rank change"
                  type="number"
                  min={1}
                  max={Number(topKeys)}
                  required
                  value={rankStep}
                  onChange={(event) => setRankStep(event.target.value)}
                />
              )}
              {mode === 'share' ? (
                <Field
                  label="Minimum share change (basis points)"
                  type="number"
                  min={1}
                  max={10000}
                  required
                  value={basisPoints}
                  onChange={(event) => setBasisPoints(event.target.value)}
                />
              ) : (
                <Field
                  label={mode === 'rank' ? 'Minimum traffic amount' : 'Minimum amount change'}
                  inputMode={mode === 'fanout' ? 'numeric' : 'decimal'}
                  required
                  value={minimum}
                  maxLength={256}
                  pattern={mode === 'fanout' ? '[0-9]+' : decimalPattern}
                  onChange={(event) => setMinimum(event.target.value)}
                />
              )}
              {mode === 'rank' &&
                secondary.map((key) => (
                  <Field
                    key={key}
                    label={`Minimum ${key}`}
                    inputMode="decimal"
                    value={floors[key] ?? ''}
                    pattern={decimalPattern}
                    maxLength={256}
                    onChange={(event) => setFloors({ ...floors, [key]: event.target.value })}
                  />
                ))}
            </div>
            {completeWeek && (
              <p>Last seven complete days compared with the preceding seven days.</p>
            )}
            <div>
              <Button type="submit">Compare fields</Button>
            </div>
          </fieldset>
        </form>
        {comparison.isPending && <p role="status">Comparing saved flow windows…</p>}
        {comparison.isError && (
          <ErrorState title="Field comparison unavailable" description={comparison.error.message} />
        )}
        {result && (
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
        )}
      </CardBody>
    </Card>
  )
}
