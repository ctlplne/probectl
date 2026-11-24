// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { a, m, useResultsHistory, type LatestResult } from '../api/results'
import { Badge, ChartShell } from '../components'
import { TimeSeries } from '../components/TimeSeries'
import { formatCount, formatDecimal, formatUnit } from '../i18n/number'
import { useI18n } from '../i18n/useI18n'

const metrics = [
  { name: 'Largest Contentful Paint', key: 'lcp_ms', unit: 'ms', good: 2500, poor: 4000 },
  { name: 'Cumulative Layout Shift', key: 'cls', unit: '', good: 0.1, poor: 0.25 },
  { name: 'Interaction to Next Paint', key: 'inp_ms', unit: 'ms', good: 200, poor: 500 },
] as const

type Vital = (typeof metrics)[number]

function observation(result: LatestResult, metric: Vital) {
  const value = m(result, `browser.web_vitals.${metric.key}`)
  return value !== undefined && Number.isFinite(value) && value >= 0 ? value : undefined
}

function percentile75(samples: number[]) {
  if (samples.length === 0) return undefined
  const values = [...samples].sort((a, b) => a - b)
  const position = (values.length - 1) * 0.75
  const left = Math.floor(position)
  return values[left] + (values[Math.ceil(position)] - values[left]) * (position - left)
}

function VitalBand({ value, metric }: { value: number; metric: Vital }) {
  if (value > metric.poor) return <Badge tone="danger">Poor</Badge>
  if (value > metric.good) return <Badge tone="warning">Needs improvement</Badge>
  return <Badge tone="success">Good</Badge>
}

export function BrowserVitals({ latest, testID }: { latest: LatestResult; testID: string }) {
  const { locale } = useI18n()
  const history = useResultsHistory('1h')
  const runs = (history.data?.items ?? []).filter(
    (run) =>
      run.type === 'browser' &&
      run.agent_id === latest.agent_id &&
      run.target === latest.target &&
      a(run, 'probectl.test.id') === testID &&
      a(run, 'browser.driver') === 'browser',
  )

  return (
    <section aria-label="Synthetic Core Web Vitals">
      <h3>Synthetic Core Web Vitals</h3>
      {metrics.map((metric) => {
        const value = observation(latest, metric)
        const trend = runs.map((run) => observation(run, metric) ?? null)
        const values = trend.filter((value): value is number => value !== null)
        const p75 = percentile75(values)
        const format = (v: number) =>
          metric.unit
            ? formatUnit(v, metric.unit, locale, { maximumFractionDigits: 1 })
            : formatDecimal(v, locale, { maximumFractionDigits: 3 })
        return (
          <section key={metric.key} aria-label={metric.name}>
            <h4>{metric.name}</h4>
            {value === undefined ? (
              <p>No observation in the latest run.</p>
            ) : (
              <p>
                Latest {format(value)} <VitalBand value={value} metric={metric} />
              </p>
            )}
            {p75 !== undefined && (
              <p>
                p75 {format(p75)} for{' '}
                {formatCount(values.length, 'cached run', 'cached runs', locale)} in the last hour{' '}
                <VitalBand value={p75} metric={metric} />
              </p>
            )}
            {values.length > 1 && (
              <ChartShell title={`${metric.name} over time`}>
                <TimeSeries
                  label={`${metric.name} for this vantage`}
                  timestamps={runs.map((run) => run.observed_at)}
                  series={[{ label: metric.name, values: trend }]}
                  formatValue={format}
                />
              </ChartShell>
            )}
          </section>
        )
      })}
    </section>
  )
}
