// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { FlowQueryDisplay } from '../api/flowViews'
import type { FlowQueryPlan } from '../api/flowExplorer'
import { Button, Select } from '../components'
import styles from './flowExplorer.module.css'

export function FlowDisplaySettings({
  plan,
  display,
  onChange,
}: {
  plan: FlowQueryPlan
  display?: FlowQueryDisplay
  onChange: (display: FlowQueryDisplay | undefined) => void
}) {
  if (!plan.view || plan.view === 'table' || plan.view === 'matrix') return null
  const value = display ?? {}
  const patch = (next: Partial<FlowQueryDisplay>) => onChange({ ...value, ...next })
  const time = plan.view === 'line' || plan.view === 'timeline'
  const metrics = (plan.metrics ?? [])
    .filter((metric) => metric.role !== 'additional')
    .map((metric) => `${metric.measure}:${metric.calculation}`)
  const options = [
    { value: 'off', label: 'Off' },
    { value: 'on', label: 'On' },
  ]
  return (
    <fieldset className={styles.group}>
      <legend>Saved chart display</legend>
      <p className={styles.hint}>
        Display changes apply to frozen results and are saved with this query. Chart group
        visibility remains temporary.
      </p>
      <div className={styles.grid}>
        <Select
          label="Total overlay"
          value={value.total_overlay ? 'on' : 'off'}
          options={options}
          onChange={(event) => patch({ total_overlay: event.target.value === 'on' })}
        />
        {time && (
          <>
            <Select
              label="Time chart style"
              value={value.time_style ?? 'line'}
              options={[
                { value: 'line', label: 'Line' },
                { value: 'stacked_area', label: 'Stacked area' },
                { value: 'stacked_columns', label: 'Stacked columns' },
                { value: 'percent_area', label: '100% stacked area' },
                { value: 'horizon', label: 'Horizon (five bands)' },
              ]}
              onChange={(event) =>
                patch({ time_style: event.target.value as FlowQueryDisplay['time_style'] })
              }
            />
            {value.time_style === 'horizon' && (
              <Select
                label="Horizon density scale"
                value={value.horizon_scale ?? 'shared'}
                options={[
                  { value: 'shared', label: 'Shared across visible lanes' },
                  { value: 'lane', label: 'Per lane (both periods)' },
                ]}
                onChange={(event) =>
                  patch({ horizon_scale: event.target.value as 'shared' | 'lane' })
                }
              />
            )}
            {value.time_style === 'percent_area' && (
              <Select
                label="Percentage basis"
                value={value.percent_basis ?? 'returned'}
                options={[
                  { value: 'returned', label: 'All returned groups' },
                  { value: 'visible', label: 'Visible groups' },
                ]}
                onChange={(event) =>
                  patch({ percent_basis: event.target.value as FlowQueryDisplay['percent_basis'] })
                }
              />
            )}
            <Select
              label="Synchronize metric axes"
              value={value.sync_axes ? 'on' : 'off'}
              options={options}
              onChange={(event) => patch({ sync_axes: event.target.value === 'on' })}
            />
            <Select
              label="One chart per group"
              value={value.one_chart_per_series ? 'on' : 'off'}
              options={options}
              onChange={(event) => patch({ one_chart_per_series: event.target.value === 'on' })}
            />
            <Select
              label="Charts per row"
              value={String(value.charts_per_row ?? 1)}
              options={[1, 2, 3, 4].map((n) => ({ value: String(n), label: String(n) }))}
              onChange={(event) => patch({ charts_per_row: Number(event.target.value) })}
            />
            <Select
              label="Chart height"
              value={value.chart_height ?? 'medium'}
              options={['short', 'medium', 'tall'].map((height) => ({
                value: height,
                label: height,
              }))}
              onChange={(event) =>
                patch({ chart_height: event.target.value as FlowQueryDisplay['chart_height'] })
              }
            />
            {metrics.map((metric) => (
              <Select
                key={metric}
                label={`Scale for ${metric}`}
                value={value.log_metrics?.includes(metric) ? 'log' : 'linear'}
                options={[
                  { value: 'linear', label: 'Linear' },
                  { value: 'log', label: 'Logarithmic' },
                ]}
                onChange={(event) =>
                  patch({
                    log_metrics:
                      event.target.value === 'log'
                        ? [...new Set([...(value.log_metrics ?? []), metric])]
                        : (value.log_metrics ?? []).filter((key) => key !== metric),
                  })
                }
              />
            ))}
          </>
        )}
      </div>
      <Button size="sm" onClick={() => onChange(undefined)}>
        Reset chart display
      </Button>
    </fieldset>
  )
}
