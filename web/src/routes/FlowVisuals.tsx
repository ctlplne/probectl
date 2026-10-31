// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from 'react'
import type { FlowExplorerResult, FlowResultRow } from '../api/flowExplorer'
import type { FlowQueryDisplay } from '../api/flowViews'
import { Button, ChartShell, ErrorState, Select } from '../components'
import { TimeSeries } from '../components/TimeSeries'
import { percentageDenominator, type PercentDenominator } from '../lib/timeGeometry'
import { horizonBasis, type HorizonBasis } from '../lib/horizonGeometry'
import {
  flowPaintRange,
  flowChartGroups,
  flowPlot,
  mergeFlowTuples,
  type FlowPlotSeries,
} from './flowPlot'
import { flowGroupKey, flowGroupLabel, type FlowDrillAction } from './flowResults'
import styles from './flowExplorer.module.css'

function exactValue(result: FlowExplorerResult | undefined, group: FlowResultRow, metric: string) {
  const row = group.other
    ? result?.chart_other
    : result?.chart_rows?.find((row) => flowGroupKey(row.group) === flowGroupKey(group.group))
  return row?.metrics[metric]
}

function FlowBars({
  current,
  previous,
  metric,
  onDrill,
  hidden,
  totalOverlay,
}: {
  current: FlowExplorerResult
  previous?: FlowExplorerResult
  metric: string
  onDrill: FlowDrillAction
  hidden: ReadonlySet<string>
  totalOverlay: boolean
}) {
  const groups = flowChartGroups(current, previous)
    .map((group, colorIndex) => ({ group, colorIndex }))
    .filter(({ group }) => !hidden.has(flowGroupKey(group.group, group.other)))
  let maximum = 0
  if (totalOverlay)
    for (const result of [current, previous]) {
      if (!result) continue
      const value = result.totals[metric]
      if (value === undefined || !Number.isFinite(Number(value)) || Number(value) < 0)
        return (
          <ErrorState
            title="Total reference unavailable"
            description="Run a fresh query to obtain exact total statistics."
          />
        )
      maximum = Math.max(maximum, Number(value))
    }
  for (const { group } of groups)
    for (const period of [current, previous]) {
      const value = exactValue(period, group, metric)
      if (value !== undefined) {
        const number = Number(value)
        if (!Number.isFinite(number) || number < 0)
          return (
            <ErrorState
              title="Bar geometry unavailable"
              description="The metric cannot be represented numerically. Exact table values and CSV remain available."
            />
          )
        maximum = Math.max(maximum, number)
      }
    }
  return (
    <figure className={styles.visual}>
      <figcaption>{metric} · global chart groups</figcaption>
      {totalOverlay &&
        [current, previous].map(
          (period, index) =>
            period && (
              <div key={index}>
                <p>
                  Total {index ? 'previous' : 'current'}: {period.totals[metric]}
                </p>
                <div className={styles.barTrack} aria-hidden="true">
                  <div
                    className={styles.totalMarker}
                    style={{
                      left: `${maximum ? (Number(period.totals[metric]) / maximum) * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>
            ),
        )}
      <ol className={styles.bars}>
        {groups.map(({ group, colorIndex }) => (
          <li
            key={flowGroupKey(group.group, group.other)}
            style={
              {
                '--flow-series-color': `hsl(var(--chart-${(colorIndex % 6) + 1}))`,
              } as CSSProperties
            }
          >
            <div>
              {group.other ? (
                flowGroupLabel({}, true)
              ) : (
                <Button className={styles.tupleButton} onClick={() => onDrill(group.group)}>
                  {flowGroupLabel(group.group)}
                </Button>
              )}
            </div>
            {[current, previous].map((period, index) => {
              if (!period) return null
              const value = exactValue(period, group, metric)
              return (
                <div key={index} className={styles.barRow}>
                  <span>
                    {index ? 'Previous' : 'Current'}: {value ?? 'Missing'}
                  </span>
                  <div className={styles.barTrack} aria-hidden="true">
                    <div
                      className={index ? styles.previousBar : styles.currentBar}
                      style={{
                        width: `${value === undefined || !maximum ? 0 : (Number(value) / maximum) * 100}%`,
                      }}
                    />
                    {totalOverlay && (
                      <div
                        className={styles.totalMarker}
                        style={{
                          left: `${maximum ? (Number(period.totals[metric]) / maximum) * 100 : 0}%`,
                        }}
                      />
                    )}
                  </div>
                </div>
              )
            })}
          </li>
        ))}
      </ol>
    </figure>
  )
}

function matrixAxes(
  current: FlowExplorerResult,
  previous: FlowExplorerResult | undefined,
  axis: 'row' | 'column',
) {
  const out = new Map<string, FlowResultRow>()
  for (const result of [current, previous]) {
    for (const item of (axis === 'row' ? result?.matrix_rows : result?.matrix_columns) ?? [])
      out.set(flowGroupKey(item.group), item)
    for (const cell of result?.matrix ?? []) {
      const other = axis === 'row' ? cell.row_other : cell.column_other
      if (other) out.set(flowGroupKey({}, true), { group: {}, other: true, metrics: {} })
    }
  }
  return [...out.values()]
}

function MatrixAxisHeader({
  item,
  fields,
  axis,
  onDrill,
}: {
  item: FlowResultRow
  fields: string[]
  axis: 'row' | 'column'
  onDrill: FlowDrillAction
}) {
  if (item.other) return <span>{flowGroupLabel({}, true)}</span>
  const ordered = [
    ...fields.filter((field) => Object.prototype.hasOwnProperty.call(item.group, field)),
    ...Object.keys(item.group).filter((field) => !fields.includes(field)),
  ]
  const first = ordered[0]
  const label = flowGroupLabel(item.group)
  return (
    <div className={styles.axisHeader}>
      <details className={styles.axisDetails}>
        <summary aria-label={`Show matrix ${axis} tuple ${label}`}>
          {first && <span>{first}</span>}
          <span className={styles.axisSummary}>
            {first ? item.group[first] || '(unassigned)' : 'All flows'}
          </span>
          {ordered.length > 1 && <span>+{ordered.length - 1} fields</span>}
        </summary>
        <div
          className={styles.axisValues}
          role="region"
          tabIndex={0}
          aria-label={`All matrix ${axis} dimension values ${label}`}
        >
          <dl>
            {ordered.map((field) => (
              <div key={field}>
                <dt>{field}</dt>
                <dd>{item.group[field] || '(unassigned)'}</dd>
              </div>
            ))}
          </dl>
        </div>
      </details>
      <Button
        size="sm"
        className={styles.tupleButton}
        aria-label={`Filter to matrix ${axis} ${label}`}
        onClick={() => onDrill(item.group)}
      >
        Filter {axis}
      </Button>
      <Button
        size="sm"
        className={styles.tupleButton}
        aria-label={`Exclude matrix ${axis} ${label}`}
        onClick={() => onDrill(item.group, 'exclude')}
      >
        Exclude {axis}
      </Button>
    </div>
  )
}

function FlowMatrix({
  current,
  previous,
  metric,
  onDrill,
}: {
  current: FlowExplorerResult
  previous?: FlowExplorerResult
  metric: string
  onDrill: FlowDrillAction
}) {
  const [error, setError] = useState('')
  const [colorPeriod, setColorPeriod] = useState('current')
  const regionRef = useRef<HTMLDivElement>(null)
  const headRef = useRef<HTMLTableSectionElement>(null)
  useLayoutEffect(() => {
    const region = regionRef.current
    const head = headRef.current
    if (!region || !head) return
    const corner = head.querySelector('th')
    const measure = () => {
      region.style.setProperty('--matrix-header-block', `${head.getBoundingClientRect().height}px`)
      region.style.setProperty(
        '--matrix-row-inline',
        `${corner?.getBoundingClientRect().width ?? 0}px`,
      )
    }
    measure()
    if (typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(measure)
    observer.observe(head)
    if (corner) observer.observe(corner)
    return () => observer.disconnect()
  }, [])
  const rows = matrixAxes(current, previous, 'row')
  const columns = matrixAxes(current, previous, 'column')
  const values = [current, previous].map(
    (result) =>
      new Map(
        (result?.matrix ?? []).map((cell) => [
          JSON.stringify([
            flowGroupKey(cell.row, cell.row_other),
            flowGroupKey(cell.column, cell.column_other),
          ]),
          cell.metrics[metric],
        ]),
      ),
  )
  const colorValues = values[colorPeriod === 'previous' && previous ? 1 : 0]
  let maximum = 0
  for (const value of colorValues.values())
    if (Number.isFinite(Number(value))) maximum = Math.max(maximum, Number(value))
  return (
    <div className={styles.stack}>
      {previous && (
        <Select
          label="Matrix color period"
          value={colorPeriod}
          options={[
            { value: 'current', label: 'Current' },
            { value: 'previous', label: 'Previous' },
          ]}
          onChange={(event) => setColorPeriod(event.target.value)}
        />
      )}
      {error && <ErrorState title="Matrix drilldown refused" description={error} />}
      <div
        ref={regionRef}
        className={styles.matrixRegion}
        tabIndex={0}
        aria-label="Global flow matrix scroll region"
      >
        <table className={styles.matrix}>
          <caption>{metric} · global matrix; each axis includes all selected tuple fields</caption>
          <thead ref={headRef}>
            <tr>
              <th scope="col">Row / column</th>
              {columns.map((column) => (
                <th key={flowGroupKey(column.group, column.other)} scope="col">
                  <MatrixAxisHeader
                    item={column}
                    fields={current.query.matrix_with ?? []}
                    axis="column"
                    onDrill={onDrill}
                  />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={flowGroupKey(row.group, row.other)}>
                <th scope="row">
                  <MatrixAxisHeader
                    item={row}
                    fields={current.query.group_by ?? []}
                    axis="row"
                    onDrill={onDrill}
                  />
                </th>
                {columns.map((column) => {
                  const key = JSON.stringify([
                    flowGroupKey(row.group, row.other),
                    flowGroupKey(column.group, column.other),
                  ])
                  const currentValue = values[0].get(key)
                  const previousValue = values[1].get(key)
                  const label = `Row ${flowGroupLabel(row.group, row.other)}; column ${flowGroupLabel(column.group, column.other)}`
                  return (
                    <td
                      key={key}
                      style={
                        {
                          '--flow-cell-strength':
                            maximum && Number.isFinite(Number(colorValues.get(key)))
                              ? Math.max(0, Number(colorValues.get(key)) / maximum)
                              : 0,
                        } as CSSProperties
                      }
                    >
                      <div>Current: {currentValue ?? 'No matching cell'}</div>
                      {previous && <div>Previous: {previousValue ?? 'No matching cell'}</div>}
                      {!row.other &&
                        !column.other &&
                        (currentValue !== undefined || previousValue !== undefined) && (
                          <div className={styles.stack}>
                            {(['include', 'exclude'] as const).map((mode) => (
                              <Button
                                key={mode}
                                size="sm"
                                className={styles.tupleButton}
                                aria-label={`${mode === 'include' ? 'Filter to' : 'Exclude'} ${label}`}
                                onClick={() => {
                                  try {
                                    const tuple = mergeFlowTuples(row.group, column.group)
                                    if (mode === 'exclude') onDrill(tuple, mode)
                                    else onDrill(tuple)
                                    setError('')
                                  } catch (cause) {
                                    setError(
                                      cause instanceof Error ? cause.message : 'Conflicting tuple.',
                                    )
                                  }
                                }}
                              >
                                {mode === 'include' ? 'Filter to cell' : 'Exclude cell'}
                              </Button>
                            ))}
                          </div>
                        )}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className={styles.hint}>
        Cell intensity compares the selected period's values; exact values are shown independently.
        A missing cell reports no matching returned cell in that period. Other summarizes unselected
        groups; choose a specific row, column or cell to refine this query.
      </p>
    </div>
  )
}

function FlowTimePlot({
  plot,
  metric,
  series,
  range,
  logarithmic,
  height,
  timeStyle,
  groupLabel,
  percentDenominator,
  densityBasis,
  horizonScale,
}: {
  plot: ReturnType<typeof flowPlot>
  metric: string
  series: FlowPlotSeries[]
  range?: [number, number]
  logarithmic: boolean
  height: FlowQueryDisplay['chart_height']
  timeStyle: FlowQueryDisplay['time_style']
  groupLabel?: string
  percentDenominator?: PercentDenominator
  densityBasis?: HorizonBasis
  horizonScale?: FlowQueryDisplay['horizon_scale']
}) {
  const plotHeight =
    height === 'short'
      ? 'calc(var(--space-8) * 5)'
      : height === 'tall'
        ? 'calc(var(--space-8) * 12)'
        : 'calc(var(--space-8) * 8)'
  return (
    <ChartShell
      title={`${metric} · ${timeStyle === 'percent_area' ? 'Share of group observations · ' : ''}${groupLabel ?? 'global bucket series'}`}
      height="auto"
    >
      <TimeSeries
        timestamps={plot.timestamps}
        series={series}
        label={`${metric} global flow time series${timeStyle === 'percent_area' ? ' · percentage of group observations' : timeStyle === 'horizon' ? ' · horizon five-band group lanes' : ''}${groupLabel ? ` · ${groupLabel}` : ''}`}
        logarithmic={logarithmic}
        yRange={range}
        plotHeight={plotHeight}
        timeStyle={timeStyle}
        percentDenominator={percentDenominator}
        horizonBasis={densityBasis}
        horizonScale={horizonScale}
      />
    </ChartShell>
  )
}

type PreparedFlowPlot = { metric: string; plot?: ReturnType<typeof flowPlot>; error?: string }

export function FlowVisuals({
  current,
  previous,
  onDrill,
  display = {},
}: {
  current: FlowExplorerResult
  previous?: FlowExplorerResult
  onDrill: FlowDrillAction
  display?: FlowQueryDisplay
}) {
  const [matrixMetric, setMatrixMetric] = useState('')
  const [hidden, setHidden] = useState<ReadonlySet<string>>(() => new Set())
  const groups = flowChartGroups(current, previous)
  const metrics = useMemo(
    () =>
      (current.query.metrics ?? [])
        .filter((metric) => metric.role !== 'additional')
        .map((metric) => `${metric.measure}:${metric.calculation}`),
    [current],
  )
  const totalOverlay = Boolean(display.total_overlay)
  const timeStyle = display.time_style ?? 'line'
  const percentage = timeStyle === 'percent_area'
  const horizon = timeStyle === 'horizon'
  const folded = percentage || horizon
  const visibleBasis = display.percent_basis === 'visible'
  const prepared = useMemo<PreparedFlowPlot[]>(() => {
    if (current.query.view !== 'line' && current.query.view !== 'timeline') return []
    return metrics.map((metric) => {
      try {
        return {
          metric,
          plot: flowPlot(current, previous, metric, undefined, {
            total: totalOverlay,
            intervals: timeStyle === 'stacked_columns' || folded,
          }),
        }
      } catch (cause) {
        return {
          metric,
          error: cause instanceof Error ? cause.message : 'Flow plot could not be prepared.',
        }
      }
    })
  }, [current, previous, metrics, totalOverlay, timeStyle, folded])
  const visible = (entries: FlowPlotSeries[]) =>
    entries.filter((entry) => entry.total || !hidden.has(entry.groupKey))
  const denominators = useMemo(
    () =>
      new Map(
        !percentage
          ? []
          : prepared.map(({ metric, plot }) => [
              metric,
              percentageDenominator(
                (plot?.series ?? []).filter(
                  (entry) => !entry.total && (!visibleBasis || !hidden.has(entry.groupKey)),
                ),
              ),
            ]),
      ),
    [prepared, visibleBasis, hidden, percentage],
  )
  const densityBases = useMemo(
    () =>
      new Map(
        !horizon
          ? []
          : prepared.map(({ metric, plot }) => [
              metric,
              horizonBasis(
                (plot?.series ?? []).filter((entry) => !entry.total && !hidden.has(entry.groupKey)),
              ),
            ]),
      ),
    [prepared, hidden, horizon],
  )
  const shown = groups.filter((group) => !hidden.has(flowGroupKey(group.group, group.other)))
  const range = display.sync_axes
    ? flowPaintRange(
        prepared.flatMap((entry) => {
          const series = visible(entry.plot?.series ?? [])
          if (folded) return [series.filter((item) => item.total)]
          return display.one_chart_per_series && shown.length
            ? shown.map((group) =>
                series.filter(
                  (item) => item.total || item.groupKey === flowGroupKey(group.group, group.other),
                ),
              )
            : [series]
        }),
        folded ? 'line' : timeStyle,
        metrics.some((metric) => display.log_metrics?.includes(metric)),
      )
    : undefined
  if (!current.query.view || current.query.view === 'table') return null
  if (current.query.view === 'matrix') {
    const metric = metrics.includes(matrixMetric) ? matrixMetric : metrics[0]
    return (
      <section className={styles.stack} aria-label="Global flow visualizations">
        <Select
          label="Matrix metric"
          value={metric}
          options={metrics.map((value) => ({ value, label: value }))}
          onChange={(event) => setMatrixMetric(event.target.value)}
        />
        <FlowMatrix current={current} previous={previous} metric={metric} onDrill={onDrill} />
      </section>
    )
  }
  return (
    <section className={styles.stack} aria-label="Global flow visualizations">
      <details className={styles.chartControls}>
        <summary>
          Chart groups (
          {groups.filter((group) => !hidden.has(flowGroupKey(group.group, group.other))).length} of{' '}
          {groups.length} shown)
        </summary>
        <p className={styles.hint}>
          Changes affect this chart only. Exact results, totals and CSV retain every selected group.
          Both periods and all plotted metrics follow the same group selection.
        </p>
        <Button size="sm" onClick={() => setHidden(new Set())}>
          Show all chart groups
        </Button>
        <div
          className={styles.chartGroupRegion}
          role="region"
          tabIndex={0}
          aria-label="All global chart group controls"
        >
          <ul className={styles.chartGroupList}>
            {groups.map((group) => {
              const key = flowGroupKey(group.group, group.other)
              const label = flowGroupLabel(group.group, group.other)
              const visible = !hidden.has(key)
              return (
                <li key={key}>
                  <span>{label}</span>
                  <div className={styles.actions}>
                    <Button
                      size="sm"
                      aria-label={`${visible ? 'Hide' : 'Show'} chart group ${label}`}
                      onClick={() =>
                        setHidden((before) => {
                          const next = new Set(before)
                          if (next.has(key)) next.delete(key)
                          else next.add(key)
                          return next
                        })
                      }
                    >
                      {visible ? 'Hide' : 'Show'}
                    </Button>
                    <Button
                      size="sm"
                      aria-label={`Only show chart group ${label}`}
                      onClick={() =>
                        setHidden(
                          new Set(
                            groups
                              .map((item) => flowGroupKey(item.group, item.other))
                              .filter((item) => item !== key),
                          ),
                        )
                      }
                    >
                      Only
                    </Button>
                    <Button
                      size="sm"
                      aria-label={`Show all except chart group ${label}`}
                      onClick={() => setHidden(new Set([key]))}
                    >
                      All except
                    </Button>
                    {!group.other && (
                      <>
                        <Button
                          size="sm"
                          aria-label={`Filter to chart group ${label}`}
                          onClick={() => onDrill(group.group)}
                        >
                          Filter to group
                        </Button>
                        <Button
                          size="sm"
                          aria-label={`Exclude chart group ${label}`}
                          onClick={() => onDrill(group.group, 'exclude')}
                        >
                          Exclude group
                        </Button>
                      </>
                    )}
                  </div>
                </li>
              )
            })}
          </ul>
        </div>
      </details>
      {!shown.length && !totalOverlay ? (
        <p role="status">No chart groups are visible. Use Show all chart groups to restore them.</p>
      ) : current.query.view === 'bar' ? (
        metrics.map((metric) => (
          <FlowBars
            key={metric}
            current={current}
            previous={previous}
            metric={metric}
            onDrill={onDrill}
            hidden={hidden}
            totalOverlay={totalOverlay}
          />
        ))
      ) : (
        <>
          <div
            className={styles.chartGrid}
            style={
              {
                '--flow-chart-columns': display.one_chart_per_series
                  ? (display.charts_per_row ?? 1)
                  : 1,
              } as CSSProperties
            }
          >
            {prepared.flatMap(({ metric, plot, error }) => {
              if (!plot)
                return [
                  <ErrorState
                    key={metric}
                    title="Flow plot unavailable"
                    description={error ?? 'Flow plot could not be prepared.'}
                  />,
                ]
              const series = visible(plot.series)
              const totals = folded
                ? [
                    ...(totalOverlay
                      ? [
                          <FlowTimePlot
                            key={`${metric}:absolute-total`}
                            metric={metric}
                            plot={plot}
                            series={series.filter((entry) => entry.total)}
                            range={range}
                            logarithmic={Boolean(display.log_metrics?.includes(metric))}
                            height={display.chart_height}
                            timeStyle="line"
                            groupLabel="Total (all matching inputs), absolute scale"
                          />,
                        ]
                      : []),
                  ]
                : []
              const plotted = folded ? series.filter((entry) => !entry.total) : series
              if (folded && !plotted.length)
                return [
                  ...totals,
                  <p key={`${metric}:hidden`} className={styles.hint}>
                    All chart groups are hidden. Show a group to plot this visualization.
                  </p>,
                ]
              const facets = display.one_chart_per_series && shown.length ? shown : [undefined]
              return [
                ...totals,
                ...facets.map((group) => {
                  const key = group ? flowGroupKey(group.group, group.other) : undefined
                  return (
                    <FlowTimePlot
                      key={`${metric}:${key ?? 'all'}`}
                      metric={metric}
                      plot={plot}
                      series={
                        key
                          ? plotted.filter((entry) => entry.total || entry.groupKey === key)
                          : plotted
                      }
                      range={range}
                      logarithmic={!folded && Boolean(display.log_metrics?.includes(metric))}
                      height={display.chart_height}
                      timeStyle={timeStyle}
                      percentDenominator={percentage ? denominators.get(metric) : undefined}
                      densityBasis={horizon ? densityBases.get(metric) : undefined}
                      horizonScale={display.horizon_scale}
                      groupLabel={group ? flowGroupLabel(group.group, group.other) : undefined}
                    />
                  )
                }),
              ]
            })}
          </div>
          <p className={styles.hint}>
            Empty query buckets mean no matching observed flow, not proven exporter health. Previous
            samples align by elapsed offset from each period start; exact readouts retain actual
            previous timestamps. Values outside a period remain missing. Lines show bucket
            observations; the selected calculation controls ranking and whole-period statistics.
            Current lines are solid; previous lines are dashed with the same group color. Total
            overlays use all matching inputs independently of visible groups.
            {percentage &&
              ` Percentage axes are linear. Shares use ${visibleBasis ? 'visible' : 'all returned'} group observations separately for each metric and period, including Other. Unique identities can overlap across groups. Hidden shares stay unpainted with the returned-group basis; visible-group basis re-normalizes. An all-zero or absent denominator has no defined percentage. Readouts and export keep original counts. Source totals use separate absolute scales; saved logarithmic choices apply there.`}
            {horizon &&
              ` Horizon uses one equal-height lane per group, with five folded bands. Density scales are ${display.horizon_scale === 'lane' ? 'separate per lane' : 'shared across visible lanes'} for each metric; paired current/previous observations always use the same amplitude, including in generated charts. Source totals use separate absolute plots. Logarithmic settings apply to those totals; horizon lanes remain linear. Exact readouts and export preserve original values.`}
            {!folded &&
              timeStyle !== 'line' &&
              ' Stacks add displayed group observations separately for each period. Unique identities may overlap across groups; a stack is not a deduplicated total. Previous stacks use dashed outlines. Columns span actual source bucket intervals.'}
          </p>
        </>
      )}
    </section>
  )
}
