// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  ChartShell,
  ErrorState,
  Field,
  LoadingState,
  Select,
  Sparkline,
  Table,
  type Column,
} from '../components'
import {
  useExplorerComparison,
  useExplorerQuery,
  useExplorerSchema,
  type ExplorerComparisonExecutionReceipt,
  type ExplorerComparisonRow,
  type ExplorerExecutionReceipt,
  type ExplorerQuery,
  type ExplorerSource,
  type ExplorerTemplate,
  type ExplorerVisualization,
} from '../api/explorer'
import { Page } from './RoutePage'
// Direct import (not the components barrel): uplot must ride only in lazy
// route chunks so the app-shell entry stays inside its bundle budget.
import { TimeSeries } from '../components/TimeSeries'
import { SavedViews } from './listControls'
import { ExplainView } from './ExplainView'
import { pivotHref } from './pivotContext'
import styles from './explorer.module.css'

const SOURCE_OPTIONS: { value: ExplorerSource; label: string }[] = [
  { value: 'flow', label: 'Flow' },
  { value: 'changes', label: 'Changes / BGP' },
  { value: 'path', label: 'Synthetic path' },
  { value: 'topology', label: 'Topology / eBPF' },
  { value: 'endpoints', label: 'Endpoints' },
  { value: 'tls', label: 'TLS certificates' },
  { value: 'cost', label: 'Network cost' },
  { value: 'slo', label: 'SLOs' },
]

function rangeNow() {
  const to = new Date()
  const from = new Date(to.getTime() - 60 * 60 * 1000)
  return { from: from.toISOString(), to: to.toISOString() }
}

interface ComparisonWindow {
  from: string
  to: string
}

function precedingWindow(query: ExplorerQuery): ComparisonWindow {
  const from = new Date(query.from).getTime()
  const to = new Date(query.to).getTime()
  const duration = Math.max(1, to - from)
  return {
    from: new Date(from - duration).toISOString(),
    to: new Date(from).toISOString(),
  }
}

function fromTemplate(template: ExplorerTemplate, range = rangeNow()): ExplorerQuery {
  return {
    template: template.id,
    question: template.question,
    source: template.source,
    from: range.from,
    to: range.to,
    dimensions: template.dimensions,
    filters: {},
    groupings: template.groupings,
    measures: template.measures,
    visualization: template.visualization,
    limit: 100,
  }
}

function csv(value: string) {
  return Array.from(
    new Set(
      value
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  )
}

function localTime(value: string) {
  const date = new Date(value)
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}

function absoluteTime(value: string) {
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date.toISOString() : new Date().toISOString()
}

function grammarQuestion(query: ExplorerQuery) {
  const measure = query.measures.join(' and ') || 'records'
  const grouping = query.groupings.length ? ` by ${query.groupings.join(' and ')}` : ''
  return `Show ${measure}${grouping} from ${query.source}`
}

function preview(query: ExplorerQuery) {
  const filters = Object.entries(query.filters)
    .map(([key, value]) => `${key}=${value}`)
    .sort()
  return [
    `FROM ${query.source}`,
    `TIME ${query.from} .. ${query.to}`,
    filters.length ? `WHERE ${filters.join(', ')}` : '',
    query.groupings.length ? `GROUP BY ${query.groupings.join(', ')}` : '',
    query.measures.length ? `MEASURE ${query.measures.join(', ')}` : '',
    `VIEW ${query.visualization}`,
  ]
    .filter(Boolean)
    .join(' | ')
}

function stableHref(query: ExplorerQuery, comparison: ComparisonWindow | null) {
  const params = new URLSearchParams()
  if (query.template) params.set('template', query.template)
  params.set('from', query.from)
  params.set('to', query.to)
  for (const [key, value] of Object.entries(query.filters))
    params.append('filter', `${key}:${value}`)
  if (comparison) {
    params.set('compare', '1')
    params.set('previous_from', comparison.from)
    params.set('previous_to', comparison.to)
  }
  params.set('run', '1')
  return `/explore?${params.toString()}`
}

function savedState(query: ExplorerQuery, comparison: ComparisonWindow | null) {
  const firstFilter = Object.entries(query.filters)[0]
  return {
    template: query.template ?? '',
    source: query.source,
    from: query.from,
    to: query.to,
    dimensions: query.dimensions.join(','),
    groupings: query.groupings.join(','),
    measures: query.measures.join(','),
    visualization: query.visualization,
    filter_key: firstFilter?.[0] ?? '',
    filter_value: firstFilter?.[1] ?? '',
    compare: comparison ? '1' : '',
    previous_from: comparison?.from ?? '',
    previous_to: comparison?.to ?? '',
  }
}

function displayValue(value: unknown) {
  if (value == null) return '—'
  if (typeof value === 'number') return new Intl.NumberFormat().format(value)
  if (typeof value === 'object') return JSON.stringify(value)
  if (typeof value === 'string') return value
  if (typeof value === 'boolean' || typeof value === 'bigint') return `${value}`
  return '—'
}

function chartValues(rows: Record<string, unknown>[], measures: string[]) {
  const key = measures[0]
  if (!key) return rows.length ? rows.map(() => 1) : [0]
  const values = rows
    .map((row) => row[key])
    .filter((value): value is number => typeof value === 'number')
  return values.length ? values : [0]
}

function comparisonValue(value: number | null) {
  if (value == null) return '—'
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 3 }).format(value)
}

function comparisonStateLabel(state: ExplorerComparisonRow['delta_state']) {
  switch (state) {
    case 'zero_baseline':
      return 'Zero baseline'
    case 'missing_current':
      return 'Missing current'
    case 'missing_previous':
      return 'Missing previous'
    default:
      return 'Comparable'
  }
}

function receiptList(values: string[]) {
  return values.length ? values.join(', ') : 'None'
}

function ExecutionReceiptFacts({ receipt }: { receipt: ExplorerExecutionReceipt }) {
  return (
    <dl className={styles.executionFacts}>
      <div>
        <dt>Recipe / source</dt>
        <dd>
          {receipt.recipe} / {receipt.source}
        </dd>
      </div>
      <div>
        <dt>Tenant boundary</dt>
        <dd>{receipt.tenant_scoped ? 'Authenticated tenant enforced' : 'Unavailable'}</dd>
      </div>
      <div>
        <dt>Time bound</dt>
        <dd>
          <time dateTime={receipt.bounds.from}>{receipt.bounds.from}</time> →{' '}
          <time dateTime={receipt.bounds.to}>{receipt.bounds.to}</time>
        </dd>
      </div>
      <div>
        <dt>Row budget</dt>
        <dd>
          {receipt.returned_rows} returned / {receipt.bounds.row_limit} maximum from{' '}
          {receipt.source_rows} authorized source rows
        </dd>
      </div>
      <div>
        <dt>Dimensions</dt>
        <dd>{receiptList(receipt.projection.dimensions)}</dd>
      </div>
      <div>
        <dt>Groupings</dt>
        <dd>{receiptList(receipt.projection.groupings)}</dd>
      </div>
      <div>
        <dt>Measures</dt>
        <dd>{receiptList(receipt.projection.measures)}</dd>
      </div>
      <div>
        <dt>Filter keys</dt>
        <dd>{receiptList(receipt.filter_keys)}</dd>
      </div>
      <div>
        <dt>Truncation</dt>
        <dd>{receipt.truncation_reason}</dd>
      </div>
      <div>
        <dt>Timing</dt>
        <dd>
          source {receipt.timings.source_ms} ms · shaping {receipt.timings.shaping_ms} ms · total{' '}
          {receipt.timings.total_ms} ms
        </dd>
      </div>
    </dl>
  )
}

function ExecutionReceipt({
  receipt,
  label = 'Query',
}: {
  receipt: ExplorerExecutionReceipt
  label?: string
}) {
  return (
    <details className={styles.executionReceipt}>
      <summary>{label} execution receipt</summary>
      <p>
        <code>{receipt.contract_version}</code> is a sanitized logical plan. It never contains SQL,
        a physical database plan, tenant identity, or filter values.
      </p>
      <ExecutionReceiptFacts receipt={receipt} />
    </details>
  )
}

function ComparisonExecutionReceipt({ receipt }: { receipt: ExplorerComparisonExecutionReceipt }) {
  return (
    <details className={styles.executionReceipt}>
      <summary>Comparison execution receipt</summary>
      <p>
        <code>{receipt.contract_version}</code> applies one authenticated tenant boundary to both
        windows. Total elapsed time: {receipt.total_ms} ms.
      </p>
      <section aria-labelledby="explorer-current-execution">
        <h3 id="explorer-current-execution">Current window</h3>
        <ExecutionReceiptFacts receipt={receipt.current} />
      </section>
      <section aria-labelledby="explorer-previous-execution">
        <h3 id="explorer-previous-execution">Previous window</h3>
        <ExecutionReceiptFacts receipt={receipt.previous} />
      </section>
      <section aria-labelledby="explorer-alignment-execution">
        <h3 id="explorer-alignment-execution">Alignment</h3>
        <p>
          {receipt.alignment.returned_rows} aligned rows / {receipt.alignment.row_limit} maximum ·{' '}
          {receipt.alignment.truncation_reason} · {receipt.alignment.elapsed_ms} ms
        </p>
      </section>
    </details>
  )
}

function ComparisonBars({ rows }: { rows: ExplorerComparisonRow[] }) {
  const plotted = rows
    .filter((row) => row.current_value !== null || row.previous_value !== null)
    .slice(0, 12)
  const maximum = Math.max(
    1,
    ...plotted.flatMap((row) => [
      Math.abs(row.current_value ?? 0),
      Math.abs(row.previous_value ?? 0),
    ]),
  )
  return (
    <div
      className={styles.comparisonBars}
      role="img"
      aria-label={`Current and previous values for ${plotted.length} aligned Explorer measure${plotted.length === 1 ? '' : 's'}`}
    >
      <div className={styles.comparisonLegend} aria-hidden="true">
        <span className={styles.currentSwatch} />
        <span>Current</span>
        <span className={styles.previousSwatch} />
        <span>Previous</span>
      </div>
      <ol>
        {plotted.map((row) => {
          const label = [...Object.values(row.group), row.measure].filter(Boolean).join(' · ')
          return (
            <li key={`${JSON.stringify(row.group)}:${row.measure}`}>
              <span className={styles.barLabel}>{label}</span>
              <span className={`${styles.barValue} ${styles.currentValue}`}>
                {comparisonValue(row.current_value)}
              </span>
              <span className={`${styles.barTrack} ${styles.currentTrack}`} aria-hidden="true">
                <span
                  className={styles.currentBar}
                  style={{ width: `${(Math.abs(row.current_value ?? 0) / maximum) * 100}%` }}
                />
              </span>
              <span className={`${styles.barValue} ${styles.previousValue}`}>
                {comparisonValue(row.previous_value)}
              </span>
              <span className={`${styles.barTrack} ${styles.previousTrack}`} aria-hidden="true">
                <span
                  className={styles.previousBar}
                  style={{ width: `${(Math.abs(row.previous_value ?? 0) / maximum) * 100}%` }}
                />
              </span>
            </li>
          )
        })}
      </ol>
    </div>
  )
}

const TIME_COLUMN = /(^|_)(occurred_at|observed_at|timestamp|time|ts|hour|bucket|date)($|_)/i

/** When the result carries a real time column, line/timeline visualizations
 * upgrade from the indexed Sparkline to the S11 TimeSeries; results without
 * one (hop-indexed lines, bars) honestly stay indexed. */
function timeSeriesFromRows(
  rows: Record<string, unknown>[],
  columns: { key: string }[],
  measures: string[],
): { timestamps: string[]; values: (number | null)[] } | null {
  const measure = measures[0]
  if (!measure || rows.length < 2) return null
  const timeKey = columns.find(
    (column) =>
      TIME_COLUMN.test(column.key) &&
      rows.every((row) => {
        const value = row[column.key]
        return typeof value === 'string' && Number.isFinite(Date.parse(value))
      }),
  )?.key
  if (!timeKey) return null
  const timestamps: string[] = []
  const values: (number | null)[] = []
  for (const row of rows) {
    timestamps.push(row[timeKey] as string)
    const value = row[measure]
    values.push(typeof value === 'number' ? value : null)
  }
  return { timestamps, values }
}

export function ExplorerPage() {
  const [params, setParams] = useSearchParams()
  const schema = useExplorerSchema()
  const run = useExplorerQuery()
  const comparisonRun = useExplorerComparison()
  const [query, setQuery] = useState<ExplorerQuery | null>(null)
  const [comparison, setComparison] = useState<ComparisonWindow | null>(null)
  const [filterKey, setFilterKey] = useState('')
  const autoExecutedHref = useRef('')

  useEffect(() => {
    if (query || !schema.data?.templates.length) return
    const requested = params.get('template')
    const template =
      schema.data.templates.find((item) => item.id === requested) ?? schema.data.templates[0]
    const from = params.get('from')
    const to = params.get('to')
    const range = from && to ? { from: absoluteTime(from), to: absoluteTime(to) } : rangeNow()
    const next = fromTemplate(template, range)
    for (const encoded of params.getAll('filter')) {
      const split = encoded.indexOf(':')
      const key = encoded.slice(0, split)
      if (split > 0 && !key.toLowerCase().startsWith('tenant'))
        next.filters[key] = encoded.slice(split + 1)
    }
    if (params.get('compare') === '1') {
      const previousFrom = params.get('previous_from')
      const previousTo = params.get('previous_to')
      setComparison(
        previousFrom && previousTo
          ? { from: absoluteTime(previousFrom), to: absoluteTime(previousTo) }
          : precedingWindow(next),
      )
    }
    setFilterKey(Object.keys(next.filters)[0] ?? next.dimensions[0] ?? '')
    setQuery(next)
  }, [params, query, schema.data])

  useEffect(() => {
    if (!query || params.get('run') !== '1') return
    const requestedHref = `/explore?${params.toString()}`
    if (stableHref(query, comparison) !== requestedHref) return
    if (autoExecutedHref.current === requestedHref) return
    autoExecutedHref.current = requestedHref
    if (comparison) {
      run.reset()
      comparisonRun.mutate({
        query,
        previous_from: comparison.from,
        previous_to: comparison.to,
      })
    } else {
      comparisonRun.reset()
      run.mutate(query)
    }
  }, [comparison, comparisonRun, params, query, run])

  const columns = useMemo<Column<Record<string, unknown>>[]>(
    () =>
      (run.data?.columns ?? []).map((column) => ({
        key: column.key,
        header: column.label,
        numeric: column.numeric,
        render: (row) => displayValue(row[column.key]),
      })),
    [run.data?.columns],
  )
  const comparisonColumns = useMemo<Column<ExplorerComparisonRow>[]>(
    () => [
      ...(comparisonRun.data?.groupings ?? []).map((grouping) => ({
        key: grouping,
        header: grouping.replace(/_/g, ' '),
        render: (row: ExplorerComparisonRow) => row.group[grouping] || 'All rows',
      })),
      { key: 'measure', header: 'Measure', render: (row) => row.measure },
      {
        key: 'current',
        header: 'Current',
        numeric: true,
        render: (row) => comparisonValue(row.current_value),
      },
      {
        key: 'previous',
        header: 'Previous',
        numeric: true,
        render: (row) => comparisonValue(row.previous_value),
      },
      {
        key: 'delta',
        header: 'Absolute delta',
        numeric: true,
        render: (row) => comparisonValue(row.delta),
      },
      {
        key: 'percent',
        header: 'Percent change',
        numeric: true,
        render: (row) =>
          row.percent_change == null ? '—' : `${comparisonValue(row.percent_change)}%`,
      },
      {
        key: 'state',
        header: 'Delta state',
        render: (row) => comparisonStateLabel(row.delta_state),
      },
      { key: 'aggregation', header: 'Aggregation', render: (row) => row.aggregation },
    ],
    [comparisonRun.data?.groupings],
  )

  if (schema.isPending || !query) return <LoadingState label="Loading Explorer grammar…" />
  if (schema.isError) return <ErrorState description="The Explorer grammar is unavailable." />

  const applyTemplate = (template: ExplorerTemplate) => {
    const next = fromTemplate(template, { from: query.from, to: query.to })
    setQuery(next)
    setFilterKey(next.dimensions[0] ?? '')
  }
  const updateStructure = (patch: Partial<ExplorerQuery>) => {
    setQuery((current) => {
      if (!current) return current
      const next = { ...current, ...patch, template: undefined }
      return { ...next, question: grammarQuestion(next) }
    })
  }
  const updateFilter = (key: string, value: string) => {
    setQuery((current) => {
      if (!current) return current
      const filters = { ...current.filters }
      for (const existing of Object.keys(filters)) delete filters[existing]
      if (key && value.trim()) filters[key] = value.trim()
      return { ...current, filters }
    })
  }
  const applySaved = (filters: Record<string, string>) => {
    const template = schema.data.templates.find((item) => item.id === filters.template)
    const base = template ? fromTemplate(template) : query
    const key = filters.filter_key ?? ''
    setFilterKey(key)
    const next = {
      ...base,
      from: filters.from ? absoluteTime(filters.from) : base.from,
      to: filters.to ? absoluteTime(filters.to) : base.to,
      filters: key && filters.filter_value ? { [key]: filters.filter_value } : {},
    }
    setQuery(next)
    setComparison(
      filters.compare === '1'
        ? {
            from: filters.previous_from
              ? absoluteTime(filters.previous_from)
              : precedingWindow(next).from,
            to: filters.previous_to ? absoluteTime(filters.previous_to) : precedingWindow(next).to,
          }
        : null,
    )
  }
  const comparisonSources = schema.data.comparison_sources ?? []
  const comparisonSupported = comparisonSources.includes(query.source)
  const link = stableHref(query, comparison)
  const activeEvidencePath = comparisonRun.data?.evidence_path ?? run.data?.evidence_path
  const evidenceLink = activeEvidencePath
    ? pivotHref(activeEvidencePath, {
        from: query.from,
        to: query.to,
        filters: query.filters,
        returnTo: link,
      })
    : undefined
  const suggestionValues =
    comparisonRun.data?.suggestions[filterKey] ?? run.data?.suggestions[filterKey] ?? []

  return (
    <Page
      title="Explorer"
      subtitle="Ask a question, see the exact query grammar, and keep every result tenant-scoped."
    >
      <Card data-explorer-workspace>
        <CardHeader
          title="Query builder"
          description="Start with a proven question, then inspect or refine its exact tenant-scoped grammar."
        />
        <CardBody>
          <section className={styles.recipeSection} aria-labelledby="explorer-recipes-title">
            <div className={styles.recipeHeading}>
              <h3 id="explorer-recipes-title">Canonical questions</h3>
              <p>Choose a recipe to populate the working query.</p>
            </div>
            <div
              className={styles.recipes}
              aria-label="Canonical Explorer questions"
              data-explorer-recipes
              role="group"
            >
              {schema.data.templates.map((template) => (
                <Button
                  key={template.id}
                  className={styles.recipe}
                  variant={query.template === template.id ? 'primary' : 'secondary'}
                  onClick={() => applyTemplate(template)}
                >
                  {template.question}
                </Button>
              ))}
            </div>
          </section>
          <form
            className={styles.builder}
            data-explorer-builder
            onSubmit={(event) => {
              event.preventDefault()
              const href = stableHref(query, comparison)
              autoExecutedHref.current = href
              setParams(new URLSearchParams(href.slice(href.indexOf('?') + 1)))
              if (comparison) {
                run.reset()
                comparisonRun.mutate({
                  query,
                  previous_from: comparison.from,
                  previous_to: comparison.to,
                })
              } else {
                comparisonRun.reset()
                run.mutate(query)
              }
            }}
          >
            <Field
              className={styles.wide}
              label="Ask in natural language"
              value={query.question}
              onChange={(event) => {
                const question = event.target.value
                const match = schema.data.templates.find(
                  (item) => item.question.toLowerCase() === question.trim().toLowerCase(),
                )
                if (match) applyTemplate(match)
                else setQuery({ ...query, question, template: undefined })
              }}
              hint="Known questions synchronize the structured controls; changing the structure rewrites this sentence."
            />
            <Field
              label="From"
              type="datetime-local"
              value={localTime(query.from)}
              onChange={(event) => setQuery({ ...query, from: absoluteTime(event.target.value) })}
            />
            <Field
              label="To"
              type="datetime-local"
              value={localTime(query.to)}
              onChange={(event) => setQuery({ ...query, to: absoluteTime(event.target.value) })}
            />
            <Select
              label="Source / plane"
              value={query.source}
              options={SOURCE_OPTIONS}
              onChange={(event) => {
                const source = event.target.value as ExplorerSource
                updateStructure({ source })
                if (!comparisonSources.includes(source)) setComparison(null)
              }}
            />
            <Field
              label="Dimensions"
              value={query.dimensions.join(', ')}
              onChange={(event) => updateStructure({ dimensions: csv(event.target.value) })}
            />
            <Field
              label="Group by"
              value={query.groupings.join(', ')}
              onChange={(event) => updateStructure({ groupings: csv(event.target.value) })}
            />
            <Field
              label="Measures"
              value={query.measures.join(', ')}
              onChange={(event) => updateStructure({ measures: csv(event.target.value) })}
            />
            <Select
              label="Visualization"
              value={query.visualization}
              options={schema.data.visualizations.map((value) => ({ value, label: value }))}
              onChange={(event) =>
                setQuery({ ...query, visualization: event.target.value as ExplorerVisualization })
              }
            />
            <Select
              label="Filter dimension"
              value={filterKey}
              options={[
                { value: '', label: 'No filter' },
                ...query.dimensions.map((value) => ({ value, label: value })),
              ]}
              onChange={(event) => {
                setFilterKey(event.target.value)
                updateFilter('', '')
              }}
            />
            <Field
              label="Filter exact value"
              list="explorer-filter-values"
              value={filterKey ? (query.filters[filterKey] ?? '') : ''}
              disabled={!filterKey}
              onChange={(event) => updateFilter(filterKey, event.target.value)}
            />
            <datalist id="explorer-filter-values">
              {suggestionValues.map((value) => (
                <option key={value} value={value} />
              ))}
            </datalist>
            <label
              className={styles.compareToggle}
              aria-disabled={comparisonSupported ? undefined : true}
            >
              <input
                type="checkbox"
                checked={comparison !== null}
                disabled={!comparisonSupported}
                onChange={(event) =>
                  setComparison(event.target.checked ? precedingWindow(query) : null)
                }
              />
              <span>Compare with another period</span>
            </label>
            {!comparisonSupported ? (
              <p className={styles.comparisonHint}>
                This source exposes only a current snapshot. Choose Flow, Changes, Topology,
                Endpoints, or TLS for exact two-window comparison.
              </p>
            ) : null}
            {comparison ? (
              <>
                <Field
                  label="Previous from"
                  type="datetime-local"
                  value={localTime(comparison.from)}
                  onChange={(event) =>
                    setComparison({
                      ...comparison,
                      from: absoluteTime(event.target.value),
                    })
                  }
                />
                <Field
                  label="Previous to"
                  type="datetime-local"
                  value={localTime(comparison.to)}
                  onChange={(event) =>
                    setComparison({
                      ...comparison,
                      to: absoluteTime(event.target.value),
                    })
                  }
                />
              </>
            ) : null}
            <div className={styles.preview} aria-label="Readable query preview">
              <span>{comparison ? 'Current query preview' : 'Query preview'}</span>
              <code>{preview(query)}</code>
              {comparison ? (
                <>
                  <span>Previous query preview</span>
                  <code>{preview({ ...query, from: comparison.from, to: comparison.to })}</code>
                </>
              ) : null}
            </div>
            <div className={styles.actions}>
              <Button
                type="submit"
                variant="primary"
                disabled={run.isPending || comparisonRun.isPending}
              >
                {comparisonRun.isPending
                  ? 'Comparing…'
                  : run.isPending
                    ? 'Running…'
                    : comparison
                      ? 'Compare periods'
                      : 'Run query'}
              </Button>
              <Link to={link}>Stable view link</Link>
            </div>
          </form>
          <div className={styles.saved}>
            <SavedViews
              surface="explorer"
              filters={savedState(query, comparison)}
              onApply={applySaved}
              placeholder="Explorer view"
            />
          </div>
        </CardBody>
      </Card>

      {run.isError || comparisonRun.isError ? (
        <ErrorState
          description={
            comparison
              ? 'The comparison failed inside the authorized tenant scope. Check both absolute windows and source availability.'
              : 'The query failed inside the authorized tenant scope.'
          }
        />
      ) : null}
      {comparisonRun.data ? (
        <Card>
          <CardHeader
            title="Period comparison"
            actions={
              <div className={styles.actions}>
                <Badge tone="neutral">{comparisonRun.data.state.replace('_', ' ')}</Badge>
                <Badge tone="neutral">{comparisonRun.data.contract_version}</Badge>
                {evidenceLink ? <Link to={evidenceLink}>Open evidence</Link> : null}
              </div>
            }
          />
          <CardBody>
            <div className={styles.comparisonReceipts}>
              <p className={styles.receipt}>
                <strong>Current</strong> <code>{comparisonRun.data.current_preview}</code>
              </p>
              <p className={styles.receipt}>
                <strong>Previous</strong> <code>{comparisonRun.data.previous_preview}</code>
              </p>
            </div>
            <ComparisonExecutionReceipt receipt={comparisonRun.data.execution} />
            {comparisonRun.data.rows.length ? (
              <ChartShell
                title="Current versus previous"
                legend={<span>Exact aligned values; aggregation is declared per row</span>}
              >
                <ComparisonBars rows={comparisonRun.data.rows} />
              </ChartShell>
            ) : null}
            <Table
              caption="Explorer period comparison results"
              columns={comparisonColumns}
              rows={comparisonRun.data.rows}
              rowKey={(row) => `${JSON.stringify(row.group)}:${row.measure}`}
              empty="Neither authorized window contains comparable numeric evidence."
            />
            {comparisonRun.data.state === 'current_only' ? (
              <p className={styles.note}>
                The previous window has no authorized rows. Previous values and deltas remain
                undefined.
              </p>
            ) : null}
            {comparisonRun.data.state === 'previous_only' ? (
              <p className={styles.note}>
                The current window has no authorized rows. Current values and deltas remain
                undefined.
              </p>
            ) : null}
            {comparisonRun.data.state === 'empty' ? (
              <p className={styles.note}>
                Neither window has authorized rows. Explorer will not turn missing evidence into a
                zero.
              </p>
            ) : null}
            {comparisonRun.data.current_truncated ||
            comparisonRun.data.previous_truncated ||
            comparisonRun.data.rows_truncated ? (
              <p className={styles.note}>
                This comparison is partial because a bounded row limit was reached. Narrow both
                windows or add a filter before interpreting the delta.
              </p>
            ) : null}
          </CardBody>
        </Card>
      ) : null}
      {run.data ? (
        <Card>
          <CardHeader
            title="Exact results"
            actions={
              <div className={styles.actions}>
                <Badge tone="neutral">{run.data.query.visualization}</Badge>
                {evidenceLink ? <Link to={evidenceLink}>Open evidence</Link> : null}
              </div>
            }
          />
          <CardBody>
            <p className={styles.receipt}>
              <code>{run.data.preview}</code>
            </p>
            <ExecutionReceipt receipt={run.data.execution} />
            {run.data.query.visualization !== 'table' ? (
              <ChartShell
                title={`${run.data.query.visualization} visualization`}
                legend={<span>Exact {run.data.query.measures[0] ?? 'row count'} values</span>}
              >
                {(() => {
                  const timed =
                    run.data.query.visualization === 'line' ||
                    run.data.query.visualization === 'timeline'
                      ? timeSeriesFromRows(run.data.rows, run.data.columns, run.data.query.measures)
                      : null
                  return timed ? (
                    <TimeSeries
                      label={`${run.data.query.visualization} visualization of authorized Explorer results`}
                      timestamps={timed.timestamps}
                      series={[
                        { label: run.data.query.measures[0] ?? 'value', values: timed.values },
                      ]}
                    />
                  ) : (
                    <Sparkline
                      data={chartValues(run.data.rows, run.data.query.measures)}
                      label={`${run.data.query.visualization} visualization of authorized Explorer results`}
                    />
                  )
                })()}
              </ChartShell>
            ) : null}
            <Table
              caption="Explorer exact-value results"
              columns={columns}
              rows={run.data.rows}
              rowKey={(row) => JSON.stringify(row)}
              empty="No authorized rows matched this query."
            />
            {run.data.truncated ? (
              <p className={styles.note}>
                Results were capped. Narrow the time range or add a filter.
              </p>
            ) : null}
            <ExplainView
              surface="explorer"
              question={query.question}
              subject={query.filters}
              pivotContext={{
                from: query.from,
                to: query.to,
                filters: query.filters,
                returnTo: link,
              }}
            />
          </CardBody>
        </Card>
      ) : null}
    </Page>
  )
}
