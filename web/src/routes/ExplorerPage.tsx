// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useEffect, useMemo, useState } from 'react'
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
  useExplorerQuery,
  useExplorerSchema,
  type ExplorerQuery,
  type ExplorerSource,
  type ExplorerTemplate,
  type ExplorerVisualization,
} from '../api/explorer'
import { Page } from './RoutePage'
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

function stableHref(query: ExplorerQuery) {
  const params = new URLSearchParams()
  if (query.template) params.set('template', query.template)
  params.set('from', query.from)
  params.set('to', query.to)
  for (const [key, value] of Object.entries(query.filters))
    params.append('filter', `${key}:${value}`)
  return `/explore?${params.toString()}`
}

function savedState(query: ExplorerQuery) {
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

export function ExplorerPage() {
  const [params] = useSearchParams()
  const schema = useExplorerSchema()
  const run = useExplorerQuery()
  const [query, setQuery] = useState<ExplorerQuery | null>(null)
  const [filterKey, setFilterKey] = useState('')

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
    setFilterKey(Object.keys(next.filters)[0] ?? next.dimensions[0] ?? '')
    setQuery(next)
  }, [params, query, schema.data])

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
    setQuery({
      ...base,
      from: filters.from ? absoluteTime(filters.from) : base.from,
      to: filters.to ? absoluteTime(filters.to) : base.to,
      filters: key && filters.filter_value ? { [key]: filters.filter_value } : {},
    })
  }
  const link = stableHref(query)
  const evidenceLink = run.data
    ? pivotHref(run.data.evidence_path, {
        from: query.from,
        to: query.to,
        filters: query.filters,
        returnTo: link,
      })
    : undefined
  const suggestionValues = run.data?.suggestions[filterKey] ?? []

  return (
    <Page
      title="Explorer"
      subtitle="Ask a question, see the exact query grammar, and keep every result tenant-scoped."
    >
      <Card>
        <CardHeader title="Canonical questions" />
        <CardBody>
          <div className={styles.recipes} aria-label="Canonical Explorer questions">
            {schema.data.templates.map((template) => (
              <Button
                key={template.id}
                variant={query.template === template.id ? 'primary' : 'secondary'}
                onClick={() => applyTemplate(template)}
              >
                {template.question}
              </Button>
            ))}
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Query builder" />
        <CardBody>
          <form
            className={styles.builder}
            onSubmit={(event) => {
              event.preventDefault()
              run.mutate(query)
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
              onChange={(event) =>
                updateStructure({ source: event.target.value as ExplorerSource })
              }
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
            <div className={styles.preview} aria-label="Readable query preview">
              <span>Query preview</span>
              <code>{preview(query)}</code>
            </div>
            <div className={styles.actions}>
              <Button type="submit" variant="primary" disabled={run.isPending}>
                {run.isPending ? 'Running…' : 'Run query'}
              </Button>
              <Link to={link}>Stable view link</Link>
            </div>
          </form>
          <div className={styles.saved}>
            <SavedViews
              surface="explorer"
              filters={savedState(query)}
              onApply={applySaved}
              placeholder="Explorer view"
            />
          </div>
        </CardBody>
      </Card>

      {run.isError ? (
        <ErrorState description="The query failed inside the authorized tenant scope." />
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
            {run.data.query.visualization !== 'table' ? (
              <ChartShell
                title={`${run.data.query.visualization} visualization`}
                legend={<span>Exact {run.data.query.measures[0] ?? 'row count'} values</span>}
              >
                <Sparkline
                  data={chartValues(run.data.rows, run.data.query.measures)}
                  label={`${run.data.query.visualization} visualization of authorized Explorer results`}
                />
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
