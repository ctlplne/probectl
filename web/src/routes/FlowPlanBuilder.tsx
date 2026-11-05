// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { Button, Field, Select } from '../components'
import type {
  FlowExplorerSchema,
  FlowQueryFilterGroup,
  FlowQueryMetric,
  FlowQueryPlan,
  FlowQueryPredicate,
  FlowQueryField,
} from '../api/flowExplorer'
import styles from './flowExplorer.module.css'

export interface ReusableFlowFilter {
  id: string
  name: string
}

function replace<T>(items: T[], index: number, value: T) {
  return items.map((item, i) => (i === index ? value : item))
}

function DimensionPicker({
  title,
  values,
  schema,
  onChange,
}: {
  title: string
  values: string[]
  schema: FlowExplorerSchema
  onChange: (values: string[]) => void
}) {
  const available = schema.fields.filter((field) => !values.includes(field.name))
  return (
    <fieldset className={styles.group}>
      <legend>
        {title} ({values.length}/8)
      </legend>
      {values.map((value, index) => (
        <div className={styles.row} key={index}>
          <Select
            label={`${title} dimension ${index + 1}`}
            value={value}
            options={schema.fields
              .filter((field) => field.name === value || !values.includes(field.name))
              .map((field) => ({ value: field.name, label: field.name.replace(/_/g, ' ') }))}
            onChange={(event) => onChange(replace(values, index, event.target.value))}
          />
          <Button
            disabled={index === 0}
            onClick={() => {
              const next = [...values]
              ;[next[index - 1], next[index]] = [next[index], next[index - 1]]
              onChange(next)
            }}
            aria-label={`Move ${title} dimension ${index + 1} up`}
          >
            Up
          </Button>
          <Button
            onClick={() => onChange(values.filter((_, i) => i !== index))}
            aria-label={`Remove ${title} dimension ${index + 1}`}
          >
            Remove
          </Button>
        </div>
      ))}
      <Button
        disabled={values.length >= 8 || !available.length}
        onClick={() => onChange([...values, available[0].name])}
      >
        Add {title.toLowerCase()} dimension
      </Button>
    </fieldset>
  )
}

const twoValues = new Set(['between', 'not_between'])
const manyValues = new Set(['in', 'not_in', 'cidr', 'not_cidr', 'has_any', 'has_none'])

export function FlowFilterGroupEditor({
  value,
  schema,
  filters,
  onChange,
  depth = 1,
  path = '1',
  onRemove,
  allowSaved = true,
}: {
  value: FlowQueryFilterGroup
  schema: {
    fields: Pick<FlowQueryField, 'name' | 'type' | 'operators'>[]
    limits: Record<string, number>
  }
  filters: ReusableFlowFilter[]
  onChange: (value: FlowQueryFilterGroup) => void
  depth?: number
  path?: string
  onRemove?: () => void
  allowSaved?: boolean
}) {
  const [entryPage, setEntryPage] = useState(0)
  const conditionCount = value.conditions?.length ?? 0
  const savedCount = value.saved?.length ?? 0
  const entries =
    (value.conditions?.length ?? 0) + (value.groups?.length ?? 0) + (value.saved?.length ?? 0)
  const canAdd = entries < schema.limits.max_group_entries
  const pageSize = 25
  const start = Math.min(
    entryPage * pageSize,
    Math.max(0, Math.ceil(entries / pageSize) - 1) * pageSize,
  )
  const visible = (index: number) => index >= start && index < start + pageSize
  const setCondition = (index: number, condition: FlowQueryPredicate) =>
    onChange({ ...value, conditions: replace(value.conditions ?? [], index, condition) })
  return (
    <fieldset className={styles.group}>
      <legend>Filter group {path}</legend>
      <div className={styles.row}>
        <Select
          label={`Group ${path} inclusion`}
          value={value.mode ?? 'include'}
          options={[
            { value: 'include', label: 'Include matches' },
            { value: 'exclude', label: 'Exclude matches' },
          ]}
          onChange={(event) =>
            onChange({ ...value, mode: event.target.value as 'include' | 'exclude' })
          }
        />
        <Select
          label={`Group ${path} match`}
          value={
            value.match === 'or' ? 'any' : value.match === 'and' ? 'all' : (value.match ?? 'all')
          }
          options={[
            { value: 'all', label: 'All conditions (AND)' },
            { value: 'any', label: 'Any condition (OR)' },
          ]}
          onChange={(event) => onChange({ ...value, match: event.target.value as 'all' | 'any' })}
        />
        {onRemove && <Button onClick={onRemove}>Remove group {path}</Button>}
      </div>
      {(value.conditions ?? []).map((condition, index) => {
        if (!visible(index)) return null
        const field = schema.fields.find((field) => field.name === condition.field)
        const values = condition.values.length ? condition.values : ['']
        return (
          <fieldset className={styles.condition} key={index}>
            <legend>
              Condition {path}.{index + 1}
            </legend>
            <div className={styles.row}>
              <Select
                label={`Condition ${path}.${index + 1} field`}
                value={condition.field}
                options={schema.fields.map((field) => ({
                  value: field.name,
                  label: field.name.replace(/_/g, ' '),
                }))}
                onChange={(event) => {
                  const next = schema.fields.find((field) => field.name === event.target.value)!
                  setCondition(index, { field: next.name, op: next.operators[0], values: [''] })
                }}
              />
              <Select
                label={`Condition ${path}.${index + 1} operator`}
                value={condition.op}
                options={(field?.operators ?? []).map((op) => ({
                  value: op,
                  label: op.replace(/_/g, ' '),
                }))}
                onChange={(event) => {
                  const op = event.target.value
                  const count = twoValues.has(op) ? 2 : manyValues.has(op) ? values.length : 1
                  setCondition(index, {
                    ...condition,
                    op,
                    values: Array.from({ length: count }, (_, i) => values[i] ?? ''),
                  })
                }}
              />
              <Button
                onClick={() =>
                  onChange({
                    ...value,
                    conditions: value.conditions?.filter((_, i) => i !== index),
                  })
                }
                aria-label={`Remove condition ${path}.${index + 1}`}
              >
                Remove condition
              </Button>
            </div>
            <div className={styles.row}>
              {values.map((operand, i) => (
                <div className={styles.operand} key={i}>
                  <Field
                    label={`Condition ${path}.${index + 1} value ${i + 1}`}
                    value={operand}
                    maxLength={
                      condition.op.includes('regex')
                        ? schema.limits.max_regex_bytes
                        : schema.limits.max_value_bytes
                    }
                    onChange={(event) =>
                      setCondition(index, {
                        ...condition,
                        values: replace(values, i, event.target.value),
                      })
                    }
                    hint={
                      i === 0
                        ? `${field?.type ?? 'text'}; a blank value selects unassigned data where supported. Values stay exact text.`
                        : undefined
                    }
                  />
                  {manyValues.has(condition.op) && values.length > 1 && (
                    <Button
                      onClick={() =>
                        setCondition(index, {
                          ...condition,
                          values: values.filter((_, j) => j !== i),
                        })
                      }
                      aria-label={`Remove condition ${path}.${index + 1} value ${i + 1}`}
                    >
                      Remove value
                    </Button>
                  )}
                </div>
              ))}
              {manyValues.has(condition.op) && (
                <Button
                  disabled={values.length >= schema.limits.max_values_per_predicate}
                  onClick={() => setCondition(index, { ...condition, values: [...values, ''] })}
                >
                  Add value to condition {path}.{index + 1}
                </Button>
              )}
            </div>
          </fieldset>
        )
      })}
      {(value.saved ?? []).map(
        (reference, index) =>
          visible(conditionCount + index) && (
            <div className={styles.row} key={index}>
              <Select
                label={`Group ${path} saved filter ${index + 1}`}
                value={reference.id}
                options={[
                  ...filters,
                  ...(!filters.some((filter) => filter.id === reference.id)
                    ? [{ id: reference.id, name: reference.id }]
                    : []),
                ].map((filter) => ({ value: filter.id, label: filter.name }))}
                onChange={(event) =>
                  onChange({
                    ...value,
                    saved: replace(value.saved ?? [], index, {
                      ...reference,
                      id: event.target.value,
                    }),
                  })
                }
              />
              <Select
                label={`Group ${path} saved filter ${index + 1} inclusion`}
                value={reference.mode ?? 'include'}
                options={[
                  { value: 'include', label: 'Include saved matches' },
                  { value: 'exclude', label: 'Exclude saved matches' },
                ]}
                onChange={(event) =>
                  onChange({
                    ...value,
                    saved: replace(value.saved ?? [], index, {
                      ...reference,
                      mode: event.target.value as 'include' | 'exclude',
                    }),
                  })
                }
              />
              <Button
                onClick={() =>
                  onChange({ ...value, saved: value.saved?.filter((_, i) => i !== index) })
                }
              >
                Remove saved filter {path}.{index + 1}
              </Button>
            </div>
          ),
      )}
      {(value.groups ?? []).map(
        (group, index) =>
          visible(conditionCount + savedCount + index) && (
            <FlowFilterGroupEditor
              key={index}
              value={group}
              schema={schema}
              filters={filters}
              allowSaved={allowSaved}
              depth={depth + 1}
              path={`${path}.${index + 1}`}
              onChange={(group) =>
                onChange({ ...value, groups: replace(value.groups ?? [], index, group) })
              }
              onRemove={() =>
                onChange({ ...value, groups: value.groups?.filter((_, i) => i !== index) })
              }
            />
          ),
      )}
      {entries > pageSize && (
        <div className={styles.actions} aria-label={`Group ${path} entry navigation`}>
          <Button
            disabled={start === 0}
            onClick={() => setEntryPage(Math.max(0, Math.floor(start / pageSize) - 1))}
          >
            Previous entries in group {path}
          </Button>
          <span role="status">
            Entries {start + 1}–{Math.min(start + pageSize, entries)} of {entries} in group {path}
          </span>
          <Button
            disabled={start + pageSize >= entries}
            onClick={() => setEntryPage(Math.floor(start / pageSize) + 1)}
          >
            Next entries in group {path}
          </Button>
        </div>
      )}
      <div className={styles.actions}>
        <Button
          disabled={!canAdd || schema.fields.length === 0}
          onClick={() => {
            if (schema.fields.length === 0) return
            setEntryPage(Math.floor(conditionCount / pageSize))
            onChange({
              ...value,
              conditions: [
                ...(value.conditions ?? []),
                { field: schema.fields[0].name, op: schema.fields[0].operators[0], values: [''] },
              ],
            })
          }}
        >
          Add condition to group {path}
        </Button>
        <Button
          disabled={!canAdd || depth >= schema.limits.max_filter_depth}
          onClick={() => {
            setEntryPage(Math.floor(entries / pageSize))
            onChange({
              ...value,
              groups: [...(value.groups ?? []), { match: 'all', mode: 'include' }],
            })
          }}
        >
          Add nested group to {path}
        </Button>
        {allowSaved ? (
          <Button
            disabled={!canAdd || !filters.length}
            onClick={() => {
              setEntryPage(Math.floor((conditionCount + savedCount) / pageSize))
              onChange({
                ...value,
                saved: [...(value.saved ?? []), { id: filters[0].id, mode: 'include' }],
              })
            }}
          >
            Add saved filter to group {path}
          </Button>
        ) : null}
      </div>
    </fieldset>
  )
}

function MetricPicker({
  plan,
  schema,
  onChange,
}: {
  plan: FlowQueryPlan
  schema: FlowExplorerSchema
  onChange: (patch: Partial<FlowQueryPlan>) => void
}) {
  const metrics = plan.metrics ?? [{ measure: 'bps', calculation: 'avg', role: 'primary' }]
  const change = (index: number, metric: FlowQueryMetric) => {
    const next = replace(metrics, index, metric).map((item, i) =>
      metric.role === 'primary' && i !== index && item.role === 'primary'
        ? { ...item, role: 'additional' as const }
        : item,
    )
    onChange({ metrics: next })
  }
  const candidates = schema.metrics
    .flatMap((definition) =>
      definition.calculations.map((calculation) => ({ measure: definition.name, calculation })),
    )
    .filter(
      (candidate) =>
        !metrics.some(
          (metric) =>
            metric.measure === candidate.measure && metric.calculation === candidate.calculation,
        ),
    )
  return (
    <fieldset className={styles.group}>
      <legend>Metrics and calculations</legend>
      {metrics.map((metric, index) => {
        const definition = schema.metrics.find((definition) => definition.name === metric.measure)
        return (
          <div className={styles.row} key={index}>
            <Select
              label={`Metric ${index + 1}`}
              value={metric.measure}
              options={schema.metrics.map((definition) => ({
                value: definition.name,
                label: `${definition.name} (${definition.unit})`,
              }))}
              onChange={(event) => {
                const definition = schema.metrics.find((item) => item.name === event.target.value)!
                change(index, {
                  ...metric,
                  measure: definition.name,
                  calculation: definition.calculations.includes(metric.calculation)
                    ? metric.calculation
                    : definition.calculations[0],
                })
              }}
            />
            <Select
              label={`Metric ${index + 1} calculation`}
              value={metric.calculation}
              options={(definition?.calculations ?? []).map((calculation) => ({
                value: calculation,
                label: `${calculation} (${definition?.calculation_units[calculation] ?? ''})`,
              }))}
              onChange={(event) =>
                change(index, {
                  ...metric,
                  calculation: event.target.value as FlowQueryMetric['calculation'],
                })
              }
            />
            <Select
              label={`Metric ${index + 1} role`}
              value={metric.role}
              options={['primary', 'secondary', 'additional']
                .filter(
                  (role) =>
                    role !== 'secondary' ||
                    metric.role === 'secondary' ||
                    metrics.filter((metric) => metric.role === 'secondary').length < 3,
                )
                .map((role) => ({
                  value: role,
                  label: role === 'additional' ? 'Table only' : role,
                }))}
              onChange={(event) =>
                change(index, { ...metric, role: event.target.value as FlowQueryMetric['role'] })
              }
            />
            <Button
              disabled={metrics.length === 1}
              onClick={() => {
                const next = metrics.filter((_, i) => i !== index)
                if (metric.role === 'primary') next[0] = { ...next[0], role: 'primary' }
                onChange({ metrics: next })
              }}
              aria-label={`Remove metric ${index + 1}`}
            >
              Remove metric
            </Button>
          </div>
        )
      })}
      <Button
        disabled={!candidates.length}
        onClick={() =>
          onChange({ metrics: [...metrics, { ...candidates[0], role: 'additional' }] })
        }
      >
        Add metric
      </Button>
    </fieldset>
  )
}

export function FlowPlanBuilder({
  plan,
  schema,
  filters,
  onChange,
}: {
  plan: FlowQueryPlan
  schema: FlowExplorerSchema
  filters: ReusableFlowFilter[]
  onChange: (patch: Partial<FlowQueryPlan>) => void
}) {
  return (
    <div className={styles.stack}>
      <DimensionPicker
        title="Group by"
        values={plan.group_by ?? []}
        schema={schema}
        onChange={(group_by) => onChange({ group_by })}
      />
      <div className={styles.grid}>
        <Select
          label="Flow visualization"
          value={plan.view ?? 'table'}
          options={['table', 'line', 'bar', 'timeline', 'matrix'].map((value) => ({
            value,
            label: value,
          }))}
          onChange={(event) => {
            const view = event.target.value as FlowQueryPlan['view']
            const row_limit = Math.min(
              plan.row_limit ?? 100,
              view === 'table' ? schema.limits.max_table_rows : schema.limits.max_chart_rows,
            )
            onChange({
              view,
              row_limit,
              page_size: Math.min(plan.page_size ?? 100, row_limit),
              matrix_with:
                view === 'matrix'
                  ? plan.matrix_with?.length
                    ? plan.matrix_with
                    : ['dst_addr']
                  : [],
              group_by: view === 'matrix' && !plan.group_by?.length ? ['src_addr'] : plan.group_by,
            })
          }}
        />
        <Select
          label="Flow data source"
          value={plan.dataseries ?? 'auto'}
          options={[
            { value: 'auto', label: 'Automatic coverage' },
            { value: 'raw', label: 'Raw inputs' },
            { value: 'rollup', label: 'Retained inputs' },
          ]}
          onChange={(event) =>
            onChange({ dataseries: event.target.value as FlowQueryPlan['dataseries'] })
          }
        />
        <Field
          label="Bucket width (seconds)"
          type="number"
          min={schema.limits.min_bucket_seconds}
          max={schema.limits.max_bucket_seconds}
          value={plan.bucket_seconds ?? 60}
          onChange={(event) => onChange({ bucket_seconds: Number(event.target.value) })}
        />
        <Field
          label="Selected detail groups"
          type="number"
          min={1}
          max={plan.view === 'table' ? schema.limits.max_table_rows : schema.limits.max_chart_rows}
          value={plan.row_limit ?? 100}
          onChange={(event) => {
            const row_limit = Number(event.target.value)
            onChange({ row_limit, page_size: Math.min(plan.page_size ?? 100, row_limit) })
          }}
        />
        <Field
          label="Groups per server page"
          type="number"
          min={1}
          max={Math.min(plan.row_limit ?? 100, schema.limits.max_page_rows)}
          value={plan.page_size ?? 100}
          onChange={(event) => onChange({ page_size: Number(event.target.value) })}
        />
        <Field
          label="Plotted group series"
          type="number"
          min={1}
          max={schema.limits.max_chart_series}
          value={plan.series_depth ?? 40}
          onChange={(event) => onChange({ series_depth: Number(event.target.value) })}
        />
        <Field
          label="IPv4 prefix length"
          type="number"
          min={0}
          max={32}
          value={plan.ipv4_prefix_length ?? 24}
          onChange={(event) => onChange({ ipv4_prefix_length: Number(event.target.value) })}
        />
        <Field
          label="IPv6 prefix length"
          type="number"
          min={0}
          max={128}
          value={plan.ipv6_prefix_length ?? 48}
          onChange={(event) => onChange({ ipv6_prefix_length: Number(event.target.value) })}
        />
      </div>
      <details className={styles.group}>
        <summary>Retained dimension coverage</summary>
        <p>
          Retained input fields:{' '}
          {schema.fields
            .filter((field) => field.rollup_available)
            .map((field) => field.name.replace(/_/g, ' '))
            .join(', ') || 'None'}
          .
        </p>
        <p>
          Older hourly schema fields:{' '}
          {schema.fields
            .filter((field) => field.legacy_hourly_available)
            .map((field) => field.name.replace(/_/g, ' '))
            .join(', ') || 'None'}
          .
        </p>
        <p>
          Raw-only fields:{' '}
          {schema.fields
            .filter((field) => field.raw_available && !field.rollup_available)
            .map((field) => field.name.replace(/_/g, ' '))
            .join(', ') || 'None'}
          .
        </p>
        <p className={styles.hint}>
          Coverage and access for the selected time range are checked when you run the query.
        </p>
      </details>
      {plan.view === 'matrix' && (
        <>
          <DimensionPicker
            title="Matrix with"
            values={plan.matrix_with ?? []}
            schema={schema}
            onChange={(matrix_with) => onChange({ matrix_with })}
          />
          <Field
            label="Matrix values per axis"
            type="number"
            min={1}
            max={schema.limits.max_matrix_depth}
            value={plan.matrix_depth ?? 15}
            onChange={(event) => onChange({ matrix_depth: Number(event.target.value) })}
          />
        </>
      )}
      <MetricPicker plan={plan} schema={schema} onChange={onChange} />
      <FlowFilterGroupEditor
        value={plan.filter ?? { match: 'all', mode: 'include' }}
        schema={schema}
        filters={filters}
        onChange={(filter) => onChange({ filter })}
        onRemove={plan.filter ? () => onChange({ filter: undefined }) : undefined}
      />
      <p className={styles.hint}>
        Filters allow {schema.limits.max_group_entries} entries per group,{' '}
        {schema.limits.max_expanded_conditions} expanded conditions and{' '}
        {schema.limits.max_filter_depth} levels. Source coverage and query budgets are checked by
        the server.
      </p>
    </div>
  )
}
