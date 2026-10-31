// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { apiDownload } from '../api/client'
import {
  useExplorerSchema,
  useExplorerFlowPage,
  useExplorerFlowComparisonPage,
  useExplorerFlowQuery,
  useExplorerFlowComparison,
  useExplorerFlowPlan,
  type FlowQuestionProposal,
} from '../api/explorer'
import {
  useRunFlowQueryView,
  useSaveFlowQueryView,
  type FlowQueryViewDefinition,
  type SavedFlowQueryView,
} from '../api/flowViews'
import { useFlowFilters } from '../api/flowFilters'
import type { FlowQueryPlan } from '../api/flowExplorer'
import { useAuth } from '../auth/useAuth'
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  LoadingState,
  Select,
} from '../components'
import { FlowPlanBuilder } from './FlowPlanBuilder'
import { FlowVisuals } from './FlowVisuals'
import { FlowDisplaySettings } from './FlowDisplaySettings'
import { FlowExactSummary, FlowResultTable } from './FlowResultTable'
import {
  flowDrilldown,
  isFlowComparison,
  type NativeFlowResult,
  type FlowDrillAction,
} from './flowResults'
import { FlowViewLibrary } from './FlowViewLibrary'
import { FlowFilterLibrary } from './FlowFilterLibrary'
import { Page } from './RoutePage'
import styles from './flowExplorer.module.css'

function initialDefinition(): FlowQueryViewDefinition {
  return {
    name: 'Untitled flow query',
    visibility: 'private',
    time: { mode: 'lookback', lookback_seconds: 3600 },
    plan: {
      group_by: ['src_addr'],
      view: 'table',
      row_limit: 100,
      page_size: 100,
      bucket_seconds: 60,
      series_depth: 40,
      matrix_depth: 15,
      metrics: [{ measure: 'bps', calculation: 'avg', role: 'primary' }],
    },
  }
}

function FlowLabelsField({
  values,
  onChange,
}: {
  values: string[]
  onChange: (values: string[]) => void
}) {
  const [draft, setDraft] = useState('')
  const [editing, setEditing] = useState(false)
  return (
    <Field
      label="Flow query labels (comma separated)"
      value={editing ? draft : values.join(', ')}
      onFocus={() => {
        setDraft(values.join(', '))
        setEditing(true)
      }}
      onBlur={() => setEditing(false)}
      onChange={(event) => {
        const next = event.target.value
        setDraft(next)
        setEditing(true)
        onChange(
          next
            .split(',')
            .map((value) => value.trim())
            .filter(Boolean),
        )
      }}
    />
  )
}

function materialize(definition: FlowQueryViewDefinition, now: number) {
  const plan: FlowQueryPlan = { ...definition.plan }
  if (definition.time?.mode === 'lookback') {
    plan.to = new Date(now).toISOString()
    plan.from = new Date(now - (definition.time.lookback_seconds ?? 3600) * 1000).toISOString()
  }
  if (!plan.from || !plan.to || !(Date.parse(plan.to) > Date.parse(plan.from)))
    throw new Error('Choose valid increasing current-period bounds.')
  let previous: { previous_from: string; previous_to: string } | undefined
  if (definition.comparison?.mode === 'preceding') {
    const from = Date.parse(plan.from)
    previous = {
      previous_from: new Date(from - (Date.parse(plan.to) - from)).toISOString(),
      previous_to: plan.from,
    }
  } else if (definition.comparison) {
    const { from, to } = definition.comparison
    if (!from || !to || !(Date.parse(to) > Date.parse(from)))
      throw new Error('Choose valid increasing previous-period bounds.')
    previous = { previous_from: from, previous_to: to }
  }
  return { query: { source: 'flow', flow: plan }, previous }
}

export function NativeFlowPage() {
  const { tenant, user } = useAuth()
  const [params] = useSearchParams()
  return (
    <FlowWorkspace
      key={`${tenant.id}:${user.id}:${params.get('flow_view') ?? ''}`}
      identity={`${tenant.id}:${user.id}`}
    />
  )
}

function FlowWorkspace({ identity }: { identity: string }) {
  const [params, setParams] = useSearchParams()
  const schema = useExplorerSchema(identity)
  const [definition, setDefinition] = useState(initialDefinition)
  const [saved, setSaved] = useState<SavedFlowQueryView>()
  const [result, setResult] = useState<NativeFlowResult>()
  const [first, setFirst] = useState<NativeFlowResult>()
  const [history, setHistory] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [executed, setExecuted] = useState('')
  const [question, setQuestion] = useState('')
  const [proposal, setProposal] = useState<FlowQuestionProposal>()
  const definitionRef = useRef(definition)
  definitionRef.current = definition
  const lifetime = useRef({ active: true, epoch: 0 })
  const runSaved = useRunFlowQueryView()
  const runNative = useExplorerFlowQuery()
  const planQuestion = useExplorerFlowPlan()
  const compareNative = useExplorerFlowComparison()
  const saveView = useSaveFlowQueryView()
  const page = useExplorerFlowPage()
  const comparisonPage = useExplorerFlowComparisonPage()
  const [filterAfter, setFilterAfter] = useState('')
  const filters = useFlowFilters(filterAfter, identity)
  const { permissions, user } = useAuth()
  const canWrite = permissions.includes('flow.views.write')
  const dirty = JSON.stringify(definition) !== JSON.stringify(saved?.definition)
  const waitingForSaved = Boolean(params.get('flow_view') && params.get('flow_view') !== saved?.id)

  function newQuery() {
    lifetime.current.epoch++
    setBusy(false)
    setSaved(undefined)
    setDefinition(initialDefinition())
    setResult(undefined)
    setFirst(undefined)
    setHistory([])
    setExecuted('')
    setError('')
    setQuestion('')
    setProposal(undefined)
    setParams({ native_flow: '1' }, { replace: true })
  }

  useEffect(() => {
    const guard = lifetime.current
    guard.active = true
    return () => {
      guard.active = false
      guard.epoch++
    }
  }, [])

  const selectSaved = (item: SavedFlowQueryView) => {
    lifetime.current.epoch++
    setBusy(false)
    setSaved(item)
    setDefinition(item.definition)
    setResult(undefined)
    setFirst(undefined)
    setHistory([])
    setExecuted('')
    setError('')
    setQuestion('')
    setProposal(undefined)
    setParams({ native_flow: '1', flow_view: item.id }, { replace: true })
  }

  async function propose() {
    const epoch = ++lifetime.current.epoch
    const original = JSON.stringify(definition)
    setBusy(true)
    setError('')
    setProposal(undefined)
    try {
      const next = (await planQuestion.mutateAsync(question)).proposal
      if (!lifetime.current.active || lifetime.current.epoch !== epoch) return
      if (JSON.stringify(definitionRef.current) !== original) {
        setError('The builder changed while planning. Preview the question again to apply it.')
        return
      }
      setProposal(next)
      if (next.status === 'ready' && next.plan) {
        setDefinition({
          ...definition,
          plan: next.plan,
          time: { mode: 'absolute' },
          comparison: next.comparison,
          display: next.display,
          auto_refresh_seconds: 0,
        })
        setResult(undefined)
        setFirst(undefined)
        setHistory([])
        setExecuted('')
      }
    } catch (cause) {
      if (lifetime.current.active && lifetime.current.epoch === epoch)
        setError(cause instanceof Error ? cause.message : 'Flow question planning failed.')
    } finally {
      if (lifetime.current.active && lifetime.current.epoch === epoch) setBusy(false)
    }
  }

  async function execute() {
    const epoch = ++lifetime.current.epoch
    const serialized = JSON.stringify(definition)
    setBusy(true)
    setError('')
    try {
      let next: NativeFlowResult
      if (saved && !dirty) next = await runSaved.mutateAsync(saved.id)
      else {
        const { query, previous } = materialize(definition, Date.now())
        next = previous
          ? await compareNative.mutateAsync({ flow: query.flow, ...previous })
          : await runNative.mutateAsync(query.flow)
      }
      if (!lifetime.current.active || lifetime.current.epoch !== epoch) return
      setFirst(next)
      setResult(next)
      setHistory([])
      setExecuted(serialized)
    } catch (cause) {
      if (lifetime.current.active && lifetime.current.epoch === epoch)
        setError(cause instanceof Error ? cause.message : 'Flow query failed.')
    } finally {
      if (lifetime.current.active && lifetime.current.epoch === epoch) setBusy(false)
    }
  }

  useEffect(() => {
    const seconds = definition.auto_refresh_seconds ?? 0
    if (!seconds || !result || busy || executed !== JSON.stringify(definition)) return
    const timer = window.setTimeout(() => {
      void execute()
    }, seconds * 1000)
    return () => window.clearTimeout(timer)
    // Execute reads this render's frozen definition; edits stop this timer.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [definition, result, busy, executed])

  async function movePage(direction: 'next' | 'previous') {
    if (!result || !first) return
    const epoch = ++lifetime.current.epoch
    const cursor =
      direction === 'next' ? result.flow_paging?.next_cursor : history[history.length - 2]
    if (direction === 'previous' && history.length === 1) {
      setResult(first)
      setHistory([])
      return
    }
    if (!cursor) return
    setBusy(true)
    setError('')
    try {
      const next = await (isFlowComparison(result)
        ? comparisonPage.mutateAsync(cursor)
        : page.mutateAsync(cursor))
      if (!lifetime.current.active || epoch !== lifetime.current.epoch) return
      setResult(next)
      setHistory(direction === 'next' ? [...history, cursor] : history.slice(0, -1))
    } catch (cause) {
      if (lifetime.current.active && epoch === lifetime.current.epoch)
        setError(cause instanceof Error ? cause.message : 'Snapshot page failed.')
    } finally {
      if (lifetime.current.active && epoch === lifetime.current.epoch) setBusy(false)
    }
  }

  async function save(asNew: boolean) {
    const epoch = ++lifetime.current.epoch
    setBusy(true)
    setError('')
    try {
      const next = await saveView.mutateAsync({
        id: !asNew ? saved?.id : undefined,
        version: !asNew ? saved?.version : undefined,
        definition,
      })
      if (lifetime.current.active && epoch === lifetime.current.epoch) selectSaved(next)
    } catch (cause) {
      if (lifetime.current.active && epoch === lifetime.current.epoch)
        setError(cause instanceof Error ? cause.message : 'Saving failed.')
    } finally {
      if (lifetime.current.active && epoch === lifetime.current.epoch) setBusy(false)
    }
  }

  const plan = definition.plan ?? {}
  const primary = result && (isFlowComparison(result) ? result.flow?.current : result.flow)
  const previous = result && isFlowComparison(result) ? result.flow?.previous : undefined
  const patchPlan = (patch: Partial<FlowQueryPlan>) => {
    const next = { ...plan, ...patch }
    const known = (next.metrics ?? [])
      .filter((metric) => metric.role !== 'additional')
      .map((metric) => `${metric.measure}:${metric.calculation}`)
    setDefinition({
      ...definition,
      plan: next,
      display: definition.display
        ? {
            ...definition.display,
            log_metrics: (definition.display.log_metrics ?? []).filter((key) =>
              known.includes(key),
            ),
          }
        : undefined,
    })
  }
  const drill: FlowDrillAction = (group, mode) => {
    if (!schema.data?.flow) return
    try {
      patchPlan({
        filter: flowDrilldown(
          plan.filter,
          group,
          schema.data.flow.limits.max_filter_depth,
          schema.data.flow.limits.max_group_entries,
          mode,
        ),
      })
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Drilldown refused.')
    }
  }

  return (
    <Page
      title="Flow explorer"
      subtitle="Build, save and compare tenant-scoped flow queries. Exact values remain available in every result."
      actions={
        <Link className={styles.link} to="/explore">
          All-plane Explorer
        </Link>
      }
    >
      <div className={styles.stack}>
        <FlowViewLibrary
          identity={identity}
          selectedID={params.get('flow_view') ?? undefined}
          onSelect={selectSaved}
        />
        <Card>
          <CardHeader
            title="Native flow query"
            description={
              saved
                ? `Saved revision ${saved.version}${dirty ? ' · unsaved changes' : ''}`
                : 'Unsaved query'
            }
          />
          <CardBody className={styles.stack}>
            {error && <ErrorState title="Flow request failed" description={error} />}
            <Field
              label="Ask a flow question"
              value={question}
              disabled={busy}
              onChange={(event) => setQuestion(event.target.value)}
            />
            <div className={styles.actions}>
              <Button
                disabled={busy || !question.trim() || waitingForSaved}
                onClick={() => {
                  void propose()
                }}
              >
                Preview query plan
              </Button>
            </div>
            <p>
              Questions are stateless. Preview updates the builder; review it and run the query to
              read telemetry.
            </p>
            {proposal && (
              <div role="status" className={styles.stack}>
                <p>
                  {proposal.status === 'ready'
                    ? 'Proposed plan ready for review. Run flow query to execute.'
                    : proposal.status === 'clarify'
                      ? 'Clarification needed.'
                      : 'Question refused.'}
                </p>
                {proposal.guidance && <p>{proposal.guidance}</p>}
                {proposal.assumptions?.map((assumption, index) => (
                  <p key={index}>{assumption}</p>
                ))}
                {proposal.needs_confirmation && (
                  <p>Review the proposed bounds, filters and comparison before running.</p>
                )}
              </div>
            )}
            <div className={styles.grid}>
              <Field
                label="Flow query name"
                value={definition.name}
                onChange={(event) => setDefinition({ ...definition, name: event.target.value })}
              />
              <Field
                label="Flow query description"
                value={definition.description ?? ''}
                onChange={(event) =>
                  setDefinition({ ...definition, description: event.target.value })
                }
              />
              <FlowLabelsField
                values={definition.labels ?? []}
                onChange={(labels) => setDefinition({ ...definition, labels })}
              />
              <Select
                label="Flow query visibility"
                value={definition.visibility ?? 'private'}
                options={[
                  { value: 'private', label: 'Private to me' },
                  { value: 'tenant', label: 'Shared with tenant' },
                ]}
                onChange={(event) =>
                  setDefinition({
                    ...definition,
                    visibility: event.target.value as 'private' | 'tenant',
                  })
                }
              />
              <Select
                label="Current time range"
                value={definition.time?.mode ?? 'absolute'}
                options={[
                  { value: 'lookback', label: 'Relative lookback' },
                  { value: 'absolute', label: 'Absolute bounds' },
                ]}
                onChange={(event) => {
                  const mode = event.target.value as 'lookback' | 'absolute'
                  const now = Date.now()
                  setDefinition({
                    ...definition,
                    time: { mode, lookback_seconds: definition.time?.lookback_seconds ?? 3600 },
                    plan:
                      mode === 'lookback'
                        ? { ...plan, from: undefined, to: undefined }
                        : {
                            ...plan,
                            from: new Date(now - 3600000).toISOString(),
                            to: new Date(now).toISOString(),
                          },
                  })
                }}
              />
              {definition.time?.mode === 'lookback' ? (
                <Field
                  label="Lookback seconds"
                  type="number"
                  min={1}
                  value={definition.time.lookback_seconds ?? 3600}
                  onChange={(event) =>
                    setDefinition({
                      ...definition,
                      time: { mode: 'lookback', lookback_seconds: Number(event.target.value) },
                    })
                  }
                />
              ) : (
                <>
                  <Field
                    label="Current from (RFC3339)"
                    value={plan.from ?? ''}
                    onChange={(event) => patchPlan({ from: event.target.value })}
                  />
                  <Field
                    label="Current to (RFC3339)"
                    value={plan.to ?? ''}
                    onChange={(event) => patchPlan({ to: event.target.value })}
                  />
                </>
              )}
              <Select
                label="Compare with"
                value={definition.comparison?.mode ?? 'none'}
                options={[
                  { value: 'none', label: 'No comparison' },
                  { value: 'preceding', label: 'Preceding period' },
                  { value: 'absolute', label: 'Any previous period' },
                ]}
                onChange={(event) =>
                  setDefinition({
                    ...definition,
                    comparison:
                      event.target.value === 'none'
                        ? undefined
                        : { mode: event.target.value as 'absolute' | 'preceding' },
                  })
                }
              />
              {definition.comparison?.mode === 'absolute' && (
                <>
                  <Field
                    label="Previous from (RFC3339)"
                    value={definition.comparison.from ?? ''}
                    onChange={(event) =>
                      setDefinition({
                        ...definition,
                        comparison: { ...definition.comparison!, from: event.target.value },
                      })
                    }
                  />
                  <Field
                    label="Previous to (RFC3339)"
                    value={definition.comparison.to ?? ''}
                    onChange={(event) =>
                      setDefinition({
                        ...definition,
                        comparison: { ...definition.comparison!, to: event.target.value },
                      })
                    }
                  />
                </>
              )}
              <Select
                label="Auto refresh"
                value={String(definition.auto_refresh_seconds ?? 0)}
                options={[
                  { value: '0', label: 'Off' },
                  ...[60, 90, 120].map((value) => ({
                    value: String(value),
                    label: `${value} seconds`,
                  })),
                ]}
                onChange={(event) =>
                  setDefinition({
                    ...definition,
                    auto_refresh_seconds: Number(event.target.value) as 0 | 60 | 90 | 120,
                  })
                }
              />
            </div>
            {schema.isPending ? (
              <LoadingState label="Loading flow grammar" />
            ) : schema.isError ? (
              <ErrorState title="Flow grammar unavailable" description={schema.error.message} />
            ) : schema.data.flow ? (
              <FlowPlanBuilder
                schema={schema.data.flow}
                plan={plan}
                filters={filters.data?.items ?? []}
                onChange={patchPlan}
              />
            ) : (
              <ErrorState
                title="Native flow grammar unavailable"
                description="The authenticated server did not publish a flow query registry."
              />
            )}
            {filters.isError && (
              <ErrorState
                title="Reusable filters unavailable"
                description={filters.error.message}
              />
            )}
            <FlowDisplaySettings
              plan={plan}
              display={definition.display}
              onChange={(display) => setDefinition({ ...definition, display })}
            />
            <div className={styles.actions}>
              <Button
                disabled={busy || waitingForSaved || !schema.data?.flow}
                onClick={() => {
                  void execute()
                }}
              >
                Run flow query
              </Button>
              {canWrite && (
                <>
                  <Button
                    disabled={busy || !saved || saved.owner_id !== user.id}
                    onClick={() => {
                      void save(false)
                    }}
                  >
                    Save changes
                  </Button>
                  <Button
                    disabled={busy || waitingForSaved}
                    onClick={() => {
                      void save(true)
                    }}
                  >
                    Save as new query
                  </Button>
                </>
              )}
              <Button disabled={!saved || busy} onClick={() => saved && selectSaved(saved)}>
                Revert to saved query
              </Button>
              <Button onClick={newQuery}>New unsaved query</Button>
            </div>
            {busy && <p role="status">Flow request running…</p>}
          </CardBody>
        </Card>
        <FlowFilterLibrary
          identity={identity}
          page={filters}
          after={filterAfter}
          setAfter={setFilterAfter}
          expression={plan.filter ?? {}}
          onApply={(filter) => patchPlan({ filter })}
        />
        {result && primary && (
          <Card>
            <CardHeader
              title="Frozen flow results"
              description={`Source ${primary.source}; resolution ${primary.resolution_seconds}s; ${primary.total_groups} matching groups${primary.detail_limited ? '; detail selection limited by this query' : ''}.`}
            />
            <CardBody className={styles.stack}>
              <p>
                Current period: {primary.query.from} – {primary.query.to}
                {previous ? `; previous: ${previous.query.from} – ${previous.query.to}` : ''}.
              </p>
              {primary.coverage && (
                <p>
                  Retained coverage: {primary.coverage.resolution_seconds}s;{' '}
                  {primary.coverage.complete_inputs
                    ? 'complete input fields'
                    : 'legacy field coverage'}
                  .
                </p>
              )}
              <FlowVisuals
                current={primary}
                previous={previous}
                onDrill={drill}
                display={definition.display}
              />
              <FlowResultTable
                key={`${result.flow_paging?.snapshot_id}:${result.flow_paging?.offset}`}
                result={result}
                onDrill={drill}
              />
              <div className={styles.actions}>
                <Button
                  disabled={busy || !history.length}
                  onClick={() => {
                    void movePage('previous')
                  }}
                >
                  Previous snapshot page
                </Button>
                <span role="status">
                  Selected {result.flow_paging?.selected_rows ?? primary.rows.length} groups; page
                  offset {result.flow_paging?.offset ?? 0}
                </span>
                <Button
                  disabled={busy || !result.flow_paging?.more}
                  onClick={() => {
                    void movePage('next')
                  }}
                >
                  Next snapshot page
                </Button>
                <Button
                  disabled={!result.flow_paging}
                  onClick={() => {
                    try {
                      apiDownload(
                        `/explorer/flow-snapshots/${encodeURIComponent(result.flow_paging!.snapshot_id)}/csv`,
                      )
                    } catch (cause) {
                      setError(cause instanceof Error ? cause.message : 'Download refused.')
                    }
                  }}
                >
                  Download all selected rows as CSV
                </Button>
              </div>
              {result.flow_paging && (
                <p>
                  Snapshot expires {result.flow_paging.expires_at}. CSV includes all selected rows,
                  global Other and totals.
                </p>
              )}
              <FlowExactSummary
                title="Current global totals"
                row={{ group: {}, other: false, metrics: primary.totals }}
              />
              <FlowExactSummary title="Current detail Other" row={primary.other} />
              {previous && (
                <>
                  <FlowExactSummary
                    title="Previous global totals"
                    row={{ group: {}, other: false, metrics: previous.totals }}
                  />
                  <FlowExactSummary title="Previous detail Other" row={previous.other} />
                </>
              )}
            </CardBody>
          </Card>
        )}
      </div>
    </Page>
  )
}
