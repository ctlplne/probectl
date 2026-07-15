// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import styles from './path.module.css'
import { Page } from './RoutePage'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  FirstRunPreview,
  Icon,
  LoadingState,
  Select,
  StatusDot,
  TopologyPreview,
  useToast,
} from '../components'
import { useTests } from '../api/tests'
import { usePath, useDiscoverPath, usePathHistory, type PathSnapshot } from '../api/paths'
import { severityTone, useChanges, useIncidents } from '../api/incidents'
import { PathGraph } from '../viz/PathGraph'
import { LossByHop } from '../viz/LossByHop'
import { NodeDetailModal } from '../viz/NodeDetailModal'
import { PathHopTable } from '../viz/PathHopTable'
import { PathHistoryPanel } from '../viz/PathHistoryPanel'
import { layoutPath, worstPathNode, type VizNode } from '../viz/layout'
import { parsePivotContext, pivotHref, replacePivotContext } from './pivotContext'
import { ExplainView } from './ExplainView'
import { DateTime } from '../time/DateTime'

function Legend() {
  return (
    <div className={styles.legend}>
      <span>
        <i className={styles.ok} /> no loss
      </span>
      <span>
        <i className={styles.warning} /> partial
      </span>
      <span>
        <i className={styles.danger} /> high loss
      </span>
      <span>
        <i className={styles.dest} /> destination
      </span>
    </div>
  )
}

function inTimeWindow(value: string, from?: string, to?: string) {
  const timestamp = Date.parse(value)
  return (
    Number.isFinite(timestamp) &&
    (!from || timestamp >= Date.parse(from)) &&
    (!to || timestamp <= Date.parse(to))
  )
}

function overlapsTimeWindow(start: string, end: string, from?: string, to?: string) {
  const startAt = Date.parse(start)
  const endAt = Date.parse(end)
  return (
    Number.isFinite(startAt) &&
    Number.isFinite(endAt) &&
    (!from || endAt >= Date.parse(from)) &&
    (!to || startAt <= Date.parse(to))
  )
}

export function PathPage() {
  const tests = useTests()
  const [params, setParams] = useSearchParams()
  const parsedPivot = useMemo(() => parsePivotContext(params), [params])
  const pivotContext = parsedPivot.context
  const chosen = pivotContext.filters.path_test ?? ''
  const requestedRoundID = pivotContext.filters.path_round
  const requestedComparisonID = pivotContext.filters.compare_round
  const requestedRoundIDs = useMemo(
    () =>
      Array.from(new Set([requestedRoundID, requestedComparisonID].filter(Boolean))).slice(0, 2),
    [requestedComparisonID, requestedRoundID],
  )
  const { push } = useToast()
  const [copiedLink, setCopiedLink] = useState(false)
  const autoCopyHandled = useRef(false)

  const testId = chosen || tests.data?.[0]?.id
  const test = tests.data?.find((t) => t.id === testId)
  const path = usePath(testId)
  const history = usePathHistory(testId, { from: pivotContext.from, to: pivotContext.to })
  const exactRoundIDs = useMemo(() => {
    if (!history.isSuccess) return []
    const inWindow = new Set((history.data ?? []).map((round) => round.id))
    return requestedRoundIDs.filter((id) => !inWindow.has(id))
  }, [history.data, history.isSuccess, requestedRoundIDs])
  const linkedHistory = usePathHistory(
    testId,
    { roundIds: exactRoundIDs },
    exactRoundIDs.length > 0,
  )
  const discover = useDiscoverPath(testId)
  const rounds = useMemo(() => {
    const byID = new Map<string, PathSnapshot>()
    for (const round of [...(history.data ?? []), ...(linkedHistory.data ?? [])]) {
      byID.set(round.id, round)
    }
    return Array.from(byID.values()).sort(
      (left, right) => Date.parse(right.observed_at) - Date.parse(left.observed_at),
    )
  }, [history.data, linkedHistory.data])
  const selectedRound =
    (requestedRoundID ? rounds.find((round) => round.id === requestedRoundID) : undefined) ??
    rounds[0]
  const comparisonRound = requestedComparisonID
    ? rounds.find((round) => round.id === requestedComparisonID && round.id !== selectedRound?.id)
    : undefined
  const displayedPath = selectedRound?.path ?? path.data
  const pathNodes = useMemo(
    () => (displayedPath ? layoutPath(displayedPath).nodes : []),
    [displayedPath],
  )
  const worst = useMemo(
    () => (displayedPath ? worstPathNode(displayedPath) : undefined),
    [displayedPath],
  )
  const requestedNodeID =
    pivotContext.selection?.kind === 'entity' ? pivotContext.selection.id : undefined
  const selected = requestedNodeID
    ? (pathNodes.find((node) => node.id === requestedNodeID) ?? null)
    : null
  const [nodeDetailOpen, setNodeDetailOpen] = useState(Boolean(requestedNodeID))
  const incidents = useIncidents(Boolean(testId))
  const changes = useChanges(Boolean(testId))

  const sharedPathContext = useMemo(() => {
    const filters = { ...pivotContext.filters }
    delete filters.path_round
    delete filters.compare_round
    if (testId) filters.path_test = testId
    if (selectedRound) filters.path_round = selectedRound.id
    if (comparisonRound) filters.compare_round = comparisonRound.id

    const observed = [selectedRound?.observed_at, comparisonRound?.observed_at]
      .filter((value): value is string => Boolean(value))
      .sort()
    return {
      ...pivotContext,
      filters,
      from: pivotContext.from ?? observed[0],
      to: pivotContext.to ?? observed.at(-1),
      selection: selected ? { kind: 'entity' as const, id: selected.id } : undefined,
      returnTo: '/path',
    }
  }, [comparisonRound, pivotContext, selected, selectedRound, testId])
  const stablePathHref = pivotHref('/path', sharedPathContext)
  const evidenceTarget = displayedPath?.target ?? test?.target
  const clockFrom = sharedPathContext.from
  const clockTo = sharedPathContext.to
  const relatedIncidents = useMemo(
    () =>
      (incidents.data ?? [])
        .filter(
          (incident) =>
            Boolean(evidenceTarget) &&
            (incident.target === evidenceTarget ||
              incident.prefix === evidenceTarget ||
              incident.signals?.some(
                (signal) => signal.target === evidenceTarget || signal.prefix === evidenceTarget,
              )) &&
            overlapsTimeWindow(incident.started_at, incident.last_seen_at, clockFrom, clockTo),
        )
        .slice(0, 5),
    [clockFrom, clockTo, evidenceTarget, incidents.data],
  )
  const relatedChanges = useMemo(
    () =>
      (changes.data ?? [])
        .filter(
          (change) =>
            Boolean(evidenceTarget) &&
            (change.target === evidenceTarget || change.prefix === evidenceTarget) &&
            inTimeWindow(change.occurred_at, clockFrom, clockTo),
        )
        .slice(0, 5),
    [changes.data, clockFrom, clockTo, evidenceTarget],
  )

  useEffect(() => {
    const unknownTest = Boolean(
      tests.data && chosen && !tests.data.some((candidate) => candidate.id === chosen),
    )
    const unknownNode = Boolean(displayedPath && requestedNodeID && !selected)
    if (unknownTest || unknownNode || (parsedPivot.hasContract && !parsedPivot.referencesValid)) {
      const filters = { ...pivotContext.filters }
      if (unknownTest) delete filters.path_test
      setParams(replacePivotContext(params, { ...pivotContext, filters, selection: undefined }), {
        replace: true,
      })
    }
  }, [
    chosen,
    params,
    parsedPivot.hasContract,
    parsedPivot.referencesValid,
    displayedPath,
    pivotContext,
    requestedNodeID,
    selected,
    setParams,
    tests.data,
  ])

  useEffect(() => {
    if (
      requestedRoundIDs.length === 0 ||
      !history.isSuccess ||
      (exactRoundIDs.length > 0 && !linkedHistory.isSuccess)
    )
      return
    const authorized = new Set(rounds.map((round) => round.id))
    const filters = { ...pivotContext.filters }
    let changed = false
    if (requestedRoundID && !authorized.has(requestedRoundID)) {
      delete filters.path_round
      changed = true
    }
    if (requestedComparisonID && !authorized.has(requestedComparisonID)) {
      delete filters.compare_round
      changed = true
    }
    if (changed) {
      setParams(replacePivotContext(params, { ...pivotContext, filters }), { replace: true })
    }
  }, [
    exactRoundIDs.length,
    history.isSuccess,
    linkedHistory.isSuccess,
    params,
    pivotContext,
    requestedComparisonID,
    requestedRoundID,
    requestedRoundIDs.length,
    rounds,
    setParams,
  ])

  useEffect(() => setCopiedLink(false), [stablePathHref])

  function chooseTest(id: string) {
    const filters: Record<string, string> = { ...pivotContext.filters, path_test: id }
    delete filters.path_round
    delete filters.compare_round
    setParams(
      replacePivotContext(params, {
        ...pivotContext,
        filters,
        selection: undefined,
      }),
    )
  }

  function chooseRound(round: PathSnapshot) {
    const filters: Record<string, string> = {
      ...pivotContext.filters,
      path_round: round.id,
    }
    if (testId) filters.path_test = testId
    if (filters.compare_round === round.id) delete filters.compare_round
    setParams(replacePivotContext(params, { ...pivotContext, filters }))
  }

  function chooseComparison(id?: string) {
    const filters = { ...pivotContext.filters }
    if (testId) filters.path_test = testId
    if (selectedRound) filters.path_round = selectedRound.id
    if (id) filters.compare_round = id
    else delete filters.compare_round
    setParams(replacePivotContext(params, { ...pivotContext, filters }))
  }

  function selectNode(node: VizNode) {
    setNodeDetailOpen(true)
    setParams(
      replacePivotContext(params, {
        ...pivotContext,
        selection: { kind: 'entity', id: node.id },
      }),
    )
  }

  function closeNode() {
    setNodeDetailOpen(false)
  }

  function runDiscover() {
    discover.mutate(undefined, {
      onSuccess: () => push({ tone: 'success', title: 'Path discovered' }),
      onError: (e) => push({ tone: 'danger', title: 'Discovery failed', message: e.message }),
    })
  }

  const copyStablePathLink = useCallback(() => {
    const stableURL = new URL(stablePathHref, window.location.origin).toString()
    if (!navigator.clipboard) {
      setCopiedLink(true)
      return
    }
    void navigator.clipboard
      .writeText(stableURL)
      .then(() => setCopiedLink(true))
      .catch(() =>
        push({ tone: 'danger', title: 'Copy failed', message: 'Clipboard access was denied.' }),
      )
  }, [push, stablePathHref])

  useEffect(() => {
    const requested = params.get('task') === 'copy-stable-link'
    if (!requested) {
      autoCopyHandled.current = false
      return
    }
    if (autoCopyHandled.current || !selectedRound) return
    autoCopyHandled.current = true
    const next = new URLSearchParams(params)
    next.delete('task')
    setParams(next, { replace: true })
    copyStablePathLink()
  }, [copyStablePathLink, params, selectedRound, setParams])

  const topologyLink = displayedPath
    ? pivotHref('/topology', {
        ...pivotContext,
        filters: { ...pivotContext.filters, ...(testId ? { path_test: testId } : {}) },
        selection: worst ? { kind: 'entity', id: worst.id } : undefined,
        returnTo: '/path',
      })
    : '/topology'

  return (
    <Page
      title="Path & Topology"
      subtitle="ECMP/MPLS-aware path to a target, merged across flows."
      actions={
        tests.data && tests.data.length > 0 ? (
          <div className={styles.toolbar}>
            <Select
              label="Test"
              className={styles.testSelect}
              value={testId ?? ''}
              onChange={(e) => chooseTest(e.target.value)}
              options={(tests.data ?? []).map((t) => ({ value: t.id, label: t.name }))}
            />
            {tests.hasNextPage ? (
              <Button
                variant="secondary"
                onClick={() => {
                  void tests.fetchNextPage()
                }}
                disabled={tests.isFetchingNextPage}
              >
                {tests.isFetchingNextPage ? 'Loading…' : 'Load more tests'}
              </Button>
            ) : null}
            <Button
              variant="primary"
              onClick={runDiscover}
              disabled={discover.isPending || !testId}
            >
              <Icon name="path" size={16} /> {discover.isPending ? 'Discovering…' : 'Discover path'}
            </Button>
          </div>
        ) : null
      }
    >
      {tests.isPending ? (
        <Card>
          <CardBody>
            <LoadingState label="Loading tests…" />
          </CardBody>
        </Card>
      ) : !tests.data || tests.data.length === 0 ? (
        <Card>
          <CardBody>
            <EmptyState
              icon="path"
              title="No tests yet"
              description="Create a test on the Targets page, then discover its network path here."
              preview={<FirstRunPreview />}
            />
          </CardBody>
        </Card>
      ) : (
        <>
          {displayedPath ? (
            <section className={styles.triage} aria-label="Path triage summary">
              <div>
                <span className={styles.triageLabel}>Selected path</span>
                <strong>
                  {test?.name ?? 'Test'} → {displayedPath.target}
                </strong>
                <span>
                  <Badge tone="neutral">{displayedPath.mode}</Badge>{' '}
                  {displayedPath.destination_reached
                    ? 'destination reached'
                    : 'destination not reached'}
                </span>
              </div>
              <div>
                <span className={styles.triageLabel}>Scope / time</span>
                <strong>Current tenant · {displayedPath.trace_count} merged flows</strong>
                <span>
                  {selectedRound ? (
                    <>
                      Round <DateTime value={selectedRound.observed_at} />
                    </>
                  ) : pivotContext.from && pivotContext.to ? (
                    <>
                      <DateTime value={pivotContext.from} /> – <DateTime value={pivotContext.to} />
                    </>
                  ) : (
                    'Latest stored discovery'
                  )}
                </span>
              </div>
              <div>
                <span className={styles.triageLabel}>Worst hop</span>
                <strong>
                  {worst ? `Hop ${worst.ttl} · ${worst.branchLabel}` : 'No responder'}
                </strong>
                <span>
                  {worst
                    ? `${worst.ip} · ${Math.round(worst.lossRatio * 100)}% loss · ${worst.node?.rtt_avg_ms ?? 0} ms avg`
                    : 'No hop evidence'}
                </span>
              </div>
              <div>
                <span className={styles.triageLabel}>Next action</span>
                <div className={styles.nextActions}>
                  {worst ? (
                    <Button size="sm" variant="primary" onClick={() => selectNode(worst)}>
                      Inspect worst hop
                    </Button>
                  ) : null}
                  <Link to={topologyLink}>Open in Topology</Link>
                </div>
                <span>Review evidence first; path analysis never changes the network.</span>
              </div>
            </section>
          ) : null}

          <div className={styles.grid}>
            <Card className={styles.graphCard}>
              <CardHeader
                title={test ? `Path to ${test.target}` : 'Path'}
                actions={
                  displayedPath ? (
                    displayedPath.destination_reached ? (
                      <StatusDot tone="success" label="Destination reached" />
                    ) : (
                      <StatusDot tone="warning" label="Incomplete" />
                    )
                  ) : null
                }
              />
              <CardBody>
                {discover.isPending || (path.isPending && !displayedPath) ? (
                  <LoadingState label="Discovering path…" />
                ) : path.isError && !displayedPath ? (
                  <ErrorState description={path.error?.message ?? 'Could not load the path.'} />
                ) : !displayedPath ? (
                  <EmptyState
                    icon="path"
                    title="No path discovered yet"
                    description="Run a discovery to map the route to this target."
                    action={
                      <Button variant="primary" onClick={runDiscover} disabled={discover.isPending}>
                        Discover path
                      </Button>
                    }
                    preview={<TopologyPreview />}
                  />
                ) : (
                  <>
                    <PathGraph
                      path={displayedPath}
                      selectedId={selected?.id}
                      onSelect={selectNode}
                    />
                    <Legend />
                  </>
                )}
              </CardBody>
            </Card>

            <div className={styles.side}>
              {displayedPath ? (
                <>
                  <LossByHop path={displayedPath} selectedId={selected?.id} onSelect={selectNode} />
                  <Card>
                    <CardBody>
                      <dl className={styles.summary}>
                        <div>
                          <dt>Hops</dt>
                          <dd>{displayedPath.hops.length}</dd>
                        </div>
                        <div>
                          <dt>Responders</dt>
                          <dd>{pathNodes.length - 1}</dd>
                        </div>
                        <div>
                          <dt>Selected</dt>
                          <dd>
                            {selected ? `${selected.branchLabel} · hop ${selected.ttl}` : 'none'}
                          </dd>
                        </div>
                      </dl>
                    </CardBody>
                  </Card>
                </>
              ) : null}
            </div>
          </div>

          {displayedPath ? (
            <Card>
              <CardHeader
                title="Path history & comparison"
                description="Scrub immutable discovery rounds, then compare responders and measurements side by side."
                actions={
                  selectedRound ? (
                    <Button size="sm" variant="secondary" onClick={copyStablePathLink}>
                      {copiedLink ? 'Stable link copied' : 'Copy stable path link'}
                    </Button>
                  ) : null
                }
              />
              <CardBody>
                {history.isPending ||
                (exactRoundIDs.length > 0 && linkedHistory.isPending && rounds.length === 0) ? (
                  <LoadingState label="Loading path history…" />
                ) : history.isError ||
                  (exactRoundIDs.length > 0 && linkedHistory.isError && rounds.length === 0) ? (
                  <ErrorState description="Could not load tenant-scoped path history." />
                ) : rounds.length === 0 ? (
                  <EmptyState
                    icon="path"
                    title="No path rounds in this time window"
                    description="Adjust the shared clock or run a fresh discovery."
                  />
                ) : (
                  <PathHistoryPanel
                    rounds={rounds}
                    selected={selectedRound}
                    comparison={comparisonRound}
                    onSelect={chooseRound}
                    onCompare={chooseComparison}
                  />
                )}
              </CardBody>
            </Card>
          ) : null}

          {displayedPath ? (
            <Card>
              <CardHeader
                title="Incident & change overlays"
                description="Evidence is matched to this target inside the selected X3 clock window."
              />
              <CardBody className={styles.evidenceGrid}>
                {incidents.isPending || changes.isPending ? (
                  <LoadingState label="Loading correlated evidence…" />
                ) : (
                  <>
                    <section aria-labelledby="path-incidents-heading">
                      <h3 id="path-incidents-heading">Incidents</h3>
                      {relatedIncidents.length > 0 ? (
                        <ul className={styles.evidenceList}>
                          {relatedIncidents.map((incident) => (
                            <li key={incident.id}>
                              <div>
                                <Badge tone={severityTone(incident.severity)}>
                                  {incident.severity}
                                </Badge>
                                <DateTime value={incident.last_seen_at} />
                              </div>
                              <Link
                                to={pivotHref('/incidents', {
                                  ...sharedPathContext,
                                  incidentId: incident.id,
                                })}
                              >
                                Open incident evidence: {incident.title || incident.id}
                              </Link>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className={styles.noEvidence}>No matching incident in this window.</p>
                      )}
                    </section>
                    <section aria-labelledby="path-changes-heading">
                      <h3 id="path-changes-heading">Changes</h3>
                      {relatedChanges.length > 0 ? (
                        <ul className={styles.evidenceList}>
                          {relatedChanges.map((change) => (
                            <li key={change.id}>
                              <div>
                                <Badge tone="info">{change.kind}</Badge>
                                <DateTime value={change.occurred_at} />
                              </div>
                              <Link
                                to={pivotHref('/explore', sharedPathContext, {
                                  template: 'deployments-before-incident',
                                  from: clockFrom,
                                  to: clockTo,
                                  filter: `id:${change.id}`,
                                })}
                              >
                                Open change evidence: {change.title || change.id}
                              </Link>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className={styles.noEvidence}>No matching change in this window.</p>
                      )}
                    </section>
                  </>
                )}
              </CardBody>
            </Card>
          ) : null}

          {displayedPath ? (
            <Card>
              <CardHeader
                title="Exact hop data"
                description="Search and select every responder, including branches summarized out of the graph viewport."
              />
              <CardBody>
                <PathHopTable
                  path={displayedPath}
                  selectedId={selected?.id}
                  onSelect={selectNode}
                />
              </CardBody>
            </Card>
          ) : null}
        </>
      )}

      <ExplainView
        surface="path"
        question={`Explain the currently displayed path${test?.target ? ` to ${test.target}` : ''}, including the strongest evidence for loss, routing, or topology changes.`}
        subject={{
          test_id: testId,
          target: test?.target,
          node: selected?.id,
        }}
        pivotContext={pivotContext}
      />

      <NodeDetailModal node={nodeDetailOpen ? selected : null} onClose={closeNode} />
    </Page>
  )
}
