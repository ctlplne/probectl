import { useEffect, useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import styles from './path.module.css'
import { Page } from './pages'
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
import { usePath, useDiscoverPath } from '../api/paths'
import { PathGraph } from '../viz/PathGraph'
import { LossByHop } from '../viz/LossByHop'
import { NodeDetailModal } from '../viz/NodeDetailModal'
import { PathHopTable } from '../viz/PathHopTable'
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

export function PathPage() {
  const tests = useTests()
  const [params, setParams] = useSearchParams()
  const parsedPivot = useMemo(() => parsePivotContext(params), [params])
  const pivotContext = parsedPivot.context
  const chosen = pivotContext.filters.path_test ?? ''
  const { push } = useToast()

  const testId = chosen || tests.data?.[0]?.id
  const test = tests.data?.find((t) => t.id === testId)
  const path = usePath(testId)
  const discover = useDiscoverPath(testId)
  const pathNodes = useMemo(() => (path.data ? layoutPath(path.data).nodes : []), [path.data])
  const worst = useMemo(() => (path.data ? worstPathNode(path.data) : undefined), [path.data])
  const requestedNodeID =
    pivotContext.selection?.kind === 'entity' ? pivotContext.selection.id : undefined
  const selected = requestedNodeID
    ? (pathNodes.find((node) => node.id === requestedNodeID) ?? null)
    : null

  useEffect(() => {
    const unknownTest = Boolean(
      tests.data && chosen && !tests.data.some((candidate) => candidate.id === chosen),
    )
    const unknownNode = Boolean(path.data && requestedNodeID && !selected)
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
    path.data,
    pivotContext,
    requestedNodeID,
    selected,
    setParams,
    tests.data,
  ])

  function chooseTest(id: string) {
    setParams(
      replacePivotContext(params, {
        ...pivotContext,
        filters: { ...pivotContext.filters, path_test: id },
        selection: undefined,
      }),
    )
  }

  function selectNode(node: VizNode) {
    setParams(
      replacePivotContext(params, {
        ...pivotContext,
        selection: { kind: 'entity', id: node.id },
      }),
    )
  }

  function closeNode() {
    setParams(replacePivotContext(params, { ...pivotContext, selection: undefined }), {
      replace: true,
    })
  }

  function runDiscover() {
    discover.mutate(undefined, {
      onSuccess: () => push({ tone: 'success', title: 'Path discovered' }),
      onError: (e) => push({ tone: 'danger', title: 'Discovery failed', message: e.message }),
    })
  }

  const topologyLink = path.data
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
          {path.data ? (
            <section className={styles.triage} aria-label="Path triage summary">
              <div>
                <span className={styles.triageLabel}>Selected path</span>
                <strong>
                  {test?.name ?? 'Test'} → {path.data.target}
                </strong>
                <span>
                  <Badge tone="neutral">{path.data.mode}</Badge>{' '}
                  {path.data.destination_reached
                    ? 'destination reached'
                    : 'destination not reached'}
                </span>
              </div>
              <div>
                <span className={styles.triageLabel}>Scope / time</span>
                <strong>Current tenant · {path.data.trace_count} merged flows</strong>
                <span>
                  {pivotContext.from && pivotContext.to ? (
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
                  path.data ? (
                    path.data.destination_reached ? (
                      <StatusDot tone="success" label="Destination reached" />
                    ) : (
                      <StatusDot tone="warning" label="Incomplete" />
                    )
                  ) : null
                }
              />
              <CardBody>
                {discover.isPending || path.isPending ? (
                  <LoadingState label="Discovering path…" />
                ) : path.isError ? (
                  <ErrorState description={path.error?.message ?? 'Could not load the path.'} />
                ) : !path.data ? (
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
                    <PathGraph path={path.data} selectedId={selected?.id} onSelect={selectNode} />
                    <Legend />
                  </>
                )}
              </CardBody>
            </Card>

            <div className={styles.side}>
              {path.data ? (
                <>
                  <LossByHop path={path.data} selectedId={selected?.id} onSelect={selectNode} />
                  <Card>
                    <CardBody>
                      <dl className={styles.summary}>
                        <div>
                          <dt>Hops</dt>
                          <dd>{path.data.hops.length}</dd>
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

          {path.data ? (
            <Card>
              <CardHeader
                title="Exact hop data"
                description="Search and select every responder, including branches summarized out of the graph viewport."
              />
              <CardBody>
                <PathHopTable path={path.data} selectedId={selected?.id} onSelect={selectNode} />
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

      <NodeDetailModal node={selected} onClose={closeNode} />
    </Page>
  )
}
