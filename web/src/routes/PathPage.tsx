import { useState } from 'react'
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
  Icon,
  LoadingState,
  Select,
  StatusDot,
  useToast,
} from '../components'
import { useTests } from '../api/tests'
import { usePath, useDiscoverPath } from '../api/paths'
import { PathGraph } from '../viz/PathGraph'
import { LossByHop } from '../viz/LossByHop'
import { NodeDetailModal } from '../viz/NodeDetailModal'
import type { VizNode } from '../viz/layout'

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
  const [chosen, setChosen] = useState('')
  const [selected, setSelected] = useState<VizNode | null>(null)
  const { push } = useToast()

  const testId = chosen || tests.data?.[0]?.id
  const test = tests.data?.find((t) => t.id === testId)
  const path = usePath(testId)
  const discover = useDiscoverPath(testId)

  function runDiscover() {
    discover.mutate(undefined, {
      onSuccess: () => push({ tone: 'success', title: 'Path discovered' }),
      onError: (e) => push({ tone: 'danger', title: 'Discovery failed', message: e.message }),
    })
  }

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
              onChange={(e) => setChosen(e.target.value)}
              options={(tests.data ?? []).map((t) => ({ value: t.id, label: t.name }))}
            />
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
            />
          </CardBody>
        </Card>
      ) : (
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
                />
              ) : (
                <>
                  <PathGraph path={path.data} selectedId={selected?.id} onSelect={setSelected} />
                  <Legend />
                </>
              )}
            </CardBody>
          </Card>

          <div className={styles.side}>
            {path.data ? (
              <>
                <LossByHop path={path.data} />
                <Card>
                  <CardBody>
                    <dl className={styles.summary}>
                      <div>
                        <dt>Hops</dt>
                        <dd>{path.data.hops.length}</dd>
                      </div>
                      <div>
                        <dt>Flows merged</dt>
                        <dd>{path.data.trace_count}</dd>
                      </div>
                      <div>
                        <dt>Mode</dt>
                        <dd>
                          <Badge tone="neutral">{path.data.mode}</Badge>
                        </dd>
                      </div>
                    </dl>
                  </CardBody>
                </Card>
              </>
            ) : null}
          </div>
        </div>
      )}

      <NodeDetailModal node={selected} onClose={() => setSelected(null)} />
    </Page>
  )
}
