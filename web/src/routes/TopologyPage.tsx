import { useMemo, useState } from 'react'
import styles from './topology.module.css'
import { Page } from './pages'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
} from '../components'
import { useTopology, useWhatIf, type TopoNode, type WhatIfImpact } from '../api/topology'
import { layoutTopology, T_NODE_H, T_NODE_W, type TopoLayout } from '../viz/topoLayout'

/** TopologyPage (S43, PR1): the tenant's dependency graph — agents, hops,
 * devices, hosts, services, prefixes — with temporal time travel (?at) and
 * the what-if failure simulation. The functional view; PR2+ iterates layout/
 * drill-down/change-overlay polish (design-led, multi-PR). */
export function TopologyPage() {
  const [at, setAt] = useState('') // '' = live
  const { data, isPending, isError } = useTopology(at || undefined)
  const whatIf = useWhatIf()
  const [selected, setSelected] = useState<TopoNode | null>(null)

  const layout = useMemo(() => layoutTopology(data?.nodes ?? [], data?.edges ?? []), [data])
  const impact = whatIf.data ?? null
  const impacted = useMemo(() => impactedNodeIDs(impact), [impact])

  const simulate = (target: string) => {
    whatIf.mutate({ target, at: at || undefined })
  }

  const updateTime = (value: string) => {
    setSelected(null)
    whatIf.reset()
    setAt(value ? new Date(value).toISOString() : '')
  }

  return (
    <Page
      title="Topology"
      subtitle="The dependency graph across planes — and what breaks if an element fails."
    >
      <TopologyToolbar at={at} onTimeChange={updateTime} onLive={() => updateTime('')} />

      {isPending || isError || !data?.topology_running || layout.nodes.length === 0 ? (
        <TopologyFallbackCard
          isPending={isPending}
          isError={isError}
          topologyRunning={data?.topology_running}
        />
      ) : (
        <div className={styles.grid}>
          <TopologyGraphCard
            layout={layout}
            coverageNotes={data.coverage?.notes ?? []}
            selected={selected}
            impact={impact}
            impacted={impacted}
            onSelect={setSelected}
          />
          <TopologySidePanel
            selected={selected}
            impact={impact}
            isSimulating={whatIf.isPending}
            simulationFailed={whatIf.isError}
            onSimulate={simulate}
          />
        </div>
      )}
    </Page>
  )
}

function TopologyToolbar({
  at,
  onTimeChange,
  onLive,
}: {
  at: string
  onTimeChange: (value: string) => void
  onLive: () => void
}) {
  return (
    <div className={styles.toolbar}>
      <Field
        label="As of"
        hint="Empty = live; pick a time to view the graph as it was."
        type="datetime-local"
        value={at ? at.slice(0, 16) : ''}
        onChange={(e) => onTimeChange(e.target.value)}
      />
      {at !== '' && (
        <Button variant="ghost" onClick={onLive}>
          Back to live
        </Button>
      )}
    </div>
  )
}

function TopologyFallbackCard({
  isPending,
  isError,
  topologyRunning,
}: {
  isPending: boolean
  isError: boolean
  topologyRunning?: boolean
}) {
  return (
    <Card>
      <CardHeader
        title="Dependency graph"
        description="Click a node to inspect it, then simulate its failure."
      />
      <CardBody>
        {isPending ? (
          <LoadingState label="Loading topology…" />
        ) : isError ? (
          <ErrorState description="Could not load the topology graph." />
        ) : !topologyRunning ? (
          <EmptyState
            icon="path"
            title="Topology not wired"
            description="The control plane started without a topology store."
          />
        ) : (
          <EmptyState
            icon="path"
            title="No topology observed yet"
            description="Run a path discovery, or let eBPF/BGP/device telemetry stream in."
          />
        )}
      </CardBody>
    </Card>
  )
}

function TopologyGraphCard({
  layout,
  coverageNotes,
  selected,
  impact,
  impacted,
  onSelect,
}: {
  layout: TopoLayout
  coverageNotes: string[]
  selected: TopoNode | null
  impact: WhatIfImpact | null
  impacted: ImpactOverlay
  onSelect: (node: TopoNode) => void
}) {
  return (
    <Card className={styles.graphCard}>
      <CardHeader
        title="Dependency graph"
        description="Click a node to inspect it, then simulate its failure."
      />
      <CardBody>
        {coverageNotes.length > 0 && (
          <div className={styles.coverage} role="note" aria-label="coverage gaps">
            {coverageNotes.map((n) => (
              <span key={n}>{n}</span>
            ))}
          </div>
        )}
        {layout.truncated && (
          <p className={styles.truncated}>
            Showing {layout.nodes.length} of {layout.total} nodes (densest view is capped for
            legibility).
          </p>
        )}
        <div className={styles.graphWrap}>
          <svg
            role="group"
            aria-label="Topology graph"
            width={layout.width}
            height={layout.height}
            viewBox={`0 0 ${layout.width} ${layout.height}`}
          >
            {layout.edges.map((e) => (
              <line
                key={e.id}
                className={[
                  styles.edge,
                  e.kind === 'flow' ? styles.edgeFlow : '',
                  e.kind === 'routing' ? styles.edgeRouting : '',
                  e.kind === 'device' ? styles.edgeDevice : '',
                  impacted.edges.has(e.id) ? styles.edgeImpacted : '',
                ]
                  .filter(Boolean)
                  .join(' ')}
                x1={e.x1}
                y1={e.y1}
                x2={e.x2}
                y2={e.y2}
              />
            ))}
            {layout.nodes.map((n) => (
              <TopologyNode
                key={n.id}
                node={n}
                selected={selected?.id === n.id}
                failed={impact?.target === n.id}
                impacted={impacted.nodes.has(n.id)}
                onSelect={onSelect}
              />
            ))}
          </svg>
        </div>
      </CardBody>
    </Card>
  )
}

function TopologyNode({
  node,
  selected,
  failed,
  impacted,
  onSelect,
}: {
  node: TopoLayout['nodes'][number]
  selected: boolean
  failed: boolean
  impacted: boolean
  onSelect: (node: TopoNode) => void
}) {
  const select = () => onSelect(node)
  return (
    <g
      role="button"
      tabIndex={0}
      aria-label={`${node.kind} ${node.label}`}
      className={[
        styles.node,
        selected ? styles.nodeSelected : '',
        failed ? styles.nodeFailed : '',
        impacted ? styles.nodeImpacted : '',
      ]
        .filter(Boolean)
        .join(' ')}
      transform={`translate(${node.x}, ${node.y})`}
      onClick={select}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          select()
        }
      }}
    >
      <rect className={styles.nodeBox} width={T_NODE_W} height={T_NODE_H} rx={8} />
      <text className={styles.nodeKind} x={10} y={15}>
        {node.kind}
      </text>
      <text className={styles.nodeLabel} x={10} y={30}>
        {node.label.length > 20 ? `${node.label.slice(0, 19)}…` : node.label}
      </text>
    </g>
  )
}

function TopologySidePanel({
  selected,
  impact,
  isSimulating,
  simulationFailed,
  onSimulate,
}: {
  selected: TopoNode | null
  impact: WhatIfImpact | null
  isSimulating: boolean
  simulationFailed: boolean
  onSimulate: (target: string) => void
}) {
  return (
    <div className={styles.side}>
      <Card>
        <CardHeader title="Inspector" />
        <CardBody>
          {!selected ? (
            <EmptyState icon="path" title="No node selected" description="Click a node in the graph." />
          ) : (
            <>
              <dl className={styles.detailList}>
                <dt>Node</dt>
                <dd>
                  <code>{selected.id}</code>
                </dd>
                <dt>Kind</dt>
                <dd>
                  <Badge tone="info">{selected.kind}</Badge>
                </dd>
                <dt>Label</dt>
                <dd>{selected.label}</dd>
              </dl>
              <p>
                <Button onClick={() => onSimulate(selected.id)} disabled={isSimulating}>
                  {isSimulating ? 'Simulating…' : 'Simulate failure'}
                </Button>
              </p>
            </>
          )}
        </CardBody>
      </Card>

      {impact && <ImpactCard impact={impact} />}
      {simulationFailed && (
        <Card>
          <CardBody>
            <ErrorState description="Simulation failed — the element may not exist at that time." />
          </CardBody>
        </Card>
      )}
    </div>
  )
}

/** ImpactCard renders the what-if prediction: broken/rerouted paths with
 * routes, impacted services/prefixes, and the coverage honesty notes. */
function ImpactCard({ impact }: { impact: WhatIfImpact }) {
  return (
    <Card>
      <CardHeader
        title="Predicted impact"
        description={`If ${impact.target} fails — a simulation, nothing was touched.`}
      />
      <CardBody>
        {(impact.coverage.notes?.length ?? 0) > 0 && (
          <div className={styles.coverage} role="note" aria-label="simulation coverage gaps">
            {impact.coverage.notes?.map((n) => (
              <span key={n}>{n}</span>
            ))}
          </div>
        )}
        <dl className={styles.detailList}>
          <dt>Broken paths</dt>
          <dd>
            {impact.broken_paths.length === 0 ? (
              '0'
            ) : (
              <ul className={styles.impactList} aria-label="broken paths">
                {impact.broken_paths.map((p) => (
                  <li key={`${p.from}-${p.to}`}>
                    <Badge tone="danger">broken</Badge> {p.from} → {p.to}
                  </li>
                ))}
              </ul>
            )}
          </dd>
          <dt>Rerouted</dt>
          <dd>
            {impact.rerouted_paths.length === 0 ? (
              '0'
            ) : (
              <ul className={styles.impactList} aria-label="rerouted paths">
                {impact.rerouted_paths.map((p) => (
                  <li key={`${p.from}-${p.to}`}>
                    <Badge tone="warning">rerouted</Badge> {p.from} → {p.to}
                    <div className={styles.route}>via {p.alt_route?.join(' → ')}</div>
                  </li>
                ))}
              </ul>
            )}
          </dd>
          <dt>Services</dt>
          <dd>{impact.impacted_services.length ? impact.impacted_services.join(', ') : '0'}</dd>
          <dt>Prefixes</dt>
          <dd>{impact.impacted_prefixes.length ? impact.impacted_prefixes.join(', ') : '0'}</dd>
          <dt>Disconnected</dt>
          <dd>{impact.disconnected.length ? impact.disconnected.join(', ') : '0'}</dd>
          <dt>SLOs</dt>
          <dd>{impact.impacted_slos.length ? impact.impacted_slos.join(', ') : '—'}</dd>
        </dl>
      </CardBody>
    </Card>
  )
}

type ImpactOverlay = {
  nodes: Set<string>
  edges: Set<string>
}

/** impactedNodeIDs derives the overlay sets from a simulation result. */
function impactedNodeIDs(impact: WhatIfImpact | null): ImpactOverlay {
  const nodes = new Set<string>()
  const edges = new Set<string>()
  if (!impact) return { nodes, edges }
  for (const p of [...impact.broken_paths, ...impact.rerouted_paths]) {
    nodes.add(p.from)
    nodes.add(p.to)
    for (let i = 0; i + 1 < p.route.length; i++) {
      edges.add(`${p.route[i]}|path|${p.route[i + 1]}`)
    }
  }
  for (const s of impact.impacted_services) nodes.add(s)
  for (const s of impact.impacted_prefixes) nodes.add(s)
  for (const s of impact.disconnected) nodes.add(s)
  return { nodes, edges }
}
