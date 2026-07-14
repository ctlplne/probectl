import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
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
  Select,
  Table,
  TopologyPreview,
  type Column,
} from '../components'
import { useTopology, useWhatIf, type TopoNode, type WhatIfImpact } from '../api/topology'
import { layoutTopology, T_NODE_H, T_NODE_W, type TopoLayout } from '../viz/topoLayout'
import { FilterBar, SavedViews } from './listControls'
import { filterValue } from './urlFilters'
import { parsePivotContext, replacePivotContext, type PivotContext } from './pivotContext'
import { ExplainView } from './ExplainView'

const TOPOLOGY_FILTER_DEFAULTS = {
  topo_q: '',
  topo_kind: 'all',
  topo_site: 'all',
  topo_tag: 'all',
}

/** TopologyPage (S43, PR1): the tenant's dependency graph — agents, hops,
 * devices, hosts, services, prefixes — with temporal time travel (?at) and
 * the what-if failure simulation. The functional view; PR2+ iterates layout/
 * drill-down/change-overlay polish (design-led, multi-PR). */
export function TopologyPage() {
  const [params, setParams] = useSearchParams()
  const parsedPivot = useMemo(() => parsePivotContext(params), [params])
  const pivotContext = parsedPivot.context
  const initialAt = params.get('at') ?? pivotContext.to ?? ''
  const [at, setAt] = useState(initialAt) // '' = live
  const [timeInput, setTimeInput] = useState(toDateTimeLocal(initialAt))
  const { data, isPending, isError } = useTopology(at || undefined)
  const whatIf = useWhatIf()
  const urlQuery = filterValue(params, 'topo_q', pivotContext.filters.topo_q ?? '')
  const [query, setQuery] = useState(urlQuery)
  const kind = filterValue(params, 'topo_kind', pivotContext.filters.topo_kind ?? 'all')
  const site = filterValue(params, 'topo_site', pivotContext.filters.topo_site ?? 'all')
  const tag = filterValue(params, 'topo_tag', pivotContext.filters.topo_tag ?? 'all')

  const nodes = useMemo(() => data?.nodes ?? [], [data?.nodes])
  const edges = useMemo(() => data?.edges ?? [], [data?.edges])
  const kindOptions = useMemo(() => unique(nodes.map((node) => node.kind)), [nodes])
  const siteOptions = useMemo(() => unique(nodes.map((node) => node.site ?? '')), [nodes])
  const tagOptions = useMemo(() => unique(nodes.flatMap((node) => node.tags ?? [])), [nodes])
  const filteredNodes = useMemo(
    () => nodes.filter((node) => nodeMatches(node, { query, kind, site, tag })),
    [kind, nodes, query, site, tag],
  )
  const filteredNodeIDs = useMemo(
    () => new Set(filteredNodes.map((node) => node.id)),
    [filteredNodes],
  )
  const filteredEdges = useMemo(
    () => edges.filter((edge) => filteredNodeIDs.has(edge.from) && filteredNodeIDs.has(edge.to)),
    [edges, filteredNodeIDs],
  )
  const requestedNodeID =
    pivotContext.selection?.kind === 'entity' ? pivotContext.selection.id : undefined
  const selected = requestedNodeID
    ? (filteredNodes.find((node) => node.id === requestedNodeID) ?? null)
    : null
  const layout = useMemo(
    () => layoutTopology(filteredNodes, filteredEdges),
    [filteredEdges, filteredNodes],
  )
  const impact = whatIf.data ?? null
  const impacted = useMemo(() => impactedNodeIDs(impact), [impact])
  const currentFilters = useMemo(
    () => ({ topo_q: query, topo_kind: kind, topo_site: site, topo_tag: tag }),
    [kind, query, site, tag],
  )
  const setFilter = (patch: Record<string, string>) =>
    setParams(topologySearchParams(params, pivotContext, { ...currentFilters, ...patch }), {
      replace: true,
    })
  const savedFilters = activeFiltersForSave(currentFilters, TOPOLOGY_FILTER_DEFAULTS)

  useEffect(() => {
    if (
      (!isPending && requestedNodeID && !filteredNodeIDs.has(requestedNodeID)) ||
      (parsedPivot.hasContract && !parsedPivot.referencesValid)
    ) {
      setParams(replacePivotContext(params, { ...pivotContext, selection: undefined }), {
        replace: true,
      })
    }
  }, [
    filteredNodeIDs,
    isPending,
    params,
    parsedPivot.hasContract,
    parsedPivot.referencesValid,
    pivotContext,
    requestedNodeID,
    setParams,
  ])

  useEffect(() => {
    setQuery(urlQuery)
  }, [urlQuery])

  useEffect(() => {
    if (query === urlQuery) return undefined
    const handle = window.setTimeout(() => {
      setParams(topologySearchParams(params, pivotContext, currentFilters), { replace: true })
    }, 250)
    return () => window.clearTimeout(handle)
  }, [currentFilters, params, pivotContext, query, setParams, urlQuery])

  useEffect(() => {
    const nextAt = params.get('at') ?? pivotContext.to ?? ''
    setAt(nextAt)
    setTimeInput(toDateTimeLocal(nextAt))
  }, [params, pivotContext.to])

  function selectNode(node: TopoNode) {
    setParams(
      replacePivotContext(params, {
        ...pivotContext,
        selection: { kind: 'entity', id: node.id },
      }),
    )
  }

  const simulate = (target: string) => {
    whatIf.mutate({ target, at: at || undefined })
  }

  const updateTime = (value: string) => {
    setTimeInput(value)
    whatIf.reset()
    if (!value) {
      setAt('')
      const next = new URLSearchParams(params)
      next.delete('at')
      setParams(replacePivotContext(next, { ...pivotContext, to: undefined, selection: undefined }))
      return
    }
    const next = new Date(value)
    if (!Number.isNaN(next.getTime())) {
      const absolute = next.toISOString()
      setAt(absolute)
      const nextParams = new URLSearchParams(params)
      nextParams.set('at', absolute)
      setParams(
        replacePivotContext(nextParams, {
          ...pivotContext,
          to: absolute,
          selection: undefined,
        }),
      )
    }
  }

  return (
    <Page
      title="Topology"
      subtitle="The dependency graph across planes — and what breaks if an element fails."
    >
      <TopologyToolbar
        at={at}
        timeInput={timeInput}
        onTimeChange={updateTime}
        onLive={() => updateTime('')}
      />
      <TopologyFilters
        query={query}
        kind={kind}
        site={site}
        tag={tag}
        kindOptions={kindOptions}
        siteOptions={siteOptions}
        tagOptions={tagOptions}
        filters={savedFilters}
        onQueryChange={setQuery}
        onChange={setFilter}
        onApply={(filters) =>
          setParams(
            topologySearchParams(params, pivotContext, {
              topo_q: filters.topo_q ?? '',
              topo_kind: filters.topo_kind ?? 'all',
              topo_site: filters.topo_site ?? 'all',
              topo_tag: filters.topo_tag ?? 'all',
            }),
            { replace: true },
          )
        }
      />

      {isPending || isError || !data?.topology_running || nodes.length === 0 ? (
        <TopologyFallbackCard
          isPending={isPending}
          isError={isError}
          topologyRunning={data?.topology_running}
        />
      ) : (
        <div className={styles.grid}>
          <div className={styles.mainColumn}>
            <TopologyGraphCard
              layout={layout}
              coverageNotes={data.coverage?.notes ?? []}
              selected={selected}
              impact={impact}
              impacted={impacted}
              onSelect={selectNode}
            />
            <TopologyListCard
              nodes={filteredNodes}
              renderedCount={layout.nodes.length}
              selected={selected}
              onSelect={selectNode}
            />
          </div>
          <TopologySidePanel
            selected={selected}
            impact={impact}
            isSimulating={whatIf.isPending}
            simulationFailed={whatIf.isError}
            onSimulate={simulate}
          />
        </div>
      )}

      <ExplainView
        surface="topology"
        question="Explain the currently displayed topology and identify only evidence-backed dependency, routing, or change signals that matter in this view."
        subject={{ node: selected?.id }}
        pivotContext={pivotContext}
      />
    </Page>
  )
}

function topologySearchParams(
  current: URLSearchParams,
  pivotContext: PivotContext,
  filters: Record<string, string>,
): URLSearchParams {
  const next = new URLSearchParams(current)
  for (const [key, fallback] of Object.entries(TOPOLOGY_FILTER_DEFAULTS)) {
    const value = (filters[key] ?? fallback).trim()
    if (!value || value === fallback) next.delete(key)
    else next.set(key, value)
  }
  const contextFilters = { ...pivotContext.filters }
  for (const key of Object.keys(TOPOLOGY_FILTER_DEFAULTS)) delete contextFilters[key]
  Object.assign(contextFilters, activeFiltersForSave(filters, TOPOLOGY_FILTER_DEFAULTS))
  return replacePivotContext(next, { ...pivotContext, filters: contextFilters })
}

function toDateTimeLocal(value: string): string {
  const timestamp = Date.parse(value)
  if (!value || !Number.isFinite(timestamp)) return ''
  return new Date(timestamp).toISOString().slice(0, 16)
}

function TopologyToolbar({
  at,
  timeInput,
  onTimeChange,
  onLive,
}: {
  at: string
  timeInput: string
  onTimeChange: (value: string) => void
  onLive: () => void
}) {
  return (
    <div className={styles.toolbar}>
      <Field
        label="As of"
        hint="Empty = live; pick a time to view the graph as it was."
        type="datetime-local"
        value={timeInput}
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

function TopologyFilters({
  query,
  kind,
  site,
  tag,
  kindOptions,
  siteOptions,
  tagOptions,
  filters,
  onQueryChange,
  onChange,
  onApply,
}: {
  query: string
  kind: string
  site: string
  tag: string
  kindOptions: string[]
  siteOptions: string[]
  tagOptions: string[]
  filters: Record<string, string>
  onQueryChange: (query: string) => void
  onChange: (patch: Record<string, string>) => void
  onApply: (filters: Record<string, string>) => void
}) {
  return (
    <FilterBar>
      <Field
        label="Search topology"
        value={query}
        onChange={(e) => onQueryChange(e.target.value)}
        placeholder="device, service, prefix, tag"
      />
      <Select
        label="Kind"
        value={kind}
        onChange={(e) => onChange({ topo_kind: e.target.value })}
        options={[
          { value: 'all', label: 'All kinds' },
          ...kindOptions.map((value) => ({ value, label: value })),
        ]}
      />
      <Select
        label="Site"
        value={site}
        onChange={(e) => onChange({ topo_site: e.target.value })}
        options={[
          { value: 'all', label: 'All sites' },
          ...siteOptions.map((value) => ({ value, label: value })),
        ]}
      />
      <Select
        label="Tag"
        value={tag}
        onChange={(e) => onChange({ topo_tag: e.target.value })}
        options={[
          { value: 'all', label: 'All tags' },
          ...tagOptions.map((value) => ({ value, label: value })),
        ]}
      />
      <SavedViews surface="topology" filters={filters} onApply={onApply} placeholder="Core graph" />
    </FilterBar>
  )
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean))).sort((a, b) => a.localeCompare(b))
}

function activeFiltersForSave(
  filters: Record<string, string>,
  defaults: Record<string, string>,
): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(filters)) {
    const v = value.trim()
    if (v && v !== defaults[key]) out[key] = v
  }
  return out
}

function nodeMatches(
  node: TopoNode,
  filters: { query: string; kind: string; site: string; tag: string },
): boolean {
  const tags = node.tags ?? []
  if (filters.kind !== 'all' && node.kind !== filters.kind) return false
  if (filters.site !== 'all' && node.site !== filters.site) return false
  if (filters.tag !== 'all' && !tags.includes(filters.tag)) return false
  const q = filters.query.trim().toLowerCase()
  if (!q) return true
  return [node.id, node.kind, node.label, node.site ?? '', ...tags]
    .join(' ')
    .toLowerCase()
    .includes(q)
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
            preview={<TopologyPreview />}
          />
        ) : (
          <EmptyState
            icon="path"
            title="No topology observed yet"
            description="Run a path discovery, or let eBPF/BGP/device telemetry stream in."
            preview={<TopologyPreview />}
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
        {layout.nodes.length === 0 ? (
          <EmptyState title="No matching nodes" description="Adjust search or filters." />
        ) : (
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
        )}
      </CardBody>
    </Card>
  )
}

function TopologyListCard({
  nodes,
  renderedCount,
  selected,
  onSelect,
}: {
  nodes: TopoNode[]
  renderedCount: number
  selected: TopoNode | null
  onSelect: (node: TopoNode) => void
}) {
  const columns: Column<TopoNode>[] = [
    {
      key: 'kind',
      header: 'Kind',
      render: (node) => <Badge tone="info">{node.kind}</Badge>,
    },
    {
      key: 'label',
      header: 'Node',
      render: (node) => (
        <Button
          size="sm"
          variant={selected?.id === node.id ? 'primary' : 'ghost'}
          onClick={() => onSelect(node)}
        >
          {node.label}
        </Button>
      ),
    },
    { key: 'id', header: 'ID', render: (node) => <code>{node.id}</code> },
    { key: 'site', header: 'Site', render: (node) => node.site || 'none' },
    { key: 'tags', header: 'Tags', render: (node) => node.tags?.join(', ') || 'none' },
  ]

  return (
    <Card>
      <CardHeader
        title="Topology list"
        description={`${nodes.length} matching node${nodes.length === 1 ? '' : 's'}; graph renders ${renderedCount}.`}
      />
      <CardBody>
        <Table
          caption="Topology nodes"
          columns={columns}
          rows={nodes}
          rowKey={(node) => node.id}
          maxRows={nodes.length}
          empty={<EmptyState title="No matching nodes" description="Adjust search or filters." />}
        />
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
            <EmptyState
              icon="path"
              title="No node selected"
              description="Click a node in the graph."
            />
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
                <dt>Site</dt>
                <dd>{selected.site || 'none'}</dd>
                <dt>Tags</dt>
                <dd>{selected.tags?.join(', ') || 'none'}</dd>
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
