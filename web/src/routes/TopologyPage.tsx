// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import styles from './topology.module.css'
import { Page } from './RoutePage'
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
import {
  topologyWhatIfExportHref,
  useTopology,
  useWhatIf,
  type TopoEdge,
  type TopoNode,
  type TopologyResponse,
  type WhatIfImpact,
} from '../api/topology'
import { useIncident } from '../api/incidents'
import { layoutTopology, T_HEADER, T_NODE_H, T_NODE_W, type TopoLayout } from '../viz/topoLayout'
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
  const initialAt = topologyTime(params, pivotContext)
  const [at, setAt] = useState(initialAt) // '' = live
  const [timeInput, setTimeInput] = useState(toDateTimeLocal(initialAt))
  const { data, isPending, isError } = useTopology(at || undefined)
  const comparisonAt =
    at && pivotContext.from && pivotContext.from !== at ? pivotContext.from : undefined
  const comparison = useTopology(comparisonAt, Boolean(at))
  const linkedIncident = useIncident(pivotContext.incidentId)
  const whatIf = useWhatIf()
  const autoPreviewed = useRef('')
  const urlQuery = filterValue(params, 'topo_q', pivotContext.filters.topo_q ?? '')
  const [query, setQuery] = useState(urlQuery)
  const kind = filterValue(params, 'topo_kind', pivotContext.filters.topo_kind ?? 'all')
  const site = filterValue(params, 'topo_site', pivotContext.filters.topo_site ?? 'all')
  const tag = filterValue(params, 'topo_tag', pivotContext.filters.topo_tag ?? 'all')

  const nodes = useMemo(() => data?.nodes ?? [], [data?.nodes])
  const edges = useMemo(() => data?.edges ?? [], [data?.edges])
  const comparisonNodes = useMemo(() => comparison.data?.nodes ?? [], [comparison.data?.nodes])
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
    ? (nodes.find((node) => node.id === requestedNodeID) ??
      comparisonNodes.find((node) => node.id === requestedNodeID) ??
      null)
    : null
  const layout = useMemo(
    () => layoutTopology(filteredNodes, filteredEdges),
    [filteredEdges, filteredNodes],
  )
  const impact = whatIf.data ?? null
  const impacted = useMemo(() => impactedNodeIDs(impact), [impact])
  const versionDiff = useMemo(
    () => (at && data && comparison.data ? diffTopology(comparison.data, data) : null),
    [at, comparison.data, data],
  )
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
    const invalidContract = parsedPivot.hasContract && !parsedPivot.referencesValid
    const invalidEntity =
      Boolean(requestedNodeID) && !isPending && (!at || !comparison.isPending) && !selected
    const invalidIncident = Boolean(pivotContext.incidentId) && linkedIncident.isError
    if (invalidContract || invalidEntity || invalidIncident) {
      setParams(
        replacePivotContext(params, {
          ...pivotContext,
          incidentId: invalidContract || invalidIncident ? undefined : pivotContext.incidentId,
          selection: invalidContract || invalidEntity ? undefined : pivotContext.selection,
        }),
        {
          replace: true,
        },
      )
    }
  }, [
    at,
    comparison.isPending,
    isPending,
    linkedIncident.isError,
    params,
    parsedPivot.hasContract,
    parsedPivot.referencesValid,
    pivotContext,
    requestedNodeID,
    selected,
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
    const nextAt = topologyTime(params, pivotContext)
    setAt(nextAt)
    setTimeInput(toDateTimeLocal(nextAt))
  }, [params, pivotContext])

  function selectNode(node: TopoNode) {
    whatIf.reset()
    const next = new URLSearchParams(params)
    next.delete('preview')
    setParams(
      replacePivotContext(next, {
        ...pivotContext,
        selection: { kind: 'entity', id: node.id },
      }),
    )
  }

  const simulate = (target: string) => {
    whatIf.mutate({ target, at: at || undefined })
  }

  useEffect(() => {
    const target = params.get('preview') === 'blast' ? selected?.id : undefined
    const incidentReady = !pivotContext.incidentId || linkedIncident.data?.id
    if (!target || !incidentReady) return
    const key = `${target}|${at || 'live'}|${linkedIncident.data?.id ?? ''}`
    if (autoPreviewed.current === key) return
    autoPreviewed.current = key
    whatIf.mutate({ target, at: at || undefined })
  }, [at, linkedIncident.data?.id, params, pivotContext.incidentId, selected?.id, whatIf])

  const updateTime = (value: string) => {
    setTimeInput(value)
    whatIf.reset()
    if (!value) {
      setAt('')
      const next = new URLSearchParams(params)
      next.set('at', 'live')
      setParams(replacePivotContext(next, pivotContext))
      return
    }
    const next = new Date(value)
    if (!Number.isNaN(next.getTime())) {
      const absolute = next.toISOString()
      setAt(absolute)
      const nextParams = new URLSearchParams(params)
      nextParams.set('at', absolute)
      setParams(replacePivotContext(nextParams, pivotContext))
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
        comparisonAt={comparisonAt}
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

      {at && comparison.isError ? (
        <ErrorState
          title="Topology comparison unavailable"
          description="The selected topology loaded, but the comparison snapshot could not be read."
        />
      ) : null}

      {isPending || isError || !data?.topology_running || nodes.length === 0 ? (
        <TopologyFallbackCard
          isPending={isPending}
          isError={isError}
          topologyRunning={data?.topology_running}
        />
      ) : (
        <div className={styles.grid}>
          <div className={styles.mainColumn}>
            {versionDiff && (
              <TopologyVersionDiffCard
                diff={versionDiff}
                from={comparison.data?.at ?? comparisonAt ?? 'live'}
                to={data.at ?? at}
                selectedID={selected?.id}
              />
            )}
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
            affectedIncidentID={linkedIncident.data?.id}
            at={at}
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

function topologyTime(params: URLSearchParams, context: PivotContext): string {
  const pageTime = params.get('at')
  if (pageTime === 'live') return ''
  return pageTime ?? context.to ?? ''
}

function toDateTimeLocal(value: string): string {
  const timestamp = Date.parse(value)
  if (!value || !Number.isFinite(timestamp)) return ''
  return new Date(timestamp).toISOString().slice(0, 16)
}

function TopologyToolbar({
  at,
  timeInput,
  comparisonAt,
  onTimeChange,
  onLive,
}: {
  at: string
  timeInput: string
  comparisonAt?: string
  onTimeChange: (value: string) => void
  onLive: () => void
}) {
  return (
    <div className={styles.clock} role="group" aria-label="Topology version clock">
      <div className={styles.clockCopy}>
        <strong>Version clock</strong>
        <span>
          Scrub the graph without dropping the selected entity. Historical views explain every node
          and edge change against {comparisonAt ? 'the investigation start' : 'live'}.
        </span>
      </div>
      <div className={styles.toolbar}>
        <Field
          label="As of"
          hint="Empty = live; pick a time to view the graph as it was."
          type="datetime-local"
          value={timeInput}
          onChange={(e) => onTimeChange(e.target.value)}
        />
        <Badge tone={at ? 'info' : 'success'}>{at ? `Selected ${at}` : 'Live topology'}</Badge>
        {at !== '' && (
          <Button variant="ghost" onClick={onLive}>
            Back to live
          </Button>
        )}
      </div>
    </div>
  )
}

function TopologyVersionDiffCard({
  diff,
  from,
  to,
  selectedID,
}: {
  diff: TopologyDiff
  from: string
  to: string
  selectedID?: string
}) {
  const changed =
    diff.addedNodes.length +
    diff.removedNodes.length +
    diff.changedNodes.length +
    diff.addedEdges.length +
    diff.removedEdges.length +
    diff.changedEdges.length
  return (
    <Card>
      <CardHeader
        title="Version changes"
        description={`${from} → ${to}; ${changed} explained graph change${changed === 1 ? '' : 's'}.`}
        actions={selectedID ? <Badge tone="accent">Selection preserved: {selectedID}</Badge> : null}
      />
      <CardBody>
        {changed === 0 ? (
          <p className={styles.noChanges}>No node or edge changes in this interval.</p>
        ) : (
          <div className={styles.diffGrid} aria-label="Topology version differences">
            <TopologyDiffGroup
              title="Added nodes"
              tone="success"
              items={diff.addedNodes.map(nodeSummary)}
            />
            <TopologyDiffGroup
              title="Removed nodes"
              tone="danger"
              items={diff.removedNodes.map(nodeSummary)}
            />
            <TopologyDiffGroup
              title="Changed nodes"
              tone="warning"
              items={diff.changedNodes.map(nodeSummary)}
            />
            <TopologyDiffGroup
              title="Added edges"
              tone="success"
              items={diff.addedEdges.map(edgeSummary)}
            />
            <TopologyDiffGroup
              title="Removed edges"
              tone="danger"
              items={diff.removedEdges.map(edgeSummary)}
            />
            <TopologyDiffGroup
              title="Changed edges"
              tone="warning"
              items={diff.changedEdges.map(edgeSummary)}
            />
          </div>
        )}
      </CardBody>
    </Card>
  )
}

function TopologyDiffGroup({
  title,
  tone,
  items,
}: {
  title: string
  tone: 'success' | 'danger' | 'warning'
  items: string[]
}) {
  return (
    <section className={styles.diffGroup} aria-label={title}>
      <h4>
        <Badge tone={tone}>{items.length}</Badge> {title}
      </h4>
      {items.length > 0 ? (
        <ul>
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : (
        <span>None</span>
      )}
    </section>
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
          <>
            <div className={styles.graphWrap}>
              <svg
                role="group"
                aria-label="Topology graph"
                width={layout.width}
                height={layout.height}
                viewBox={`0 0 ${layout.width} ${layout.height}`}
              >
                <defs>
                  {/* Arrowheads inherit each edge's stroke via context-stroke. */}
                  <marker
                    id="topo-arrow"
                    viewBox="0 0 8 8"
                    refX="7"
                    refY="4"
                    markerWidth="7"
                    markerHeight="7"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 0 L 8 4 L 0 8 z" className={styles.arrowHead} />
                  </marker>
                </defs>
                {/* Kind bands + headers structure the dependency order. */}
                <g aria-hidden="true">
                  {layout.columns.map((column) => (
                    <g key={column.kind}>
                      <rect
                        className={styles.colBand}
                        x={column.x - T_BAND_PAD}
                        y={0}
                        width={T_NODE_W + T_BAND_PAD * 2}
                        height={layout.height}
                        rx={10}
                      />
                      <text className={styles.colHeader} x={column.x} y={T_HEADER - 12}>
                        {column.kind}
                      </text>
                    </g>
                  ))}
                </g>
                {layout.edges.map((e) => (
                  <path
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
                    d={edgePath(e)}
                    markerEnd="url(#topo-arrow)"
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
            <TopologyLegend layout={layout} />
          </>
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

/** Node/edge kind → the token class carrying its categorical color. */
const KIND_CLASS: Record<string, string | undefined> = {
  service: styles.kindService,
  device: styles.kindDevice,
  as: styles.kindAs,
  prefix: styles.kindPrefix,
  host: styles.kindHost,
  hop: styles.kindHop,
  agent: styles.kindAgent,
}

function kindClass(kind: string): string {
  return KIND_CLASS[kind] ?? styles.kindOther
}

const T_BAND_PAD = 14
const T_EDGE_BOW = 46

/** Gentle S-curve between columns; same-column edges arc out on the right
 * instead of slicing through the node boxes between them. */
function edgePath(e: TopoLayout['edges'][number]): string {
  if (e.x2 <= e.x1) {
    const exit = e.x1 + T_EDGE_BOW
    return `M ${e.x1} ${e.y1} C ${exit} ${e.y1}, ${exit} ${e.y2}, ${e.x1} ${e.y2}`
  }
  return `M ${e.x1} ${e.y1} C ${e.x1 + T_EDGE_BOW} ${e.y1}, ${e.x2 - T_EDGE_BOW} ${e.y2}, ${e.x2} ${e.y2}`
}

function TopologyLegend({ layout }: { layout: TopoLayout }) {
  const edgeKinds = [...new Set(layout.edges.map((edge) => edge.kind))]
  return (
    <div className={styles.legend}>
      {layout.columns.map((column) => (
        <span key={column.kind} className={`${styles.legendItem} ${kindClass(column.kind)}`}>
          <span className={styles.legendNodeSwatch} aria-hidden="true" />
          {column.kind}
        </span>
      ))}
      {edgeKinds.map((kind) => (
        <span key={kind} className={styles.legendItem}>
          <svg className={styles.legendEdgeSwatch} viewBox="0 0 24 8" aria-hidden="true">
            <line
              className={[
                styles.edge,
                kind === 'flow' ? styles.edgeFlow : '',
                kind === 'routing' ? styles.edgeRouting : '',
                kind === 'device' ? styles.edgeDevice : '',
              ]
                .filter(Boolean)
                .join(' ')}
              x1="1"
              y1="4"
              x2="23"
              y2="4"
            />
          </svg>
          {kind}
        </span>
      ))}
    </div>
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
        kindClass(node.kind),
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
      <rect className={styles.nodeAccent} width={4} height={T_NODE_H} rx={2} />
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
  affectedIncidentID,
  at,
  onSimulate,
}: {
  selected: TopoNode | null
  impact: WhatIfImpact | null
  isSimulating: boolean
  simulationFailed: boolean
  affectedIncidentID?: string
  at: string
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
              <p className={styles.simulationAction}>
                <Button onClick={() => onSimulate(selected.id)} disabled={isSimulating}>
                  {isSimulating ? 'Simulating…' : 'Simulate failure (dry-run)'}
                </Button>
              </p>
              <p className={styles.safetyCopy}>
                Observe only. This tenant/RBAC-scoped preview executes and prevents nothing.
              </p>
            </>
          )}
        </CardBody>
      </Card>

      {impact && <ImpactCard impact={impact} affectedIncidentID={affectedIncidentID} at={at} />}
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
 * routes, affected tests/services/incidents/SLOs, confidence, and gaps. */
function ImpactCard({
  impact,
  affectedIncidentID,
  at,
}: {
  impact: WhatIfImpact
  affectedIncidentID?: string
  at: string
}) {
  const impactedTests = impact.impacted_tests ?? []
  const confidence = impact.confidence ?? {
    level: 'low' as const,
    score: 0,
    basis: 'The server did not report confidence coverage.',
  }
  const coverageNotes = impact.coverage.notes ?? []
  const sloCoverageMissing = coverageNotes.some((note) => note.includes('slo impact not wired'))
  return (
    <Card>
      <CardHeader
        title="Predicted impact · observe-only dry-run"
        description={`If ${impact.target} fails — a prediction, not execution or prevention.`}
      />
      <CardBody>
        <div className={styles.safetyBar} aria-label="simulation safety">
          <Badge tone="warning">DRY-RUN</Badge>
          <Badge tone="neutral">OBSERVE ONLY</Badge>
          <span>
            Tenant/RBAC scoped. The server audits this preview; export gets an export receipt.
          </span>
        </div>
        <div className={styles.confidence} aria-label="simulation confidence">
          <Badge
            tone={
              confidence.level === 'high'
                ? 'success'
                : confidence.level === 'medium'
                  ? 'warning'
                  : 'danger'
            }
          >
            {confidence.level} confidence · {confidence.score}% coverage
          </Badge>
          <span>{confidence.basis}. Coverage is not probability or a guarantee.</span>
        </div>
        <div className={styles.coverage} role="note" aria-label="simulation coverage gaps">
          <strong>Coverage gaps</strong>
          <span>
            Edges: path {impact.coverage.path_edges}, flow {impact.coverage.flow_edges}, routing{' '}
            {impact.coverage.routing_edges}, device {impact.coverage.device_edges}.
          </span>
          {coverageNotes.length > 0 ? (
            coverageNotes.map((note) => <span key={note}>{note}</span>)
          ) : (
            <span>No declared graph or SLO coverage gaps.</span>
          )}
        </div>
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
                    <div className={styles.route}>lost route {p.route.join(' → ')}</div>
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
                    <div className={styles.route}>original {p.route.join(' → ')}</div>
                    <div className={styles.route}>alternate {p.alt_route?.join(' → ')}</div>
                  </li>
                ))}
              </ul>
            )}
          </dd>
          <dt>Affected tests</dt>
          <dd>
            {impactedTests.length === 0 ? (
              '0'
            ) : (
              <ul className={styles.impactList} aria-label="affected tests">
                {impactedTests.map((test) => (
                  <li key={`${test.agent_id}-${test.target}-${test.status}`}>
                    <Badge tone={test.status === 'broken' ? 'danger' : 'warning'}>
                      {test.status}
                    </Badge>{' '}
                    {test.agent_id} → {test.target}
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
          <dt>Affected incidents</dt>
          <dd>{affectedIncidentID ?? '0 linked incident evidence objects'}</dd>
          <dt>Known SLO impact</dt>
          <dd>
            {impact.impacted_slos.length
              ? impact.impacted_slos.join(', ')
              : sloCoverageMissing
                ? 'Unknown — SLO impact is not wired'
                : '0 known impacted SLOs'}
          </dd>
        </dl>
        <div className={styles.exportRow}>
          <a
            className={styles.exportLink}
            href={topologyWhatIfExportHref(impact.target, impact.at || at || undefined)}
            download
          >
            Export audited JSON
          </a>
          <span>Saving is not implicit; this deliberate export is audit-recorded.</span>
        </div>
      </CardBody>
    </Card>
  )
}

interface TopologyDiff {
  addedNodes: TopoNode[]
  removedNodes: TopoNode[]
  changedNodes: TopoNode[]
  addedEdges: TopoEdge[]
  removedEdges: TopoEdge[]
  changedEdges: TopoEdge[]
}

function diffTopology(from: TopologyResponse, to: TopologyResponse): TopologyDiff {
  const fromNodes = new Map(from.nodes.map((node) => [node.id, node]))
  const toNodes = new Map(to.nodes.map((node) => [node.id, node]))
  const fromEdges = new Map(from.edges.map((edge) => [topologyEdgeID(edge), edge]))
  const toEdges = new Map(to.edges.map((edge) => [topologyEdgeID(edge), edge]))
  return {
    addedNodes: to.nodes.filter((node) => !fromNodes.has(node.id)),
    removedNodes: from.nodes.filter((node) => !toNodes.has(node.id)),
    changedNodes: to.nodes.filter((node) => {
      const previous = fromNodes.get(node.id)
      return previous ? topologyNodeState(previous) !== topologyNodeState(node) : false
    }),
    addedEdges: to.edges.filter((edge) => !fromEdges.has(topologyEdgeID(edge))),
    removedEdges: from.edges.filter((edge) => !toEdges.has(topologyEdgeID(edge))),
    changedEdges: to.edges.filter((edge) => {
      const previous = fromEdges.get(topologyEdgeID(edge))
      return previous ? (previous.label ?? '') !== (edge.label ?? '') : false
    }),
  }
}

function topologyNodeState(node: TopoNode): string {
  return JSON.stringify({
    kind: node.kind,
    label: node.label,
    site: node.site ?? '',
    tags: [...(node.tags ?? [])].sort((left, right) => left.localeCompare(right)),
  })
}

function topologyEdgeID(edge: TopoEdge): string {
  return `${edge.from}|${edge.kind}|${edge.to}`
}

function nodeSummary(node: TopoNode): string {
  return `${node.kind} ${node.label} (${node.id})`
}

function edgeSummary(edge: TopoEdge): string {
  return `${edge.from} → ${edge.to} [${edge.kind}]${edge.label ? ` ${edge.label}` : ''}`
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
