import { Fragment, useMemo, useState, type ReactNode } from 'react'
import { Navigate, useNavigate, useParams } from 'react-router-dom'
import styles from './planes.module.css'
import { Page } from './pages'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingState,
  Select,
  Table,
  type Column,
} from '../components'
import { useEndpoints, type EndpointView } from '../api/endpoints'
import { useFlowAnomalies, useFlowCapacity, useFlowTop, type FlowGroupBy } from '../api/planes'
import { useTopology, type TopoEdge, type TopoNode } from '../api/topology'
import { DateTime } from '../time/DateTime'
import { useI18n } from '../i18n/useI18n'
import {
  formatDecimal,
  formatInteger,
  formatScaledBitRate,
  formatScaledBytes,
} from '../i18n/number'
import { BgpAsPathView, FlowSankeyView } from '../viz/PlaneRelationships'

type PlaneID = 'bgp' | 'flow' | 'device' | 'ebpf'

interface Plane {
  id: PlaneID
  label: string
  feature: string
}

const PLANES: Plane[] = [
  { id: 'bgp', label: 'BGP', feature: 'F6 / P2' },
  { id: 'flow', label: 'Flow', feature: 'F17 / P3' },
  { id: 'device', label: 'Device', feature: 'F18 / P4' },
  { id: 'ebpf', label: 'eBPF', feature: 'F11 / P5' },
]

function isPlaneID(value: string | undefined): value is PlaneID {
  return PLANES.some((plane) => plane.id === value)
}

const EMPTY_TOPO_NODES: TopoNode[] = []
const EMPTY_TOPO_EDGES: TopoEdge[] = []

function compact(n: number, locale: string): string {
  return formatInteger(n, locale)
}

function bytes(n: number | undefined, locale: string): string {
  return formatScaledBytes(n, locale)
}

function rate(n: number | undefined, locale: string): string {
  return formatScaledBitRate(n, locale)
}

function labelFor(nodes: TopoNode[], id: string): string {
  return nodes.find((n) => n.id === id)?.label ?? id
}

function edgesOf(edges: TopoEdge[], kind: string): TopoEdge[] {
  return edges.filter((e) => e.kind === kind)
}

function nodesOf(nodes: TopoNode[], kind: string): TopoNode[] {
  return nodes.filter((n) => n.kind === kind)
}

function toneForCount(n: number) {
  return n > 0 ? 'success' : 'warning'
}

export function PlanesPage() {
  const { plane } = useParams()
  const navigate = useNavigate()
  const { locale } = useI18n()
  const active: PlaneID = isPlaneID(plane) ? plane : 'bgp'
  const [flowBy, setFlowBy] = useState<FlowGroupBy>('src')
  const topology = useTopology()
  const endpoints = useEndpoints()
  const topTalkers = useFlowTop(flowBy, '1h', 8)
  const capacity = useFlowCapacity('1h', '5m')
  const anomalies = useFlowAnomalies('1h', '5m')

  const nodes = topology.data?.nodes ?? EMPTY_TOPO_NODES
  const edges = topology.data?.edges ?? EMPTY_TOPO_EDGES
  const routingEdges = useMemo(() => edgesOf(edges, 'routing'), [edges])
  const flowEdges = useMemo(() => edgesOf(edges, 'flow'), [edges])
  const deviceEdges = useMemo(() => edgesOf(edges, 'device'), [edges])
  const serviceNodes = useMemo(() => nodesOf(nodes, 'service'), [nodes])
  const prefixNodes = useMemo(() => nodesOf(nodes, 'prefix'), [nodes])
  const asNodes = useMemo(() => nodesOf(nodes, 'as'), [nodes])
  const deviceNodes = useMemo(() => nodesOf(nodes, 'device'), [nodes])
  const endpointItems = endpoints.data?.items ?? []
  const flowBytes = (topTalkers.data?.items ?? []).reduce((sum, row) => sum + row.bytes, 0)
  const latestCapacity = [...(capacity.data?.items ?? [])].sort((a, b) =>
    b.ts.localeCompare(a.ts),
  )[0]
  const impairedEndpoints = endpointItems.filter((e) => e.slow).length
  const setActive = (next: PlaneID) => navigate(`/planes/${next}`)

  if (plane && !isPlaneID(plane)) {
    return <Navigate to="/planes/bgp" replace />
  }

  return (
    <Page
      title="Planes"
      subtitle="First-class workspaces for routing, flow, device, and host/L7 telemetry."
      actions={<PlaneTabs active={active} onChange={setActive} />}
    >
      <div className={styles.overview}>
        <PlaneStat
          title="BGP routing"
          value={routingEdges.length}
          detail={`${compact(prefixNodes.length, locale)} prefixes, ${compact(
            asNodes.length,
            locale,
          )} AS nodes`}
          tone={toneForCount(routingEdges.length)}
          onOpen={() => setActive('bgp')}
          locale={locale}
        />
        <PlaneStat
          title="Flow analytics"
          value={topTalkers.data?.items.length ?? 0}
          detail={`${bytes(flowBytes, locale)} in top talkers`}
          tone={toneForCount(topTalkers.data?.items.length ?? 0)}
          onOpen={() => setActive('flow')}
          locale={locale}
        />
        <PlaneStat
          title="Device telemetry"
          value={deviceNodes.length + endpointItems.length}
          detail={`${compact(impairedEndpoints, locale)} endpoint impairments`}
          tone={toneForCount(deviceNodes.length + endpointItems.length)}
          onOpen={() => setActive('device')}
          locale={locale}
        />
        <PlaneStat
          title="eBPF host/L7"
          value={flowEdges.length}
          detail={`${compact(serviceNodes.length, locale)} services in topology`}
          tone={toneForCount(flowEdges.length)}
          onOpen={() => setActive('ebpf')}
          locale={locale}
        />
      </div>

      {active === 'bgp' ? (
        <BGPPanel
          isLoading={topology.isLoading}
          isError={topology.isError}
          nodes={nodes}
          routingEdges={routingEdges}
          coverage={topology.data?.coverage?.routing_edges ?? 0}
        />
      ) : null}
      {active === 'flow' ? (
        <FlowPanel
          flowBy={flowBy}
          onFlowBy={setFlowBy}
          topTalkers={topTalkers}
          anomalies={anomalies}
          latestCapacity={latestCapacity}
        />
      ) : null}
      {active === 'device' ? (
        <DevicePanel
          isLoading={topology.isLoading || endpoints.isLoading}
          isError={topology.isError || endpoints.isError}
          nodes={nodes}
          deviceEdges={deviceEdges}
          deviceNodes={deviceNodes}
          endpoints={endpointItems}
          collectorRunning={endpoints.data?.collector_running}
        />
      ) : null}
      {active === 'ebpf' ? (
        <EBPFPanel
          isLoading={topology.isLoading}
          isError={topology.isError}
          nodes={nodes}
          flowEdges={flowEdges}
          serviceNodes={serviceNodes}
        />
      ) : null}
    </Page>
  )
}

function PlaneTabs({ active, onChange }: { active: PlaneID; onChange: (plane: PlaneID) => void }) {
  return (
    <div className={styles.tabs} role="tablist" aria-label="Telemetry planes">
      {PLANES.map((plane) => (
        <Button
          key={plane.id}
          role="tab"
          aria-selected={active === plane.id}
          aria-controls={`plane-panel-${plane.id}`}
          variant={active === plane.id ? 'primary' : 'secondary'}
          onClick={() => onChange(plane.id)}
        >
          {plane.label}
        </Button>
      ))}
    </div>
  )
}

function PlaneStat({
  title,
  value,
  detail,
  tone,
  onOpen,
  locale,
}: {
  title: string
  value: number
  detail: string
  tone: 'success' | 'warning'
  onOpen: () => void
  locale: string
}) {
  return (
    <Card>
      <CardHeader
        title={title}
        actions={
          <Button size="sm" variant="ghost" onClick={onOpen}>
            Open
          </Button>
        }
      />
      <CardBody className={styles.statBody}>
        <span className={styles.statValue}>{compact(value, locale)}</span>
        <span className={styles.muted}>{detail}</span>
        <Badge tone={tone}>{value > 0 ? 'observed' : 'waiting for telemetry'}</Badge>
      </CardBody>
    </Card>
  )
}

function BGPPanel({
  isLoading,
  isError,
  nodes,
  routingEdges,
  coverage,
}: {
  isLoading: boolean
  isError: boolean
  nodes: TopoNode[]
  routingEdges: TopoEdge[]
  coverage: number
}) {
  const { locale } = useI18n()
  const rows = routingEdges.map((edge, index) => ({
    ...edge,
    id: `${edge.from}-${edge.to}-${index}`,
  }))
  const columns: Column<(typeof rows)[number]>[] = [
    { key: 'origin', header: 'Origin AS', render: (e) => labelFor(nodes, e.from) },
    { key: 'prefix', header: 'Prefix', render: (e) => labelFor(nodes, e.to) },
    { key: 'kind', header: 'Source', render: () => <Badge tone="info">routing</Badge> },
  ]
  return (
    <section id="plane-panel-bgp" role="tabpanel" className={styles.panelGrid}>
      <Card>
        <CardHeader
          title="BGP routing events"
          description="Origin AS to prefix evidence folded into the tenant graph."
        />
        <CardBody>
          {isLoading ? (
            <LoadingState label="Loading BGP plane..." />
          ) : isError ? (
            <ErrorState description="Could not load topology routing evidence." />
          ) : rows.length > 0 ? (
            <div className={styles.visualStack}>
              <BgpAsPathView nodes={nodes} routingEdges={routingEdges} />
              <Table
                caption="BGP routing edges"
                columns={columns}
                rows={rows}
                rowKey={(r) => r.id}
              />
            </div>
          ) : (
            <Table
              caption="BGP routing edges"
              columns={columns}
              rows={rows}
              rowKey={(r) => r.id}
              empty={
                <EmptyState
                  title="No BGP routing evidence"
                  description="BGP events appear here after the analyzer publishes tenant-scoped routing events."
                />
              }
            />
          )}
        </CardBody>
      </Card>
      <PlaneSummary
        title="Routing coverage"
        items={[
          ['Routing edges', compact(coverage, locale)],
          ['Prefixes', compact(nodesOf(nodes, 'prefix').length, locale)],
          ['Autonomous systems', compact(nodesOf(nodes, 'as').length, locale)],
        ]}
      />
    </section>
  )
}

function FlowPanel({
  flowBy,
  onFlowBy,
  topTalkers,
  anomalies,
  latestCapacity,
}: {
  flowBy: FlowGroupBy
  onFlowBy: (value: FlowGroupBy) => void
  topTalkers: ReturnType<typeof useFlowTop>
  anomalies: ReturnType<typeof useFlowAnomalies>
  latestCapacity?: { bps: number; pps: number; exporter: string; iface: number; ts: string }
}) {
  const { locale } = useI18n()
  const topRows = topTalkers.data?.items ?? []
  const topColumns: Column<NonNullable<typeof topTalkers.data>['items'][number]>[] = [
    {
      key: 'key',
      header: 'Contributor',
      render: (r) => (
        <div>
          <strong>{r.key}</strong>
          {r.detail ? <div className={styles.muted}>{r.detail}</div> : null}
        </div>
      ),
    },
    { key: 'bytes', header: 'Bytes', numeric: true, render: (r) => bytes(r.bytes, locale) },
    { key: 'packets', header: 'Packets', numeric: true, render: (r) => compact(r.packets, locale) },
    { key: 'flows', header: 'Flows', numeric: true, render: (r) => compact(r.flows, locale) },
  ]
  const anomalyColumns: Column<NonNullable<typeof anomalies.data>['items'][number]>[] = [
    { key: 'exporter', header: 'Exporter', render: (a) => a.exporter || 'any' },
    { key: 'iface', header: 'Iface', numeric: true, render: (a) => a.iface },
    {
      key: 'current',
      header: 'Current',
      numeric: true,
      render: (a) => rate(a.current_bps, locale),
    },
    {
      key: 'baseline',
      header: 'Baseline',
      numeric: true,
      render: (a) => rate(a.baseline_bps, locale),
    },
    {
      key: 'sigma',
      header: 'Sigma',
      numeric: true,
      render: (a) => formatDecimal(a.sigma, locale, { maximumFractionDigits: 1 }),
    },
    { key: 'model', header: 'Model', render: (a) => a.model || 'local' },
  ]
  return (
    <section id="plane-panel-flow" role="tabpanel" className={styles.panelGrid}>
      <div className={styles.stack}>
        <Card>
          <CardHeader
            title="Top talkers"
            description="Sampling-corrected flow contributors from the tenant flow store."
            actions={
              <Select
                label="Group"
                value={flowBy}
                onChange={(e) => onFlowBy(e.target.value as FlowGroupBy)}
                options={[
                  { value: 'src', label: 'Source' },
                  { value: 'dst', label: 'Destination' },
                  { value: 'pair', label: 'Pair' },
                  { value: 'src_asn', label: 'Source ASN' },
                  { value: 'dst_asn', label: 'Destination ASN' },
                ]}
              />
            }
          />
          <CardBody>
            {topTalkers.isLoading ? (
              <LoadingState label="Loading flow analytics..." />
            ) : topTalkers.isError ? (
              <ErrorState description="Could not load flow top talkers." />
            ) : topRows.length > 0 ? (
              <div className={styles.visualStack}>
                <FlowSankeyView rows={topRows} />
                <Table
                  caption="Flow top talkers"
                  columns={topColumns}
                  rows={topRows}
                  rowKey={(r) => `${r.key}-${r.detail ?? ''}`}
                />
              </div>
            ) : (
              <Table
                caption="Flow top talkers"
                columns={topColumns}
                rows={topRows}
                rowKey={(r) => `${r.key}-${r.detail ?? ''}`}
                empty={
                  <EmptyState
                    title="No flow rows"
                    description="Flow collectors have not reported in this window."
                  />
                }
              />
            )}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Capacity anomalies" />
          <CardBody>
            {anomalies.isLoading ? (
              <LoadingState label="Loading anomalies..." />
            ) : anomalies.isError ? (
              <ErrorState description="Could not load flow anomalies." />
            ) : (
              <Table
                caption="Flow capacity anomalies"
                columns={anomalyColumns}
                rows={anomalies.data?.items ?? []}
                rowKey={(a) => `${a.exporter}-${a.iface}-${a.ts}`}
                empty={
                  <EmptyState
                    title="No anomalies"
                    description="No interface departed from baseline in the current window."
                  />
                }
              />
            )}
          </CardBody>
        </Card>
      </div>
      <PlaneSummary
        title="Capacity"
        items={[
          ['Latest throughput', rate(latestCapacity?.bps, locale)],
          [
            'Latest packets/s',
            latestCapacity
              ? formatDecimal(latestCapacity.pps, locale, { maximumFractionDigits: 1 })
              : formatInteger(0, locale),
          ],
          ['Exporter', latestCapacity?.exporter || 'none'],
          ['Interface', latestCapacity ? String(latestCapacity.iface) : 'none'],
        ]}
        footer={latestCapacity ? <DateTime value={latestCapacity.ts} /> : undefined}
      />
    </section>
  )
}

function DevicePanel({
  isLoading,
  isError,
  nodes,
  deviceEdges,
  deviceNodes,
  endpoints,
  collectorRunning,
}: {
  isLoading: boolean
  isError: boolean
  nodes: TopoNode[]
  deviceEdges: TopoEdge[]
  deviceNodes: TopoNode[]
  endpoints: EndpointView[]
  collectorRunning?: boolean
}) {
  const { locale } = useI18n()
  const deviceColumns: Column<TopoNode>[] = [
    { key: 'device', header: 'Device', render: (n) => <strong>{n.label}</strong> },
    { key: 'id', header: 'Graph ID', render: (n) => <code>{n.id}</code> },
  ]
  const endpointColumns: Column<EndpointView>[] = [
    { key: 'agent', header: 'Endpoint agent', render: (e) => e.agent_id },
    {
      key: 'status',
      header: 'State',
      render: (e) => (
        <Badge tone={e.slow ? 'warning' : 'success'}>{e.slow ? 'impaired' : 'healthy'}</Badge>
      ),
    },
    { key: 'cause', header: 'Cause', render: (e) => e.cause ?? 'none' },
    { key: 'seen', header: 'Last seen', render: (e) => <DateTime value={e.last_seen_at} /> },
  ]
  return (
    <section id="plane-panel-device" role="tabpanel" className={styles.panelGrid}>
      <div className={styles.stack}>
        <Card>
          <CardHeader
            title="Network devices"
            description="Managed device nodes and device-to-hop links in the topology graph."
          />
          <CardBody>
            {isLoading ? (
              <LoadingState label="Loading device plane..." />
            ) : isError ? (
              <ErrorState description="Could not load device telemetry." />
            ) : (
              <Table
                caption="Topology device nodes"
                columns={deviceColumns}
                rows={deviceNodes}
                rowKey={(n) => n.id}
                empty={
                  <EmptyState
                    title="No devices"
                    description="Device collectors have not reported topology-visible devices yet."
                  />
                }
              />
            )}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Endpoint telemetry" />
          <CardBody>
            <Table
              caption="Endpoint telemetry"
              columns={endpointColumns}
              rows={endpoints}
              rowKey={(e) => e.agent_id}
              empty={
                <EmptyState
                  title="No endpoint telemetry"
                  description="Endpoint agents publish last-mile and WiFi evidence here."
                />
              }
            />
          </CardBody>
        </Card>
      </div>
      <PlaneSummary
        title="Device coverage"
        items={[
          ['Device nodes', compact(deviceNodes.length, locale)],
          ['Device links', compact(deviceEdges.length, locale)],
          ['Endpoint agents', compact(endpoints.length, locale)],
          ['Collector', collectorRunning === false ? 'off' : 'on'],
        ]}
        footer={
          deviceEdges.length > 0 ? `${labelFor(nodes, deviceEdges[0].from)} linked` : undefined
        }
      />
    </section>
  )
}

function EBPFPanel({
  isLoading,
  isError,
  nodes,
  flowEdges,
  serviceNodes,
}: {
  isLoading: boolean
  isError: boolean
  nodes: TopoNode[]
  flowEdges: TopoEdge[]
  serviceNodes: TopoNode[]
}) {
  const { locale } = useI18n()
  const rows = flowEdges.map((edge, index) => ({ ...edge, id: `${edge.from}-${edge.to}-${index}` }))
  const columns: Column<(typeof rows)[number]>[] = [
    { key: 'src', header: 'Source workload', render: (e) => labelFor(nodes, e.from) },
    { key: 'dst', header: 'Destination workload', render: (e) => labelFor(nodes, e.to) },
    { key: 'l7', header: 'L7', render: (e) => e.label || 'L4' },
  ]
  const protocols = new Set(flowEdges.map((e) => e.label).filter(Boolean))
  return (
    <section id="plane-panel-ebpf" role="tabpanel" className={styles.panelGrid}>
      <Card>
        <CardHeader
          title="Host/L7 service edges"
          description="eBPF-derived workload-to-workload evidence folded into the topology graph."
        />
        <CardBody>
          {isLoading ? (
            <LoadingState label="Loading eBPF plane..." />
          ) : isError ? (
            <ErrorState description="Could not load eBPF service edges." />
          ) : (
            <Table
              caption="eBPF service edges"
              columns={columns}
              rows={rows}
              rowKey={(r) => r.id}
              empty={
                <EmptyState
                  title="No service edges"
                  description="The eBPF agent has not reported service-to-service traffic yet."
                />
              }
            />
          )}
        </CardBody>
      </Card>
      <PlaneSummary
        title="Host/L7 coverage"
        items={[
          ['Service nodes', compact(serviceNodes.length, locale)],
          ['Service edges', compact(flowEdges.length, locale)],
          ['Protocols', compact(protocols.size, locale)],
        ]}
      />
    </section>
  )
}

function PlaneSummary({
  title,
  items,
  footer,
}: {
  title: string
  items: Array<[string, string]>
  footer?: ReactNode
}) {
  return (
    <Card>
      <CardHeader title={title} />
      <CardBody>
        <dl className={styles.kv}>
          {items.map(([k, v]) => (
            <Fragment key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </Fragment>
          ))}
        </dl>
        {footer ? <p className={styles.muted}>{footer}</p> : null}
      </CardBody>
    </Card>
  )
}
