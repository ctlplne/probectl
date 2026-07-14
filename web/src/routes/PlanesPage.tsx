import { Fragment, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Navigate, useNavigate, useParams, useSearchParams } from 'react-router-dom'
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
  PlanesPreview,
  Select,
  Table,
  type Column,
} from '../components'
import { useEndpoints, type EndpointView } from '../api/endpoints'
import {
  useDeviceConfigs,
  useDeviceSyslog,
  useFlowAnomalies,
  useFlowCapacity,
  useFlowTop,
  type DeviceConfigVersion,
  type DeviceSyslogEvent,
  type FlowGroupBy,
} from '../api/planes'
import { useTopology, type TopoEdge, type TopoNode } from '../api/topology'
import { DateTime } from '../time/DateTime'
import { useI18n } from '../i18n/useI18n'
import type { MessageKey } from '../i18n/messages'
import {
  formatDecimal,
  formatInteger,
  formatScaledBitRate,
  formatScaledBytes,
} from '../i18n/number'
import { BgpAsPathView, FlowSankeyView } from '../viz/PlaneRelationships'
import {
  parsePivotContext,
  planePivotHref,
  replacePivotContext,
  type PlaneID,
} from './pivotContext'

interface Plane {
  id: PlaneID
  labelKey: MessageKey
}

const PLANES: Plane[] = [
  { id: 'bgp', labelKey: 'planes.tab.bgp' },
  { id: 'flow', labelKey: 'planes.tab.flow' },
  { id: 'device', labelKey: 'planes.tab.device' },
  { id: 'ebpf', labelKey: 'planes.tab.ebpf' },
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
  const [params, setParams] = useSearchParams()
  const parsedPivot = useMemo(() => parsePivotContext(params), [params])
  const pivotContext = parsedPivot.context
  const { locale, t } = useI18n()
  const active: PlaneID = isPlaneID(plane) ? plane : 'bgp'
  const [flowBy, setFlowBy] = useState<FlowGroupBy>('src')
  const topology = useTopology()
  const endpoints = useEndpoints()
  const topTalkers = useFlowTop(flowBy, '1h', 8)
  const capacity = useFlowCapacity('1h', '5m')
  const anomalies = useFlowAnomalies('1h', '5m')
  const deviceSyslog = useDeviceSyslog(5)
  const deviceConfigs = useDeviceConfigs(5)

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
  const setActive = (next: PlaneID) => navigate(planePivotHref(next, pivotContext))

  useEffect(() => {
    const selectionUnavailable = Boolean(
      pivotContext.selection &&
      !topology.isLoading &&
      (pivotContext.selection.kind === 'evidence' ||
        !nodes.some((node) => node.id === pivotContext.selection?.id)),
    )
    if (selectionUnavailable || (parsedPivot.hasContract && !parsedPivot.referencesValid)) {
      setParams(replacePivotContext(params, { ...pivotContext, selection: undefined }), {
        replace: true,
      })
    }
  }, [
    nodes,
    params,
    parsedPivot.hasContract,
    parsedPivot.referencesValid,
    pivotContext,
    setParams,
    topology.isLoading,
  ])

  if (plane && !isPlaneID(plane)) {
    return <Navigate to={planePivotHref('bgp', pivotContext)} replace />
  }

  return (
    <Page
      title={t('planes.page.title')}
      subtitle={t('planes.page.subtitle')}
      actions={<PlaneTabs active={active} onChange={setActive} />}
    >
      <div className={styles.overview}>
        <PlaneStat
          title={t('planes.stat.bgp.title')}
          value={routingEdges.length}
          detail={t('planes.stat.bgp.detail', {
            prefixes: compact(prefixNodes.length, locale),
            ases: compact(asNodes.length, locale),
          })}
          tone={toneForCount(routingEdges.length)}
          onOpen={() => setActive('bgp')}
          locale={locale}
        />
        <PlaneStat
          title={t('planes.stat.flow.title')}
          value={topTalkers.data?.items.length ?? 0}
          detail={t('planes.stat.flow.detail', { bytes: bytes(flowBytes, locale) })}
          tone={toneForCount(topTalkers.data?.items.length ?? 0)}
          onOpen={() => setActive('flow')}
          locale={locale}
        />
        <PlaneStat
          title={t('planes.stat.device.title')}
          value={deviceNodes.length + endpointItems.length}
          detail={t('planes.stat.device.detail', {
            count: compact(impairedEndpoints, locale),
          })}
          tone={toneForCount(deviceNodes.length + endpointItems.length)}
          onOpen={() => setActive('device')}
          locale={locale}
        />
        <PlaneStat
          title={t('planes.stat.ebpf.title')}
          value={flowEdges.length}
          detail={t('planes.stat.ebpf.detail', {
            count: compact(serviceNodes.length, locale),
          })}
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
          syslog={deviceSyslog.data?.items ?? []}
          configs={deviceConfigs.data?.items ?? []}
          opsLoading={deviceSyslog.isLoading || deviceConfigs.isLoading}
          opsError={deviceSyslog.isError || deviceConfigs.isError}
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
  const { t } = useI18n()
  return (
    <div className={styles.tabs} role="tablist" aria-label={t('planes.tabs.aria')}>
      {PLANES.map((plane) => (
        <Button
          key={plane.id}
          role="tab"
          aria-selected={active === plane.id}
          aria-controls={`plane-panel-${plane.id}`}
          variant={active === plane.id ? 'primary' : 'secondary'}
          onClick={() => onChange(plane.id)}
        >
          {t(plane.labelKey)}
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
  const { t } = useI18n()
  return (
    <Card>
      <CardHeader
        title={title}
        actions={
          <Button size="sm" variant="ghost" onClick={onOpen}>
            {t('planes.stat.open')}
          </Button>
        }
      />
      <CardBody className={styles.statBody}>
        <span className={styles.statValue}>{compact(value, locale)}</span>
        <span className={styles.muted}>{detail}</span>
        <Badge tone={tone}>
          {value > 0 ? t('planes.stat.observed') : t('planes.stat.waiting')}
        </Badge>
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
  const { locale, t } = useI18n()
  const rows = routingEdges.map((edge, index) => ({
    ...edge,
    id: `${edge.from}-${edge.to}-${index}`,
  }))
  const columns: Column<(typeof rows)[number]>[] = [
    {
      key: 'origin',
      header: t('planes.bgp.column.origin'),
      render: (e) => labelFor(nodes, e.from),
    },
    { key: 'prefix', header: t('planes.bgp.column.prefix'), render: (e) => labelFor(nodes, e.to) },
    {
      key: 'kind',
      header: t('planes.column.source'),
      render: () => <Badge tone="info">{t('planes.badge.routing')}</Badge>,
    },
  ]
  return (
    <section id="plane-panel-bgp" role="tabpanel" className={styles.panelGrid}>
      <Card>
        <CardHeader
          title={t('planes.bgp.card.title')}
          description={t('planes.bgp.card.description')}
        />
        <CardBody>
          {isLoading ? (
            <LoadingState label={t('planes.bgp.loading')} />
          ) : isError ? (
            <ErrorState description={t('planes.bgp.error')} />
          ) : rows.length > 0 ? (
            <div className={styles.visualStack}>
              <BgpAsPathView nodes={nodes} routingEdges={routingEdges} />
              <Table
                caption={t('planes.bgp.table.caption')}
                columns={columns}
                rows={rows}
                rowKey={(r) => r.id}
              />
            </div>
          ) : (
            <Table
              caption={t('planes.bgp.table.caption')}
              columns={columns}
              rows={rows}
              rowKey={(r) => r.id}
              empty={
                <EmptyState
                  title={t('planes.bgp.empty.title')}
                  description={t('planes.bgp.empty.description')}
                  preview={<PlanesPreview />}
                />
              }
            />
          )}
        </CardBody>
      </Card>
      <PlaneSummary
        title={t('planes.bgp.summary.title')}
        items={[
          [t('planes.bgp.summary.edges'), compact(coverage, locale)],
          [t('planes.bgp.summary.prefixes'), compact(nodesOf(nodes, 'prefix').length, locale)],
          [t('planes.bgp.summary.systems'), compact(nodesOf(nodes, 'as').length, locale)],
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
  const { locale, t } = useI18n()
  const topRows = topTalkers.data?.items ?? []
  const topColumns: Column<NonNullable<typeof topTalkers.data>['items'][number]>[] = [
    {
      key: 'key',
      header: t('planes.flow.column.contributor'),
      render: (r) => (
        <div>
          <strong>{r.key}</strong>
          {r.detail ? <div className={styles.muted}>{r.detail}</div> : null}
        </div>
      ),
    },
    {
      key: 'bytes',
      header: t('planes.flow.column.bytes'),
      numeric: true,
      render: (r) => bytes(r.bytes, locale),
    },
    {
      key: 'packets',
      header: t('planes.flow.column.packets'),
      numeric: true,
      render: (r) => compact(r.packets, locale),
    },
    {
      key: 'flows',
      header: t('planes.flow.column.flows'),
      numeric: true,
      render: (r) => compact(r.flows, locale),
    },
  ]
  const anomalyColumns: Column<NonNullable<typeof anomalies.data>['items'][number]>[] = [
    {
      key: 'exporter',
      header: t('planes.flow.column.exporter'),
      render: (a) => a.exporter || t('planes.value.any'),
    },
    { key: 'iface', header: t('planes.flow.column.iface'), numeric: true, render: (a) => a.iface },
    {
      key: 'current',
      header: t('planes.flow.column.current'),
      numeric: true,
      render: (a) => rate(a.current_bps, locale),
    },
    {
      key: 'baseline',
      header: t('planes.flow.column.baseline'),
      numeric: true,
      render: (a) => rate(a.baseline_bps, locale),
    },
    {
      key: 'sigma',
      header: t('planes.flow.column.sigma'),
      numeric: true,
      render: (a) => formatDecimal(a.sigma, locale, { maximumFractionDigits: 1 }),
    },
    {
      key: 'model',
      header: t('planes.flow.column.model'),
      render: (a) => a.model || t('planes.value.local'),
    },
  ]
  return (
    <section id="plane-panel-flow" role="tabpanel" className={styles.panelGrid}>
      <div className={styles.stack}>
        <Card>
          <CardHeader
            title={t('planes.flow.top.title')}
            description={t('planes.flow.top.description')}
            actions={
              <Select
                label={t('planes.flow.group.label')}
                value={flowBy}
                onChange={(e) => onFlowBy(e.target.value as FlowGroupBy)}
                options={[
                  { value: 'src', label: t('planes.flow.group.src') },
                  { value: 'dst', label: t('planes.flow.group.dst') },
                  { value: 'pair', label: t('planes.flow.group.pair') },
                  { value: 'src_asn', label: t('planes.flow.group.srcAsn') },
                  { value: 'dst_asn', label: t('planes.flow.group.dstAsn') },
                ]}
              />
            }
          />
          <CardBody>
            {topTalkers.isLoading ? (
              <LoadingState label={t('planes.flow.top.loading')} />
            ) : topTalkers.isError ? (
              <ErrorState description={t('planes.flow.top.error')} />
            ) : topRows.length > 0 ? (
              <div className={styles.visualStack}>
                <FlowSankeyView rows={topRows} />
                <Table
                  caption={t('planes.flow.top.caption')}
                  columns={topColumns}
                  rows={topRows}
                  rowKey={(r) => `${r.key}-${r.detail ?? ''}`}
                />
              </div>
            ) : (
              <Table
                caption={t('planes.flow.top.caption')}
                columns={topColumns}
                rows={topRows}
                rowKey={(r) => `${r.key}-${r.detail ?? ''}`}
                empty={
                  <EmptyState
                    title={t('planes.flow.top.empty.title')}
                    description={t('planes.flow.top.empty.description')}
                    preview={<PlanesPreview />}
                  />
                }
              />
            )}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title={t('planes.flow.anomalies.title')} />
          <CardBody>
            {anomalies.isLoading ? (
              <LoadingState label={t('planes.flow.anomalies.loading')} />
            ) : anomalies.isError ? (
              <ErrorState description={t('planes.flow.anomalies.error')} />
            ) : (
              <Table
                caption={t('planes.flow.anomalies.caption')}
                columns={anomalyColumns}
                rows={anomalies.data?.items ?? []}
                rowKey={(a) => `${a.exporter}-${a.iface}-${a.ts}`}
                empty={
                  <EmptyState
                    title={t('planes.flow.anomalies.empty.title')}
                    description={t('planes.flow.anomalies.empty.description')}
                    preview={<PlanesPreview />}
                  />
                }
              />
            )}
          </CardBody>
        </Card>
      </div>
      <PlaneSummary
        title={t('planes.flow.summary.title')}
        items={[
          [t('planes.flow.summary.throughput'), rate(latestCapacity?.bps, locale)],
          [
            t('planes.flow.summary.packets'),
            latestCapacity
              ? formatDecimal(latestCapacity.pps, locale, { maximumFractionDigits: 1 })
              : formatInteger(0, locale),
          ],
          [t('planes.flow.column.exporter'), latestCapacity?.exporter || t('planes.value.none')],
          [
            t('planes.flow.summary.interface'),
            latestCapacity ? String(latestCapacity.iface) : t('planes.value.none'),
          ],
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
  syslog,
  configs,
  opsLoading,
  opsError,
}: {
  isLoading: boolean
  isError: boolean
  nodes: TopoNode[]
  deviceEdges: TopoEdge[]
  deviceNodes: TopoNode[]
  endpoints: EndpointView[]
  collectorRunning?: boolean
  syslog: DeviceSyslogEvent[]
  configs: DeviceConfigVersion[]
  opsLoading: boolean
  opsError: boolean
}) {
  const { locale, t } = useI18n()
  const deviceColumns: Column<TopoNode>[] = [
    {
      key: 'device',
      header: t('planes.device.column.device'),
      render: (n) => <strong>{n.label}</strong>,
    },
    { key: 'id', header: t('planes.device.column.graphId'), render: (n) => <code>{n.id}</code> },
  ]
  const endpointColumns: Column<EndpointView>[] = [
    { key: 'agent', header: t('planes.device.column.endpointAgent'), render: (e) => e.agent_id },
    {
      key: 'status',
      header: t('planes.device.column.state'),
      render: (e) => (
        <Badge tone={e.slow ? 'warning' : 'success'}>
          {e.slow ? t('planes.device.badge.impaired') : t('planes.device.badge.healthy')}
        </Badge>
      ),
    },
    {
      key: 'cause',
      header: t('planes.device.column.cause'),
      render: (e) => e.cause ?? t('planes.value.none'),
    },
    {
      key: 'seen',
      header: t('planes.device.column.lastSeen'),
      render: (e) => <DateTime value={e.last_seen_at} />,
    },
  ]
  const syslogColumns: Column<DeviceSyslogEvent>[] = [
    {
      key: 'device',
      header: t('planes.device.column.device'),
      render: (e) => <strong>{e.device}</strong>,
    },
    {
      key: 'severity',
      header: t('planes.device.column.severity'),
      render: (e) => <Badge tone={syslogTone(e.severity_text)}>{e.severity_text}</Badge>,
    },
    { key: 'message', header: t('planes.device.column.message'), render: (e) => e.message },
    {
      key: 'seen',
      header: t('planes.device.column.observed'),
      render: (e) => <DateTime value={e.observed_at} />,
    },
  ]
  const configColumns: Column<DeviceConfigVersion>[] = [
    {
      key: 'device',
      header: t('planes.device.column.device'),
      render: (c) => <strong>{c.device}</strong>,
    },
    { key: 'version', header: t('planes.device.column.version'), render: (c) => String(c.version) },
    {
      key: 'drift',
      header: t('planes.device.column.drift'),
      render: (c) => (
        <Badge tone={c.drifted ? 'warning' : 'success'}>
          {c.drifted ? t('planes.device.badge.changed') : t('planes.device.badge.baseline')}
        </Badge>
      ),
    },
    {
      key: 'hash',
      header: t('planes.device.column.hash'),
      render: (c) => <code>{c.content_hash.slice(0, 12)}</code>,
    },
    {
      key: 'archived',
      header: t('planes.device.column.archived'),
      render: (c) => <DateTime value={c.archived_at} />,
    },
  ]
  return (
    <section id="plane-panel-device" role="tabpanel" className={styles.panelGrid}>
      <div className={styles.stack}>
        <Card>
          <CardHeader
            title={t('planes.device.devices.title')}
            description={t('planes.device.devices.description')}
          />
          <CardBody>
            {isLoading ? (
              <LoadingState label={t('planes.device.devices.loading')} />
            ) : isError ? (
              <ErrorState description={t('planes.device.devices.error')} />
            ) : (
              <Table
                caption={t('planes.device.devices.caption')}
                columns={deviceColumns}
                rows={deviceNodes}
                rowKey={(n) => n.id}
                empty={
                  <EmptyState
                    title={t('planes.device.devices.empty.title')}
                    description={t('planes.device.devices.empty.description')}
                    preview={<PlanesPreview />}
                  />
                }
              />
            )}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title={t('planes.device.endpoints.title')} />
          <CardBody>
            <Table
              caption={t('planes.device.endpoints.caption')}
              columns={endpointColumns}
              rows={endpoints}
              rowKey={(e) => e.agent_id}
              empty={
                <EmptyState
                  title={t('planes.device.endpoints.empty.title')}
                  description={t('planes.device.endpoints.empty.description')}
                  preview={<PlanesPreview />}
                />
              }
            />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title={t('planes.device.syslog.title')} />
          <CardBody>
            {opsLoading ? (
              <LoadingState label={t('planes.device.ops.loading')} />
            ) : opsError ? (
              <ErrorState description={t('planes.device.ops.error')} />
            ) : (
              <Table
                caption={t('planes.device.syslog.caption')}
                columns={syslogColumns}
                rows={syslog}
                rowKey={(e) => e.id}
                empty={
                  <EmptyState
                    title={t('planes.device.syslog.empty.title')}
                    description={t('planes.device.syslog.empty.description')}
                    preview={<PlanesPreview />}
                  />
                }
              />
            )}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title={t('planes.device.config.title')} />
          <CardBody>
            {opsLoading ? (
              <LoadingState label={t('planes.device.config.loading')} />
            ) : opsError ? (
              <ErrorState description={t('planes.device.config.error')} />
            ) : (
              <Table
                caption={t('planes.device.config.caption')}
                columns={configColumns}
                rows={configs}
                rowKey={(c) => c.id}
                empty={
                  <EmptyState
                    title={t('planes.device.config.empty.title')}
                    description={t('planes.device.config.empty.description')}
                    preview={<PlanesPreview />}
                  />
                }
              />
            )}
          </CardBody>
        </Card>
      </div>
      <PlaneSummary
        title={t('planes.device.summary.title')}
        items={[
          [t('planes.device.summary.nodes'), compact(deviceNodes.length, locale)],
          [t('planes.device.summary.links'), compact(deviceEdges.length, locale)],
          [t('planes.device.summary.endpointAgents'), compact(endpoints.length, locale)],
          [
            t('planes.device.summary.collector'),
            collectorRunning === false ? t('planes.value.off') : t('planes.value.on'),
          ],
        ]}
        footer={
          deviceEdges.length > 0
            ? t('planes.device.summary.linked', { label: labelFor(nodes, deviceEdges[0].from) })
            : undefined
        }
      />
    </section>
  )
}

function syslogTone(severity: string) {
  return ['emergency', 'alert', 'critical', 'error'].includes(severity)
    ? 'danger'
    : severity === 'warning'
      ? 'warning'
      : 'neutral'
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
  const { locale, t } = useI18n()
  const rows = flowEdges.map((edge, index) => ({ ...edge, id: `${edge.from}-${edge.to}-${index}` }))
  const columns: Column<(typeof rows)[number]>[] = [
    { key: 'src', header: t('planes.ebpf.column.source'), render: (e) => labelFor(nodes, e.from) },
    {
      key: 'dst',
      header: t('planes.ebpf.column.destination'),
      render: (e) => labelFor(nodes, e.to),
    },
    {
      key: 'l7',
      header: t('planes.ebpf.column.l7'),
      render: (e) => e.label || t('planes.ebpf.value.l4'),
    },
  ]
  const protocols = new Set(flowEdges.map((e) => e.label).filter(Boolean))
  return (
    <section id="plane-panel-ebpf" role="tabpanel" className={styles.panelGrid}>
      <Card>
        <CardHeader
          title={t('planes.ebpf.card.title')}
          description={t('planes.ebpf.card.description')}
        />
        <CardBody>
          {isLoading ? (
            <LoadingState label={t('planes.ebpf.loading')} />
          ) : isError ? (
            <ErrorState description={t('planes.ebpf.error')} />
          ) : (
            <Table
              caption={t('planes.ebpf.table.caption')}
              columns={columns}
              rows={rows}
              rowKey={(r) => r.id}
              empty={
                <EmptyState
                  title={t('planes.ebpf.empty.title')}
                  description={t('planes.ebpf.empty.description')}
                  preview={<PlanesPreview />}
                />
              }
            />
          )}
        </CardBody>
      </Card>
      <PlaneSummary
        title={t('planes.ebpf.summary.title')}
        items={[
          [t('planes.ebpf.summary.nodes'), compact(serviceNodes.length, locale)],
          [t('planes.ebpf.summary.edges'), compact(flowEdges.length, locale)],
          [t('planes.ebpf.summary.protocols'), compact(protocols.size, locale)],
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
