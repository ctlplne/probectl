// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { Fragment, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Navigate, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import styles from './planes.module.css'
import { Page } from './RoutePage'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  DeviceCollectionOutcomesCard,
  EmptyState,
  ErrorState,
  FlowIngestQualityCard,
  LoadingState,
  PlanesPreview,
  Select,
  Table,
  type Column,
} from '../components'
import { useEndpoints, type EndpointView } from '../api/endpoints'
import {
  useDeviceConfigs,
  useDeviceNeighbors,
  useDeviceSyslog,
  useFlowAnomalies,
  useFlowCapacity,
  useFlowTop,
  type DeviceConfigVersion,
  type DeviceNeighborEvidence,
  type DeviceSyslogEvent,
  type FlowFilter,
  type FlowGroupBy,
  type FlowTopRow,
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
import { TimeSeries } from '../components/TimeSeries'
import {
  parsePivotContext,
  planePivotHref,
  replacePivotContext,
  type PlaneID,
} from './pivotContext'
import { ExplainView } from './ExplainView'
import { IdentityConflictsCard } from './IdentityConflictsCard'

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
  const [flowFilters, setFlowFilters] = useState<FlowFilter[]>([])
  const topology = useTopology()
  const endpoints = useEndpoints()
  const topTalkers = useFlowTop(flowBy, '1h', 8, flowFilters)
  const capacity = useFlowCapacity('1h', '5m')
  const anomalies = useFlowAnomalies('1h', '5m')
  const deviceSyslog = useDeviceSyslog(5)
  const deviceConfigs = useDeviceConfigs(5)
  const deviceNeighbors = useDeviceNeighbors(100)

  const nodes = topology.data?.nodes ?? EMPTY_TOPO_NODES
  const edges = topology.data?.edges ?? EMPTY_TOPO_EDGES
  const routingEdges = useMemo(() => edgesOf(edges, 'routing'), [edges])
  const flowEdges = useMemo(() => edgesOf(edges, 'flow'), [edges])
  const deviceEdges = useMemo(() => edgesOf(edges, 'device'), [edges])
  const physicalEdges = useMemo(() => edgesOf(edges, 'physical'), [edges])
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
  const setActive = (next: PlaneID) => {
    void navigate(planePivotHref(next, pivotContext))
  }

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
        <>
          {capacity.isError ? (
            <ErrorState description="Could not load flow capacity samples." />
          ) : null}
          <FlowPanel
            flowBy={flowBy}
            onFlowBy={setFlowBy}
            filters={flowFilters}
            onFilters={setFlowFilters}
            topTalkers={topTalkers}
            anomalies={anomalies}
            latestCapacity={latestCapacity}
          />
        </>
      ) : null}
      {active === 'device' ? (
        <DevicePanel
          isLoading={topology.isLoading || endpoints.isLoading}
          isError={topology.isError || endpoints.isError}
          nodes={nodes}
          deviceEdges={deviceEdges}
          physicalEdges={physicalEdges}
          deviceNodes={deviceNodes}
          endpoints={endpointItems}
          collectorRunning={endpoints.data?.collector_running}
          syslog={deviceSyslog.data?.items ?? []}
          configs={deviceConfigs.data?.items ?? []}
          neighbors={deviceNeighbors.data?.items ?? []}
          neighborsRunning={deviceNeighbors.data?.collection_running}
          neighborsTruncated={deviceNeighbors.data?.truncated}
          neighborRetentionHours={deviceNeighbors.data?.retention.stale_retention_hours}
          neighborsLoading={deviceNeighbors.isLoading}
          neighborsError={deviceNeighbors.isError}
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

      <ExplainView
        surface={`plane:${active}`}
        question={`Explain the currently displayed ${active} plane using only exact evidence from the current entity, filters, and time window.`}
        subject={{
          plane: active,
          node: pivotContext.selection?.kind === 'entity' ? pivotContext.selection.id : undefined,
          type: active === 'bgp' ? 'routing' : active,
        }}
        pivotContext={pivotContext}
      />
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
  filters,
  onFilters,
  topTalkers,
  anomalies,
  latestCapacity,
}: {
  flowBy: FlowGroupBy
  onFlowBy: (value: FlowGroupBy) => void
  filters: FlowFilter[]
  onFilters: (filters: FlowFilter[]) => void
  topTalkers: ReturnType<typeof useFlowTop>
  anomalies: ReturnType<typeof useFlowAnomalies>
  latestCapacity?: { bps: number; pps: number; exporter: string; iface: number; ts: string }
}) {
  const { locale, t } = useI18n()
  const topRows = topTalkers.data?.items ?? []
  const seriesPoints = topTalkers.data?.series ?? []
  const seriesRows = topRows.slice(0, topTalkers.data?.series_limit ?? 6)
  const seriesTimestamps = [...new Set(seriesPoints.map((point) => point.ts))].sort()
  const chartSeries = seriesRows.map((row) => {
    const values = new Map(
      seriesPoints
        .filter((point) => point.key === row.key && (point.detail ?? '') === (row.detail ?? ''))
        .map((point) => [point.ts, point.bytes]),
    )
    return {
      label: row.detail ? `${row.key} → ${row.detail}` : row.key,
      values: seriesTimestamps.map((timestamp) => values.get(timestamp) ?? null),
    }
  })
  const narrow = (row: FlowTopRow) => {
    const next = flowFiltersForRow(flowBy, row)
    const merged = [...filters]
    for (const filter of next) {
      if (
        !merged.some(
          (existing) => existing.field === filter.field && existing.value === filter.value,
        )
      ) {
        merged.push(filter)
      }
    }
    onFilters(merged)
  }
  const observation = (row: FlowTopRow) => {
    const count = row.exporter_count ?? 0
    const label =
      count === 0
        ? t('planes.flow.observation.unavailable')
        : count === 1
          ? t('planes.flow.observation.one')
          : t('planes.flow.observation.many', { count })
    return <Badge tone={count > 1 ? 'info' : 'neutral'}>{label}</Badge>
  }
  const topColumns: Column<NonNullable<typeof topTalkers.data>['items'][number]>[] = [
    {
      key: 'key',
      header: t('planes.flow.column.contributor'),
      render: (r) => (
        <Button
          variant="ghost"
          size="sm"
          className={styles.contributorButton}
          onClick={() => narrow(r)}
          aria-label={t('planes.flow.filter.narrow', {
            value: r.detail ? `${r.key} → ${r.detail}` : r.key,
          })}
        >
          <span>
            <strong>{r.key}</strong>
            {r.detail ? <div className={styles.muted}>{r.detail}</div> : null}
          </span>
        </Button>
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
    {
      key: 'observation',
      header: t('planes.flow.column.observation'),
      render: observation,
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
        <FlowIngestQualityCard />
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
                  { value: 'as_name', label: t('planes.flow.group.asName') },
                  { value: 'src_country', label: t('planes.flow.group.srcCountry') },
                  { value: 'dst_country', label: t('planes.flow.group.dstCountry') },
                  { value: 'port', label: t('planes.flow.group.port') },
                  { value: 'protocol', label: t('planes.flow.group.protocol') },
                  { value: 'exporter', label: t('planes.flow.group.exporter') },
                ]}
              />
            }
          />
          <CardBody>
            <div className={styles.filterBar} aria-label={t('planes.flow.filter.active')}>
              <span className={styles.muted}>{t('planes.flow.filter.active')}</span>
              {filters.length === 0 ? (
                <span className={styles.muted}>{t('planes.flow.filter.none')}</span>
              ) : (
                filters.map((filter, index) => (
                  <Button
                    key={`${filter.field}-${filter.value}`}
                    size="sm"
                    variant="secondary"
                    className={styles.filterChip}
                    aria-label={t('planes.flow.filter.remove', {
                      field: filter.field,
                      value: filter.value,
                    })}
                    onClick={() => onFilters(filters.filter((_, candidate) => candidate !== index))}
                  >
                    <span>{filter.field}</span>
                    <strong>{filter.value}</strong>
                    <span aria-hidden="true">×</span>
                  </Button>
                ))
              )}
              {filters.length > 0 ? (
                <Button size="sm" variant="ghost" onClick={() => onFilters([])}>
                  {t('planes.flow.filter.clear')}
                </Button>
              ) : null}
            </div>
            {topTalkers.isLoading ? (
              <LoadingState label={t('planes.flow.top.loading')} />
            ) : topTalkers.isError ? (
              <ErrorState description={t('planes.flow.top.error')} />
            ) : topRows.length > 0 ? (
              <div className={styles.visualStack}>
                {seriesTimestamps.length > 0 && chartSeries.length > 0 ? (
                  <TimeSeries
                    timestamps={seriesTimestamps}
                    series={chartSeries}
                    label={t('planes.flow.series.label')}
                    formatValue={(value) => bytes(value, locale)}
                  />
                ) : null}
                <FlowSankeyView rows={topRows} />
                <div className={styles.flowTalkersDesktop} data-flow-top-desktop>
                  <Table
                    caption={t('planes.flow.top.caption')}
                    columns={topColumns}
                    rows={topRows}
                    rowKey={(r) => `${r.key}-${r.detail ?? ''}`}
                  />
                </div>
                <ul
                  className={styles.flowTalkersMobile}
                  aria-label={t('planes.flow.top.caption')}
                  data-flow-top-mobile
                >
                  {topRows.map((row) => (
                    <li
                      key={`${row.key}-${row.detail ?? ''}`}
                      className={styles.flowTalkerRecord}
                      data-flow-top-mobile-record
                    >
                      <div className={styles.flowTalkerHeader}>
                        <Button
                          variant="ghost"
                          size="sm"
                          className={`${styles.contributorButton} ${styles.flowTalkerContributor}`}
                          onClick={() => narrow(row)}
                          aria-label={t('planes.flow.filter.narrow', {
                            value: row.detail ? `${row.key} → ${row.detail}` : row.key,
                          })}
                          data-flow-top-field="contributor"
                        >
                          <span>
                            <strong>{row.key}</strong>
                            {row.detail ? <span className={styles.muted}>{row.detail}</span> : null}
                          </span>
                        </Button>
                        <span data-flow-top-field="observation">{observation(row)}</span>
                      </div>
                      <dl className={styles.flowTalkerFacts}>
                        <div data-flow-top-field="bytes">
                          <dt>{t('planes.flow.column.bytes')}</dt>
                          <dd>{bytes(row.bytes, locale)}</dd>
                        </div>
                        <div data-flow-top-field="packets">
                          <dt>{t('planes.flow.column.packets')}</dt>
                          <dd>{compact(row.packets, locale)}</dd>
                        </div>
                        <div data-flow-top-field="flows">
                          <dt>{t('planes.flow.column.flows')}</dt>
                          <dd>{compact(row.flows, locale)}</dd>
                        </div>
                      </dl>
                    </li>
                  ))}
                </ul>
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

function flowFiltersForRow(by: FlowGroupBy, row: FlowTopRow): FlowFilter[] {
  if (by === 'pair') {
    return [
      { field: 'src', value: row.key },
      { field: 'dst', value: row.detail ?? '' },
    ].filter((filter) => filter.value !== '') as FlowFilter[]
  }
  return [{ field: by, value: row.key }]
}

function DevicePanel({
  isLoading,
  isError,
  nodes,
  deviceEdges,
  physicalEdges,
  deviceNodes,
  endpoints,
  collectorRunning,
  syslog,
  configs,
  neighbors,
  neighborsRunning,
  neighborsTruncated,
  neighborRetentionHours,
  neighborsLoading,
  neighborsError,
  opsLoading,
  opsError,
}: {
  isLoading: boolean
  isError: boolean
  nodes: TopoNode[]
  deviceEdges: TopoEdge[]
  physicalEdges: TopoEdge[]
  deviceNodes: TopoNode[]
  endpoints: EndpointView[]
  collectorRunning?: boolean
  syslog: DeviceSyslogEvent[]
  configs: DeviceConfigVersion[]
  neighbors: DeviceNeighborEvidence[]
  neighborsRunning?: boolean
  neighborsTruncated?: boolean
  neighborRetentionHours?: number
  neighborsLoading: boolean
  neighborsError: boolean
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
  const neighborColumns: Column<DeviceNeighborEvidence>[] = [
    {
      key: 'local',
      header: t('planes.device.column.localPort'),
      render: (n) => (
        <span>
          <strong>{n.local_device_name || n.local_device_address}</strong>
          <div className={styles.muted}>{n.local_port_id}</div>
        </span>
      ),
    },
    {
      key: 'remote',
      header: t('planes.device.column.remotePort'),
      render: (n) => (
        <span>
          <strong>
            {n.remote_device_name || n.remote_management_address || n.remote_chassis_id}
          </strong>
          <div className={styles.muted}>{n.remote_port_id}</div>
        </span>
      ),
    },
    {
      key: 'protocol',
      header: t('planes.device.column.protocol'),
      render: (n) => <Badge tone="info">{n.protocol.toUpperCase()}</Badge>,
    },
    {
      key: 'confidence',
      header: t('planes.device.column.confidence'),
      numeric: true,
      render: (n) => `${formatDecimal(n.confidence * 100, locale, { maximumFractionDigits: 0 })}%`,
    },
    {
      key: 'freshness',
      header: t('planes.device.column.freshness'),
      render: (n) => (
        <Badge tone={n.freshness === 'current' ? 'success' : 'warning'}>
          {t(
            n.freshness === 'current'
              ? 'planes.device.neighbors.freshness.current'
              : n.freshness === 'stale'
                ? 'planes.device.neighbors.freshness.stale'
                : 'planes.device.neighbors.freshness.future',
          )}
        </Badge>
      ),
    },
    {
      key: 'observed',
      header: t('planes.device.column.observed'),
      render: (n) => <DateTime value={n.observed_at} />,
    },
  ]
  return (
    <section id="plane-panel-device" role="tabpanel" className={styles.panelGrid}>
      <div className={styles.stack}>
        <IdentityConflictsCard surface="device" />
        <DeviceCollectionOutcomesCard />
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
          <CardHeader
            title={t('planes.device.neighbors.title')}
            description={t('planes.device.neighbors.description')}
            actions={
              neighborsTruncated ? (
                <Badge tone="warning">{t('planes.device.neighbors.truncated')}</Badge>
              ) : null
            }
          />
          <CardBody>
            {neighborsLoading ? (
              <LoadingState label={t('planes.device.neighbors.loading')} />
            ) : neighborsError ? (
              <ErrorState description={t('planes.device.neighbors.error')} />
            ) : neighborsRunning === false ? (
              <EmptyState
                title={t('planes.device.neighbors.unavailable.title')}
                description={t('planes.device.neighbors.unavailable.description')}
              />
            ) : (
              <Table
                caption={t('planes.device.neighbors.caption')}
                columns={neighborColumns}
                rows={neighbors}
                rowKey={(n) => n.id}
                empty={
                  <EmptyState
                    title={t('planes.device.neighbors.empty.title')}
                    description={t('planes.device.neighbors.empty.description')}
                    preview={<PlanesPreview />}
                  />
                }
              />
            )}
            {neighborRetentionHours ? (
              <p className={styles.muted}>
                {t('planes.device.neighbors.retention', { hours: neighborRetentionHours })}
              </p>
            ) : null}
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
          [t('planes.device.summary.physicalLinks'), compact(physicalEdges.length, locale)],
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
