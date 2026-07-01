import { useMemo } from 'react'
import styles from './dashboards.module.css'
import { Page } from './pages'
import {
  Badge,
  Card,
  CardBody,
  CardHeader,
  ChartShell,
  EmptyState,
  ErrorState,
  LoadingState,
  Sparkline,
  Table,
  type Column,
} from '../components'
import { flattenAgents, useAgents, type Agent } from '../api/agents'
import { useActiveAlerts, type ActiveAlert } from '../api/alerts'
import { useCompliance, type ComplianceCoverage, type RuleResult } from '../api/compliance'
import { gib, usd, useCostSummary, type BudgetStatus } from '../api/cost'
import {
  useFlowAnomalies,
  useFlowCapacity,
  useFlowTop,
  type FlowAnomaly,
  type FlowTopRow,
} from '../api/planes'
import { useIncidents, severityTone, type Incident } from '../api/incidents'
import { useLatestResults, type LatestResult } from '../api/results'
import { pct, useSLOs, type SLOStatus } from '../api/slos'
import { useDetections, type Detection } from '../api/threat'
import { useTests, type Test } from '../api/tests'
import { useTopology, type TopoEdge, type TopoNode } from '../api/topology'
import { useAuth } from '../auth/useAuth'
import { DateTime } from '../time/DateTime'
import { useI18n } from '../i18n/useI18n'
import {
  formatDecimal,
  formatInteger,
  formatMultiplier,
  formatRatioPercent,
  formatScaledBitRate,
} from '../i18n/number'

function compact(n: number, locale: string): string {
  return formatInteger(n, locale)
}

function flowBytes(n: number, locale: string): string {
  return `${gib(n, locale)} GiB`
}

function metricTone(value: number, healthyWhenZero = true): 'success' | 'warning' | 'danger' {
  if (healthyWhenZero) return value === 0 ? 'success' : value > 2 ? 'danger' : 'warning'
  return value > 0 ? 'success' : 'warning'
}

type MetricTone = 'success' | 'warning' | 'danger'

interface ActiveTestRow {
  test: Test
  latest?: LatestResult
}

interface PlaneRow {
  id: string
  name: string
  status: string
  tone: MetricTone
  detail: string
  value: string
}

const EMPTY_TESTS: Test[] = []
const EMPTY_RESULTS: LatestResult[] = []
const EMPTY_FLOW_ANOMALIES: FlowAnomaly[] = []

export function DashboardsPage() {
  const { locale } = useI18n()
  const { tenant, user } = useAuth()
  const tests = useTests()
  const agentsQuery = useAgents()
  const incidents = useIncidents()
  const alerts = useActiveAlerts()
  const results = useLatestResults()
  const flowTop = useFlowTop('pair', '1h', 5)
  const flowCapacity = useFlowCapacity('1h', '5m')
  const flowAnomalies = useFlowAnomalies('1h', '5m')
  const topology = useTopology()
  const cost = useCostSummary()
  const slos = useSLOs()
  const compliance = useCompliance()
  const detections = useDetections()

  const testItems = tests.data ?? EMPTY_TESTS
  const enabledTests = testItems.filter((t) => t.enabled)
  const agents = flattenAgents(agentsQuery.data?.pages)
  const onlineAgents = agents.filter((a) => a.status === 'online')
  const incidentItems = incidents.data ?? []
  const openIncidents = incidentItems.filter((i) => i.status === 'open')
  const activeAlerts = alerts.data?.items ?? []
  const latestResults = results.data?.items ?? EMPTY_RESULTS
  const successfulResults = latestResults.filter((r) => r.success).length
  const successRate = latestResults.length > 0 ? successfulResults / latestResults.length : 0
  const topFlows = flowTop.data?.items ?? []
  const flowTotal = topFlows.reduce((sum, row) => sum + row.bytes, 0)
  const capacityPoints = flowCapacity.data?.items ?? []
  const latestCapacity = capacityPoints[capacityPoints.length - 1]
  const capacityTrend = capacityPoints.map((p) => p.bps)
  const anomalies = flowAnomalies.data?.items ?? EMPTY_FLOW_ANOMALIES
  const sloItems = slos.data?.items ?? []
  const burningSLOs = sloItems.filter((s) => s.burn_rates.some((b) => b.firing || b.burn > b.limit))
  const complianceItems = compliance.data?.items ?? []
  const complianceCoverage = compliance.data?.coverage
  const violations = complianceItems.filter((r) => r.verdict === 'violation')
  const nodes = topology.data?.nodes ?? []
  const edges = topology.data?.edges ?? []
  const serviceNodes = nodes.filter((n) => n.kind === 'service').length
  const asNodes = nodes.filter((n) => n.kind === 'as')
  const prefixNodes = nodes.filter((n) => n.kind === 'prefix')
  const deviceNodes = nodes.filter((n) => n.kind === 'device')
  const routingEdges = edges.filter((e) => e.kind === 'routing')
  const flowEdges = edges.filter((e) => e.kind === 'flow')
  const deviceEdges = edges.filter((e) => e.kind === 'device')
  const costSummary = cost.data?.summary
  const costTrend = (costSummary?.trend ?? []).map((p) => p.usd)
  const latencyTrend = latestResults.map((r) => r.duration_ms ?? r.metrics?.['rtt.avg.ms'] ?? 0)
  const threatItems = detections.data?.items ?? []
  const latestByTarget = useMemo(() => {
    const byTarget = new Map<string, LatestResult>()
    for (const result of latestResults) {
      if (result.target) byTarget.set(result.target, result)
    }
    return byTarget
  }, [latestResults])
  const activeTestRows = useMemo<ActiveTestRow[]>(
    () =>
      testItems.slice(0, 6).map((test) => ({
        test,
        latest: test.target ? latestByTarget.get(test.target) : undefined,
      })),
    [latestByTarget, testItems],
  )
  const bgpRows = useMemo(
    () => bgpDashboardRows(routingEdges, asNodes, prefixNodes),
    [asNodes, prefixNodes, routingEdges],
  )
  const deviceRows = useMemo(
    () => deviceDashboardRows(deviceNodes, deviceEdges, agents, locale),
    [agents, deviceEdges, deviceNodes, locale],
  )
  const ebpfRows = useMemo(
    () => ebpfDashboardRows(flowEdges, anomalies, complianceCoverage, agents, locale),
    [agents, anomalies, complianceCoverage, flowEdges, locale],
  )
  const tenantHealthRows = useMemo(
    () =>
      tenantHealthDashboardRows({
        tenantID: tenant.id,
        userEmail: user.email,
        agents,
        topologyRunning: topology.data?.topology_running ?? false,
        costRunning: cost.data?.cost_running ?? false,
        complianceRunning: compliance.data?.compliance_running ?? false,
        detectionsRunning: detections.data?.detections_running ?? false,
        locale,
      }),
    [
      agents,
      compliance.data?.compliance_running,
      cost.data?.cost_running,
      detections.data?.detections_running,
      locale,
      tenant.id,
      topology.data?.topology_running,
      user.email,
    ],
  )

  const anyLoading =
    tests.isLoading ||
    agentsQuery.isLoading ||
    incidents.isLoading ||
    alerts.isLoading ||
    results.isLoading ||
    flowTop.isLoading ||
    flowCapacity.isLoading ||
    flowAnomalies.isLoading ||
    topology.isLoading ||
    cost.isLoading ||
    slos.isLoading ||
    compliance.isLoading ||
    detections.isLoading
  const anyError =
    tests.isError ||
    agentsQuery.isError ||
    incidents.isError ||
    alerts.isError ||
    results.isError ||
    flowTop.isError ||
    flowCapacity.isError ||
    flowAnomalies.isError ||
    topology.isError ||
    cost.isError ||
    slos.isError ||
    compliance.isError ||
    detections.isError

  return (
    <Page
      title="Dashboards"
      subtitle="Curated operating view across active tests, routing, flow, device, eBPF, cost, threat, and tenant health."
    >
      {anyError ? (
        <ErrorState description="Could not load every dashboard panel." />
      ) : anyLoading ? (
        <LoadingState label="Loading dashboards..." />
      ) : (
        <>
          <div className={styles.metrics}>
            <DashboardMetric
              label="Active tests"
              value={enabledTests.length}
              detail={`${formatInteger(testItems.length, locale)} tests, ${formatRatioPercent(
                successRate,
                locale,
                { maximumFractionDigits: 1 },
              )} latest success`}
              tone={enabledTests.length > 0 ? 'success' : 'warning'}
              locale={locale}
            />
            <DashboardMetric
              label="BGP routes"
              value={routingEdges.length}
              detail={`${formatInteger(asNodes.length, locale)} AS nodes, ${formatInteger(
                prefixNodes.length,
                locale,
              )} prefixes`}
              tone={routingEdges.length > 0 ? 'success' : 'warning'}
              locale={locale}
            />
            <DashboardMetric
              label="Flow volume"
              value={flowBytes(flowTotal, locale)}
              detail={`${formatInteger(topFlows.length, locale)} ranked contributors`}
              tone={metricTone(topFlows.length, false)}
              locale={locale}
            />
            <DashboardMetric
              label="Device nodes"
              value={deviceNodes.length}
              detail={`${formatInteger(deviceEdges.length, locale)} device topology edges`}
              tone={deviceNodes.length > 0 ? 'success' : 'warning'}
              locale={locale}
            />
            <DashboardMetric
              label="eBPF evidence"
              value={complianceCoverage?.ebpf_observed ? 'observed' : 'watch'}
              detail={`${formatInteger(flowEdges.length, locale)} L7/service edges, ${formatInteger(
                anomalies.length,
                locale,
              )} anomalies`}
              tone={complianceCoverage?.ebpf_observed ? 'success' : 'warning'}
              locale={locale}
            />
            <DashboardMetric
              label="Cost"
              value={costSummary ? usd(costSummary.total_usd, locale) : 'unpriced'}
              detail={
                costSummary
                  ? `${flowBytes(costSummary.total_bytes, locale)} attributed`
                  : 'waiting for cost summary'
              }
              tone={costSummary?.priced ? 'success' : 'warning'}
              locale={locale}
            />
            <DashboardMetric
              label="Threat signals"
              value={threatItems.length}
              detail={`${formatInteger(
                threatItems.filter((d) => d.severity === 'critical').length,
                locale,
              )} critical`}
              tone={metricTone(threatItems.length)}
              locale={locale}
            />
            <DashboardMetric
              label="Tenant health"
              value={`${formatInteger(
                tenantHealthRows.filter((r) => r.tone === 'success').length,
                locale,
              )}/${formatInteger(tenantHealthRows.length, locale)}`}
              detail={`${formatInteger(onlineAgents.length, locale)} of ${formatInteger(
                agents.length,
                locale,
              )} collectors online`}
              tone={
                onlineAgents.length === agents.length && agents.length > 0 ? 'success' : 'warning'
              }
              locale={locale}
            />
          </div>

          <div className={styles.grid}>
            <Card>
              <CardHeader
                title="Cost and capacity"
                description={`${formatInteger(serviceNodes, locale)} services visible in topology`}
              />
              <CardBody className={styles.chartStack}>
                <ChartShell
                  title="Network cost"
                  legend={
                    costSummary
                      ? `${flowBytes(costSummary.total_bytes, locale)} total egress, ${usd(
                          costSummary.total_usd,
                          locale,
                        )}`
                      : 'No cost summary'
                  }
                >
                  <Sparkline data={costTrend.length > 0 ? costTrend : [0]} label="Cost trend" />
                </ChartShell>
                <ChartShell
                  title="Flow capacity"
                  legend={
                    latestCapacity
                      ? `${formatScaledBitRate(latestCapacity.bps, locale)} at ${latestCapacity.exporter} if${latestCapacity.iface}`
                      : `${capacityPoints.length} tenant capacity samples`
                  }
                >
                  <Sparkline
                    data={capacityTrend.length > 0 ? capacityTrend : [0]}
                    label="Flow capacity trend"
                  />
                </ChartShell>
                <ChartShell
                  title="Latest test latency"
                  legend={`${latestResults.length} latest synthetic results`}
                >
                  <Sparkline
                    data={latencyTrend.length > 0 ? latencyTrend : [0]}
                    label="Synthetic latency trend"
                  />
                </ChartShell>
                <CostBudgetTable rows={costSummary?.budgets ?? []} locale={locale} />
              </CardBody>
            </Card>

            <Card>
              <CardHeader
                title="Active tests"
                description="Synthetic coverage and newest result by target."
              />
              <CardBody>
                <ActiveTestTable rows={activeTestRows} locale={locale} />
              </CardBody>
            </Card>

            <Card>
              <CardHeader
                title="BGP routing"
                description="AS, prefix, and routing-edge coverage."
              />
              <CardBody>
                <PlaneTable
                  caption="BGP routing dashboard"
                  rows={bgpRows}
                  emptyTitle="No BGP routing evidence"
                />
              </CardBody>
            </Card>

            <Card>
              <CardHeader title="Flow contributors" />
              <CardBody>
                <FlowTable rows={topFlows.slice(0, 5)} locale={locale} />
              </CardBody>
            </Card>

            <Card>
              <CardHeader
                title="Device inventory"
                description="Device topology and collector evidence."
              />
              <CardBody>
                <PlaneTable
                  caption="Device inventory dashboard"
                  rows={deviceRows}
                  emptyTitle="No device inventory evidence"
                />
              </CardBody>
            </Card>

            <Card>
              <CardHeader
                title="eBPF / L7"
                description="Host and service-edge evidence without enforcement."
              />
              <CardBody>
                <PlaneTable
                  caption="eBPF evidence dashboard"
                  rows={ebpfRows}
                  emptyTitle="No eBPF evidence"
                />
              </CardBody>
            </Card>

            <Card>
              <CardHeader
                title="Threat signals"
                description="Confidence-scored detections, never inline blocking."
              />
              <CardBody>
                <ThreatTable rows={threatItems.slice(0, 5)} locale={locale} />
              </CardBody>
            </Card>

            <Card>
              <CardHeader
                title="Tenant health"
                description={`Session-scoped to tenant ${tenant.id}`}
              />
              <CardBody>
                <PlaneTable
                  caption="Tenant health dashboard"
                  rows={tenantHealthRows}
                  emptyTitle="No tenant health signals"
                />
              </CardBody>
            </Card>

            <Card>
              <CardHeader title="Incident watch" />
              <CardBody>
                <IncidentTable incidents={openIncidents.slice(0, 5)} locale={locale} />
              </CardBody>
            </Card>

            <Card>
              <CardHeader title="SLO burn" />
              <CardBody>
                <SLOTable rows={burningSLOs.slice(0, 5)} locale={locale} />
              </CardBody>
            </Card>

            <Card>
              <CardHeader title="Alert signals" />
              <CardBody>
                <AlertTable rows={activeAlerts.slice(0, 5)} />
              </CardBody>
            </Card>

            <Card>
              <CardHeader title="Policy posture" />
              <CardBody>
                <ComplianceTable rows={violations.slice(0, 5)} />
              </CardBody>
            </Card>
          </div>
        </>
      )}
    </Page>
  )
}

function DashboardMetric({
  label,
  value,
  detail,
  tone,
  locale,
}: {
  label: string
  value: number | string
  detail: string
  tone: 'success' | 'warning' | 'danger'
  locale: string
}) {
  return (
    <Card>
      <CardBody className={styles.metric}>
        <span className={styles.metricLabel}>{label}</span>
        <span className={styles.metricValue}>
          {typeof value === 'number' ? compact(value, locale) : value}
        </span>
        <span className={styles.metricDetail}>{detail}</span>
        <Badge tone={tone}>{tone === 'success' ? 'steady' : 'watch'}</Badge>
      </CardBody>
    </Card>
  )
}

function ActiveTestTable({ rows, locale }: { rows: ActiveTestRow[]; locale: string }) {
  const columns: Column<ActiveTestRow>[] = [
    {
      key: 'test',
      header: 'Test',
      render: ({ test }) => (
        <span>
          <strong>{test.name}</strong>
          <span className={styles.inlineDetail}> {test.target}</span>
        </span>
      ),
    },
    { key: 'type', header: 'Type', render: ({ test }) => <Badge tone="info">{test.type}</Badge> },
    {
      key: 'latest',
      header: 'Latest',
      render: ({ test, latest }) =>
        latest ? (
          <Badge tone={latest.success ? 'success' : 'danger'}>
            {latest.success ? 'passing' : 'failing'}
          </Badge>
        ) : test.enabled ? (
          <Badge tone="warning">scheduled</Badge>
        ) : (
          <Badge tone="neutral">disabled</Badge>
        ),
    },
    {
      key: 'duration',
      header: 'Latency',
      numeric: true,
      render: ({ latest }) =>
        latest?.duration_ms ? `${formatDecimal(latest.duration_ms, locale)} ms` : 'pending',
    },
  ]
  return (
    <Table
      caption="Active tests dashboard"
      columns={columns}
      rows={rows}
      rowKey={(r) => r.test.id}
      empty={<EmptyState title="No active tests" description="Create a synthetic test first." />}
    />
  )
}

function PlaneTable({
  caption,
  rows,
  emptyTitle,
}: {
  caption: string
  rows: PlaneRow[]
  emptyTitle: string
}) {
  const columns: Column<PlaneRow>[] = [
    { key: 'status', header: 'Status', render: (r) => <Badge tone={r.tone}>{r.status}</Badge> },
    { key: 'name', header: 'Name', render: (r) => <strong>{r.name}</strong> },
    { key: 'detail', header: 'Detail', render: (r) => r.detail },
    { key: 'value', header: 'Value', render: (r) => r.value },
  ]
  return (
    <Table
      caption={caption}
      columns={columns}
      rows={rows}
      rowKey={(r) => r.id}
      empty={<EmptyState title={emptyTitle} description="This tenant has no served data yet." />}
    />
  )
}

function CostBudgetTable({ rows, locale }: { rows: BudgetStatus[]; locale: string }) {
  const columns: Column<BudgetStatus>[] = [
    { key: 'scope', header: 'Scope', render: (b) => `${b.kind}: ${b.name}` },
    { key: 'spent', header: 'Spent', numeric: true, render: (b) => usd(b.spent_usd, locale) },
    { key: 'budget', header: 'Budget', numeric: true, render: (b) => usd(b.monthly_usd, locale) },
    {
      key: 'state',
      header: 'State',
      render: (b) => (
        <Badge tone={b.exceeded ? 'danger' : 'success'}>{b.exceeded ? 'over' : 'ok'}</Badge>
      ),
    },
  ]
  return (
    <Table
      caption="Cost budget dashboard"
      columns={columns}
      rows={rows}
      rowKey={(b) => `${b.kind}-${b.name}`}
      empty={
        <EmptyState title="No cost budgets" description="Budget definitions are not configured." />
      }
    />
  )
}

function ThreatTable({ rows, locale }: { rows: Detection[]; locale: string }) {
  const columns: Column<Detection>[] = [
    {
      key: 'severity',
      header: 'Severity',
      render: (d) => <Badge tone={severityTone(d.severity)}>{d.severity}</Badge>,
    },
    { key: 'title', header: 'Detection', render: (d) => <strong>{d.title}</strong> },
    {
      key: 'confidence',
      header: 'Confidence',
      numeric: true,
      render: (d) =>
        d.confidence === undefined
          ? 'n/a'
          : formatRatioPercent(d.confidence, locale, { maximumFractionDigits: 0 }),
    },
    { key: 'source', header: 'Source', render: (d) => d.source || d.plane },
  ]
  return (
    <Table
      caption="Threat signal dashboard"
      columns={columns}
      rows={rows}
      rowKey={(d) => d.id}
      empty={<EmptyState title="No threat detections" description="Detection engine is quiet." />}
    />
  )
}

function bgpDashboardRows(
  edges: TopoEdge[],
  asNodes: TopoNode[],
  prefixNodes: TopoNode[],
): PlaneRow[] {
  const labels = new Map([...asNodes, ...prefixNodes].map((node) => [node.id, node.label]))
  const rows: PlaneRow[] = edges.slice(0, 5).map((edge, i) => ({
    id: `bgp-edge-${i}-${edge.from}-${edge.to}`,
    name:
      edge.label || `${labels.get(edge.from) ?? edge.from} -> ${labels.get(edge.to) ?? edge.to}`,
    status: 'observed',
    tone: 'success',
    detail: `${labels.get(edge.from) ?? edge.from} to ${labels.get(edge.to) ?? edge.to}`,
    value: 'routing edge',
  }))
  if (rows.length > 0) return rows
  if (asNodes.length === 0 && prefixNodes.length === 0) return []
  return [
    {
      id: 'bgp-node-coverage',
      name: 'BGP node coverage',
      status: 'partial',
      tone: 'warning',
      detail: `${asNodes.length} AS nodes, ${prefixNodes.length} prefixes`,
      value: 'waiting for routing edges',
    },
  ]
}

function deviceDashboardRows(
  deviceNodes: TopoNode[],
  deviceEdges: TopoEdge[],
  agents: Agent[],
  locale: string,
): PlaneRow[] {
  const collectors = agentsWithCapability(agents, 'device')
  return deviceNodes.slice(0, 5).map((node) => {
    const edgeCount = deviceEdges.filter(
      (edge) => edge.from === node.id || edge.to === node.id,
    ).length
    return {
      id: node.id,
      name: node.label,
      status: 'observed',
      tone: 'success',
      detail: `${formatInteger(edgeCount, locale)} topology edges`,
      value:
        collectors.length > 0
          ? `${formatInteger(collectors.length, locale)} device collectors`
          : 'topology evidence',
    }
  })
}

function ebpfDashboardRows(
  flowEdges: TopoEdge[],
  anomalies: FlowAnomaly[],
  coverage: ComplianceCoverage | undefined,
  agents: Agent[],
  locale: string,
): PlaneRow[] {
  const collectors = agentsWithCapability(agents, 'ebpf')
  const rows: PlaneRow[] = flowEdges.slice(0, 5).map((edge, i) => ({
    id: `ebpf-edge-${i}-${edge.from}-${edge.to}`,
    name: edge.label || `${edge.from} -> ${edge.to}`,
    status: coverage?.ebpf_observed ? 'observed' : 'flow-only',
    tone: coverage?.ebpf_observed ? 'success' : 'warning',
    detail: `${edge.from} to ${edge.to}`,
    value:
      collectors.length > 0
        ? `${formatInteger(collectors.length, locale)} eBPF collectors`
        : `${formatInteger(anomalies.length, locale)} anomaly signals`,
  }))
  if (rows.length > 0) return rows
  return anomalies.slice(0, 5).map((a) => ({
    id: `ebpf-anomaly-${a.exporter}-${a.iface}-${a.ts}`,
    name: `${a.exporter || 'exporter'} if${a.iface}`,
    status: 'anomaly',
    tone: 'warning',
    detail: a.model || 'local model',
    value: `${formatDecimal(a.sigma, locale, { maximumFractionDigits: 1 })} sigma`,
  }))
}

function tenantHealthDashboardRows({
  tenantID,
  userEmail,
  agents,
  topologyRunning,
  costRunning,
  complianceRunning,
  detectionsRunning,
  locale,
}: {
  tenantID: string
  userEmail: string
  agents: Agent[]
  topologyRunning: boolean
  costRunning: boolean
  complianceRunning: boolean
  detectionsRunning: boolean
  locale: string
}): PlaneRow[] {
  const online = agents.filter((a) => a.status === 'online').length
  return [
    {
      id: 'tenant-scope',
      name: 'Tenant scope',
      status: 'scoped',
      tone: 'success',
      detail: tenantID,
      value: userEmail,
    },
    {
      id: 'collector-fleet',
      name: 'Collector fleet',
      status: online === agents.length && agents.length > 0 ? 'steady' : 'watch',
      tone: online === agents.length && agents.length > 0 ? 'success' : 'warning',
      detail: `${formatInteger(online, locale)} of ${formatInteger(agents.length, locale)} online`,
      value: capabilitySummary(agents),
    },
    {
      id: 'engines',
      name: 'Engines',
      status:
        topologyRunning && costRunning && complianceRunning && detectionsRunning
          ? 'running'
          : 'watch',
      tone:
        topologyRunning && costRunning && complianceRunning && detectionsRunning
          ? 'success'
          : 'warning',
      detail: 'topology, cost, compliance, threat',
      value: `${formatInteger(
        [topologyRunning, costRunning, complianceRunning, detectionsRunning].filter(Boolean).length,
        locale,
      )}/4 running`,
    },
  ]
}

function agentsWithCapability(agents: Agent[], capability: string): Agent[] {
  return agents.filter((agent) => agent.capabilities.includes(capability))
}

function capabilitySummary(agents: Agent[]): string {
  const caps = new Set(agents.flatMap((a) => a.capabilities))
  return caps.size > 0 ? [...caps].sort().join(', ') : 'no capabilities'
}

function IncidentTable({ incidents, locale }: { incidents: Incident[]; locale: string }) {
  const columns: Column<Incident>[] = [
    {
      key: 'severity',
      header: 'Severity',
      render: (i) => <Badge tone={severityTone(i.severity)}>{i.severity}</Badge>,
    },
    {
      key: 'title',
      header: 'Incident',
      render: (i) => <strong>{i.title || i.target || i.id}</strong>,
    },
    {
      key: 'signals',
      header: 'Signals',
      numeric: true,
      render: (i) => formatInteger(i.signal_count, locale),
    },
    { key: 'seen', header: 'Last seen', render: (i) => <DateTime value={i.last_seen_at} /> },
  ]
  return (
    <Table
      caption="Open incident dashboard"
      columns={columns}
      rows={incidents}
      rowKey={(i) => i.id}
      empty={<EmptyState title="No open incidents" description="Correlated incidents are quiet." />}
    />
  )
}

function FlowTable({ rows, locale }: { rows: FlowTopRow[]; locale: string }) {
  const columns: Column<FlowTopRow>[] = [
    {
      key: 'key',
      header: 'Contributor',
      render: (r) => (
        <span>
          <strong>{r.key}</strong>
          {r.detail ? <span className={styles.inlineDetail}> {r.detail}</span> : null}
        </span>
      ),
    },
    { key: 'bytes', header: 'Bytes', numeric: true, render: (r) => flowBytes(r.bytes, locale) },
    { key: 'flows', header: 'Flows', numeric: true, render: (r) => compact(r.flows, locale) },
  ]
  return (
    <Table
      caption="Top flow contributors dashboard"
      columns={columns}
      rows={rows}
      rowKey={(r) => `${r.key}-${r.detail ?? ''}`}
      empty={<EmptyState title="No flow contributors" description="Flow collectors are quiet." />}
    />
  )
}

function SLOTable({ rows, locale }: { rows: SLOStatus[]; locale: string }) {
  const columns: Column<SLOStatus>[] = [
    { key: 'name', header: 'SLO', render: (s) => <strong>{s.display_name || s.name}</strong> },
    {
      key: 'budget',
      header: 'Budget',
      render: (s) => `${pct(s.error_budget_remaining, locale)} left`,
    },
    {
      key: 'burn',
      header: 'Burn',
      render: (s) => {
        const firing = s.burn_rates.find((b) => b.firing || b.burn > b.limit)
        return firing ? (
          <Badge tone="danger">{`${firing.window} ${formatMultiplier(firing.burn, locale)}`}</Badge>
        ) : (
          'steady'
        )
      },
    },
  ]
  return (
    <Table
      caption="SLO burn dashboard"
      columns={columns}
      rows={rows}
      rowKey={(s) => s.name}
      empty={<EmptyState title="No SLO burn" description="No SLO is above its burn threshold." />}
    />
  )
}

function AlertTable({ rows }: { rows: ActiveAlert[] }) {
  const columns: Column<ActiveAlert>[] = [
    {
      key: 'severity',
      header: 'Severity',
      render: (a) => <Badge tone={severityTone(a.severity)}>{a.severity}</Badge>,
    },
    { key: 'rule', header: 'Rule', render: (a) => <strong>{a.rule_name}</strong> },
    { key: 'reason', header: 'Reason', render: (a) => a.reason },
  ]
  return (
    <Table
      caption="Active alert dashboard"
      columns={columns}
      rows={rows}
      rowKey={(a) => a.fingerprint}
      empty={<EmptyState title="No active alerts" description="Alert evaluator is quiet." />}
    />
  )
}

function ComplianceTable({ rows }: { rows: RuleResult[] }) {
  const columns: Column<RuleResult>[] = [
    { key: 'rule', header: 'Rule', render: (r) => <strong>{r.rule_id}</strong> },
    { key: 'path', header: 'Path', render: (r) => `${r.from} to ${r.to}` },
    { key: 'violations', header: 'Violations', numeric: true, render: (r) => r.violations },
  ]
  return (
    <Table
      caption="Segmentation violation dashboard"
      columns={columns}
      rows={rows}
      rowKey={(r) => `${r.policy}-${r.rule_id}`}
      empty={
        <EmptyState title="No segmentation violations" description="Observed policies are clean." />
      }
    />
  )
}
