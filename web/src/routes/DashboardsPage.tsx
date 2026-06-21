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
import { useActiveAlerts, type ActiveAlert } from '../api/alerts'
import { useCompliance, type RuleResult } from '../api/compliance'
import { gib, usd, useCostSummary } from '../api/cost'
import { useFlowTop, type FlowTopRow } from '../api/planes'
import { useIncidents, severityTone, type Incident } from '../api/incidents'
import { useLatestResults } from '../api/results'
import { pct, useSLOs, type SLOStatus } from '../api/slos'
import { useTopology } from '../api/topology'
import { DateTime } from '../time/DateTime'
import { useI18n } from '../i18n/useI18n'
import { formatInteger, formatMultiplier, formatRatioPercent } from '../i18n/number'

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

export function DashboardsPage() {
  const { locale } = useI18n()
  const incidents = useIncidents()
  const alerts = useActiveAlerts()
  const results = useLatestResults()
  const flowTop = useFlowTop('pair', '1h', 5)
  const topology = useTopology()
  const cost = useCostSummary()
  const slos = useSLOs()
  const compliance = useCompliance()

  const incidentItems = incidents.data ?? []
  const openIncidents = incidentItems.filter((i) => i.status === 'open')
  const activeAlerts = alerts.data?.items ?? []
  const latestResults = results.data?.items ?? []
  const successfulResults = latestResults.filter((r) => r.success).length
  const successRate = latestResults.length > 0 ? successfulResults / latestResults.length : 0
  const topFlows = flowTop.data?.items ?? []
  const flowTotal = topFlows.reduce((sum, row) => sum + row.bytes, 0)
  const sloItems = slos.data?.items ?? []
  const burningSLOs = sloItems.filter((s) => s.burn_rates.some((b) => b.firing || b.burn > b.limit))
  const complianceItems = compliance.data?.items ?? []
  const violations = complianceItems.filter((r) => r.verdict === 'violation')
  const serviceNodes = topology.data?.nodes.filter((n) => n.kind === 'service').length ?? 0
  const costSummary = cost.data?.summary
  const costTrend = (costSummary?.trend ?? []).map((p) => p.usd)
  const latencyTrend = latestResults.map((r) => r.duration_ms ?? r.metrics?.['rtt.avg.ms'] ?? 0)

  const anyLoading =
    incidents.isLoading ||
    alerts.isLoading ||
    results.isLoading ||
    flowTop.isLoading ||
    topology.isLoading ||
    cost.isLoading ||
    slos.isLoading ||
    compliance.isLoading
  const anyError =
    incidents.isError ||
    alerts.isError ||
    results.isError ||
    flowTop.isError ||
    topology.isError ||
    cost.isError ||
    slos.isError ||
    compliance.isError

  return (
    <Page
      title="Dashboards"
      subtitle="Curated operating view across incidents, signals, traffic, service health, and policy posture."
    >
      {anyError ? (
        <ErrorState description="Could not load every dashboard panel." />
      ) : anyLoading ? (
        <LoadingState label="Loading dashboards..." />
      ) : (
        <>
          <div className={styles.metrics}>
            <DashboardMetric
              label="Open incidents"
              value={openIncidents.length}
              detail={`${formatInteger(incidentItems.length, locale)} total incidents`}
              tone={metricTone(openIncidents.length)}
              locale={locale}
            />
            <DashboardMetric
              label="Active alerts"
              value={activeAlerts.length}
              detail={`${formatInteger(
                activeAlerts.filter((a) => a.severity === 'critical').length,
                locale,
              )} critical`}
              tone={metricTone(activeAlerts.length)}
              locale={locale}
            />
            <DashboardMetric
              label="Synthetic success"
              value={formatRatioPercent(successRate, locale, { maximumFractionDigits: 1 })}
              detail={`${formatInteger(successfulResults, locale)}/${formatInteger(
                latestResults.length,
                locale,
              )} latest results`}
              tone={
                latestResults.length === 0 ? 'warning' : successRate >= 0.99 ? 'success' : 'warning'
              }
              locale={locale}
            />
            <DashboardMetric
              label="Top flow volume"
              value={flowBytes(flowTotal, locale)}
              detail={`${formatInteger(topFlows.length, locale)} ranked contributors`}
              tone={metricTone(topFlows.length, false)}
              locale={locale}
            />
            <DashboardMetric
              label="SLO burn watch"
              value={burningSLOs.length}
              detail={`${formatInteger(sloItems.length, locale)} SLO definitions`}
              tone={metricTone(burningSLOs.length)}
              locale={locale}
            />
            <DashboardMetric
              label="Segmentation violations"
              value={violations.length}
              detail={`${formatInteger(complianceItems.length, locale)} policy checks`}
              tone={metricTone(violations.length)}
              locale={locale}
            />
          </div>

          <div className={styles.grid}>
            <Card>
              <CardHeader
                title="Traffic and spend"
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
                  title="Latest test latency"
                  legend={`${latestResults.length} latest synthetic results`}
                >
                  <Sparkline
                    data={latencyTrend.length > 0 ? latencyTrend : [0]}
                    label="Synthetic latency trend"
                  />
                </ChartShell>
              </CardBody>
            </Card>

            <Card>
              <CardHeader title="Incident watch" />
              <CardBody>
                <IncidentTable incidents={openIncidents.slice(0, 5)} locale={locale} />
              </CardBody>
            </Card>

            <Card>
              <CardHeader title="Flow contributors" />
              <CardBody>
                <FlowTable rows={topFlows.slice(0, 5)} locale={locale} />
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
