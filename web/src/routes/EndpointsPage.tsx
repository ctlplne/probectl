import { useMemo, useState, type FormEvent } from 'react'
import styles from './security.module.css'
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
  Modal,
  Select,
  Table,
  useToast,
  type Column,
} from '../components'
import {
  attr,
  causeLabel,
  causeTone,
  metric,
  useCreateEndpointSavedView,
  useEndpoints,
  useEndpointSavedViews,
  type DEMResult,
  type EndpointView,
  type SavedInventoryView,
} from '../api/endpoints'
import { useRUM, type RUMAppStatus, type RUMVerdict } from '../api/rum'
import { DateTime } from '../time/DateTime'
import { useI18n } from '../i18n/useI18n'
import {
  formatCount,
  formatDecimal,
  formatInteger,
  formatPercentValue,
  formatUnit,
} from '../i18n/number'

/** withheld renders a privacy-minimized identifier honestly: the agent chose
 *  not to collect it, so the UI says so — it never invents a value. */
const WITHHELD = 'withheld (privacy)'

function idOrWithheld(value?: string): string {
  return value && value !== '' ? value : WITHHELD
}

/** num renders an optional metric ("—" when the OS did not report it). */
function num(v: number | undefined, unit = '', digits = 1, locale = 'en'): string {
  if (v === undefined) return '—'
  const suffix = unit.trim()
  if (suffix === '%') return formatPercentValue(v, locale, { maximumFractionDigits: digits })
  if (suffix) return formatUnit(v, suffix, locale, { maximumFractionDigits: digits })
  return formatDecimal(v, locale, { maximumFractionDigits: digits })
}

function verdictBadge(v: EndpointView) {
  return (
    <Badge tone={causeTone(v.cause, v.slow)}>
      {v.slow ? `slow: ${causeLabel(v.cause)}` : 'healthy'}
    </Badge>
  )
}

function wifiSummary(v: EndpointView, locale: string): string {
  const rssi = metric(v.wifi, 'rssi_dbm')
  const signal = metric(v.wifi, 'signal_pct')
  const band = attr(v.wifi, 'wifi.band')
  if (rssi === undefined && signal === undefined) return v.wifi ? '—' : 'no WiFi'
  const strength =
    rssi !== undefined ? `${num(rssi, 'dBm', 0, locale)}` : `${num(signal, '%', 0, locale)}`
  return band ? `${strength} · ${band}` : strength
}

/** LayerScores renders the attribution engine's per-layer assessment. */
function LayerScores({ a, locale }: { a: DEMResult; locale: string }) {
  const layers: Array<[string, string]> = [
    ['WiFi', 'wifi_score'],
    ['Local', 'local_score'],
    ['ISP', 'isp_score'],
    ['Network', 'network_score'],
  ]
  return (
    <ul className={styles.findings}>
      {layers.map(([label, key]) => {
        const score = metric(a, key)
        if (score === undefined) return null
        return (
          <li key={key}>
            <Badge tone={score > 0 ? 'warning' : 'success'}>{label}</Badge>
            <span>severity {num(score, '', 2, locale)}</span>
          </li>
        )
      })}
    </ul>
  )
}

/** EndpointDetail is the per-endpoint view: WiFi, gateway/local network,
 *  ISP/last-mile segments, sessions, and the attribution verdict. */
function EndpointDetail({ view, onClose }: { view: EndpointView; onClose: () => void }) {
  const { locale } = useI18n()
  const fmt = (v: number | undefined, unit = '', digits = 1) => num(v, unit, digits, locale)
  const hops = metric(view.last_mile, 'hops')
  const sessions = view.sessions ?? []
  return (
    <Modal open onClose={onClose} title={view.agent_id}>
      <dl className={styles.kv}>
        <dt>Verdict</dt>
        <dd>
          {verdictBadge(view)}
          {view.confidence ? <> confidence {fmt(view.confidence, '', 2)}</> : null}
        </dd>
        {view.summary ? (
          <>
            <dt>Why</dt>
            <dd>{view.summary}</dd>
          </>
        ) : null}
        <dt>Last seen</dt>
        <dd>
          <DateTime value={view.last_seen_at} />
        </dd>

        {view.wifi ? (
          <>
            <dt>WiFi</dt>
            <dd>
              SSID {idOrWithheld(attr(view.wifi, 'wifi.ssid'))}
              {attr(view.wifi, 'wifi.band') ? ` · ${attr(view.wifi, 'wifi.band')}` : ''}
              {metric(view.wifi, 'channel') !== undefined
                ? ` · ch ${fmt(metric(view.wifi, 'channel'), '', 0)}`
                : ''}
              <br />
              RSSI {fmt(metric(view.wifi, 'rssi_dbm'), 'dBm', 0)} · signal{' '}
              {fmt(metric(view.wifi, 'signal_pct'), '%', 0)} · link{' '}
              {fmt(metric(view.wifi, 'link_rate_mbps'), 'Mbps', 0)} · noise{' '}
              {fmt(metric(view.wifi, 'noise_dbm'), 'dBm', 0)}
            </dd>
          </>
        ) : null}

        {view.gateway ? (
          <>
            <dt>Gateway / local</dt>
            <dd>
              {idOrWithheld(attr(view.gateway, 'gateway.ip'))} ·{' '}
              {metric(view.gateway, 'reachable') === 1 ? 'reachable' : 'unreachable'} · RTT{' '}
              {fmt(metric(view.gateway, 'rtt_ms'), 'ms')} · loss{' '}
              {fmt(metric(view.gateway, 'loss_pct'), '%', 0)}
            </dd>
          </>
        ) : null}

        {view.last_mile ? (
          <>
            <dt>ISP / last mile</dt>
            <dd>
              local {fmt(metric(view.last_mile, 'local_rtt_ms'), 'ms')} → ISP edge{' '}
              {fmt(metric(view.last_mile, 'isp_rtt_ms'), 'ms')} (loss{' '}
              {fmt(metric(view.last_mile, 'isp_loss_pct'), '%', 0)}) → beyond{' '}
              {fmt(metric(view.last_mile, 'beyond_rtt_ms'), 'ms')} ·{' '}
              {hops === undefined ? '—' : formatCount(hops, 'hop', 'hops', locale)}
            </dd>
          </>
        ) : null}
      </dl>

      {view.attribution ? (
        <>
          <h3>Layer assessment</h3>
          <LayerScores a={view.attribution} locale={locale} />
        </>
      ) : null}

      {sessions.length > 0 ? (
        <>
          <h3>Sessions</h3>
          <Table
            caption={`Sessions for ${view.agent_id}`}
            columns={[
              { key: 'target', header: 'Target', render: (s: DEMResult) => s.target ?? '—' },
              {
                key: 'ok',
                header: 'OK',
                render: (s: DEMResult) => (s.success ? '✓' : s.error || '✗'),
              },
              {
                key: 'dns',
                header: 'DNS',
                numeric: true,
                render: (s: DEMResult) => fmt(metric(s, 'dns_ms'), 'ms'),
              },
              {
                key: 'tls',
                header: 'TLS',
                numeric: true,
                render: (s: DEMResult) => fmt(metric(s, 'tls_ms'), 'ms'),
              },
              {
                key: 'ttfb',
                header: 'TTFB',
                numeric: true,
                render: (s: DEMResult) => fmt(metric(s, 'ttfb_ms'), 'ms'),
              },
              {
                key: 'total',
                header: 'Total',
                numeric: true,
                render: (s: DEMResult) => fmt(metric(s, 'total_ms'), 'ms'),
              },
            ]}
            rows={sessions}
            rowKey={(s) => `${view.agent_id}-${s.target}`}
          />
        </>
      ) : null}
    </Modal>
  )
}

type CauseFilter = 'all' | 'impaired' | 'wifi' | 'local' | 'isp' | 'network' | 'none'

/** EndpointsPage is the endpoint / last-mile / WiFi DEM surface (S-FE4): the
 *  fleet list + per-endpoint detail with slowdown attribution — the
 *  "it's your WiFi, not us" story, privacy-respecting. */
export function EndpointsPage() {
  const { locale } = useI18n()
  const { push } = useToast()
  const [cause, setCause] = useState<CauseFilter>('all')
  const [needle, setNeedle] = useState('')
  const [viewName, setViewName] = useState('')
  const [detailID, setDetailID] = useState<string | null>(null)
  const endpointFilters = useMemo(() => ({ q: needle, cause }), [needle, cause])
  const endpoints = useEndpoints(endpointFilters)
  const savedViews = useEndpointSavedViews()
  const createView = useCreateEndpointSavedView()

  const items = useMemo(() => endpoints.data?.items ?? [], [endpoints.data])

  const detail = items.find((v) => v.agent_id === detailID) ?? null

  const applySavedView = (id: string) => {
    if (!id) return
    const view = savedViews.data?.items.find((v) => v.id === id)
    if (!view) return
    setNeedle(view.filters.q ?? '')
    setCause(causeFromSavedView(view))
  }

  const saveView = (e: FormEvent) => {
    e.preventDefault()
    const name = viewName.trim()
    if (!name) {
      push({ tone: 'warning', title: 'Name required', message: 'Saved views need a label.' })
      return
    }
    const filters: Record<string, string> = {}
    if (needle.trim()) filters.q = needle.trim()
    if (cause !== 'all') filters.cause = cause
    createView.mutate(
      { surface: 'endpoints', name, filters },
      {
        onSuccess: (view) => {
          setViewName('')
          push({ tone: 'success', title: 'View saved', message: view.name })
        },
        onError: (err) => push({ tone: 'danger', title: 'Save failed', message: err.message }),
      },
    )
  }

  const columns: Column<EndpointView>[] = [
    { key: 'verdict', header: 'Verdict', render: (v) => verdictBadge(v) },
    { key: 'agent', header: 'Endpoint', render: (v) => v.agent_id },
    { key: 'wifi', header: 'WiFi', render: (v) => wifiSummary(v, locale) },
    {
      key: 'gateway',
      header: 'Gateway RTT',
      numeric: true,
      render: (v) => num(metric(v.gateway, 'rtt_ms'), 'ms', 1, locale),
    },
    {
      key: 'isp',
      header: 'ISP edge RTT',
      numeric: true,
      render: (v) => num(metric(v.last_mile, 'isp_rtt_ms'), 'ms', 1, locale),
    },
    { key: 'seen', header: 'Last seen', render: (v) => <DateTime value={v.last_seen_at} /> },
    {
      key: 'actions',
      header: <span className="sr-only">Actions</span>,
      align: 'end',
      render: (v) => (
        <Button size="sm" variant="ghost" onClick={() => setDetailID(v.agent_id)}>
          Details
        </Button>
      ),
    },
  ]

  return (
    <Page
      title="Endpoints"
      subtitle="Last-mile / WiFi digital experience per endpoint — slowdowns attributed to WiFi, local network, ISP, or beyond."
    >
      <Card>
        <CardHeader
          title={`Fleet (${formatInteger(items.length, locale)})`}
          actions={
            <form className={styles.filters} onSubmit={saveView}>
              <Field
                label="Find"
                value={needle}
                onChange={(e) => setNeedle(e.target.value)}
                placeholder="endpoint…"
              />
              <Select
                label="Attribution"
                value={cause}
                onChange={(e) => setCause(e.target.value as CauseFilter)}
                options={[
                  { value: 'all', label: 'All endpoints' },
                  { value: 'impaired', label: 'Impaired only' },
                  { value: 'wifi', label: 'WiFi' },
                  { value: 'local', label: 'Local network' },
                  { value: 'isp', label: 'ISP / last mile' },
                  { value: 'network', label: 'Network / service' },
                  { value: 'none', label: 'Healthy' },
                ]}
              />
              <Select
                label="Saved views"
                value=""
                onChange={(e) => applySavedView(e.target.value)}
                options={[
                  { value: '', label: 'Choose view' },
                  ...(savedViews.data?.items ?? []).map((v) => ({ value: v.id, label: v.name })),
                ]}
              />
              <Field
                label="View name"
                value={viewName}
                onChange={(e) => setViewName(e.target.value)}
                placeholder="WiFi trouble"
              />
              <Button type="submit" disabled={createView.isPending}>
                Save view
              </Button>
            </form>
          }
        />
        <CardBody>
          {endpoints.isLoading ? (
            <LoadingState label="Loading endpoints…" />
          ) : endpoints.isError ? (
            <ErrorState description="Could not load the endpoint fleet." />
          ) : (
            <>
              {endpoints.data && !endpoints.data.collector_running ? (
                <p role="status" className={styles.notice}>
                  <Badge tone="warning">collector off</Badge> The endpoint-view consumer is not
                  wired — deploy endpoint agents (S37) to populate the fleet.
                </p>
              ) : null}
              <Table
                caption="Endpoint fleet"
                columns={columns}
                rows={items}
                rowKey={(v) => v.agent_id}
                empty={
                  <EmptyState
                    title="No endpoints reporting"
                    description="Endpoint agents publish WiFi/gateway/last-mile DEM samples automatically."
                  />
                }
              />
            </>
          )}
        </CardBody>
      </Card>

      <RUMCard />

      {detail ? <EndpointDetail view={detail} onClose={() => setDetailID(null)} /> : null}
    </Page>
  )
}

function causeFromSavedView(view: SavedInventoryView): CauseFilter {
  const cause = view.filters.cause
  switch (cause) {
    case 'impaired':
    case 'wifi':
    case 'local':
    case 'isp':
    case 'network':
    case 'none':
      return cause
    default:
      return 'all'
  }
}

/** rumVerdictBadge renders the convergence call with honesty wording: every
 *  claim is about what probectl OBSERVED, never more. */
function rumVerdictBadge(v: RUMVerdict) {
  switch (v) {
    case 'user_impact_confirmed':
      return <Badge tone="danger">user impact confirmed</Badge>
    case 'user_only_synthetic_blind':
      return <Badge tone="warning">users degraded — synthetic blind spot</Badge>
    case 'synthetic_only_no_user_impact':
      return <Badge tone="neutral">synthetic only — no user impact observed</Badge>
    default:
      return <Badge tone="success">healthy</Badge>
  }
}

/** RUMCard folds real-user monitoring into the DEM surface (S47b): the
 *  synthetic↔RUM convergence per app, plus the enforced privacy posture. */
function RUMCard() {
  const { locale } = useI18n()
  const rum = useRUM()

  const columns: Column<RUMAppStatus>[] = [
    {
      key: 'app',
      header: 'Application',
      render: (a) => (
        <div>
          <strong>{a.app}</strong>
          <div className={styles.notice}>{a.host}</div>
        </div>
      ),
    },
    { key: 'verdict', header: 'Convergence', render: (a) => rumVerdictBadge(a.verdict) },
    {
      key: 'views',
      header: 'Views (15m)',
      numeric: true,
      render: (a) => formatInteger(a.window_views, locale),
    },
    {
      key: 'errors',
      header: 'Error rate',
      numeric: true,
      render: (a) => formatPercentValue(a.error_rate * 100, locale, { maximumFractionDigits: 1 }),
    },
    {
      key: 'lcp',
      header: 'p75 LCP',
      numeric: true,
      render: (a) =>
        a.p75_lcp_ms ? formatUnit(a.p75_lcp_ms, 'ms', locale, { maximumFractionDigits: 0 }) : '—',
    },
    {
      key: 'synth',
      header: 'Synthetic coverage',
      render: (a) =>
        a.synthetic_observed ? (
          a.synthetic_degraded ? (
            <Badge tone="danger">degraded</Badge>
          ) : (
            <Badge tone="success">green</Badge>
          )
        ) : (
          <Badge tone="neutral">none for this host</Badge>
        ),
    },
    {
      key: 'top',
      header: 'Top page',
      render: (a) => (a.pages[0] ? `${a.pages[0].page} (${a.pages[0].views})` : '—'),
    },
  ]

  return (
    <Card>
      <CardHeader
        title="Real-user monitoring (RUM)"
        description="Real-user page views joined with synthetic coverage per application — consent-gated, URL-redacted, no IP stored."
      />
      <CardBody>
        {rum.isLoading ? (
          <LoadingState label="Loading RUM convergence…" />
        ) : rum.isError ? (
          <ErrorState description="Could not load the RUM view." />
        ) : !rum.data?.rum_running ? (
          <EmptyState
            title="RUM not wired"
            description="Enable the beacon ingest (PROBECTL_RUM_ENABLED + PROBECTL_RUM_APPS) and embed the probectl-rum.js snippet to see real-user impact here."
          />
        ) : (rum.data.apps?.length ?? 0) === 0 ? (
          <EmptyState
            title="No real-user views in the window"
            description="Instrumented pages report here once users (who consented) browse them — see docs/rum.md for the embed snippet."
          />
        ) : (
          <>
            <p role="note" aria-label="rum privacy posture" className={styles.notice}>
              <Badge tone="info">privacy</Badge> consent required · URLs redacted · IP never stored
              · {rum.data.privacy?.rejected_no_consent ?? 0} beacons rejected without consent.{' '}
              {rum.data.coverage_notes?.[0] ?? ''}
            </p>
            <Table
              caption="RUM convergence by application"
              columns={columns}
              rows={rum.data.apps ?? []}
              rowKey={(a) => `${a.app}|${a.host}`}
              empty={<EmptyState title="No apps" description="—" />}
            />
          </>
        )}
      </CardBody>
    </Card>
  )
}
