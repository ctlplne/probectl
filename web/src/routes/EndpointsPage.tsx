import { useMemo, useState } from 'react'
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
  type Column,
} from '../components'
import {
  attr,
  causeLabel,
  causeTone,
  metric,
  useEndpoints,
  type DEMResult,
  type EndpointView,
} from '../api/endpoints'

function when(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

/** withheld renders a privacy-minimized identifier honestly: the agent chose
 *  not to collect it, so the UI says so — it never invents a value. */
const WITHHELD = 'withheld (privacy)'

function idOrWithheld(value?: string): string {
  return value && value !== '' ? value : WITHHELD
}

/** num renders an optional metric ("—" when the OS did not report it). */
function num(v: number | undefined, unit = '', digits = 1): string {
  if (v === undefined) return '—'
  return `${Number(v.toFixed(digits))}${unit}`
}

function verdictBadge(v: EndpointView) {
  return (
    <Badge tone={causeTone(v.cause, v.slow)}>
      {v.slow ? `slow: ${causeLabel(v.cause)}` : 'healthy'}
    </Badge>
  )
}

function wifiSummary(v: EndpointView): string {
  const rssi = metric(v.wifi, 'rssi_dbm')
  const signal = metric(v.wifi, 'signal_pct')
  const band = attr(v.wifi, 'wifi.band')
  if (rssi === undefined && signal === undefined) return v.wifi ? '—' : 'no WiFi'
  const strength = rssi !== undefined ? `${num(rssi, ' dBm', 0)}` : `${num(signal, '%', 0)}`
  return band ? `${strength} · ${band}` : strength
}

/** LayerScores renders the attribution engine's per-layer assessment. */
function LayerScores({ a }: { a: DEMResult }) {
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
            <span>severity {num(score, '', 2)}</span>
          </li>
        )
      })}
    </ul>
  )
}

/** EndpointDetail is the per-endpoint view: WiFi, gateway/local network,
 *  ISP/last-mile segments, sessions, and the attribution verdict. */
function EndpointDetail({ view, onClose }: { view: EndpointView; onClose: () => void }) {
  const sessions = view.sessions ?? []
  return (
    <Modal open onClose={onClose} title={view.agent_id}>
      <dl className={styles.kv}>
        <dt>Verdict</dt>
        <dd>
          {verdictBadge(view)}
          {view.confidence ? <> confidence {num(view.confidence, '', 2)}</> : null}
        </dd>
        {view.summary ? (
          <>
            <dt>Why</dt>
            <dd>{view.summary}</dd>
          </>
        ) : null}
        <dt>Last seen</dt>
        <dd>{when(view.last_seen_at)}</dd>

        {view.wifi ? (
          <>
            <dt>WiFi</dt>
            <dd>
              SSID {idOrWithheld(attr(view.wifi, 'wifi.ssid'))}
              {attr(view.wifi, 'wifi.band') ? ` · ${attr(view.wifi, 'wifi.band')}` : ''}
              {metric(view.wifi, 'channel') !== undefined ? ` · ch ${num(metric(view.wifi, 'channel'), '', 0)}` : ''}
              <br />
              RSSI {num(metric(view.wifi, 'rssi_dbm'), ' dBm', 0)} · signal{' '}
              {num(metric(view.wifi, 'signal_pct'), '%', 0)} · link {num(metric(view.wifi, 'link_rate_mbps'), ' Mbps', 0)}{' '}
              · noise {num(metric(view.wifi, 'noise_dbm'), ' dBm', 0)}
            </dd>
          </>
        ) : null}

        {view.gateway ? (
          <>
            <dt>Gateway / local</dt>
            <dd>
              {idOrWithheld(attr(view.gateway, 'gateway.ip'))} ·{' '}
              {metric(view.gateway, 'reachable') === 1 ? 'reachable' : 'unreachable'} · RTT{' '}
              {num(metric(view.gateway, 'rtt_ms'), ' ms')} · loss {num(metric(view.gateway, 'loss_pct'), '%', 0)}
            </dd>
          </>
        ) : null}

        {view.last_mile ? (
          <>
            <dt>ISP / last mile</dt>
            <dd>
              local {num(metric(view.last_mile, 'local_rtt_ms'), ' ms')} → ISP edge{' '}
              {num(metric(view.last_mile, 'isp_rtt_ms'), ' ms')} (loss {num(metric(view.last_mile, 'isp_loss_pct'), '%', 0)})
              → beyond {num(metric(view.last_mile, 'beyond_rtt_ms'), ' ms')} ·{' '}
              {num(metric(view.last_mile, 'hops'), ' hops', 0)}
            </dd>
          </>
        ) : null}
      </dl>

      {view.attribution ? (
        <>
          <h3>Layer assessment</h3>
          <LayerScores a={view.attribution} />
        </>
      ) : null}

      {sessions.length > 0 ? (
        <>
          <h3>Sessions</h3>
          <Table
            caption={`Sessions for ${view.agent_id}`}
            columns={[
              { key: 'target', header: 'Target', render: (s: DEMResult) => s.target ?? '—' },
              { key: 'ok', header: 'OK', render: (s: DEMResult) => (s.success ? '✓' : s.error || '✗') },
              { key: 'dns', header: 'DNS', numeric: true, render: (s: DEMResult) => num(metric(s, 'dns_ms'), ' ms') },
              { key: 'tls', header: 'TLS', numeric: true, render: (s: DEMResult) => num(metric(s, 'tls_ms'), ' ms') },
              { key: 'ttfb', header: 'TTFB', numeric: true, render: (s: DEMResult) => num(metric(s, 'ttfb_ms'), ' ms') },
              { key: 'total', header: 'Total', numeric: true, render: (s: DEMResult) => num(metric(s, 'total_ms'), ' ms') },
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
  const endpoints = useEndpoints()
  const [cause, setCause] = useState<CauseFilter>('all')
  const [needle, setNeedle] = useState('')
  const [detailID, setDetailID] = useState<string | null>(null)

  const items = useMemo(() => endpoints.data?.items ?? [], [endpoints.data])

  const filtered = useMemo(() => {
    const q = needle.trim().toLowerCase()
    return items.filter((v) => {
      if (cause === 'impaired' && !v.slow) return false
      if (cause !== 'all' && cause !== 'impaired' && (v.cause ?? 'none') !== cause) return false
      return !q || v.agent_id.toLowerCase().includes(q)
    })
  }, [items, cause, needle])

  const detail = items.find((v) => v.agent_id === detailID) ?? null

  const columns: Column<EndpointView>[] = [
    { key: 'verdict', header: 'Verdict', render: (v) => verdictBadge(v) },
    { key: 'agent', header: 'Endpoint', render: (v) => v.agent_id },
    { key: 'wifi', header: 'WiFi', render: (v) => wifiSummary(v) },
    {
      key: 'gateway',
      header: 'Gateway RTT',
      numeric: true,
      render: (v) => num(metric(v.gateway, 'rtt_ms'), ' ms'),
    },
    {
      key: 'isp',
      header: 'ISP edge RTT',
      numeric: true,
      render: (v) => num(metric(v.last_mile, 'isp_rtt_ms'), ' ms'),
    },
    { key: 'seen', header: 'Last seen', render: (v) => when(v.last_seen_at) },
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
          title={`Fleet (${items.length})`}
          actions={
            <div className={styles.filters}>
              <Field label="Find" value={needle} onChange={(e) => setNeedle(e.target.value)} placeholder="endpoint…" />
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
            </div>
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
                  <Badge tone="warning">collector off</Badge> The endpoint-view consumer is not wired — deploy
                  endpoint agents (S37) to populate the fleet.
                </p>
              ) : null}
              <Table
                caption="Endpoint fleet"
                columns={columns}
                rows={filtered}
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

      {detail ? <EndpointDetail view={detail} onClose={() => setDetailID(null)} /> : null}
    </Page>
  )
}
