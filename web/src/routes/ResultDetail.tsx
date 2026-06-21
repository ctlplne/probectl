import styles from './results.module.css'
import { Badge, EmptyState, Modal, Table, type Column } from '../components'
import { a, latencyFamily, m, useLatestResults, type LatestResult } from '../api/results'
import type { Test } from '../api/tests'
import { DateTime } from '../time/DateTime'
import { useI18n } from '../i18n/useI18n'
import { formatCount, formatDecimal, formatPercentValue, formatUnit } from '../i18n/number'

/** Per-type synthetic result views (S-FE5). One consistent pattern across
 *  types — header kv + a type-specific breakdown — extending the S9 screens
 *  with S8a components only. Every shipped type renders named fields; unknown
 *  types fall back to a named metrics table, never raw JSON. */

function num(v: number | undefined, unit = '', digits = 1, locale = 'en'): string {
  if (v === undefined) return '—'
  const suffix = unit.trim()
  if (suffix === '%') return formatPercentValue(v, locale, { maximumFractionDigits: digits })
  if (suffix) return formatUnit(v, suffix, locale, { maximumFractionDigits: digits })
  return formatDecimal(v, locale, { maximumFractionDigits: digits })
}

/** HTTPWaterfall renders the dns→connect→tls→ttfb phase breakdown (S13). */
function HTTPWaterfall({ r }: { r: LatestResult }) {
  const { locale } = useI18n()
  const fmt = (v: number | undefined, unit = '', digits = 1) => num(v, unit, digits, locale)
  const phases: Array<[string, number | undefined]> = [
    ['DNS', m(r, 'http.dns.ms')],
    ['Connect', m(r, 'http.connect.ms')],
    ['TLS', m(r, 'http.tls.ms')],
    ['TTFB', m(r, 'http.ttfb.ms')],
  ]
  const total = m(r, 'http.total.ms') ?? phases.reduce((s, [, v]) => s + (v ?? 0), 0)
  let offset = 0
  return (
    <>
      <ul className={styles.waterfall} aria-label="HTTP timing waterfall">
        {phases.map(([name, v]) => {
          const left = total > 0 ? (offset / total) * 100 : 0
          const width = total > 0 && v !== undefined ? (v / total) * 100 : 0
          offset += v ?? 0
          return (
            <li key={name}>
              <span className={styles.phaseName}>{name}</span>
              <span className={styles.track} aria-hidden="true">
                {v !== undefined ? (
                  <span
                    className={styles.bar}
                    style={{ left: `${left}%`, width: `${Math.max(width, 1)}%` }}
                  />
                ) : null}
              </span>
              <span className={styles.value}>{fmt(v, 'ms')}</span>
            </li>
          )
        })}
      </ul>
      <dl className={styles.kv}>
        <dt>Total</dt>
        <dd>
          {fmt(total, 'ms')}
          {m(r, 'http.status') !== undefined ? ` · HTTP ${fmt(m(r, 'http.status'), '', 0)}` : ''}
        </dd>
        {m(r, 'http.throughput.kbps') !== undefined ? (
          <>
            <dt>Throughput</dt>
            <dd>
              {fmt(m(r, 'http.throughput.kbps'), 'kbps', 0)} ·{' '}
              {fmt(m(r, 'http.content.bytes'), 'bytes', 0)}
            </dd>
          </>
        ) : null}
        {m(r, 'http.tls.cert_expiry_days') !== undefined ? (
          <>
            <dt>Cert expiry</dt>
            <dd>
              {formatCount(m(r, 'http.tls.cert_expiry_days') ?? 0, 'day', 'days', locale)}
            </dd>
          </>
        ) : null}
      </dl>
    </>
  )
}

/** DNSBreakdown renders the resolution detail (S12). */
function DNSBreakdown({ r }: { r: LatestResult }) {
  const { locale } = useI18n()
  const secure = m(r, 'dns.dnssec.secure')
  const answerCount = m(r, 'dns.answers')
  return (
    <dl className={styles.kv}>
      <dt>Query</dt>
      <dd>
        {num(m(r, 'dns.query.ms'), 'ms', 1, locale)} ·{' '}
        {answerCount === undefined ? '—' : formatCount(answerCount, 'answer', 'answers', locale)} ·{' '}
        {a(r, 'dns.rcode') ?? '—'}
      </dd>
      {a(r, 'dns.answer') ? (
        <>
          <dt>Answers</dt>
          <dd>{a(r, 'dns.answer')}</dd>
        </>
      ) : null}
      <dt>Resolver</dt>
      <dd>
        {a(r, 'dns.server') ?? a(r, 'server.address') ?? '—'}
        {a(r, 'dns.transport') ? ` via ${a(r, 'dns.transport')}` : ''}
        {a(r, 'dns.qtype') ? ` · ${a(r, 'dns.qtype')}` : ''}
      </dd>
      {secure !== undefined ? (
        <>
          <dt>DNSSEC</dt>
          <dd>
            <Badge tone={secure === 1 ? 'success' : 'warning'}>
              {secure === 1 ? 'validated' : 'not validated'}
            </Badge>
          </dd>
        </>
      ) : null}
    </dl>
  )
}

/** LatencyLoss renders the shared latency family + loss (S7/S8: icmp/tcp/udp). */
function LatencyLoss({ r }: { r: LatestResult }) {
  const { locale } = useI18n()
  const fmt = (v: number | undefined, unit = '', digits = 1) => num(v, unit, digits, locale)
  const fam = latencyFamily(r.type) ?? 'rtt'
  const loss = m(r, 'loss.ratio')
  return (
    <dl className={styles.kv}>
      <dt>Loss</dt>
      <dd>
        {loss !== undefined ? (
          <Badge tone={loss === 0 ? 'success' : loss < 0.05 ? 'warning' : 'danger'}>
            {fmt(loss * 100, '%', 1)}
          </Badge>
        ) : (
          '—'
        )}{' '}
        {fmt(m(r, 'packets.received'), '', 0)}/{fmt(m(r, 'packets.sent'), '', 0)} received
      </dd>
      <dt>{fam === 'rtt' ? 'RTT' : 'Connect'}</dt>
      <dd>
        min {fmt(m(r, `${fam}.min.ms`), 'ms')} · avg {fmt(m(r, `${fam}.avg.ms`), 'ms')} ·
        max {fmt(m(r, `${fam}.max.ms`), 'ms')} · σ {fmt(m(r, `${fam}.stddev.ms`), 'ms')}
      </dd>
      <dt>Jitter</dt>
      <dd>{fmt(m(r, 'jitter.ms'), 'ms')}</dd>
    </dl>
  )
}

/** mosTone maps a MOS onto the standard satisfaction bands. */
function mosTone(mos: number): 'success' | 'warning' | 'danger' {
  if (mos >= 4.0) return 'success'
  if (mos >= 3.6) return 'warning'
  return 'danger'
}

/** VoiceBreakdown renders the RTP voice-quality result (S47c): MOS up front,
 *  then R-factor / jitter / loss / delay — with the model named so a computed
 *  MOS is never mistaken for a measured listening score. */
function VoiceBreakdown({ r }: { r: LatestResult }) {
  const { locale } = useI18n()
  const fmt = (v: number | undefined, unit = '', digits = 1) => num(v, unit, digits, locale)
  const mos = m(r, 'voice.mos')
  return (
    <dl className={styles.kv}>
      <dt>MOS</dt>
      <dd>
        {mos !== undefined ? (
          <>
            <Badge tone={mosTone(mos)}>{fmt(mos, '', 2)}</Badge> · R-factor{' '}
            {fmt(m(r, 'voice.r_factor'), '', 1)}
          </>
        ) : (
          '— (no echoes — voice path unmeasurable)'
        )}
      </dd>
      <dt>Jitter / loss</dt>
      <dd>
        {fmt(m(r, 'voice.jitter.ms'), 'ms')} (RFC 3550) · loss{' '}
        {fmt(m(r, 'voice.loss.pct'), '%', 1)} · {fmt(m(r, 'packets.received'), '', 0)}/
        {fmt(m(r, 'packets.sent'), '', 0)} packets
      </dd>
      <dt>Delay</dt>
      <dd>
        one-way est. {fmt(m(r, 'voice.one_way.ms'), 'ms')} · RTT avg{' '}
        {fmt(m(r, 'rtt.avg.ms'), 'ms')}
      </dd>
      <dt>Model</dt>
      <dd>
        {a(r, 'voice.codec') ?? '—'} · {a(r, 'voice.model') ?? '—'} · one-way ={' '}
        {a(r, 'voice.one_way_estimate') ?? '—'}
      </dd>
    </dl>
  )
}

interface BrowserStepRow {
  index: number
  name: string
  action: string
  duration?: number
  success?: string
  detail?: string
}

/** BrowserBreakdown renders transaction-level totals plus per-step timings. */
function BrowserBreakdown({ r }: { r: LatestResult }) {
  const { locale } = useI18n()
  const fmt = (v: number | undefined, unit = '', digits = 1) => num(v, unit, digits, locale)
  const declared = Number(a(r, 'browser.step_count') ?? m(r, 'transaction.steps') ?? 0)
  const metricStepCount =
    Math.max(
      -1,
      ...Object.keys(r.metrics ?? {})
        .map((key) => /^transaction\.step\.(\d+)\.duration_ms$/.exec(key)?.[1])
        .filter((v): v is string => Boolean(v))
        .map((v) => Number(v)),
    ) + 1
  const count = Math.max(Number.isFinite(declared) ? declared : 0, metricStepCount)
  const rows: BrowserStepRow[] = Array.from({ length: count }, (_, index) => ({
    index,
    name: a(r, `browser.step.${index}.name`) ?? `step ${index + 1}`,
    action: a(r, `browser.step.${index}.action`) ?? '—',
    duration: m(r, `transaction.step.${index}.duration_ms`),
    success: a(r, `browser.step.${index}.success`),
    detail: a(r, `browser.step.${index}.detail`),
  }))
  const columns: Column<BrowserStepRow>[] = [
    { key: 'step', header: 'Step', render: (row) => row.name },
    { key: 'action', header: 'Action', render: (row) => row.action },
    {
      key: 'duration',
      header: 'Duration',
      numeric: true,
      render: (row) => fmt(row.duration, 'ms'),
    },
    {
      key: 'result',
      header: 'Result',
      render: (row) =>
        row.success ? (
          <Badge tone={row.success === 'true' ? 'success' : 'danger'}>
            {row.success === 'true' ? 'ok' : row.detail || 'failed'}
          </Badge>
        ) : (
          (row.detail ?? '—')
        ),
    },
  ]
  return (
    <>
      <dl className={styles.kv}>
        <dt>Transaction</dt>
        <dd>
          {a(r, 'browser.script') ?? 'browser'} · {fmt(m(r, 'transaction.total_ms'), 'ms')}
        </dd>
        <dt>Resources</dt>
        <dd>
          {formatCount(m(r, 'transaction.resources') ?? 0, 'resource', 'resources', locale)} ·{' '}
          {formatCount(m(r, 'transaction.failed_steps') ?? 0, 'failed step', 'failed steps', locale)}
        </dd>
      </dl>
      <Table
        caption="Browser transaction steps"
        columns={columns}
        rows={rows}
        rowKey={(row) => String(row.index)}
      />
    </>
  )
}

/** GenericMetrics is the named-field fallback for types without a dedicated
 *  view — still a labeled table, never raw JSON. */
function GenericMetrics({ r }: { r: LatestResult }) {
  const { locale } = useI18n()
  const rows = Object.entries(r.metrics ?? {}).sort(([x], [y]) => x.localeCompare(y))
  const columns: Column<[string, number]>[] = [
    { key: 'metric', header: 'Metric', render: ([k]) => k },
    {
      key: 'value',
      header: 'Value',
      numeric: true,
      render: ([, v]) => formatDecimal(v, locale, { maximumFractionDigits: 3 }),
    },
  ]
  if (rows.length === 0) return <p>No metrics reported.</p>
  return (
    <Table caption={`Metrics for ${r.type}`} columns={columns} rows={rows} rowKey={([k]) => k} />
  )
}

function TypedBreakdown({ r }: { r: LatestResult }) {
  switch (r.type) {
    case 'http':
      return <HTTPWaterfall r={r} />
    case 'dns':
      return <DNSBreakdown r={r} />
    case 'icmp':
    case 'tcp':
    case 'udp':
      return <LatencyLoss r={r} />
    case 'voice':
      return <VoiceBreakdown r={r} />
    case 'browser':
      return <BrowserBreakdown r={r} />
    default:
      return <GenericMetrics r={r} />
  }
}

/** ResultDetail shows a test's latest result per reporting agent. */
export function ResultDetail({ test, onClose }: { test: Test; onClose: () => void }) {
  const latest = useLatestResults()
  const matches = (latest.data?.items ?? []).filter(
    (r) => r.type === test.type && r.target === test.target,
  )

  return (
    <Modal open onClose={onClose} title={`${test.name} — latest results`}>
      {matches.length === 0 ? (
        <EmptyState
          title="No results yet"
          description={
            latest.data && !latest.data.collector_running
              ? 'The result-view consumer is not wired.'
              : 'Results appear after the first probe run for this test.'
          }
        />
      ) : (
        matches.map((r) => (
          <div className={styles.agentBlock} key={`${r.agent_id}-${r.type}-${r.target}`}>
            <dl className={styles.kv}>
              <dt>Agent</dt>
              <dd>
                {r.agent_id || '—'} ·{' '}
                <Badge tone={r.success ? 'success' : 'danger'}>{r.success ? 'ok' : 'failed'}</Badge>{' '}
                · <DateTime value={r.observed_at} />
              </dd>
              {r.error ? (
                <>
                  <dt>Error</dt>
                  <dd>{r.error}</dd>
                </>
              ) : null}
            </dl>
            <TypedBreakdown r={r} />
          </div>
        ))
      )}
    </Modal>
  )
}
