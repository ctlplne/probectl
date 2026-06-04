import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
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
import { severityTone } from '../api/incidents'
import {
  daysUntil,
  findingLabel,
  useTLSPosture,
  type TLSPosture,
} from '../api/tls'
import { useDetections, type Detection } from '../api/threat'

function when(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

/** expiryBadge renders days-to-expiry with a tone that matches urgency. */
function expiryBadge(p: TLSPosture) {
  if (!p.leaf) return <Badge tone="neutral">no cert</Badge>
  const days = daysUntil(p.leaf.not_after)
  if (Number.isNaN(days)) return <Badge tone="neutral">unknown</Badge>
  if (days < 0) return <Badge tone="danger">expired {-days}d ago</Badge>
  if (days <= 14) return <Badge tone="danger">{days}d left</Badge>
  if (days <= 30) return <Badge tone="warning">{days}d left</Badge>
  return <Badge tone="success">{days}d left</Badge>
}

/** flagBadges renders a posture's finding flags (weakness/CT/intel). */
function flagBadges(p: TLSPosture) {
  const findings = p.findings ?? []
  if (findings.length === 0) return <Badge tone="success">clean</Badge>
  return (
    <>
      {findings.map((f, i) => (
        <Badge key={`${f.kind}-${i}`} tone={severityTone(f.severity)}>
          {findingLabel(f.kind)}
        </Badge>
      ))}
    </>
  )
}

/** PostureDetail shows one target's full posture + the trustctl handoff. The
 *  handoff payload is the S27 analyzer's, forwarded VERBATIM (never re-derived
 *  client-side — the 'watch out for'). */
function PostureDetail({ posture, onClose }: { posture: TLSPosture; onClose: () => void }) {
  const { push } = useToast()
  const leaf = posture.leaf
  const handoffJSON = posture.handoff ? JSON.stringify(posture.handoff, null, 2) : ''

  const copyHandoff = () => {
    void navigator.clipboard
      ?.writeText(handoffJSON)
      .then(() => push({ tone: 'success', title: 'Handoff copied', message: posture.target }))
      .catch(() => push({ tone: 'danger', title: 'Copy failed', message: 'Clipboard unavailable' }))
  }

  return (
    <Modal open onClose={onClose} title={posture.target}>
      <dl className={styles.kv}>
        <dt>Severity</dt>
        <dd>
          <Badge tone={severityTone(posture.severity)}>{posture.severity}</Badge>
        </dd>
        <dt>Protocol</dt>
        <dd>
          TLS {posture.tls_version} · {posture.cipher || '—'}
        </dd>
        {leaf ? (
          <>
            <dt>Subject</dt>
            <dd>{leaf.subject}</dd>
            <dt>Issuer</dt>
            <dd>{leaf.issuer}</dd>
            {leaf.sans?.length ? (
              <>
                <dt>SANs</dt>
                <dd>{leaf.sans.join(', ')}</dd>
              </>
            ) : null}
            <dt>Validity</dt>
            <dd>
              {when(leaf.not_before)} → {when(leaf.not_after)} ({expiryBadge(posture)})
            </dd>
            <dt>Key</dt>
            <dd>
              {leaf.key_type} {leaf.key_bits} · {leaf.signature_algorithm}
              {leaf.self_signed ? ' · self-signed' : ''}
            </dd>
            <dt>Serial</dt>
            <dd>{leaf.serial_number}</dd>
          </>
        ) : null}
        <dt>Observed</dt>
        <dd>
          {when(posture.observed_at)} via {posture.source}
        </dd>
      </dl>

      {(posture.findings ?? []).length > 0 ? (
        <>
          <h3>Findings</h3>
          <ul className={styles.findings}>
            {(posture.findings ?? []).map((f, i) => (
              <li key={`${f.kind}-${i}`}>
                <Badge tone={severityTone(f.severity)}>{findingLabel(f.kind)}</Badge>
                <span>
                  {f.message}
                  {f.source ? ` (source: ${f.source}, confidence ${f.confidence})` : ''}
                </span>
              </li>
            ))}
          </ul>
        </>
      ) : null}

      {posture.handoff ? (
        <>
          <h3>trustctl handoff</h3>
          <pre className={styles.handoff} aria-label="trustctl handoff payload">
            {handoffJSON}
          </pre>
          <div className={styles.actionsRow}>
            <Button variant="secondary" onClick={copyHandoff}>
              Copy handoff JSON
            </Button>
            {posture.handoff.url ? (
              <a href={posture.handoff.url} target="_blank" rel="noreferrer">
                Open in trustctl
              </a>
            ) : null}
          </div>
        </>
      ) : null}
    </Modal>
  )
}

/** DetectionDetail shows one detection's full provenance — honestly: a
 *  confidence-scored signal with the attributing feed, never a block, and
 *  feeds can list benign infrastructure (the 'watch out for'). */
function DetectionDetail({ detection, onClose }: { detection: Detection; onClose: () => void }) {
  return (
    <Modal open onClose={onClose} title={detection.entity}>
      <dl className={styles.kv}>
        <dt>Severity</dt>
        <dd>
          <Badge tone={severityTone(detection.severity)}>{detection.severity}</Badge>{' '}
          {typeof detection.confidence === 'number' && detection.confidence > 0 ? (
            <Badge tone="neutral">confidence {detection.confidence}</Badge>
          ) : null}
        </dd>
        <dt>Detection</dt>
        <dd>{detection.kind}</dd>
        {detection.indicator ? (
          <>
            <dt>Matched indicator</dt>
            <dd>{detection.indicator}</dd>
          </>
        ) : null}
        <dt>Provenance</dt>
        <dd>
          {detection.source ?? 'unknown'}
          {detection.category ? ` · ${detection.category}` : ''}
          {detection.license ? ` · license: ${detection.license}` : ''}
        </dd>
        {detection.summary ? (
          <>
            <dt>Summary</dt>
            <dd>{detection.summary}</dd>
          </>
        ) : null}
        <dt>Observed</dt>
        <dd>{when(detection.observed_at)}</dd>
      </dl>
      <p className={styles.notice}>
        A confidence-scored signal from {detection.source ?? 'a threat feed'} — feeds can list benign
        infrastructure, and probectl never blocks traffic. Verify before acting.
      </p>
      <div className={styles.actionsRow}>
        {detection.incident_id ? (
          <Link to={`/incidents?incident=${encodeURIComponent(detection.incident_id)}`}>
            Open incident timeline
          </Link>
        ) : (
          <span>No correlated incident</span>
        )}
      </div>
    </Modal>
  )
}

type DetSeverityFilter = 'all' | 'info' | 'warning' | 'critical'

/** DetectionsCard is the IOC/NDR triage list (S-FE3; S42 detections land here). */
function DetectionsCard() {
  const detections = useDetections()
  const [sevFilter, setSevFilter] = useState<DetSeverityFilter>('all')
  const [sourceFilter, setSourceFilter] = useState('all')
  const [needle, setNeedle] = useState('')
  const [detailID, setDetailID] = useState<string | null>(null)

  const items = useMemo(() => detections.data?.items ?? [], [detections.data])
  const sources = useMemo(() => Array.from(new Set(items.map((d) => d.source ?? 'unknown'))).sort(), [items])

  const filtered = useMemo(() => {
    const q = needle.trim().toLowerCase()
    return items.filter(
      (d) =>
        (sevFilter === 'all' || d.severity === sevFilter) &&
        (sourceFilter === 'all' || (d.source ?? 'unknown') === sourceFilter) &&
        (!q || `${d.entity} ${d.indicator ?? ''} ${d.kind}`.toLowerCase().includes(q)),
    )
  }, [items, sevFilter, sourceFilter, needle])

  const detail = items.find((d) => d.id === detailID) ?? null

  const columns: Column<Detection>[] = [
    {
      key: 'severity',
      header: 'Severity',
      render: (d) => <Badge tone={severityTone(d.severity)}>{d.severity}</Badge>,
    },
    {
      key: 'confidence',
      header: 'Confidence',
      numeric: true,
      render: (d) => (typeof d.confidence === 'number' && d.confidence > 0 ? String(d.confidence) : '—'),
    },
    { key: 'entity', header: 'Entity', render: (d) => d.entity },
    { key: 'indicator', header: 'Indicator', render: (d) => d.indicator ?? '—' },
    { key: 'source', header: 'Source', render: (d) => d.source ?? 'unknown' },
    { key: 'when', header: 'Observed', render: (d) => when(d.observed_at) },
    {
      key: 'incident',
      header: 'Incident',
      render: (d) =>
        d.incident_id ? (
          <Link to={`/incidents?incident=${encodeURIComponent(d.incident_id)}`}>timeline</Link>
        ) : (
          '—'
        ),
    },
    {
      key: 'actions',
      header: <span className="sr-only">Actions</span>,
      align: 'end',
      render: (d) => (
        <Button size="sm" variant="ghost" onClick={() => setDetailID(d.id)}>
          Details
        </Button>
      ),
    },
  ]

  return (
    <Card>
      <CardHeader
        title={`Threat detections (${items.length})`}
        actions={
          <div className={styles.filters}>
            <Field
              label="Find"
              value={needle}
              onChange={(e) => setNeedle(e.target.value)}
              placeholder="entity, indicator…"
            />
            <Select
              label="Min severity"
              value={sevFilter}
              onChange={(e) => setSevFilter(e.target.value as DetSeverityFilter)}
              options={[
                { value: 'all', label: 'All severities' },
                { value: 'critical', label: 'Critical' },
                { value: 'warning', label: 'Warning' },
                { value: 'info', label: 'Info' },
              ]}
            />
            <Select
              label="Source"
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              options={[{ value: 'all', label: 'All sources' }, ...sources.map((s) => ({ value: s, label: s }))]}
            />
          </div>
        }
      />
      <CardBody>
        {detections.isLoading ? (
          <LoadingState label="Loading detections…" />
        ) : detections.isError ? (
          <ErrorState description="Could not load threat detections." />
        ) : (
          <>
            {detections.data && !detections.data.detections_running ? (
              <p role="status" className={styles.notice}>
                <Badge tone="warning">detections off</Badge> The threat consumers are not wired — enable
                threat-intel feeds (S28) to populate triage.
              </p>
            ) : null}
            <Table
              caption="Threat detections"
              columns={columns}
              rows={filtered}
              rowKey={(d) => d.id}
              empty={
                <EmptyState
                  title="No detections"
                  description="No observed entity matched a threat-intel indicator."
                />
              }
            />
          </>
        )}
      </CardBody>
      {detail ? <DetectionDetail detection={detail} onClose={() => setDetailID(null)} /> : null}
    </Card>
  )
}

type FlagFilter = 'all' | 'flagged' | 'expiring' | 'expired' | 'weak' | 'self_signed' | 'ct' | 'intel'

function matchesFlag(p: TLSPosture, f: FlagFilter): boolean {
  const kinds = (p.findings ?? []).map((x) => x.kind)
  switch (f) {
    case 'all':
      return true
    case 'flagged':
      return kinds.length > 0
    case 'expiring':
      return kinds.includes('cert_expiring_soon')
    case 'expired':
      return kinds.includes('cert_expired')
    case 'weak':
      return kinds.some((k) => k === 'weak_key' || k === 'weak_cipher' || k === 'deprecated_protocol')
    case 'self_signed':
      return kinds.includes('cert_self_signed')
    case 'ct':
      return kinds.includes('ct_not_logged')
    case 'intel':
      return kinds.some((k) => k === 'malicious_cert' || k === 'malicious_ja3')
  }
}

/** SecurityPage is the security-plane surface: threat/IOC triage (S-FE3,
 *  fed by S28 + later S42) over the TLS/cert posture inventory, worklist, and
 *  trustctl handoff (S-FE2). */
export function SecurityPage() {
  const posture = useTLSPosture()
  const [text, setText] = useState('')
  const [flag, setFlag] = useState<FlagFilter>('all')
  const [detail, setDetail] = useState<string | null>(null) // target

  const items = useMemo(() => posture.data?.items ?? [], [posture.data])

  const filtered = useMemo(() => {
    const needle = text.trim().toLowerCase()
    return items.filter((p) => {
      if (!matchesFlag(p, flag)) return false
      if (!needle) return true
      const hay = [p.target, p.leaf?.subject ?? '', p.leaf?.issuer ?? '', ...(p.leaf?.sans ?? [])]
        .join(' ')
        .toLowerCase()
      return hay.includes(needle)
    })
  }, [items, text, flag])

  // The expiring-soon worklist: certs within 30 days (or already expired),
  // soonest first — the renewal queue.
  const worklist = useMemo(
    () =>
      items
        .filter((p) => p.leaf && daysUntil(p.leaf.not_after) <= 30)
        .sort((a, b) => daysUntil(a.leaf!.not_after) - daysUntil(b.leaf!.not_after)),
    [items],
  )

  const detailPosture = items.find((p) => p.target === detail) ?? null

  const columns: Column<TLSPosture>[] = [
    { key: 'target', header: 'Target', render: (p) => p.target },
    { key: 'issuer', header: 'Issuer', render: (p) => p.leaf?.issuer ?? '—' },
    { key: 'expiry', header: 'Expiry', render: (p) => expiryBadge(p) },
    {
      key: 'key',
      header: 'Key',
      render: (p) => (p.leaf ? `${p.leaf.key_type} ${p.leaf.key_bits}` : '—'),
    },
    { key: 'proto', header: 'Protocol', render: (p) => `TLS ${p.tls_version}` },
    { key: 'flags', header: 'Flags', render: (p) => flagBadges(p) },
    {
      key: 'actions',
      header: <span className="sr-only">Actions</span>,
      align: 'end',
      render: (p) => (
        <Button size="sm" variant="ghost" onClick={() => setDetail(p.target)}>
          Details
        </Button>
      ),
    },
  ]

  return (
    <Page title="Security" subtitle="Threat triage and certificate posture from observed traffic — signals, never blocks.">
      <div className={styles.stack}>
        <DetectionsCard />
        <Card>
          <CardHeader title={`Expiring soon (${worklist.length})`} />
          <CardBody>
            {posture.isLoading ? (
              <LoadingState label="Loading posture…" />
            ) : (
              <Table
                caption="Expiring soon worklist"
                columns={columns}
                rows={worklist}
                rowKey={(p) => `wl-${p.target}`}
                empty={<EmptyState title="Nothing expiring" description="No certificate expires within 30 days." />}
              />
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Certificate inventory"
            actions={
              <div className={styles.filters}>
                <Field
                  label="Search"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder="target, issuer, SAN…"
                />
                <Select
                  label="Flag"
                  value={flag}
                  onChange={(e) => setFlag(e.target.value as FlagFilter)}
                  options={[
                    { value: 'all', label: 'All certificates' },
                    { value: 'flagged', label: 'Flagged only' },
                    { value: 'expired', label: 'Expired' },
                    { value: 'expiring', label: 'Expiring soon' },
                    { value: 'weak', label: 'Weak key/cipher/protocol' },
                    { value: 'self_signed', label: 'Self-signed' },
                    { value: 'ct', label: 'CT anomalies' },
                    { value: 'intel', label: 'Threat-intel matches' },
                  ]}
                />
              </div>
            }
          />
          <CardBody>
            {posture.isLoading ? (
              <LoadingState label="Loading inventory…" />
            ) : posture.isError ? (
              <ErrorState description="Could not load the certificate inventory." />
            ) : (
              <>
                {posture.data && !posture.data.collector_running ? (
                  <p role="status" className={styles.notice}>
                    <Badge tone="warning">collector off</Badge> The TLS posture collector is not wired — run HTTPS
                    synthetic tests to populate the inventory.
                  </p>
                ) : null}
                <Table
                  caption="Certificate inventory"
                  columns={columns}
                  rows={filtered}
                  rowKey={(p) => p.target}
                  empty={
                    <EmptyState
                      title="No certificates observed"
                      description="HTTPS synthetic results feed this inventory automatically."
                    />
                  }
                />
              </>
            )}
          </CardBody>
        </Card>
      </div>

      {detailPosture ? <PostureDetail posture={detailPosture} onClose={() => setDetail(null)} /> : null}
    </Page>
  )
}
