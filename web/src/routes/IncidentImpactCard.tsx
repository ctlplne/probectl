// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useAuth } from '../auth/useAuth'
import { apiFetch } from '../api/client'
import type { Incident } from '../api/incidents'
import { useExportIncidentEvidence } from '../api/incidents'
import type {
  IncidentImpactPeriod,
  IncidentImpactResponse,
  IncidentImpactTestPeriod,
} from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, ErrorState, Field, Table } from '../components'
import { DateTime } from '../time/DateTime'
import styles from './flowExplorer.module.css'

const required = ['incident.read', 'flow.read', 'entities.read', 'metrics.read', 'events.read']

const coverageLabels: Record<string, string> = {
  unavailable_source: 'Current source evidence is unavailable',
  no_observed_records: 'No observed records in this window',
  unavailable_original_capture: 'Original source coverage is unavailable',
  observed_attested_records: 'Observed records have verified original sources',
  partial_capture_coverage: 'Some observed records lack verified original sources',
}

export function IncidentImpactCard({ incident }: { incident: Incident }) {
  const { tenant, user, permissions, hasScopedGrants } = useAuth()
  if (!required.every((permission) => permissions.includes(permission))) return null
  const identity = JSON.stringify([
    tenant.id,
    user.id,
    [...permissions].sort(),
    Boolean(hasScopedGrants),
    incident.id,
  ])
  return (
    <Card>
      <CardHeader
        title="Traffic and customer impact · preview"
        description="Compare observed traffic through affected measurement points with the same window one week earlier."
      />
      <CardBody>
        <IncidentImpactForm key={identity} incident={incident} />
      </CardBody>
    </Card>
  )
}

function IncidentImpactForm({ incident }: { incident: Incident }) {
  const { permissions } = useAuth()
  const exportEvidence = useExportIncidentEvidence(incident.id)
  const [from, setFrom] = useState(incident.started_at)
  const [to, setTo] = useState(() => {
    const started = Date.parse(incident.started_at),
      last = Date.parse(incident.last_seen_at)
    if (
      incident.last_seen_at !== incident.started_at &&
      Number.isFinite(started) &&
      Number.isFinite(last) &&
      last >= started
    )
      return incident.last_seen_at
    const end = Math.max(
      Date.parse(incident.last_seen_at),
      Date.parse(incident.started_at) + 60_000,
    )
    return Number.isFinite(end) ? new Date(end).toISOString() : incident.last_seen_at
  })
  const [customer, setCustomer] = useState('')
  const [includeTests, setIncludeTests] = useState(false)
  const [result, setResult] = useState<IncidentImpactResponse>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [exported, setExported] = useState(false)
  const lifetime = useRef({
    active: true,
    epoch: 0,
    request: undefined as AbortController | undefined,
  })
  function changed() {
    lifetime.current.epoch++
    lifetime.current.request?.abort()
    setResult(undefined)
    setError('')
    setBusy(false)
    setExported(false)
  }
  useEffect(() => {
    const current = lifetime.current
    current.active = true
    const invalidate = () => changed()
    window.addEventListener('focus', invalidate)
    document.addEventListener('visibilitychange', invalidate)
    return () => {
      current.active = false
      current.epoch++
      current.request?.abort()
      window.removeEventListener('focus', invalidate)
      document.removeEventListener('visibilitychange', invalidate)
    }
  }, [])
  useEffect(() => {
    if (!result?.valid_until) return
    const until = Date.parse(result.valid_until)
    let timer: ReturnType<typeof setTimeout> | undefined
    const check = () => {
      const remaining = until - Date.now()
      if (!Number.isFinite(remaining) || remaining <= 0) {
        changed()
        setError('Current source evidence expired. Run a fresh comparison.')
        return
      }
      timer = setTimeout(check, Math.min(remaining, 2_147_483_647))
    }
    check()
    return () => clearTimeout(timer)
  }, [result])
  async function submit(event: FormEvent) {
    event.preventDefault()
    changed()
    const epoch = ++lifetime.current.epoch
    const request = new AbortController()
    lifetime.current.request = request
    setBusy(true)
    try {
      const start = from.trim(),
        end = to.trim()
      if (!start || !end) throw new Error('Choose a from/to window with explicit UTC offsets.')
      const value = await apiFetch<IncidentImpactResponse>(
        `/incidents/${encodeURIComponent(incident.id)}/impact`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          signal: request.signal,
          body: JSON.stringify({
            from: start,
            to: end,
            dataseries: 'auto',
            include_tests: includeTests,
            ...(customer ? { customer_tag_key: customer } : {}),
          }),
        },
      )
      if (lifetime.current.active && lifetime.current.epoch === epoch && !request.signal.aborted)
        setResult(value)
    } catch (reason) {
      if (lifetime.current.active && lifetime.current.epoch === epoch && !request.signal.aborted)
        setError(reason instanceof Error ? reason.message : 'Incident impact is unavailable.')
    } finally {
      if (lifetime.current.active && lifetime.current.epoch === epoch) setBusy(false)
    }
  }
  async function exportSigned() {
    const epoch = ++lifetime.current.epoch
    lifetime.current.request?.abort()
    const request = new AbortController()
    lifetime.current.request = request
    setBusy(true)
    setError('')
    setExported(false)
    try {
      const bytes = await exportEvidence.mutateAsync({
        impact: {
          from: from.trim(),
          to: to.trim(),
          dataseries: 'auto',
          include_tests: includeTests,
          ...(customer ? { customer_tag_key: customer } : {}),
        },
        signal: request.signal,
      })
      if (!lifetime.current.active || lifetime.current.epoch !== epoch || request.signal.aborted)
        return
      const blob = new Blob([bytes as BlobPart], { type: 'application/vnd.probectl.evidence+json' })
      const href = URL.createObjectURL(blob)
      try {
        const anchor = document.createElement('a')
        anchor.href = href
        anchor.download = `probectl-incident-${incident.id}-impact-evidence.json`
        anchor.click()
      } finally {
        URL.revokeObjectURL(href)
      }
      setExported(true)
    } catch (reason) {
      if (lifetime.current.active && lifetime.current.epoch === epoch && !request.signal.aborted)
        setError(
          reason instanceof Error ? reason.message : 'Signed impact evidence is unavailable.',
        )
    } finally {
      exportEvidence.reset()
      if (lifetime.current.active && lifetime.current.epoch === epoch) setBusy(false)
    }
  }
  return (
    <div className={styles.stack}>
      <form onSubmit={(event) => void submit(event)} className={styles.stack}>
        <div className={styles.grid}>
          <Field
            label="Impact from (ISO 8601 with offset)"
            required
            value={from}
            onChange={(event) => {
              changed()
              setFrom(event.target.value)
            }}
          />
          <Field
            label="Impact to (exclusive, ISO 8601 with offset)"
            required
            value={to}
            onChange={(event) => {
              changed()
              setTo(event.target.value)
            }}
          />
          <Field
            label="Customer tag key (optional)"
            value={customer}
            onChange={(event) => {
              changed()
              setCustomer(event.target.value)
            }}
          />
        </div>
        {permissions.includes('test.read') && (
          <label>
            <input
              type="checkbox"
              checked={includeTests}
              onChange={(event) => {
                changed()
                setIncludeTests(event.target.checked)
              }}
            />{' '}
            Include original configured-test outcomes
          </label>
        )}
        <div className={styles.actions}>
          <Button type="submit" disabled={busy}>
            {busy && !exportEvidence.isPending ? 'Comparing…' : 'Compare incident impact'}
          </Button>
        </div>
      </form>
      {error && <ErrorState title="Incident impact unavailable" description={error} />}
      {result && (
        <section aria-label="Incident impact result" className={styles.stack}>
          <p>{result.interpretation}</p>
          <ImpactPeriod title="Current observed traffic" period={result.current} />
          <ImpactPeriod title="One week earlier" period={result.previous} />
          {result.observed_scaled_byte_change !== undefined && (
            <p>
              Observed sampling-adjusted byte change:{' '}
              <code>{result.observed_scaled_byte_change}</code>
            </p>
          )}
          <p>
            {result.customer_coverage === 'not_evaluated'
              ? 'Select a customer tag key to classify observed traffic.'
              : result.customer_coverage === 'observed_flows_and_original_test_inputs'
                ? 'Customer coverage combines observed flow prefixes and current tags on originally affected tests and SLO inputs. Test-only evidence does not imply observed traffic volume.'
                : 'Customer coverage includes observed flow prefixes. Select original configured-test outcomes to include test and SLO input attribution.'}{' '}
            Unclassified observed records: {result.unclassified_records}.
          </p>
          <ImpactCustomers result={result} />
          {result.tests?.map((test) => (
            <section
              key={`${test.context_id}/${test.entity_id}/${test.test_id}/${test.agent_id}`}
              aria-label={`Test outcomes: ${test.name}`}
            >
              <h3>
                {test.name} · {test.type}
              </h3>
              <p>
                Test <code>{test.test_id}</code> on agent <code>{test.agent_id}</code>; definition{' '}
                <code>{test.definition_digest}</code>.
              </p>
              <ImpactTestComparison title="Current test window" period={test.current} />
              <ImpactTestComparison title="Test window one week earlier" period={test.previous} />
            </section>
          ))}
          {result.slos?.map((slo) => (
            <section
              key={`${slo.name}/${slo.definition_digest}`}
              aria-label={`SLO failed inputs: ${slo.name}`}
            >
              <h3>{slo.display_name || slo.name}</h3>
              <p>
                Service: {slo.service}. Configured success ratio: <code>{slo.objective_ratio}</code>{' '}
                over {slo.window}.
              </p>
              <p>
                {slo.current.failed_inputs} original failed inputs in the selected window;{' '}
                {slo.previous.failed_inputs} one week earlier. These inputs do not establish a
                rolling error-budget violation.
              </p>
              <p>
                Definition <code>{slo.definition_digest}</code>.
              </p>
              <details>
                <summary>Original failed SLO input citations</summary>
                <pre className={styles.referenceText}>
                  {JSON.stringify(
                    { current: slo.current.sources, previous: slo.previous.sources },
                    null,
                    2,
                  )}
                </pre>
              </details>
            </section>
          ))}
          {result.test_coverage !== 'not_evaluated' &&
            result.slo_coverage === 'unavailable_slo_engine' && (
              <p>SLO comparisons are unavailable for this deployment.</p>
            )}
          {result.slo_coverage === 'no_applicable_slo_definitions' && (
            <p>No current SLO definitions apply to this tenant.</p>
          )}
          {result.slo_coverage === 'observed_failed_sli_inputs_only_not_a_rolling_budget_verdict' &&
            !result.slos?.length && (
              <p>
                No original failed inputs matched the current SLO definitions in these windows. This
                does not establish a healthy rolling budget.
              </p>
            )}
          {permissions.includes('ai.query') && (
            <div className={styles.actions}>
              <Button disabled={busy} onClick={() => void exportSigned()}>
                {exportEvidence.isPending
                  ? 'Preparing signed evidence…'
                  : 'Export signed impact evidence'}
              </Button>
            </div>
          )}
          {exported && (
            <p role="status">
              Downloaded a fresh signed evidence package. Verify it offline and pin the operator's
              signing-key fingerprint.
            </p>
          )}
          <details>
            <summary>Complete source and capture citations</summary>
            <pre className={styles.referenceText}>
              {JSON.stringify(
                {
                  members: result.members,
                  unresolved_root: result.unresolved_root,
                  unresolved_signal_ids: result.unresolved_signal_ids,
                  customers: result.customers,
                  current_captures: result.current.captures,
                  previous_captures: result.previous.captures,
                  tests: result.tests,
                  slos: result.slos,
                },
                null,
                2,
              )}
            </pre>
          </details>
        </section>
      )}
    </div>
  )
}

function ImpactTestComparison({
  title,
  period,
}: {
  title: string
  period: IncidentImpactTestPeriod
}) {
  const [page, setPage] = useState(0)
  const pages = Math.max(1, Math.ceil(period.observations.length / 200))
  return (
    <section aria-label={title}>
      <h4>{title}</h4>
      <p>
        {period.successful} successful; {period.failed} failed; {period.unknown} unknown, including{' '}
        {period.canceled} canceled.
      </p>
      {period.packets && (
        <p>
          Complete echo batches: {period.packets.transmitted} transmitted, {period.packets.received}{' '}
          received, {period.packets.lost} lost.
        </p>
      )}
      {period.observations.length === 0 && (
        <p>No retained observations; coverage is unavailable.</p>
      )}
      <ul>
        {period.observations.slice(page * 200, (page + 1) * 200).map((observation) => (
          <li key={observation.evidence_id}>
            <DateTime value={observation.observed_at} /> · {observation.status} ·{' '}
            {observation.reason} · evidence <code>{observation.evidence_id}</code> · digest{' '}
            <code>{observation.digest}</code>
          </li>
        ))}
      </ul>
      {pages > 1 && (
        <div className={styles.actions}>
          <Button
            aria-label={`Previous observations for ${title}`}
            disabled={page === 0}
            onClick={() => setPage(page - 1)}
          >
            Previous
          </Button>
          <span>
            Observation page {page + 1} of {pages}; {period.observations.length} observations total
          </span>
          <Button
            aria-label={`Next observations for ${title}`}
            disabled={page + 1 >= pages}
            onClick={() => setPage(page + 1)}
          >
            Next
          </Button>
        </div>
      )}
    </section>
  )
}

function ImpactCustomers({ result }: { result: IncidentImpactResponse }) {
  const [page, setPage] = useState(0)
  useEffect(() => setPage(0), [result])
  const pages = Math.max(1, Math.ceil(result.customers.length / 200))
  return (
    <div className={styles.stack}>
      <Table
        caption="Cited affected customers"
        rows={result.customers.slice(page * 200, (page + 1) * 200)}
        rowKey={(row) => JSON.stringify([row.context_id, row.value])}
        columns={[
          { key: 'value', header: 'Customer', render: (row) => row.value },
          {
            key: 'context',
            header: 'Routing context',
            render: (row) => <code>{row.context_id}</code>,
          },
          {
            key: 'current',
            header: 'Current scaled bytes',
            render: (row) => row.current_observed_totals?.scaled_bytes ?? 'Unavailable',
          },
          {
            key: 'previous',
            header: 'Previous scaled bytes',
            render: (row) => row.previous_observed_totals?.scaled_bytes ?? 'Unavailable',
          },
          {
            key: 'prefixes',
            header: 'Prefix citations',
            render: (row) => row.prefix_ids.join(', '),
          },
          {
            key: 'tests',
            header: 'Affected test citations',
            render: (row) => <code>{row.test_ids.join(', ') || 'None'}</code>,
          },
          {
            key: 'slos',
            header: 'SLO input citations',
            render: (row) => row.slo_ids.join(', ') || 'None',
          },
          {
            key: 'observations',
            header: 'Original test evidence',
            render: (row) => <code>{row.evidence_ids?.join(', ') || 'None'}</code>,
          },
          {
            key: 'tags',
            header: 'Current tag citations',
            render: (row) => <code>{row.tag_ids?.join(', ') || 'None'}</code>,
          },
        ]}
      />
      <div className={styles.actions}>
        <Button disabled={page === 0} onClick={() => setPage((value) => value - 1)}>
          Previous customer page
        </Button>
        <span aria-live="polite">
          Customer page {page + 1} of {pages}; {result.customers.length} customers total
        </span>
        <Button disabled={page + 1 >= pages} onClick={() => setPage((value) => value + 1)}>
          Next customer page
        </Button>
      </div>
    </div>
  )
}

function ImpactPeriod({ title, period }: { title: string; period: IncidentImpactPeriod }) {
  return (
    <section aria-label={title}>
      <h3>{title}</h3>
      <p>
        <DateTime value={period.from} /> through <DateTime value={period.to} /> (exclusive)
      </p>
      <p>
        <code>{period.from}</code> through <code>{period.to}</code> (exclusive)
      </p>
      <p>
        {coverageLabels[period.coverage] ?? 'Coverage is unavailable'}; attested records:{' '}
        {period.attested_records}; unverified records: {period.unverified_records}.
      </p>
      <dl className={styles.summary}>
        <dt>Raw bytes</dt>
        <dd>{period.observed_totals?.raw_bytes ?? 'Unavailable'}</dd>
        <dt>Sampling-adjusted bytes</dt>
        <dd>{period.observed_totals?.scaled_bytes ?? 'Unavailable'}</dd>
        <dt>Raw packets</dt>
        <dd>{period.observed_totals?.raw_packets ?? 'Unavailable'}</dd>
        <dt>Sampling-adjusted packets</dt>
        <dd>{period.observed_totals?.scaled_packets ?? 'Unavailable'}</dd>
      </dl>
    </section>
  )
}
