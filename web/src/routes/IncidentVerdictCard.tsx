// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { apiFetch } from '../api/client'
import { useExportIncidentEvidence, type Incident } from '../api/incidents'
import type { IncidentVerdictCitation, IncidentVerdictResponse } from '../api/sdk.gen'
import { useAuth } from '../auth/useAuth'
import { Button, Card, CardBody, CardHeader, ErrorState, Field } from '../components'
import { DateTime } from '../time/DateTime'
import styles from './flowExplorer.module.css'

const required = ['incident.read', 'entities.read', 'metrics.read', 'events.read', 'test.read']
const labels: Record<string, string> = {
  unknown: 'Unknown',
  your_network: 'Your network',
  carrier: 'Carrier',
  wider_internet: 'Wider internet',
  remote_service: 'Remote service',
}

export function IncidentVerdictCard({ incident }: { incident: Incident }) {
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
        title="Fault domain · preview"
        description="Compare the original evidence for each possible fault location. Thin coverage stays unknown."
      />
      <CardBody>
        <VerdictForm key={identity} incident={incident} />
      </CardBody>
    </Card>
  )
}

function VerdictForm({ incident }: { incident: Incident }) {
  const { permissions } = useAuth()
  const exportEvidence = useExportIncidentEvidence(incident.id)
  const [exported, setExported] = useState(false)
  const [from, setFrom] = useState(incident.started_at)
  const [to, setTo] = useState(() => new Date().toISOString())
  const [result, setResult] = useState<IncidentVerdictResponse>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const lifetime = useRef({
    active: true,
    epoch: 0,
    request: undefined as AbortController | undefined,
  })
  const clear = () => {
    lifetime.current.epoch++
    lifetime.current.request?.abort()
    setResult(undefined)
    setError('')
    setExported(false)
    setBusy(false)
  }
  useEffect(() => {
    const current = lifetime.current
    current.active = true
    const invalidate = () => clear()
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
    let timer: ReturnType<typeof setTimeout> | undefined
    const check = () => {
      const remaining = Date.parse(result.valid_until!) - Date.now()
      if (!Number.isFinite(remaining) || remaining <= 0) {
        clear()
        setError('Current source authority expired. Run a fresh evaluation.')
      } else timer = setTimeout(check, Math.min(remaining, 2_147_483_647))
    }
    check()
    return () => clearTimeout(timer)
  }, [result])
  async function submit(event: FormEvent) {
    event.preventDefault()
    clear()
    const epoch = ++lifetime.current.epoch
    const request = new AbortController()
    lifetime.current.request = request
    setBusy(true)
    try {
      if (!from.trim() || !to.trim())
        throw new Error('Choose a from/to window with explicit UTC offsets.')
      const value = await apiFetch<IncidentVerdictResponse>(
        `/incidents/${encodeURIComponent(incident.id)}/verdict`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          signal: request.signal,
          body: JSON.stringify({ from: from.trim(), to: to.trim() }),
        },
      )
      if (lifetime.current.active && lifetime.current.epoch === epoch && !request.signal.aborted)
        setResult(value)
    } catch (reason) {
      if (lifetime.current.active && lifetime.current.epoch === epoch && !request.signal.aborted)
        setError(reason instanceof Error ? reason.message : 'Incident verdict is unavailable.')
    } finally {
      if (lifetime.current.active && lifetime.current.epoch === epoch) setBusy(false)
    }
  }
  async function exportSigned() {
    if (!result) return
    lifetime.current.request?.abort()
    const epoch = ++lifetime.current.epoch
    const request = new AbortController()
    lifetime.current.request = request
    setBusy(true)
    setError('')
    setExported(false)
    try {
      const bytes = await exportEvidence.mutateAsync({
        verdict: { from: result.from, to: result.to },
        signal: request.signal,
      })
      if (!lifetime.current.active || lifetime.current.epoch !== epoch || request.signal.aborted)
        return
      const blob = new Blob([new Uint8Array(bytes)], {
        type: 'application/vnd.probectl.evidence+json',
      })
      const href = URL.createObjectURL(blob)
      try {
        const anchor = document.createElement('a')
        anchor.href = href
        anchor.download = `probectl-incident-${incident.id}-fault-evidence.json`
        anchor.click()
      } finally {
        URL.revokeObjectURL(href)
      }
      setExported(true)
    } catch (reason) {
      if (lifetime.current.active && lifetime.current.epoch === epoch && !request.signal.aborted)
        setError(reason instanceof Error ? reason.message : 'Signed fault evidence is unavailable.')
    } finally {
      exportEvidence.reset()
      if (lifetime.current.active && lifetime.current.epoch === epoch) setBusy(false)
    }
  }

  return (
    <div className={styles.stack}>
      <p>
        Local interface states and verified HTTPS responses supply the initial rules. Carrier and
        wider-internet evidence are not yet connected. Confidence describes evidence coverage, not a
        probability.
      </p>
      <form
        onSubmit={(event) => void submit(event)}
        className={styles.stack}
        aria-label="Incident fault domain"
      >
        <div className={styles.grid}>
          <Field
            label="Verdict from (ISO 8601 with offset)"
            required
            value={from}
            onChange={(event) => {
              clear()
              setFrom(event.target.value)
            }}
          />
          <Field
            label="Verdict to (exclusive, ISO 8601 with offset)"
            required
            value={to}
            onChange={(event) => {
              clear()
              setTo(event.target.value)
            }}
          />
          <Button type="submit" disabled={busy}>
            {busy ? 'Evaluating…' : 'Evaluate fault domain'}
          </Button>
        </div>
      </form>
      {error ? <ErrorState title="Fault domain unavailable" description={error} /> : null}
      {result ? (
        <div className={styles.stack} aria-live="polite">
          {permissions.includes('ai.query') ? (
            <div className={styles.actions}>
              <Button type="button" disabled={busy} onClick={() => void exportSigned()}>
                Export signed fault evidence
              </Button>
              <p>The export re-evaluates this window under current permissions.</p>
            </div>
          ) : null}
          {exported ? (
            <p>Signed evidence downloaded. Verify it with the offline incident verifier.</p>
          ) : null}
          <p>
            <strong>{labels[result.domain] ?? result.domain}</strong> · {result.confidence} evidence
          </p>
          <p>{readable(result.reason)}</p>
          <p>
            Evaluated <DateTime value={result.evaluated_at} />
            {result.valid_until ? (
              <>
                {' '}
                · Source authority until <DateTime value={result.valid_until} />
              </>
            ) : null}
          </p>
          {result.hypotheses.map((hypothesis) => (
            <section
              key={hypothesis.domain}
              className={styles.group}
              aria-label={labels[hypothesis.domain] ?? hypothesis.domain}
            >
              <h3>{labels[hypothesis.domain] ?? hypothesis.domain}</h3>
              <p>{hypothesis.confidence} evidence</p>
              <Citations title="Supporting observations" values={hypothesis.for} />
              <Citations title="Contradicting observations" values={hypothesis.against} />
              {hypothesis.missing.length ? (
                <>
                  <h4>Missing coverage</h4>
                  <ul>
                    {hypothesis.missing.map((reason) => (
                      <li key={reason}>{readable(reason)}</li>
                    ))}
                  </ul>
                </>
              ) : null}
            </section>
          ))}
        </div>
      ) : null}
    </div>
  )
}

function readable(reason: string) {
  return reason.replace(/_/g, ' ')
}
function Citations({ title, values }: { title: string; values: IncidentVerdictCitation[] }) {
  return (
    <div>
      <h4>{title}</h4>
      {values.length ? (
        <ol className={styles.roleSources}>
          {values.map((value) => (
            <li key={value.evidence_id}>
              {readable(value.reason)} · <DateTime value={value.observed_at} />
              <details>
                <summary>Original observation</summary>
                <dl className={styles.summary}>
                  <div>
                    <dt>Context</dt>
                    <dd>{value.context_id}</dd>
                  </div>
                  <div>
                    <dt>Entity</dt>
                    <dd>{value.entity_id}</dd>
                  </div>
                  <div>
                    <dt>Evidence</dt>
                    <dd>{value.evidence_id}</dd>
                  </div>
                  <div>
                    <dt>Agent</dt>
                    <dd>{value.agent_id}</dd>
                  </div>
                  <div>
                    <dt>Document digest</dt>
                    <dd>{value.digest}</dd>
                  </div>
                </dl>
              </details>
            </li>
          ))}
        </ol>
      ) : (
        <p>No qualifying observation.</p>
      )}
    </div>
  )
}
