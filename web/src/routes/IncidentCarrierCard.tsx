// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useAuth } from '../auth/useAuth'
import { useExportIncidentEvidence, type Incident } from '../api/incidents'
import { Button, Card, CardBody, CardHeader, ErrorState, Field } from '../components'
import styles from './flowExplorer.module.css'

const required = [
  'incident.read',
  'ai.query',
  'entities.read',
  'metrics.read',
  'events.read',
  'test.read',
  'change.read',
]

export function IncidentCarrierCard({ incident }: { incident: Incident }) {
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
        title="Carrier ticket pack · preview"
        description="Download selected original measurements as a redacted, signed package that verifies offline."
      />
      <CardBody>
        <CarrierForm key={identity} incident={incident} />
      </CardBody>
    </Card>
  )
}

function CarrierForm({ incident }: { incident: Incident }) {
  const exportEvidence = useExportIncidentEvidence(incident.id)
  const filename = `probectl-incident-${incident.id}-carrier.json`
  const [from, setFrom] = useState(incident.started_at)
  const [to, setTo] = useState(incident.last_seen_at)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [downloaded, setDownloaded] = useState(false)
  const lifetime = useRef({
    active: true,
    epoch: 0,
    request: undefined as AbortController | undefined,
  })
  function invalidate() {
    lifetime.current.epoch++
    lifetime.current.request?.abort()
    setBusy(false)
    setError('')
    setDownloaded(false)
  }
  useEffect(() => {
    const current = lifetime.current
    current.active = true
    const changed = () => invalidate()
    window.addEventListener('focus', changed)
    document.addEventListener('visibilitychange', changed)
    return () => {
      current.active = false
      current.epoch++
      current.request?.abort()
      window.removeEventListener('focus', changed)
      document.removeEventListener('visibilitychange', changed)
    }
  }, [])
  async function download(event: FormEvent) {
    event.preventDefault()
    invalidate()
    const epoch = lifetime.current.epoch
    const request = new AbortController()
    lifetime.current.request = request
    setBusy(true)
    try {
      const bytes = await exportEvidence.mutateAsync({
        carrier: { from: from.trim(), to: to.trim() },
        signal: request.signal,
      })
      if (!lifetime.current.active || epoch !== lifetime.current.epoch || request.signal.aborted)
        return
      const href = URL.createObjectURL(
        new Blob([new Uint8Array(bytes)], { type: 'application/vnd.probectl.evidence+json' }),
      )
      try {
        const anchor = document.createElement('a')
        anchor.href = href
        anchor.download = filename
        anchor.click()
      } finally {
        URL.revokeObjectURL(href)
      }
      setDownloaded(true)
    } catch (reason) {
      if (lifetime.current.active && epoch === lifetime.current.epoch && !request.signal.aborted)
        setError(reason instanceof Error ? reason.message : 'Carrier pack is unavailable.')
    } finally {
      exportEvidence.reset()
      if (lifetime.current.active && epoch === lifetime.current.epoch) setBusy(false)
    }
  }
  return (
    <div className={styles.stack}>
      <p>
        The pack includes available loss and RTT observations, original routing changes and handoff
        counters. Trace origins and missing coverage are explicit. A control-plane trace is not an
        independent agent vantage, and temporal association does not prove carrier fault.
      </p>
      <form
        className={styles.stack}
        aria-label="Carrier ticket evidence"
        onSubmit={(event) => void download(event)}
      >
        <div className={styles.grid}>
          <Field
            label="Carrier from (ISO 8601 with offset)"
            required
            value={from}
            onChange={(event) => {
              invalidate()
              setFrom(event.target.value)
            }}
          />
          <Field
            label="Carrier to (exclusive, ISO 8601 with offset)"
            required
            value={to}
            onChange={(event) => {
              invalidate()
              setTo(event.target.value)
            }}
          />
        </div>
        <Button type="submit" disabled={busy}>
          {busy ? 'Building carrier pack…' : 'Download carrier ticket pack'}
        </Button>
      </form>
      {error ? <ErrorState title="Carrier pack unavailable" description={error} /> : null}
      <p role="status">
        {downloaded ? 'Signed carrier pack downloaded. ' : ''}
        Obtain the signer fingerprint from the operator through a separate trusted channel. Verify
        the downloaded file offline with{' '}
        <code>
          probectl incident verify {filename} --trusted-key-fingerprint{' '}
          {"'sha256:<operator-published-fingerprint>'"}
        </code>
      </p>
      <p>Nothing is sent to a carrier. Downloading does not create a public share link.</p>
    </div>
  )
}
