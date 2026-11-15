// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { apiFetch } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { Button, Card, CardBody, CardHeader, ErrorState, Field } from '../components'
import styles from './flowExplorer.module.css'

interface RangeSource {
  publisher: string
  version: string
  digest: string
  fetched_at: string
  valid_until: string
  published_at?: string
  published_time?: string
  status: string
  matches: { prefix: string; service: string; region: string }[]
}

interface SourceLookup {
  ip: string
  services?: RangeSource[]
}

function currentStatus(source: RangeSource, now: number) {
  if (source.status !== 'matched' && source.status !== 'unmatched') return source.status
  const fetched = Date.parse(source.fetched_at)
  const until = Date.parse(source.valid_until)
  return Number.isFinite(fetched) && now >= fetched && now < until ? source.status : 'stale'
}

export function FlowServiceSources() {
  const { tenant, user, permissions, hasScopedGrants } = useAuth()
  if (!permissions.includes('flow.read')) return null
  const identity = JSON.stringify([tenant.id, user.id, [...permissions].sort(), !!hasScopedGrants])
  return <ServiceSourceLookup key={identity} />
}

function ServiceSourceLookup() {
  const [address, setAddress] = useState('')
  const [result, setResult] = useState<SourceLookup>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [clock, setClock] = useState(Date.now)
  const request = useRef<AbortController | undefined>(undefined)
  useEffect(() => () => request.current?.abort(), [])
  useEffect(() => {
    const now = Date.now()
    const next = (result?.services ?? []).reduce((soonest, source) => {
      const until = Date.parse(source.valid_until)
      return until > now ? Math.min(soonest, until) : soonest
    }, Infinity)
    if (!Number.isFinite(next)) return
    const timer = window.setTimeout(
      () => setClock(Date.now()),
      Math.min(next - now + 1, 2147483647),
    )
    return () => window.clearTimeout(timer)
  }, [result, clock])

  function clear() {
    request.current?.abort()
    setResult(undefined)
    setError('')
    setBusy(false)
  }
  async function submit(event: FormEvent) {
    event.preventDefault()
    clear()
    const active = new AbortController()
    request.current = active
    setBusy(true)
    try {
      const query = new URLSearchParams({ ip: address.trim() })
      const next = await apiFetch<SourceLookup>(`/opendata/enrichment?${query}`, {
        signal: active.signal,
      })
      if (!active.signal.aborted && request.current === active) setResult(next)
    } catch (cause) {
      if (!active.signal.aborted && request.current === active)
        setError(cause instanceof Error ? cause.message : 'Published source lookup is unavailable.')
    } finally {
      if (!active.signal.aborted && request.current === active) setBusy(false)
    }
  }
  const now = Math.max(clock, Date.now())
  return (
    <Card data-service-sources>
      <CardHeader
        title="Published service sources · preview"
        description="Inspect the local range evidence behind a network address."
      />
      <CardBody className={styles.stack}>
        <p>
          This lookup shows current published network candidates. Range overlap does not prove an
          application. Stored flow labels retain their original capture-time classification.
        </p>
        <form onSubmit={(event) => void submit(event)} className={styles.row}>
          <Field
            label="Address for service sources"
            required
            value={address}
            onChange={(event) => {
              clear()
              setAddress(event.target.value)
            }}
          />
          <Button type="submit" disabled={busy || !address.trim()}>
            Look up service sources
          </Button>
        </form>
        {busy && <p role="status">Looking up local service sources…</p>}
        {error && <ErrorState title="Service source lookup failed" description={error} />}
        {result && (
          <section aria-label={`Published sources for ${result.ip}`} className={styles.roleSources}>
            <p>Source lookup for {result.ip}</p>
            {!result.services?.length && <p>No published service sources are configured.</p>}
            <ol>
              {(result.services ?? []).map((source) => {
                const status = currentStatus(source, now)
                const matches = status === 'matched' ? source.matches : []
                return (
                  <li key={source.publisher}>
                    <details>
                      <summary role="button">
                        <strong>{source.publisher}</strong> · {status} ({matches.length}{' '}
                        {matches.length === 1 ? 'candidate' : 'candidates'})
                      </summary>
                      <dl className={styles.summary}>
                        <div>
                          <dt>Original fetch time</dt>
                          <dd>{source.fetched_at || 'Not available'}</dd>
                        </div>
                        <div>
                          <dt>Valid until</dt>
                          <dd>{source.valid_until || 'Not available'}</dd>
                        </div>
                        <div>
                          <dt>Publisher time</dt>
                          <dd>{source.published_at || source.published_time || 'Not published'}</dd>
                        </div>
                        <div>
                          <dt>Version</dt>
                          <dd>{source.version || 'Not available'}</dd>
                        </div>
                        <div>
                          <dt>Original body digest</dt>
                          <dd>{source.digest || 'Not available'}</dd>
                        </div>
                      </dl>
                      {!matches.length && <p>No current address attribution from this source.</p>}
                      <ul>
                        {matches.map((match, index) => (
                          <li key={`${match.prefix}:${match.service}:${match.region}:${index}`}>
                            <strong>{match.service}</strong> · {match.prefix} ·{' '}
                            {match.region || 'Unknown region'}
                          </li>
                        ))}
                      </ul>
                    </details>
                  </li>
                )
              })}
            </ol>
          </section>
        )}
      </CardBody>
    </Card>
  )
}
