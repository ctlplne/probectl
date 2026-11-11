// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useAuth } from '../auth/useAuth'
import { usePeeringContexts, usePeeringEstimate, usePeeringInterfaces } from '../api/peering'
import type { PeeringEstimateInput, PeeringEstimateResponse } from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, ErrorState, Field, Select, Table } from '../components'
import { peeringGbps } from './peeringValues'
import styles from './flowExplorer.module.css'

const required = ['flow.read', 'ai.query', 'entities.read', 'metrics.read', 'events.read']

export function PeeringEstimateCard() {
  const { tenant, user, permissions, hasScopedGrants } = useAuth()
  const [open, setOpen] = useState(false)
  if (!required.every((permission) => permissions.includes(permission))) return null
  const identity = JSON.stringify([
    tenant.id,
    user.id,
    [...permissions].sort(),
    Boolean(hasScopedGrants),
  ])
  return (
    <Card data-peering-estimate>
      <CardHeader
        title="Peering estimate · preview"
        description="Estimate known eligible traffic off transit using an owned IX interface and original routing evidence."
      />
      <CardBody>
        <details open={open} onToggle={(event) => setOpen(event.currentTarget.open)}>
          <summary className={styles.link}>Configure a hypothetical peering</summary>
          {open && <PeeringEstimateForm key={identity} identity={identity} />}
        </details>
      </CardBody>
    </Card>
  )
}

function PeeringEstimateForm({ identity }: { identity: string }) {
  const contexts = usePeeringContexts(identity)
  const [context, setContext] = useState('')
  const [iface, setInterface] = useState('')
  const [asn, setASN] = useState('')
  const [ix, setIX] = useState('')
  const [lan, setLAN] = useState('')
  const [direction, setDirection] = useState<PeeringEstimateInput['direction']>('inbound')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [bucket, setBucket] = useState('300')
  const [series, setSeries] = useState<PeeringEstimateInput['dataseries']>('auto')
  const interfaces = usePeeringInterfaces(identity, context)
  const estimate = usePeeringEstimate(identity)
  const [result, setResult] = useState<PeeringEstimateResponse>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const lifetime = useRef({
    active: true,
    epoch: 0,
    request: undefined as AbortController | undefined,
  })
  useEffect(() => {
    const current = lifetime.current
    current.active = true
    return () => {
      current.active = false
      current.epoch++
      current.request?.abort()
    }
  }, [])
  useEffect(() => {
    if (!result?.target.valid_until) return
    const deadline = Date.parse(result.target.valid_until)
    if (!Number.isFinite(deadline)) {
      setResult(undefined)
      setError('Current evidence expiry is unavailable. Run a fresh estimate.')
      return
    }
    let timer: ReturnType<typeof setTimeout> | undefined
    const check = () => {
      const remaining = deadline - Date.now()
      if (remaining <= 0) {
        setResult(undefined)
        setError('Current target evidence expired. Run a fresh estimate.')
        return
      }
      timer = setTimeout(check, Math.min(remaining, 2_147_483_647))
    }
    check()
    return () => clearTimeout(timer)
  }, [result])

  function changed() {
    lifetime.current.epoch++
    lifetime.current.request?.abort()
    setResult(undefined)
    setError('')
    setBusy(false)
  }
  async function submit(event: FormEvent) {
    event.preventDefault()
    changed()
    const epoch = ++lifetime.current.epoch
    const request = new AbortController()
    lifetime.current.request = request
    try {
      const peer = Number(asn),
        width = Number(bucket)
      if (!/^[1-9][0-9]*$/.test(asn) || !Number.isInteger(peer) || peer > 4294967295)
        throw new Error('Use a peer ASN from 1 through 4294967295.')
      for (const value of [ix, lan])
        if (
          value.length > 19 ||
          !/^[1-9][0-9]*$/.test(value) ||
          BigInt(value) > 9223372036854775807n
        )
          throw new Error('IX and IX LAN IDs must be positive exact decimal IDs.')
      if (!/^[1-9][0-9]*$/.test(bucket) || !Number.isSafeInteger(width))
        throw new Error('Use a positive whole-second bucket width.')
      setBusy(true)
      const next = await estimate.mutateAsync({
        input: {
          context_id: context,
          interface_id: iface,
          peer_asn: peer,
          ix_id: ix,
          ix_lan_id: lan,
          direction,
          from: from || undefined,
          to: to || undefined,
          bucket_seconds: width,
          dataseries: series,
        },
        signal: request.signal,
      })
      if (lifetime.current.active && lifetime.current.epoch === epoch) setResult(next)
    } catch (cause) {
      if (lifetime.current.active && lifetime.current.epoch === epoch)
        setError(cause instanceof Error ? cause.message : 'Peering estimate is unavailable.')
    } finally {
      if (lifetime.current.active && lifetime.current.epoch === epoch) setBusy(false)
    }
  }
  return (
    <div className={styles.stack}>
      <p>
        Read-only, hypothetical routing eligibility. This does not establish a live peer, forwarding
        policy or guaranteed savings.
      </p>
      {contexts.isError && (
        <ErrorState title="Cannot load owned contexts" description={contexts.error.message} />
      )}
      {interfaces.isError && (
        <ErrorState title="Cannot load owned interfaces" description={interfaces.error.message} />
      )}
      <form onSubmit={(event) => void submit(event)} className={styles.stack}>
        <div className={styles.grid}>
          <Select
            label="Peering routing context"
            required
            value={context}
            onChange={(event) => {
              changed()
              setContext(event.target.value)
              setInterface('')
            }}
            options={[
              { value: '', label: 'Choose a routing context' },
              ...(contexts.data?.pages ?? []).flatMap((page) =>
                page.items.map((item) => ({
                  value: item.context_id,
                  label: `${item.site_label} / ${item.vrf_label}`,
                })),
              ),
            ]}
          />
          <Select
            label="Owned IX interface"
            required
            value={iface}
            onChange={(event) => {
              changed()
              setInterface(event.target.value)
            }}
            options={[
              { value: '', label: 'Choose an owned interface' },
              ...(interfaces.data?.pages ?? []).flatMap((page) =>
                page.items
                  .filter((item) => item.kind === 'interface')
                  .map((item) => ({
                    value: item.id,
                    label: `${item.label} · ${item.id}`,
                  })),
              ),
            ]}
          />
          <Field
            label="Peer ASN"
            inputMode="numeric"
            required
            value={asn}
            onChange={(event) => {
              changed()
              setASN(event.target.value)
            }}
          />
          <Field
            label="IX ID"
            inputMode="numeric"
            required
            value={ix}
            onChange={(event) => {
              changed()
              setIX(event.target.value)
            }}
            hint="Exact public ID, preserved as text."
          />
          <Field
            label="IX LAN ID"
            inputMode="numeric"
            required
            value={lan}
            onChange={(event) => {
              changed()
              setLAN(event.target.value)
            }}
          />
          <Select
            label="Peering traffic direction"
            value={direction}
            onChange={(event) => {
              changed()
              setDirection(event.target.value as PeeringEstimateInput['direction'])
            }}
            options={[
              { value: 'inbound', label: 'Inbound · ingress transit, source path' },
              { value: 'outbound', label: 'Outbound · egress transit, destination path' },
            ]}
          />
          <Field
            label="Peering from (RFC3339, optional)"
            value={from}
            onChange={(event) => {
              changed()
              setFrom(event.target.value)
            }}
            hint="Blank bounds use the last hour. Fractional seconds are preserved."
          />
          <Field
            label="Peering to (RFC3339, optional)"
            value={to}
            onChange={(event) => {
              changed()
              setTo(event.target.value)
            }}
          />
          <Field
            label="Peering interval seconds"
            inputMode="numeric"
            required
            value={bucket}
            onChange={(event) => {
              changed()
              setBucket(event.target.value)
            }}
          />
          <Select
            label="Peering flow source"
            value={series}
            onChange={(event) => {
              changed()
              setSeries(event.target.value as PeeringEstimateInput['dataseries'])
            }}
            options={[
              { value: 'auto', label: 'Automatic retained coverage' },
              { value: 'raw', label: 'Raw flows' },
              { value: 'rollup', label: 'Retained complete rollups' },
            ]}
          />
        </div>
        <div className={styles.actions}>
          {contexts.hasNextPage && (
            <Button
              type="button"
              disabled={contexts.isFetchingNextPage}
              onClick={() => void contexts.fetchNextPage()}
            >
              Load more peering contexts
            </Button>
          )}
          {interfaces.hasNextPage && (
            <Button
              type="button"
              disabled={interfaces.isFetchingNextPage}
              onClick={() => void interfaces.fetchNextPage()}
            >
              Load more owned entities
            </Button>
          )}
          <Button type="submit" disabled={busy || !context || !iface}>
            Estimate observed peering traffic
          </Button>
        </div>
      </form>
      {busy && <p role="status">Peering estimate running…</p>}
      {error && <ErrorState title="Peering estimate unavailable" description={error} />}
      {result && <PeeringEstimateResult result={result} />}
    </div>
  )
}

function PeeringEstimateResult({ result }: { result: PeeringEstimateResponse }) {
  const [page, setPage] = useState(0)
  const start = Math.min(page * 25, Math.max(0, Math.ceil(result.transit.length / 25) - 1) * 25)
  return (
    <section aria-label="Peering estimate result" className={styles.stack}>
      <p role="status">
        {result.target.eligible
          ? result.coverage.complete_observed_inputs
            ? result.coverage.complete_routing_classification
              ? 'Complete observed input classification.'
              : 'Partial routing evidence: unknown volumes are excluded from known eligible p95.'
            : 'Missing observed intervals: no p95 is available.'
          : `Target unavailable: ${result.target.reason.replace(/_/g, ' ')}.`}
      </p>
      <p>{result.interpretation}</p>
      <dl className={styles.summary}>
        <div>
          <dt>Known eligible combined p95 off transit</dt>
          <dd>
            {result.known_eligible_p95 ? peeringGbps(result.known_eligible_p95) : 'Unavailable'}
          </dd>
        </div>
        <div>
          <dt>Observed intervals</dt>
          <dd>
            {result.coverage.observed_intervals} / {result.coverage.expected_intervals}
          </dd>
        </div>
        <div>
          <dt>Window</dt>
          <dd>
            {result.from} — {result.to}
          </dd>
        </div>
        {Object.entries(result.bytes).map(([name, bytes]) => (
          <div key={name}>
            <dt>{name.replace(/_/g, ' ')} bytes</dt>
            <dd>{bytes}</dd>
          </div>
        ))}
      </dl>
      {result.known_eligible_p95 && (
        <p>
          Exact combined rate: {result.known_eligible_p95.bits_per_second_numerator} /{' '}
          {result.known_eligible_p95.bits_per_second_denominator} bit/s. Gbps display is rounded
          down to three decimal places. Per-interface percentiles must not be added.
        </p>
      )}
      <Table
        caption="Known eligible p95 by transit interface"
        rows={result.transit.slice(start, start + 25)}
        rowKey={(row) => row.interface_id}
        columns={[
          { key: 'interface', header: 'Transit interface', render: (row) => row.interface_id },
          {
            key: 'rate',
            header: 'Known eligible p95',
            render: (row) =>
              `${peeringGbps(row.known_eligible_p95)} (${row.known_eligible_p95.bits_per_second_numerator}/${row.known_eligible_p95.bits_per_second_denominator} bit/s)`,
          },
        ]}
        empty="No qualified per-transit estimate is available."
      />
      {result.transit.length > 25 && (
        <div className={styles.actions}>
          <Button disabled={start === 0} onClick={() => setPage(Math.max(0, page - 1))}>
            Previous transit interfaces
          </Button>
          <span role="status">
            Transit interfaces {start + 1}–{Math.min(start + 25, result.transit.length)} of{' '}
            {result.transit.length}
          </span>
          <Button disabled={start + 25 >= result.transit.length} onClick={() => setPage(page + 1)}>
            Next transit interfaces
          </Button>
        </div>
      )}
      <details className={styles.roleSources}>
        <summary>Complete target evidence references</summary>
        <p>
          Prefix generation: {result.target.prefix_version || 'unavailable'}; membership generation:{' '}
          {result.target.membership_version || 'unavailable'}. Valid until:{' '}
          {result.target.valid_until || 'unavailable'}.
        </p>
        <label>
          All prefix sources ({result.target.prefix_sources.length})
          <textarea
            readOnly
            rows={4}
            className={styles.referenceText}
            value={result.target.prefix_sources.join('\n')}
          />
        </label>
        <label>
          All membership sources ({result.target.membership_sources.length})
          <textarea
            readOnly
            rows={6}
            className={styles.referenceText}
            value={result.target.membership_sources.join('\n')}
          />
        </label>
      </details>
    </section>
  )
}
