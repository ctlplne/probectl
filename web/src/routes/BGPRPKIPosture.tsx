// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { apiFetch } from '../api/client'
import { useCanonicalEntities, useEntityContexts } from '../api/entities'
import type {
  BGPRPKICurrentPosture,
  BGPRPKIPathPosture,
  BGPRPKITrendPoint,
  BGPVisibilityMonitor,
} from '../api/sdk.gen'
import {
  Badge,
  Button,
  ErrorState,
  Field,
  LoadingState,
  Select,
  Table,
  type Column,
} from '../components'
import { DateTime } from '../time/DateTime'
import styles from './planes.module.css'

const statusPresentation = {
  valid: { label: 'Valid', tone: 'success' },
  invalid: { label: 'Invalid', tone: 'danger' },
  not_found: { label: 'No covering authorization', tone: 'warning' },
  unknown: { label: 'Unknown', tone: 'neutral' },
} as const

const reasons: Record<string, string> = {
  matching_prefix_and_origin: 'The prefix and origin match a covering authorization.',
  no_covering_assertion: 'The validator found no covering authorization.',
  prefix_length_exceeds_origin_authorization:
    'The announced prefix is more specific than the origin authorization allows.',
  origin_mismatch: 'The announcement uses an origin outside the covering authorizations.',
  origin_and_length_mismatch:
    'The origin and announced prefix length differ from the covering authorizations.',
  as0_denial_or_insufficient_length: 'A route origin authorization with AS0 covers this prefix.',
  validator_unavailable: 'A current complete validator snapshot is unavailable.',
  historical_validator_unavailable: 'Historical validator evidence is unavailable.',
  origin_unavailable: 'The observed path does not identify one origin.',
}

const columns: Column<BGPRPKIPathPosture>[] = [
  {
    key: 'origin',
    header: 'Observed origin',
    render: (path) => (path.origin_asn === undefined ? 'Unknown' : `AS${path.origin_asn}`),
  },
  {
    key: 'validation',
    header: 'Origin validation',
    render: ({ rpki }) => {
      const badge = statusPresentation[rpki.status]
      return (
        <div className={styles.visualStack}>
          <Badge tone={badge.tone}>{badge.label}</Badge>
          <span>{reasons[rpki.reason] ?? 'Validation evidence is unavailable.'}</span>
          {rpki.validator_observed_at && (
            <span>
              Validator observed <DateTime value={rpki.validator_observed_at} />
            </span>
          )}
          {(rpki.covering.length > 0 || rpki.validator_version) && (
            <details>
              <summary>Validator evidence</summary>
              {rpki.covering.length > 0 && (
                <ul>
                  {rpki.covering.map((row) => (
                    <li key={`${row.prefix}/${row.asn}/${row.max_length}`}>
                      {row.prefix}, AS{row.asn}, maximum length {row.max_length}
                    </li>
                  ))}
                </ul>
              )}
              {rpki.validator_version && (
                <code className="break-all">{rpki.validator_version}</code>
              )}
            </details>
          )}
        </div>
      )
    },
  },
  {
    key: 'source',
    header: 'Routing evidence',
    render: (path) => (
      <div className={styles.visualStack}>
        <DateTime value={path.view_observed_at} />
        <details>
          <summary>Router and view</summary>
          <dl>
            <dt>Router</dt>
            <dd className="break-all">{path.router_id}</dd>
            <dt>Vantage</dt>
            <dd className="break-all">{path.vantage}</dd>
            <dt>Generation</dt>
            <dd className="break-all">{path.generation}</dd>
            {path.has_path_id && (
              <>
                <dt>Path ID</dt>
                <dd>{path.path_id}</dd>
              </>
            )}
          </dl>
        </details>
        {path.related_hijacks?.map((incident) => (
          <Link
            key={incident.incident_id}
            to={`/incidents?incident=${encodeURIComponent(incident.incident_id)}`}
          >
            Possible hijack <DateTime value={incident.observed_at} />
          </Link>
        ))}
      </div>
    ),
  },
  {
    key: 'suggestion',
    header: 'Exact ROA suggestion',
    render: ({ rpki }) =>
      rpki.suggestion ? (
        <span>
          {rpki.suggestion.prefix} from AS{rpki.suggestion.origin_asn}
        </span>
      ) : (
        '—'
      ),
  },
]

const trendColumns: Column<BGPRPKITrendPoint>[] = [
  {
    key: 'time',
    header: 'Route observed',
    render: (point) => <DateTime value={point.observed_at} />,
  },
  {
    key: 'origin',
    header: 'Origin',
    render: (point) => (point.origin_asn === undefined ? 'Unknown' : `AS${point.origin_asn}`),
  },
  {
    key: 'validation',
    header: 'Original validation',
    render: ({ posture }) => {
      const badge = statusPresentation[posture.status]
      return (
        <div className={styles.visualStack}>
          <Badge tone={badge.tone}>{badge.label}</Badge>
          <span>{reasons[posture.reason] ?? 'Validation evidence is unavailable.'}</span>
        </div>
      )
    },
  },
  {
    key: 'source',
    header: 'Validator observation',
    render: ({ posture }) =>
      posture.validator_observed_at ? (
        <DateTime value={posture.validator_observed_at} />
      ) : (
        'Unavailable'
      ),
  },
]

export function BGPRPKIPosture({
  tenant,
  monitor,
}: {
  tenant: string
  monitor: BGPVisibilityMonitor
}) {
  const [context, setContext] = useState('')
  const [selection, setSelection] = useState<URLSearchParams>()
  const contexts = useEntityContexts(tenant)
  const inventory = useCanonicalEntities(tenant, context)
  const prefixes =
    inventory.data?.pages
      .flatMap((page) => page.items)
      .filter((entity) => entity.kind === 'prefix' && entity.network_prefix === monitor.prefix) ??
    []
  const selected = prefixes.length === 1 ? prefixes[0] : undefined
  const query = useQuery({
    queryKey: ['bgp', 'rpki-posture', tenant, monitor.id, selection?.toString()],
    enabled: selection !== undefined,
    queryFn: ({ signal }) =>
      apiFetch<BGPRPKICurrentPosture>(
        `/bgp/visibility/${encodeURIComponent(monitor.id)}/rpki-posture?${selection?.toString() ?? ''}`,
        { signal },
      ),
  })
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected) return
    const input = new FormData(event.currentTarget).get('origin')
    const parameters = new URLSearchParams({ context_id: context, prefix_id: selected.id })
    if (typeof input === 'string' && input) parameters.set('intended_asn', input)
    if (selection?.toString() === parameters.toString()) void query.refetch()
    else setSelection(parameters)
  }
  if (contexts.isLoading) return <LoadingState label="Loading routing contexts…" />
  if (contexts.isError)
    return <ErrorState description="Could not load the owned routing contexts." />
  return (
    <div className={styles.visualStack}>
      <form className={styles.visualStack} onSubmit={submit}>
        <Select
          label="Routing context"
          value={context}
          onChange={(event) => {
            setContext(event.target.value)
            setSelection(undefined)
          }}
          options={[
            { value: '', label: 'Select a routing context' },
            ...(contexts.data?.pages
              .flatMap((page) => page.items)
              .map((item) => ({
                value: item.context_id,
                label: `${item.site_label} / ${item.vrf_label}`,
              })) ?? []),
          ]}
        />
        {contexts.hasNextPage && (
          <Button
            type="button"
            variant="secondary"
            disabled={contexts.isFetchingNextPage}
            onClick={() => void contexts.fetchNextPage()}
          >
            Load more routing contexts
          </Button>
        )}
        {inventory.isLoading && context && <LoadingState label="Loading owned prefixes…" />}
        {inventory.isError && <ErrorState description="Could not load prefixes in this context." />}
        {inventory.hasNextPage && !selected && (
          <Button
            type="button"
            variant="secondary"
            disabled={inventory.isFetchingNextPage}
            onClick={() => void inventory.fetchNextPage()}
          >
            Search more owned prefixes
          </Button>
        )}
        {inventory.isSuccess && !inventory.hasNextPage && !selected && (
          <p>Select a context with one owned inventory entry for {monitor.prefix}.</p>
        )}
        {selected && (
          <>
            <p>
              Owned prefix {selected.label} ({monitor.prefix})
            </p>
            <Field
              label="Intended origin ASN (optional)"
              name="origin"
              type="number"
              min="1"
              max="4294967295"
              step="1"
            />
            <Button type="submit" disabled={query.isFetching}>
              Check RPKI posture
            </Button>
          </>
        )}
      </form>
      {query.isFetching && <LoadingState label="Checking originated routes…" />}
      {query.isError && (
        <ErrorState description="Could not read RPKI posture in the selected context." />
      )}
      {query.data && (
        <>
          {query.data.coverage === 'incomplete_source_population' && (
            <p>Some owned routing sources are unavailable.</p>
          )}
          <Table
            caption={`Current RPKI posture for ${monitor.prefix}`}
            columns={columns}
            rows={query.data.paths}
            rowKey={(row) => `${row.vantage}/${row.generation}/${row.has_path_id}/${row.path_id}`}
            empty="No currently observed owned origins."
          />
          <Table
            caption="RPKI trend for retained route observations"
            columns={trendColumns}
            rows={query.data.trend}
            rowKey={(point) => point.id}
            empty="No retained route observations for this context."
          />
        </>
      )}
    </div>
  )
}
