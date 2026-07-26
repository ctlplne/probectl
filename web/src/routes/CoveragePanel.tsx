// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  Field,
  HonestDataState,
  LoadingState,
  Select,
  StatusDot,
  Table,
  classifySurfaceTruth,
  type BadgeTone,
  type Column,
} from '../components'
import { useCoverageMatrix, type CoverageMatrixItem, type CoverageStatus } from '../api/coverage'
import { DateTime } from '../time/DateTime'
import styles from './pages.module.css'
import { FilterBar } from './listControls'

const statusLabels: Record<CoverageStatus, string> = {
  uncovered: 'Uncovered',
  stale: 'Stale',
  non_redundant: 'Non-redundant',
  covered: 'Covered',
}

const statusTones: Record<CoverageStatus, BadgeTone> = {
  uncovered: 'danger',
  stale: 'warning',
  non_redundant: 'warning',
  covered: 'success',
}

export function CoveragePanel() {
  const navigate = useNavigate()
  const { data, isPending, isError, error, refetch } = useCoverageMatrix()
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<CoverageStatus | 'all'>('all')
  const [region, setRegion] = useState('all')

  const regions = useMemo(
    () => [...new Set((data?.items ?? []).map((item) => item.region))].sort(),
    [data?.items],
  )
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return (data?.items ?? []).filter((item) => {
      const haystack = [item.test_name, item.region, item.site, item.probe_family, item.target]
        .join(' ')
        .toLowerCase()
      return (
        (!needle || haystack.includes(needle)) &&
        (status === 'all' || item.status === status) &&
        (region === 'all' || item.region === region)
      )
    })
  }, [data?.items, query, region, status])

  const columns: Column<CoverageMatrixItem>[] = [
    {
      key: 'status',
      header: 'Coverage',
      render: (item) => (
        <span className={styles.fleetCell}>
          <StatusDot tone={statusTones[item.status]} label={statusLabels[item.status]} />
          {item.next_action ? (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => void navigate(item.next_action!.href)}
            >
              {item.next_action.label}
            </Button>
          ) : (
            <Badge tone="success">No gap</Badge>
          )}
        </span>
      ),
    },
    {
      key: 'location',
      header: 'Owned vantage',
      render: (item) => (
        <span className={styles.fleetCell}>
          <strong>{item.site}</strong>
          <small>{item.region}</small>
          <StatusDot
            tone={
              item.agent_readiness === 'ready'
                ? 'success'
                : item.agent_readiness === 'degraded'
                  ? 'warning'
                  : 'danger'
            }
            label={`${item.agent_readiness} · ${item.ready_agent_count}/${item.agent_count} ready`}
          />
        </span>
      ),
    },
    {
      key: 'target',
      header: 'Probe / target',
      render: (item) => (
        <span className={styles.fleetCell}>
          <strong>{item.test_name}</strong>
          <Badge tone="neutral">{item.probe_family}</Badge>
          <code>{item.target || '—'}</code>
        </span>
      ),
    },
    {
      key: 'evidence',
      header: 'Evidence',
      render: (item) => (
        <span className={styles.fleetCell}>
          {item.last_evidence_at ? <DateTime value={item.last_evidence_at} /> : 'Never'}
          <small>
            {item.independent_vantage_count}{' '}
            {item.independent_vantage_count === 1 ? 'independent vantage' : 'independent vantages'}
          </small>
        </span>
      ),
    },
  ]

  const gapCount = (data?.items ?? []).filter((item) => item.status !== 'covered').length
  return (
    <Card data-targets-coverage>
      <CardHeader
        title="Owned-vantage coverage"
        description="Local agent labels × enabled tests × recent evidence. Region and site are operator-declared; no geolocation or external service is used."
        actions={
          data ? (
            <span className={styles.fleetBadges}>
              <Badge tone={gapCount > 0 ? 'warning' : 'success'}>
                {gapCount} {gapCount === 1 ? 'gap' : 'gaps'}
              </Badge>
              <Badge tone="neutral">{data.items.length} matrix rows</Badge>
            </span>
          ) : null
        }
      />
      <CardBody>
        {isPending ? (
          <LoadingState label="Deriving tenant coverage…" />
        ) : isError ? (
          <HonestDataState
            state={classifySurfaceTruth({ error })}
            producer="Owned-vantage coverage query"
            producerReadiness={`The server did not return an authoritative tenant-scoped matrix: ${error?.message ?? 'request failed'}`}
            lastSuccessfulIngest={null}
            coverageLimitation="Agent placement, test definitions, and evidence recency are not shown while this read is unavailable."
            action={
              <Button variant="secondary" onClick={() => void refetch()}>
                Retry coverage query
              </Button>
            }
          />
        ) : (data?.items.length ?? 0) === 0 ? (
          <HonestDataState
            state="ready-no-data"
            producer="Owned-vantage coverage query"
            producerReadiness="Ready; no enabled test definitions produced matrix rows"
            lastSuccessfulIngest={null}
            coverageLimitation="Coverage cannot be measured until at least one synthetic test is enabled."
            action={
              <Button variant="primary" onClick={() => void navigate('/targets?create=test')}>
                New test
              </Button>
            }
          />
        ) : (
          <>
            {!data?.evidence_running ? (
              <p role="status" className={styles.fleetNotice}>
                Result evidence is not wired on this control-plane instance. Rows remain uncovered;
                they are not presented as healthy.
              </p>
            ) : null}
            {data?.truncated ? (
              <p role="status" className={styles.fleetNotice}>
                Candidate scan reached its {data.candidate_limit}-row safety bound. Refine the
                tenant inventory before treating this snapshot as complete.
              </p>
            ) : null}
            <FilterBar>
              <Field
                label="Find coverage"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="site, region, probe, target"
              />
              <Select
                label="Coverage state"
                value={status}
                onChange={(event) => setStatus(event.target.value as CoverageStatus | 'all')}
                options={[
                  { value: 'all', label: 'All coverage states' },
                  ...Object.entries(statusLabels).map(([value, label]) => ({ value, label })),
                ]}
              />
              <Select
                label="Region"
                value={region}
                onChange={(event) => setRegion(event.target.value)}
                options={[
                  { value: 'all', label: 'All regions' },
                  ...regions.map((value) => ({ value, label: value })),
                ]}
              />
            </FilterBar>
            <Table
              caption="Owned-vantage coverage matrix"
              columns={columns}
              rows={filtered}
              rowKey={(item) => `${item.test_id}:${item.region}:${item.site}`}
              empty={
                <EmptyState
                  title="No coverage rows match these filters"
                  description="Clear or change the local filters; no server data was deleted."
                  action={
                    <Button
                      variant="secondary"
                      onClick={() => {
                        setQuery('')
                        setStatus('all')
                        setRegion('all')
                      }}
                    >
                      Clear filters
                    </Button>
                  }
                />
              }
            />
          </>
        )}
      </CardBody>
    </Card>
  )
}
