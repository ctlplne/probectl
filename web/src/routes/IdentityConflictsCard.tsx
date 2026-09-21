// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  useIdentityConflicts,
  type DeviceIdentityConflict,
  type IdentityConflictKind,
  type IdentityConflictStatus,
} from '../api/identity'
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
  Select,
  Table,
  type Column,
} from '../components'
import { DateTime } from '../time/DateTime'
import styles from './IdentityConflictsCard.module.css'

type KindFilter = IdentityConflictKind | 'all'
type StatusFilter = IdentityConflictStatus | 'all'

export function IdentityConflictsCard({ surface }: { surface: 'device' | 'topology' }) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState<KindFilter>('all')
  const [source, setSource] = useState('')
  const [status, setStatus] = useState<StatusFilter>('all')
  const conflicts = useIdentityConflicts({ q: query, kind, source, status, limit: 100 })
  const rows = conflicts.data?.items ?? []
  const filtered = Boolean(query.trim() || source.trim() || kind !== 'all' || status !== 'all')
  const columns: Column<DeviceIdentityConflict>[] = [
    {
      key: 'state',
      header: 'State',
      render: (item) => (
        <div className={styles.subject}>
          <Badge tone={identityStatusTone(item.status)}>{item.status}</Badge>
          <span className={styles.muted}>{item.confidence} confidence</span>
        </div>
      ),
    },
    {
      key: 'identity',
      header: 'Disputed identity',
      render: (item) => (
        <div className={styles.subject}>
          <strong>{kindLabel(item.kind)}</strong>
          <code>{item.subject}</code>
          <span className={styles.muted}>
            Last observed <DateTime value={item.last_seen} />
          </span>
        </div>
      ),
    },
    {
      key: 'claims',
      header: 'Competing claims',
      render: (item) => (
        <ul className={styles.claims}>
          {item.claims.map((claim) => (
            <li
              className={styles.claim}
              key={`${claim.source}-${claim.agent_id ?? ''}-${claim.value}`}
            >
              <span className={styles.claimHeader}>
                <strong>{claim.value}</strong>
                <Badge tone={claim.freshness === 'fresh' ? 'success' : 'warning'}>
                  {claim.freshness}
                </Badge>
              </span>
              <span className={styles.claimMeta}>
                <span>{claim.source}</span>
                {claim.agent_id ? <code>{claim.agent_id}</code> : null}
              </span>
              <span className={styles.muted}>
                {formatAge(claim.age_seconds)} · {claim.basis}
              </span>
            </li>
          ))}
        </ul>
      ),
    },
    {
      key: 'affected',
      header: 'Affected correlations',
      render: (item) => (
        <ul className={styles.correlations}>
          {item.affected_correlations.map((correlation) => (
            <li key={`${correlation.plane}-${correlation.kind}-${correlation.ref}`}>
              <Button
                size="sm"
                variant="ghost"
                className={styles.evidenceButton}
                onClick={() => void navigate(correlation.href)}
                aria-label={`Inspect ${correlation.plane} evidence ${correlation.ref}`}
              >
                {correlation.plane} · {correlation.ref}
              </Button>
              <div className={styles.muted}>{correlation.reason}</div>
            </li>
          ))}
        </ul>
      ),
    },
    {
      key: 'review',
      header: 'Human review',
      render: (item) => (
        <details className={styles.review}>
          <summary>Review proposal</summary>
          <div className={styles.reviewBody}>
            <Badge tone="neutral">Read only</Badge>
            <span>{item.review_proposal.instruction}</span>
            <span className={styles.muted}>
              probectl will not select a winner, merge records, or rewrite topology.
            </span>
            <div className={styles.reviewActions}>
              <Button size="sm" disabled>
                Merge unavailable
              </Button>
            </div>
          </div>
        </details>
      ),
    },
  ]

  return (
    <Card data-identity-conflicts data-surface={surface}>
      <CardHeader
        title="Cross-source identity conflicts"
        description="See where local telemetry disagrees before topology, path, or flow attribution chooses the wrong entity."
        actions={
          conflicts.data?.topology_running ? (
            <Badge tone={rows.length > 0 ? 'warning' : 'success'}>
              {rows.length > 0 ? `${rows.length} need review` : 'No retained conflicts'}
            </Badge>
          ) : (
            <Badge tone="neutral">Unavailable</Badge>
          )
        }
      />
      <CardBody>
        <div className={styles.filters} aria-label="Identity conflict filters">
          <Field
            label="Find identity"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="address, name, interface, agent"
          />
          <Select
            label="Identity field"
            value={kind}
            onChange={(event) => setKind(event.target.value as KindFilter)}
            options={[
              { value: 'all', label: 'All fields' },
              { value: 'management_address', label: 'Management address' },
              { value: 'device_name', label: 'Device name' },
              { value: 'interface_address', label: 'Interface address' },
              { value: 'interface_name', label: 'Interface name' },
              { value: 'interface_index', label: 'Interface index' },
            ]}
          />
          <Field
            label="Source"
            value={source}
            onChange={(event) => setSource(event.target.value)}
            placeholder="snmp or gnmi"
          />
          <Select
            label="Review state"
            value={status}
            onChange={(event) => setStatus(event.target.value as StatusFilter)}
            options={[
              { value: 'all', label: 'All states' },
              { value: 'active', label: 'Active' },
              { value: 'stale', label: 'Stale' },
              { value: 'unknown', label: 'Unknown clock' },
            ]}
          />
        </div>
        {conflicts.isPending ? (
          <LoadingState label="Loading identity conflicts…" />
        ) : conflicts.isError ? (
          <ErrorState description="Could not load identity conflict evidence." />
        ) : !conflicts.data?.topology_running ? (
          <EmptyState
            icon="path"
            title="Identity conflict detection unavailable"
            description="The local topology identity store is not wired. This is unavailable—not a clean bill of health."
          />
        ) : (
          <>
            {conflicts.data.truncated ? (
              <div className={styles.partial} role="note">
                Partial result: {conflicts.data.partial_reasons.join(' ')}
              </div>
            ) : null}
            <Table
              caption="Tenant-local identity disagreements with source provenance"
              columns={columns}
              rows={rows}
              rowKey={(item) => item.id}
              empty={
                <EmptyState
                  title={
                    filtered ? 'No conflicts match these filters' : 'No identity conflicts observed'
                  }
                  description={
                    filtered
                      ? 'Clear or widen a filter to review retained disagreement evidence.'
                      : 'No competing values are retained. This does not prove every identity source is connected.'
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

function kindLabel(kind: IdentityConflictKind): string {
  return kind.replace(/_/g, ' ')
}

function identityStatusTone(status: IdentityConflictStatus): 'warning' | 'neutral' | 'danger' {
  if (status === 'active') return 'danger'
  if (status === 'stale') return 'warning'
  return 'neutral'
}

function formatAge(seconds: number): string {
  if (seconds < 60) return `${seconds}s old`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m old`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h old`
  return `${Math.floor(seconds / 86400)}d old`
}
