import { useState } from 'react'
import styles from '../pages.module.css'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  Column,
  EmptyState,
  ErrorState,
  Field,
  StatusDot,
  Table,
} from '../../components'
import { ApiError } from '../../api/client'
import { useKeys, useRotateKey, type KeyInfo } from '../../api/keys'
import { useRemediations, useDecideRemediation, type Proposal } from '../../api/remediation'

/** RemediationCard (S-EE5, ee): AI-proposed remediations awaiting a human
 *  decision. probectl NEVER executes — Approve is a recorded, audited sign-off
 *  that an operator carries out elsewhere. Advisory-only by default: until an
 *  operator enables approvals, Approve is unavailable and the card says so.
 *  Unlicensed deployments answer 404 and the card renders NOTHING
 *  (hidden-unlicensed). */
export function RemediationCard() {
  const { data, isPending, isError, error } = useRemediations()
  const decide = useDecideRemediation()

  // Hidden-unlicensed: render NOTHING until the API proves the feature is on.
  if (isPending) return null
  if (isError && error instanceof ApiError && error.status === 404) return null

  const approvalsEnabled = data?.approvals_enabled ?? false

  const columns: Column<Proposal>[] = [
    { key: 'title', header: 'Proposal', render: (p) => <strong>{p.title}</strong> },
    { key: 'kind', header: 'Kind', render: (p) => <code>{p.kind}</code> },
    {
      key: 'blast',
      header: 'Blast radius',
      render: (p) =>
        p.dry_run.blast_radius < 0 ? (
          <Badge tone="warning">unknown</Badge>
        ) : (
          <Badge tone={p.dry_run.blast_radius > 0 ? 'accent' : 'neutral'}>
            {p.dry_run.blast_radius}
          </Badge>
        ),
    },
    {
      key: 'state',
      header: 'State',
      render: (p) =>
        p.state === 'proposed' ? (
          <StatusDot tone="warning" label="Proposed" />
        ) : p.state === 'approved' ? (
          <StatusDot tone="success" label="Approved (not executed)" />
        ) : p.state === 'rejected' ? (
          <StatusDot tone="neutral" label="Rejected" />
        ) : (
          <StatusDot tone="neutral" label="Applied (by operator)" />
        ),
    },
    {
      key: 'actions',
      header: 'Decision',
      render: (p) =>
        p.state !== 'proposed' ? (
          <span>{p.decided_by ? `by ${p.decided_by}` : '—'}</span>
        ) : (
          <span className={styles.actions}>
            <Button
              variant="primary"
              disabled={!approvalsEnabled || decide.isPending}
              onClick={() => decide.mutate({ id: p.id, decision: 'approve' })}
            >
              Approve
            </Button>
            <Button
              variant="ghost"
              disabled={decide.isPending}
              onClick={() => decide.mutate({ id: p.id, decision: 'reject' })}
            >
              Reject
            </Button>
          </span>
        ),
    },
  ]

  return (
    <Card>
      <CardHeader
        title="AI remediation proposals"
        description="The assistant PROPOSES remediations grounded in RCA + a topology what-if; a human decides. probectl never executes — Approve is a recorded, audited sign-off you carry out in your own change process."
      />
      <CardBody>
        {!approvalsEnabled ? (
          <p role="status" className={styles.editionsLede}>
            <Badge tone="neutral">advisory-only</Badge> Approvals are disabled — proposals are
            review-only until an operator enables them (
            <code>PROBECTL_REMEDIATION_APPROVALS_ENABLED=true</code>).
          </p>
        ) : null}
        {isError ? (
          <ErrorState description="Could not load remediation proposals." />
        ) : (
          <Table
            caption="Proposed remediations"
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(p) => p.id}
            empty={
              <EmptyState
                icon="admin"
                title="No proposals"
                description="The assistant files proposals here when it has an RCA-grounded remediation to suggest."
              />
            }
          />
        )}
        {decide.isError ? (
          <p role="alert" className={styles.editionsLede}>
            {decide.error.message}
          </p>
        ) : null}
      </CardBody>
    </Card>
  )
}

/** KeysCard (S-T6, ee): the tenant's at-rest key chain — versions, mode,
 *  state — with managed rotation and BYOK. Key MATERIAL never reaches the
 *  browser. Unlicensed deployments answer 404 and the card renders nothing
 *  (hidden-unlicensed, the usage-card pattern). */
export function KeysCard() {
  const { data, isPending, isError, error } = useKeys()
  const rotate = useRotateKey()
  const [byokRef, setByokRef] = useState('')

  // Hidden-unlicensed: render NOTHING until the API proves the keyring is
  // installed — no frame during pending, no card at all on the 404.
  if (isPending) return null
  if (isError && error instanceof ApiError && error.status === 404) return null

  const columns: Column<KeyInfo>[] = [
    { key: 'version', header: 'Version', render: (k) => <strong>v{k.version}</strong> },
    {
      key: 'mode',
      header: 'Mode',
      render: (k) => <Badge tone={k.mode === 'byok' ? 'accent' : 'neutral'}>{k.mode}</Badge>,
    },
    {
      key: 'state',
      header: 'State',
      render: (k) =>
        k.state === 'active' ? (
          <StatusDot tone="success" label="Active" />
        ) : k.state === 'retired' ? (
          <StatusDot tone="neutral" label="Retired (decrypt-only)" />
        ) : (
          <StatusDot tone="danger" label="Destroyed" />
        ),
    },
    { key: 'created', header: 'Created', render: (k) => k.created_at || '—' },
  ]

  return (
    <Card>
      <CardHeader
        title="Encryption keys"
        description="Your tenant's at-rest key chain. Rotation re-keys new data immediately; retired versions stay decrypt-only (no downtime). BYOK points at YOUR secret manager — if you revoke it, your data becomes unreadable (no shared-key fallback)."
      />
      <CardBody>
        {isError ? (
          <ErrorState description="Could not load the key chain." />
        ) : (
          <>
            <Table
              caption="Tenant key chain"
              columns={columns}
              rows={data ?? []}
              rowKey={(k) => String(k.version)}
              empty={
                <EmptyState
                  icon="admin"
                  title="No tenant key yet"
                  description="A managed key is provisioned automatically on first use, or rotate one in now."
                />
              }
            />
            <form
              className={styles.actions}
              onSubmit={(e) => {
                e.preventDefault()
                rotate.mutate(byokRef ? { mode: 'byok', byok_ref: byokRef } : { mode: 'managed' })
              }}
            >
              <Field
                label="BYOK secret reference (blank = managed rotation)"
                value={byokRef}
                onChange={(e) => setByokRef(e.target.value)}
                placeholder="vault:kv/tenants/acme#kek"
              />
              <Button type="submit" variant="primary" disabled={rotate.isPending}>
                {byokRef ? 'Activate BYOK' : 'Rotate managed key'}
              </Button>
            </form>
            {rotate.isSuccess ? (
              <p className={styles.editionsLede}>
                Rotated — new data seals under v{rotate.data.version}.
              </p>
            ) : null}
            {rotate.isError ? (
              <p role="alert" className={styles.editionsLede}>
                {rotate.error.message}
              </p>
            ) : null}
          </>
        )}
      </CardBody>
    </Card>
  )
}
