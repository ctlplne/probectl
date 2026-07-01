import { useMemo, useState, type FormEvent } from 'react'
import styles from './audit.module.css'
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
  Icon,
  LoadingState,
  Select,
  Table,
  useToast,
  type Column,
} from '../components'
import { auditExportHref, useAuditEvents, useVerifyAudit, type AuditEvent } from '../api/audit'
import { useAuth } from '../auth/useAuth'
import { DateTime } from '../time/DateTime'

interface AuditDraft {
  actor: string
  action: string
  target: string
  limit: string
}

function shortHash(hash?: string): string {
  return hash ? hash.slice(0, 12) : 'none'
}

function dataPreview(ev: AuditEvent): string {
  const entries = Object.entries(ev.data ?? {})
  if (entries.length === 0) return 'none'
  return entries
    .slice(0, 3)
    .map(([k, v]) => `${k}=${String(v)}`)
    .join(', ')
}

function appliedFilters(draft: AuditDraft, after?: number) {
  return {
    actor: draft.actor,
    action: draft.action,
    target: draft.target,
    limit: Number(draft.limit) || 100,
    after,
  }
}

export function AuditPage() {
  const { permissions } = useAuth()
  const { push } = useToast()
  const [draft, setDraft] = useState<AuditDraft>({
    actor: '',
    action: '',
    target: '',
    limit: '100',
  })
  const [submitted, setSubmitted] = useState<AuditDraft>(draft)
  const [after, setAfter] = useState<number | undefined>(undefined)
  const filters = useMemo(() => appliedFilters(submitted, after), [submitted, after])
  const page = useAuditEvents(filters)
  const verify = useVerifyAudit()
  const readOnlyAuditor =
    permissions.length === 0 || (permissions.includes('audit.read') && permissions.length === 1)

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setAfter(undefined)
    setSubmitted(draft)
  }

  const runVerify = () => {
    verify.mutate(undefined, {
      onSuccess: (res) =>
        push({
          tone: res.ok ? 'success' : 'danger',
          title: res.ok ? 'Audit chain verified' : 'Audit chain failed',
          message: res.detail ?? 'Tenant chain is intact',
        }),
      onError: (err) =>
        push({ tone: 'danger', title: 'Verification failed', message: err.message }),
    })
  }

  const columns: Column<AuditEvent>[] = [
    { key: 'seq', header: 'Seq', numeric: true, render: (ev) => ev.seq },
    {
      key: 'created',
      header: 'Time',
      render: (ev) => (ev.created_at ? <DateTime value={ev.created_at} /> : 'unknown'),
    },
    { key: 'actor', header: 'Actor', render: (ev) => ev.actor },
    { key: 'action', header: 'Action', render: (ev) => <code>{ev.action}</code> },
    { key: 'target', header: 'Target', render: (ev) => ev.target || 'none' },
    { key: 'data', header: 'Data', render: dataPreview },
    { key: 'hash', header: 'Hash', render: (ev) => <code>{shortHash(ev.hash)}</code> },
  ]

  const events = page.data?.items ?? []
  const next = page.data?.next ?? 0
  const canPage = events.length > 0 && next > 0

  return (
    <Page title="Audit trail" subtitle="Tenant-scoped read-only evidence.">
      <div className={styles.stack}>
        <div className={styles.toolbar}>
          <Badge tone={readOnlyAuditor ? 'info' : 'neutral'}>
            {readOnlyAuditor ? 'Auditor read-only' : 'Read-only audit view'}
          </Badge>
          {verify.data ? (
            <Badge tone={verify.data.ok ? 'success' : 'danger'}>
              {verify.data.ok ? 'Chain intact' : 'Chain failed'}
            </Badge>
          ) : null}
          <span className={styles.spacer} />
          <Button variant="secondary" onClick={runVerify} disabled={verify.isPending}>
            <Icon name="check" /> {verify.isPending ? 'Verifying...' : 'Verify chain'}
          </Button>
          <a className={styles.linkButton} href={auditExportHref(filters)} download>
            Export JSON
          </a>
        </div>

        {verify.data && !verify.data.ok ? (
          <Card>
            <CardBody>
              <ErrorState description={verify.data.detail ?? 'Audit chain verification failed.'} />
            </CardBody>
          </Card>
        ) : null}

        <Card>
          <CardHeader title="Filters" description={`Cursor ${after ?? 0}`} />
          <CardBody>
            <form className={styles.filters} onSubmit={submit}>
              <Field
                label="Actor"
                value={draft.actor}
                onChange={(e) => setDraft((d) => ({ ...d, actor: e.target.value }))}
                placeholder="alice@example.com"
              />
              <Field
                label="Action"
                value={draft.action}
                onChange={(e) => setDraft((d) => ({ ...d, action: e.target.value }))}
                placeholder="alert.create"
              />
              <Field
                label="Target"
                value={draft.target}
                onChange={(e) => setDraft((d) => ({ ...d, target: e.target.value }))}
                placeholder="alert/api-latency"
              />
              <Select
                label="Limit"
                value={draft.limit}
                onChange={(e) => setDraft((d) => ({ ...d, limit: e.target.value }))}
                options={[
                  { value: '50', label: '50' },
                  { value: '100', label: '100' },
                  { value: '250', label: '250' },
                  { value: '500', label: '500' },
                ]}
              />
              <div className={styles.filterActions}>
                <Button type="submit" variant="primary">
                  <Icon name="search" /> Apply
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => {
                    const reset = { actor: '', action: '', target: '', limit: '100' }
                    setDraft(reset)
                    setSubmitted(reset)
                    setAfter(undefined)
                  }}
                >
                  Clear
                </Button>
              </div>
            </form>
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Events"
            description={`${events.length} rows · next cursor ${next || 'none'}`}
          />
          <CardBody>
            {page.isLoading ? (
              <LoadingState label="Loading audit events..." />
            ) : page.isError ? (
              <ErrorState description={page.error.message} />
            ) : (
              <>
                <Table
                  caption="Audit events"
                  columns={columns}
                  rows={events}
                  rowKey={(ev) => String(ev.seq)}
                  empty={<EmptyState title="No audit events" description="No events matched." />}
                />
                <div className={styles.pager}>
                  <Button variant="ghost" disabled={!after} onClick={() => setAfter(undefined)}>
                    First page
                  </Button>
                  <Button variant="secondary" disabled={!canPage} onClick={() => setAfter(next)}>
                    Next page
                  </Button>
                </div>
              </>
            )}
          </CardBody>
        </Card>
      </div>
    </Page>
  )
}
