// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  Field,
  LoadingState,
  Select,
  StatusDot,
  Table,
  type Column,
} from '../../../web/src/components'
import styles from './ProviderConsole.module.css'

export type ProviderAPI = <T>(method: string, path: string, body?: unknown) => Promise<T>

interface Tenant {
  id: string
  slug: string
  name: string
  status: string
  isolation_model?: string
  residency?: string
}

type TenantAction = 'suspend' | 'resume' | 'offboard'

export function TenantsCard({ readOnly, api }: { readOnly: boolean; api: ProviderAPI }) {
  const [tenants, setTenants] = useState<Tenant[] | null>(null)
  const [error, setError] = useState('')
  const [slug, setSlug] = useState('')
  const [name, setName] = useState('')
  const [isolation, setIsolation] = useState('pooled')
  const [residency, setResidency] = useState('')
  // UX-005: offboard is destructive (removes a siloed tenant's isolated stores),
  // so it is gated behind a typed-slug confirm rather than a one-click button.
  const [confirmTenant, setConfirmTenant] = useState<Tenant | null>(null)
  const [confirmText, setConfirmText] = useState('')

  const load = useCallback(() => {
    api<{ items: Tenant[] }>('GET', '/provider/v1/tenants')
      .then((r) => setTenants(r.items ?? []))
      .catch((e: Error) => setError(e.message))
  }, [api])
  useEffect(load, [load])

  const provision = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      await api('POST', '/provider/v1/tenants', {
        slug,
        name,
        isolation_model: isolation,
        residency: isolation === 'pooled' ? '' : residency,
      })
      setSlug('')
      setName('')
      setResidency('')
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  const act = async (id: string, action: TenantAction) => {
    setError('')
    try {
      await api('POST', `/provider/v1/tenants/${id}/${action}`)
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  const beginOffboard = (tenant: Tenant) => {
    setConfirmText('')
    setConfirmTenant(tenant)
  }

  const confirmOffboard = async () => {
    const t = confirmTenant
    if (!t || confirmText !== t.slug) return
    setConfirmTenant(null)
    setConfirmText('')
    await act(t.id, 'offboard')
  }

  const columns = tenantColumns({ readOnly, onAction: act, onOffboard: beginOffboard })

  return (
    <Card>
      <CardHeader
        title="Tenants"
        description="Lifecycle metadata only. Suspension blocks the tenant's users at the API; data and ingestion are untouched. Offboarding removes a siloed/hybrid tenant's isolated stores; pooled-data export/deletion is the S-T5 compliance flow."
      />
      <CardBody>
        {tenants === null ? (
          <LoadingState label="Loading tenants…" />
        ) : (
          <>
            <TenantProvisionForm
              readOnly={readOnly}
              slug={slug}
              name={name}
              isolation={isolation}
              residency={residency}
              onSubmit={provision}
              onSlug={setSlug}
              onName={setName}
              onIsolation={setIsolation}
              onResidency={setResidency}
            />
            {error ? <p role="alert" className={styles.note}>{error}</p> : null}
            <TenantInventoryTable tenants={tenants} columns={columns} />
            <OffboardConfirm
              tenant={confirmTenant}
              confirmText={confirmText}
              readOnly={readOnly}
              onConfirmText={setConfirmText}
              onConfirm={confirmOffboard}
              onCancel={() => {
                setConfirmTenant(null)
                setConfirmText('')
              }}
            />
          </>
        )}
      </CardBody>
    </Card>
  )
}

function TenantProvisionForm({
  readOnly,
  slug,
  name,
  isolation,
  residency,
  onSubmit,
  onSlug,
  onName,
  onIsolation,
  onResidency,
}: {
  readOnly: boolean
  slug: string
  name: string
  isolation: string
  residency: string
  onSubmit: (e: FormEvent) => void
  onSlug: (value: string) => void
  onName: (value: string) => void
  onIsolation: (value: string) => void
  onResidency: (value: string) => void
}) {
  return (
    <form className={styles.row} onSubmit={onSubmit}>
      <span className={styles.grow}>
        <Field
          label="New tenant slug"
          value={slug}
          onChange={(e) => onSlug(e.target.value)}
          placeholder="acme"
          required
          disabled={readOnly}
        />
      </span>
      <span className={styles.grow}>
        <Field
          label="Display name"
          value={name}
          onChange={(e) => onName(e.target.value)}
          placeholder="Acme Industries"
          required
          disabled={readOnly}
        />
      </span>
      <Select
        label="Isolation"
        value={isolation}
        onChange={(e) => onIsolation(e.target.value)}
        disabled={readOnly}
        options={[
          { value: 'pooled', label: 'pooled (default)' },
          { value: 'siloed', label: 'siloed' },
          { value: 'hybrid', label: 'hybrid' },
        ]}
      />
      {isolation !== 'pooled' ? (
        <span className={styles.grow}>
          <Field
            label="Residency (data plane, optional)"
            value={residency}
            onChange={(e) => onResidency(e.target.value)}
            placeholder="eu"
            disabled={readOnly}
          />
        </span>
      ) : null}
      <Button type="submit" variant="primary" disabled={readOnly}>
        Provision
      </Button>
    </form>
  )
}

function TenantInventoryTable({
  tenants,
  columns,
}: {
  tenants: Tenant[]
  columns: Column<Tenant>[]
}) {
  return (
    <Table
      caption="Tenant inventory"
      columns={columns}
      rows={tenants}
      rowKey={(t) => t.id}
      empty={<EmptyState icon="admin" title="No tenants" description="Provision the first tenant above." />}
    />
  )
}

function OffboardConfirm({
  tenant,
  confirmText,
  readOnly,
  onConfirmText,
  onConfirm,
  onCancel,
}: {
  tenant: Tenant | null
  confirmText: string
  readOnly: boolean
  onConfirmText: (value: string) => void
  onConfirm: () => void
  onCancel: () => void
}) {
  if (!tenant) return null
  return (
    <div role="alertdialog" aria-label="Confirm offboard" className={styles.note}>
      <p>
        Offboarding <strong>{tenant.name}</strong> is destructive: it removes a siloed/hybrid
        tenant&apos;s isolated stores and cannot be undone. Type the slug <code>{tenant.slug}</code>{' '}
        to confirm.
      </p>
      <span className={styles.row}>
        <span className={styles.grow}>
          <Field
            label="Tenant slug"
            value={confirmText}
            onChange={(e) => onConfirmText(e.target.value)}
            placeholder={tenant.slug}
            disabled={readOnly}
          />
        </span>
        <Button variant="danger" disabled={readOnly || confirmText !== tenant.slug} onClick={onConfirm}>
          Offboard {tenant.slug}
        </Button>
        <Button variant="secondary" onClick={onCancel}>
          Cancel
        </Button>
      </span>
    </div>
  )
}

function tenantColumns({
  readOnly,
  onAction,
  onOffboard,
}: {
  readOnly: boolean
  onAction: (id: string, action: TenantAction) => void
  onOffboard: (tenant: Tenant) => void
}): Column<Tenant>[] {
  return [
    { key: 'slug', header: 'Slug', render: (t) => <code>{t.slug}</code> },
    { key: 'name', header: 'Name', render: (t) => t.name },
    {
      key: 'isolation',
      header: 'Isolation',
      render: (t) => (
        <>
          <Badge tone={t.isolation_model === 'siloed' ? 'accent' : t.isolation_model === 'hybrid' ? 'info' : 'neutral'}>
            {t.isolation_model || 'pooled'}
          </Badge>
          {t.residency ? <> {t.residency}</> : null}
        </>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (t) =>
        t.status === 'active' ? (
          <StatusDot tone="success" label="Active" />
        ) : t.status === 'suspended' ? (
          <StatusDot tone="danger" label="Suspended" />
        ) : (
          <StatusDot tone="neutral" label={t.status} />
        ),
    },
    {
      key: 'actions',
      header: 'Lifecycle',
      render: (t) => (
        <span className={styles.actions}>
          {t.status === 'active' ? (
            <Button size="sm" variant="secondary" disabled={readOnly} onClick={() => onAction(t.id, 'suspend')}>
              Suspend
            </Button>
          ) : null}
          {t.status === 'suspended' ? (
            <Button size="sm" variant="secondary" disabled={readOnly} onClick={() => onAction(t.id, 'resume')}>
              Resume
            </Button>
          ) : null}
          {t.status === 'active' || t.status === 'suspended' ? (
            <Button size="sm" variant="danger" disabled={readOnly} onClick={() => onOffboard(t)}>
              Offboard…
            </Button>
          ) : null}
        </span>
      ),
    },
  ]
}
