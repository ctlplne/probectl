import { useState, type FormEvent } from 'react'
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
  LoadingState,
  Select,
  StatusDot,
  Table,
} from '../../components'
import {
  useABACPolicies,
  useCreateABACPolicy,
  useCreateScimToken,
  useDeleteABACPolicy,
  useRevokeScimToken,
  useScimTokens,
  type ABACPolicy,
  type ScimToken,
} from '../../api/identity'

type DirectorySurface = {
  name: string
  endpoint: string
  owner: string
  status: 'ready' | 'token'
}

const directorySurfaces: DirectorySurface[] = [
  {
    name: 'SSO login',
    endpoint: '/auth/login',
    owner: 'OIDC IdP',
    status: 'ready',
  },
  {
    name: 'Users',
    endpoint: '/scim/v2/Users',
    owner: 'SCIM IdP push',
    status: 'token',
  },
  {
    name: 'Groups and roles',
    endpoint: '/scim/v2/Groups',
    owner: 'SCIM group sync',
    status: 'token',
  },
]

function parseAttrs(raw: string): Record<string, string> | undefined {
  const attrs: Record<string, string> = {}
  for (const part of raw.split(',')) {
    const trimmed = part.trim()
    if (!trimmed) continue
    const eq = trimmed.indexOf('=')
    if (eq <= 0) continue
    const key = trimmed.slice(0, eq).trim()
    const value = trimmed.slice(eq + 1).trim()
    if (key && value) attrs[key] = value
  }
  return Object.keys(attrs).length ? attrs : undefined
}

function formatAttrs(attrs?: Record<string, string>) {
  if (!attrs || Object.keys(attrs).length === 0) return 'any'
  return Object.entries(attrs)
    .map(([k, v]) => `${k}=${v}`)
    .join(', ')
}

function formatTime(ts?: string) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString()
}

export function IdentityCard() {
  const scimTokens = useScimTokens()
  const createToken = useCreateScimToken()
  const revokeToken = useRevokeScimToken()
  const policies = useABACPolicies()
  const createPolicy = useCreateABACPolicy()
  const deletePolicy = useDeleteABACPolicy()

  const [tokenName, setTokenName] = useState('okta')
  const [createdToken, setCreatedToken] = useState('')
  const [tokenError, setTokenError] = useState('')
  const [policyName, setPolicyName] = useState('contractor write guard')
  const [effect, setEffect] = useState<'allow' | 'deny'>('deny')
  const [permission, setPermission] = useState('test.write')
  const [subject, setSubject] = useState('department=contractor')
  const [resource, setResource] = useState('')
  const [priority, setPriority] = useState('10')
  const [enabled, setEnabled] = useState(true)
  const [policyError, setPolicyError] = useState('')

  const tokenColumns: Column<ScimToken>[] = [
    { key: 'name', header: 'Token', render: (t) => <strong>{t.name}</strong> },
    {
      key: 'status',
      header: 'Status',
      render: (t) =>
        t.revoked_at ? (
          <StatusDot tone="neutral" label="Revoked" />
        ) : (
          <StatusDot tone="success" label="Live" />
        ),
    },
    { key: 'created', header: 'Created', render: (t) => formatTime(t.created_at) },
    { key: 'last', header: 'Last used', render: (t) => formatTime(t.last_used_at) },
    {
      key: 'action',
      header: 'Action',
      render: (t) =>
        t.revoked_at ? (
          '—'
        ) : (
          <Button
            type="button"
            variant="ghost"
            disabled={revokeToken.isPending}
            onClick={() => revokeToken.mutate(t.id)}
          >
            Revoke
          </Button>
        ),
    },
  ]

  const policyColumns: Column<ABACPolicy>[] = [
    { key: 'name', header: 'Policy', render: (p) => <strong>{p.name || p.id}</strong> },
    {
      key: 'effect',
      header: 'Effect',
      render: (p) => <Badge tone={p.effect === 'deny' ? 'danger' : 'success'}>{p.effect}</Badge>,
    },
    { key: 'permission', header: 'Permission', render: (p) => <code>{p.permission}</code> },
    { key: 'subject', header: 'Subject', render: (p) => <code>{formatAttrs(p.subject)}</code> },
    { key: 'resource', header: 'Resource', render: (p) => <code>{formatAttrs(p.resource)}</code> },
    {
      key: 'state',
      header: 'State',
      render: (p) =>
        p.enabled === false ? (
          <StatusDot tone="neutral" label="Disabled" />
        ) : (
          <StatusDot tone="success" label="Enabled" />
        ),
    },
    {
      key: 'action',
      header: 'Action',
      render: (p) =>
        p.id ? (
          <Button
            type="button"
            variant="ghost"
            disabled={deletePolicy.isPending}
            onClick={() => deletePolicy.mutate(p.id!)}
          >
            Delete
          </Button>
        ) : (
          '—'
        ),
    },
  ]

  const surfaceColumns: Column<DirectorySurface>[] = [
    { key: 'name', header: 'Surface', render: (s) => <strong>{s.name}</strong> },
    { key: 'endpoint', header: 'Endpoint', render: (s) => <code>{s.endpoint}</code> },
    { key: 'owner', header: 'Owner', render: (s) => s.owner },
    {
      key: 'status',
      header: 'Status',
      render: (s) =>
        s.status === 'ready' ? (
          <StatusDot tone="success" label="Session-backed" />
        ) : (
          <StatusDot tone="warning" label="Needs SCIM token" />
        ),
    },
  ]

  const submitToken = async (e: FormEvent) => {
    e.preventDefault()
    setTokenError('')
    setCreatedToken('')
    try {
      const out = await createToken.mutateAsync({ name: tokenName || 'scim' })
      setCreatedToken(out.token)
    } catch (err) {
      setTokenError((err as Error).message)
    }
  }

  const submitPolicy = async (e: FormEvent) => {
    e.preventDefault()
    setPolicyError('')
    try {
      await createPolicy.mutateAsync({
        name: policyName,
        effect,
        permission,
        subject: parseAttrs(subject),
        resource: parseAttrs(resource),
        priority: priority === '' ? 0 : Number(priority),
        enabled,
      })
    } catch (err) {
      setPolicyError((err as Error).message)
    }
  }

  return (
    <Card>
      <CardHeader
        title="Identity administration"
        description="SSO status, IdP-provisioned users/groups, SCIM bearer tokens, and tenant ABAC policies. Tokens are shown once; group membership maps to tenant roles."
      />
      <CardBody>
        <Table
          caption="Identity surfaces"
          columns={surfaceColumns}
          rows={directorySurfaces}
          rowKey={(s) => s.endpoint}
        />

        <form className={styles.actions} onSubmit={submitToken}>
          <Field
            label="SCIM token name"
            value={tokenName}
            onChange={(e) => setTokenName(e.target.value)}
            placeholder="okta"
          />
          <Button type="submit" variant="primary" disabled={createToken.isPending}>
            Create SCIM token
          </Button>
        </form>
        {createdToken ? (
          <p role="status" className={styles.editionsLede}>
            One-time SCIM token: <code>{createdToken}</code>
          </p>
        ) : null}
        {tokenError || revokeToken.isError ? (
          <p role="alert" className={styles.editionsLede}>
            {tokenError || revokeToken.error?.message}
          </p>
        ) : null}

        {scimTokens.isPending ? (
          <LoadingState label="Loading SCIM tokens…" />
        ) : scimTokens.isError ? (
          <ErrorState description="Could not load SCIM tokens." />
        ) : (
          <Table
            caption="SCIM bearer tokens"
            columns={tokenColumns}
            rows={scimTokens.data ?? []}
            rowKey={(t) => t.id}
            empty={
              <EmptyState
                icon="admin"
                title="No SCIM tokens"
                description="Create a token, paste it into the IdP once, then let the IdP push users and groups."
              />
            }
          />
        )}

        <form className={styles.actions} onSubmit={submitPolicy}>
          <Field
            label="Policy name"
            value={policyName}
            onChange={(e) => setPolicyName(e.target.value)}
          />
          <Select
            label="Effect"
            value={effect}
            onChange={(e) => setEffect(e.target.value as 'allow' | 'deny')}
            options={[
              { value: 'deny', label: 'Deny' },
              { value: 'allow', label: 'Allow' },
            ]}
          />
          <Field
            label="Permission"
            value={permission}
            onChange={(e) => setPermission(e.target.value)}
            placeholder="test.write"
          />
          <Field
            label="Subject attributes"
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="department=contractor"
          />
          <Field
            label="Resource attributes"
            value={resource}
            onChange={(e) => setResource(e.target.value)}
            placeholder="org=payments"
          />
          <Field
            label="Priority"
            inputMode="numeric"
            value={priority}
            onChange={(e) => setPriority(e.target.value)}
          />
          <label>
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />{' '}
            Enabled
          </label>
          <Button type="submit" variant="primary" disabled={createPolicy.isPending}>
            Create ABAC policy
          </Button>
        </form>
        {policyError ? (
          <p role="alert" className={styles.editionsLede}>
            {policyError}
          </p>
        ) : null}

        {policies.isPending ? (
          <LoadingState label="Loading ABAC policies…" />
        ) : policies.isError ? (
          <ErrorState description="Could not load ABAC policies." />
        ) : (
          <Table
            caption="ABAC policies"
            columns={policyColumns}
            rows={policies.data ?? []}
            rowKey={(p) => p.id ?? `${p.permission}:${p.effect}:${p.name ?? ''}`}
            empty={
              <EmptyState
                icon="admin"
                title="No ABAC policies"
                description="RBAC grants access first; ABAC policies can narrow or delegate that access by attributes."
              />
            }
          />
        )}
      </CardBody>
    </Card>
  )
}
