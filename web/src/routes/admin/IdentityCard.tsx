// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useState, type FormEvent } from 'react'
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
  useBindDirectoryRole,
  useCreateABACPolicy,
  useCreateDirectoryUser,
  useCreateScimToken,
  useDeleteABACPolicy,
  useDirectoryRoles,
  useDirectoryUsers,
  useRevokeScimToken,
  useScimTokens,
  useTenantIdPSettings,
  useUnbindDirectoryRole,
  useUpdateTenantIdPSettings,
  type ABACPolicy,
  type DirectoryUser,
  type ScimToken,
} from '../../api/identity'
import { DateTime } from '../../time/DateTime'

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

export function IdentityCard() {
  const idpSettings = useTenantIdPSettings()
  const updateIdP = useUpdateTenantIdPSettings()
  const scimTokens = useScimTokens()
  const createToken = useCreateScimToken()
  const revokeToken = useRevokeScimToken()
  const policies = useABACPolicies()
  const createPolicy = useCreateABACPolicy()
  const deletePolicy = useDeleteABACPolicy()
  // DPR-027: people & roles without SCIM — list, add a teammate, grant, revoke.
  const people = useDirectoryUsers()
  const roles = useDirectoryRoles()
  const createPerson = useCreateDirectoryUser()
  const bindRole = useBindDirectoryRole()
  const unbindRole = useUnbindDirectoryRole()
  const [personEmail, setPersonEmail] = useState('')
  const [personRole, setPersonRole] = useState('viewer')
  const [personError, setPersonError] = useState('')

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
  const [idpIssuer, setIdpIssuer] = useState('')
  const [idpClientID, setIdpClientID] = useState('')
  const [idpClientSecret, setIdpClientSecret] = useState('')
  const [idpRedirectURL, setIdpRedirectURL] = useState('')
  const [idpScopes, setIdpScopes] = useState('openid, email, profile')
  const [idpEnabled, setIdpEnabled] = useState(true)
  const [idpError, setIdpError] = useState('')
  const [idpSaved, setIdpSaved] = useState(false)

  useEffect(() => {
    const settings = idpSettings.data
    if (!settings) return
    setIdpIssuer(settings.issuer ?? '')
    setIdpClientID(settings.client_id ?? '')
    setIdpRedirectURL(settings.redirect_url ?? '')
    setIdpScopes((settings.scopes ?? ['openid', 'email', 'profile']).join(', '))
    setIdpEnabled(settings.enabled ?? true)
  }, [idpSettings.data])

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
    { key: 'created', header: 'Created', render: (t) => <DateTime value={t.created_at} /> },
    { key: 'last', header: 'Last used', render: (t) => <DateTime value={t.last_used_at} /> },
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

  const roleOptions = (roles.data ?? []).map((r) => ({ value: r.slug, label: r.name }))
  // One form grants a role to an existing person or creates the person with
  // that role: fewer controls in the tab order, one obvious action.
  const submitGrant = async (e: FormEvent) => {
    e.preventDefault()
    setPersonError('')
    const email = personEmail.trim().toLowerCase()
    if (!email) return
    try {
      const existing = (people.data ?? []).find((u) => u.email.toLowerCase() === email)
      if (existing) {
        await bindRole.mutateAsync({ id: existing.id, role: personRole })
      } else {
        await createPerson.mutateAsync({ email, role: personRole })
      }
      setPersonEmail('')
    } catch (err) {
      setPersonError(err instanceof Error ? err.message : 'Could not grant the role.')
    }
  }
  const revoke = async (user: DirectoryUser, role: string) => {
    setPersonError('')
    try {
      await unbindRole.mutateAsync({ id: user.id, role })
    } catch (err) {
      setPersonError(err instanceof Error ? err.message : 'Could not remove the role.')
    }
  }
  const peopleColumns: Column<DirectoryUser>[] = [
    {
      key: 'person',
      header: 'Person',
      render: (u) => (
        <span>
          {u.display_name && u.display_name !== u.email ? <strong>{u.display_name} </strong> : null}
          <code>{u.email}</code>
        </span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (u) => (
        <StatusDot tone={u.status === 'active' ? 'success' : 'neutral'} label={u.status} />
      ),
    },
    {
      key: 'roles',
      header: 'Roles',
      render: (u) =>
        u.roles.length === 0 ? (
          <Badge tone="warning">No role yet</Badge>
        ) : (
          <span className={styles.actions}>
            {u.roles.map((r) => (
              <span key={r}>
                <Badge>{r}</Badge>{' '}
                <Button
                  type="button"
                  size="sm"
                  aria-label={`Remove ${r} from ${u.email}`}
                  disabled={unbindRole.isPending}
                  onClick={() => {
                    void revoke(u, r)
                  }}
                >
                  Remove
                </Button>
              </span>
            ))}
          </span>
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

  const submitIdP = async (e: FormEvent) => {
    e.preventDefault()
    setIdpError('')
    setIdpSaved(false)
    try {
      await updateIdP.mutateAsync({
        issuer: idpIssuer,
        client_id: idpClientID,
        ...(idpClientSecret ? { client_secret: idpClientSecret } : {}),
        redirect_url: idpRedirectURL,
        scopes: idpScopes
          .split(',')
          .map((scope) => scope.trim())
          .filter(Boolean),
        enabled: idpEnabled,
        flags: idpSettings.data?.flags ?? {},
      })
      setIdpClientSecret('')
      setIdpSaved(true)
    } catch (err) {
      setIdpError((err as Error).message)
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
        {idpSettings.isPending ? (
          <LoadingState label="Loading tenant OIDC settings…" />
        ) : idpSettings.isError ? (
          <ErrorState description="Could not load tenant OIDC settings." />
        ) : (
          <form
            className={styles.actions}
            onSubmit={(e) => {
              void submitIdP(e)
            }}
          >
            <Field
              label="OIDC issuer"
              type="url"
              required
              value={idpIssuer}
              onChange={(e) => setIdpIssuer(e.target.value)}
              placeholder="https://idp.example/realms/network"
              hint={`Current source: ${idpSettings.data?.source ?? 'none'}`}
            />
            <Field
              label="OIDC client ID"
              required
              value={idpClientID}
              onChange={(e) => setIdpClientID(e.target.value)}
              placeholder="probectl"
            />
            <Field
              label="OIDC client secret"
              type="password"
              autoComplete="new-password"
              value={idpClientSecret}
              onChange={(e) => setIdpClientSecret(e.target.value)}
              placeholder={
                idpSettings.data?.client_secret_configured ? 'Leave blank to preserve' : 'Required'
              }
              hint="Write-only: the API envelope-encrypts this value and never returns it."
            />
            <Field
              label="OIDC redirect URL"
              type="url"
              required
              value={idpRedirectURL}
              onChange={(e) => setIdpRedirectURL(e.target.value)}
              placeholder="https://probectl.example/auth/callback"
            />
            <Field
              label="OIDC scopes"
              required
              value={idpScopes}
              onChange={(e) => setIdpScopes(e.target.value)}
              hint="Comma-separated; openid is required."
            />
            <label>
              <input
                type="checkbox"
                checked={idpEnabled}
                onChange={(e) => setIdpEnabled(e.target.checked)}
              />{' '}
              Use tenant IdP override
            </label>
            <Button type="submit" variant="primary" disabled={updateIdP.isPending}>
              Save OIDC settings
            </Button>
          </form>
        )}
        {idpSaved ? <p role="status">Tenant OIDC settings saved.</p> : null}
        {idpError ? <p role="alert">{idpError}</p> : null}

        <Table
          caption="Identity surfaces"
          columns={surfaceColumns}
          rows={directorySurfaces}
          rowKey={(s) => s.endpoint}
        />

        <form
          className={styles.actions}
          aria-label="Grant a role"
          onSubmit={(e) => {
            void submitGrant(e)
          }}
        >
          <Field
            label="Teammate email"
            hint="An existing person gets the role; a new address is created before their first login."
            value={personEmail}
            onChange={(e) => setPersonEmail(e.target.value)}
            placeholder="ada@example.com"
            required
          />
          <Select
            label="Role"
            value={personRole}
            onChange={(e) => setPersonRole(e.target.value)}
            options={roleOptions}
          />
          <Button
            type="submit"
            variant="primary"
            disabled={createPerson.isPending || bindRole.isPending || roleOptions.length === 0}
          >
            Grant
          </Button>
        </form>
        {personError ? (
          <p role="alert" className={styles.editionsLede}>
            {personError}
          </p>
        ) : null}
        {roles.isError ? (
          <ErrorState description="Could not load the tenant's roles; grants are unavailable until they load." />
        ) : null}
        {people.isPending ? (
          <LoadingState label="Loading people…" />
        ) : people.isError ? (
          <ErrorState description="Could not load the tenant's people." />
        ) : (
          <Table
            caption="People & roles"
            columns={peopleColumns}
            rows={people.data ?? []}
            rowKey={(u) => u.id}
            empty={
              <EmptyState
                icon="admin"
                title="No people yet"
                description="Grant a role above, or let your IdP push users and groups over SCIM."
              />
            }
          />
        )}

        <form
          className={styles.actions}
          onSubmit={(e) => {
            void submitToken(e)
          }}
        >
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

        <form
          className={styles.actions}
          onSubmit={(e) => {
            void submitPolicy(e)
          }}
        >
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
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />{' '}
            Enabled
          </label>
          <Button type="submit" variant="primary" disabled={createPolicy.isPending}>
            Create ABAC policy
          </Button>
        </form>
        {policyError || deletePolicy.isError ? (
          <p role="alert" className={styles.editionsLede}>
            {policyError || deletePolicy.error?.message}
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
