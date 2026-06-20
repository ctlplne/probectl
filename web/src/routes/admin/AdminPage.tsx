import { useState, type FormEvent } from 'react'
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
  Icon,
  LoadingState,
  Modal,
  StatusDot,
  Table,
} from '../../components'
import { Page } from '../pages'
import {
  useAgents,
  useMintAgentEnrollToken,
  flattenAgents,
  type Agent,
  type AgentEnrollToken,
} from '../../api/agents'
import { useSecretsHealth, type SecretBackendHealth } from '../../api/secrets'
import { RemediationCard, KeysCard } from './AdminCards'
import { LifecycleCard, SupportCard, EditionsCard } from './LifecycleCards'
import { IdentityCard } from './IdentityCard'
import styles from '../pages.module.css'

// --- Admin & Settings: the agent fleet (live /v1/agents) + secret-backend
// health (S41, live /v1/secrets/health) ---

function initialControlPlaneURL(): string {
  if (typeof window === 'undefined' || window.location.protocol !== 'https:') {
    return 'https://<control-host>:8443'
  }
  return window.location.origin
}

function enrollCommand(token: AgentEnrollToken, server: string): string {
  const trust = token.server_cert_pin
    ? ` --ca-pin ${token.server_cert_pin}`
    : ' --ca-file /etc/probectl/control-plane-ca.crt'
  return `probectl-agent enroll --server ${server} --token ${token.token} --dir /var/lib/probectl-agent/identity${trust}`
}

function AgentEnrollDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const mint = useMintAgentEnrollToken()
  const [name, setName] = useState('')
  const [agentID, setAgentID] = useState('')
  const [ttlMinutes, setTTLMinutes] = useState('60')
  const [server, setServer] = useState(initialControlPlaneURL)
  const [created, setCreated] = useState<AgentEnrollToken | null>(null)

  function submit(e: FormEvent) {
    e.preventDefault()
    const ttl = Number(ttlMinutes)
    const input = {
      ...(agentID.trim() ? { agent_id: agentID.trim() } : {}),
      ...(name.trim() ? { name: name.trim() } : {}),
      ...(Number.isFinite(ttl) && ttl > 0 ? { ttl_seconds: Math.round(ttl * 60) } : {}),
    }
    mint.mutate(input, { onSuccess: setCreated })
  }

  const command = created ? enrollCommand(created, server.trim() || initialControlPlaneURL()) : ''
  const expires = created ? new Date(created.expires_at).toISOString() : ''

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={created ? 'Agent enrollment token' : 'Enroll agent'}
      footer={
        created ? (
          <span className={styles.actions}>
            <Button
              variant="secondary"
              onClick={() => void navigator.clipboard?.writeText(command)}
            >
              <Icon name="check" /> Copy command
            </Button>
            <Button variant="primary" onClick={onClose}>
              Done
            </Button>
          </span>
        ) : null
      }
    >
      {created ? (
        <div className={styles.form}>
          <p className={styles.editionsLede}>
            Token <code>{created.id}</code> expires at{' '}
            <time dateTime={created.expires_at}>{expires}</time>. It is single-use and stored
            server-side only as a hash.
          </p>
          <Field label="Enrollment token" value={created.token} readOnly />
          <Field label="Enrollment command" value={command} readOnly />
          <p className={styles.editionsLede}>
            {created.server_cert_pin ? (
              <>
                The command pins the current control-plane serving certificate with{' '}
                <code>--ca-pin</code>. Use <code>--ca-file</code> instead when agents trust a
                CA-issued control-plane certificate.
              </>
            ) : (
              <>
                Add the control-plane CA bundle with <code>--ca-file</code>, or mint from the
                control host with <code>PROBECTL_TLS_CERT_FILE</code> set to print a{' '}
                <code>--ca-pin</code> value.
              </>
            )}
          </p>
        </div>
      ) : (
        <form className={styles.form} onSubmit={submit}>
          <Field
            label="Agent label"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="edge-probe-1"
            hint="Optional operator label recorded with the one-time token."
          />
          <Field
            label="Pinned agent id"
            value={agentID}
            onChange={(e) => setAgentID(e.target.value)}
            placeholder="blank = assign on enroll"
            hint="Optional. Leave blank when the control plane should mint the identity."
          />
          <Field
            label="Token TTL minutes"
            type="number"
            min={1}
            value={ttlMinutes}
            onChange={(e) => setTTLMinutes(e.target.value)}
            hint="Default is 60 minutes; expired or reused tokens fail closed."
          />
          <Field
            label="Control plane URL"
            value={server}
            onChange={(e) => setServer(e.target.value)}
            hint="Use the HTTPS URL reachable from the agent host."
          />
          {mint.isError ? (
            <p role="alert" className={styles.editionsLede}>
              {mint.error.message}
            </p>
          ) : null}
          <span className={styles.actions}>
            <Button type="submit" variant="primary" disabled={mint.isPending}>
              <Icon name="admin" /> {mint.isPending ? 'Minting…' : 'Mint token'}
            </Button>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
          </span>
        </form>
      )}
    </Modal>
  )
}

/** SecretBackendsCard is the S41 surface: per-backend credential-resolution
 * health. No secret material ever reaches this card — the API serves counters
 * and redacted errors only. resolver_running=false renders as the honest
 * "not wired" empty state, never as a healthy zero. */
function SecretBackendsCard() {
  const { data, isPending, isError } = useSecretsHealth()

  const columns: Column<SecretBackendHealth>[] = [
    { key: 'scheme', header: 'Backend', render: (b) => <code>{b.scheme}</code> },
    {
      key: 'status',
      header: 'Status',
      render: (b) =>
        !b.configured ? (
          <StatusDot tone="neutral" label="Not configured" />
        ) : b.failures > 0 && (!b.last_ok || (b.last_error_at && b.last_error_at > b.last_ok)) ? (
          <StatusDot tone="danger" label="Failing" />
        ) : (
          <StatusDot tone="success" label="OK" />
        ),
    },
    { key: 'resolves', header: 'Resolves', render: (b) => b.resolves },
    { key: 'failures', header: 'Failures', render: (b) => b.failures },
    {
      key: 'leases',
      header: 'Live leases',
      render: (b) => (b.cached_leases > 0 ? <Badge tone="info">{b.cached_leases}</Badge> : '0'),
    },
    {
      key: 'last',
      header: 'Last error',
      render: (b) => (b.last_error ? <code>{b.last_error}</code> : '—'),
    },
  ]

  return (
    <Card>
      <CardHeader
        title="Secret backends"
        description="Credential resolution (Vault / CyberArk / cloud KMS). Values are sealed in memory with short-lived leases; failures fail closed."
      />
      <CardBody>
        {isPending ? (
          <LoadingState label="Loading secret-backend health…" />
        ) : isError ? (
          <ErrorState description="Could not load secret-backend health." />
        ) : !data?.resolver_running ? (
          <EmptyState
            icon="admin"
            title="Secrets resolver not wired"
            description="The control plane started without a secrets resolver — credential references cannot resolve."
          />
        ) : (
          <Table
            caption="Secret backend health"
            columns={columns}
            rows={data.backends}
            rowKey={(b) => b.scheme}
            empty={
              <EmptyState
                icon="admin"
                title="No backends configured"
                description="Set PROBECTL_SECRETS_VAULT_ADDR (or CyberArk / cloud credentials) to enable secret references."
              />
            }
          />
        )}
      </CardBody>
    </Card>
  )
}

export function AdminPage() {
  const { data, isPending, isError, fetchNextPage, hasNextPage, isFetchingNextPage } = useAgents()
  const [enrollOpen, setEnrollOpen] = useState(false)
  // UX-004: flatten the cursor-paged result into the rows fetched so far.
  const agents = flattenAgents(data?.pages)

  const columns: Column<Agent>[] = [
    { key: 'name', header: 'Agent', render: (a) => <strong>{a.name}</strong> },
    { key: 'host', header: 'Hostname', render: (a) => <code>{a.hostname || '—'}</code> },
    { key: 'version', header: 'Version', render: (a) => a.agent_version || '—' },
    {
      key: 'caps',
      header: 'Capabilities',
      render: (a) => (a.capabilities.length ? a.capabilities.join(', ') : '—'),
    },
    {
      key: 'status',
      header: 'Status',
      render: (a) =>
        a.status === 'online' ? (
          <StatusDot tone="success" label="Online" />
        ) : a.status === 'offline' ? (
          <StatusDot tone="danger" label="Offline" />
        ) : (
          <StatusDot tone="neutral" label="Registered" />
        ),
    },
  ]

  return (
    <Page title="Admin & Settings" subtitle="The agent fleet registered to this tenant.">
      <Card>
        <CardHeader
          title="Agents"
          description="Agents register over mTLS; identity is certificate-derived."
          actions={
            <Button variant="primary" onClick={() => setEnrollOpen(true)}>
              <Icon name="admin" /> Enroll agent
            </Button>
          }
        />
        <CardBody>
          {isPending ? (
            <LoadingState label="Loading agents…" />
          ) : isError ? (
            <ErrorState description="Could not load agents." />
          ) : (
            <>
              <Table
                caption="Registered agents"
                columns={columns}
                rows={agents}
                rowKey={(a) => a.id}
                empty={
                  <EmptyState
                    icon="admin"
                    title="No agents registered"
                    description="Deploy a probectl agent to begin."
                  />
                }
              />
              {hasNextPage && (
                <button type="button" onClick={() => fetchNextPage()} disabled={isFetchingNextPage}>
                  {isFetchingNextPage ? 'Loading…' : 'Load more agents'}
                </button>
              )}
            </>
          )}
        </CardBody>
      </Card>
      <AgentEnrollDialog open={enrollOpen} onClose={() => setEnrollOpen(false)} />
      <SecretBackendsCard />
      <IdentityCard />
      <KeysCard />
      <LifecycleCard />
      <RemediationCard />
      <SupportCard />
      <EditionsCard />
    </Page>
  )
}
