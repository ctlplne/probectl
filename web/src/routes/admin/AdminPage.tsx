import {
  Badge,
  Card,
  CardBody,
  CardHeader,
  Column,
  EmptyState,
  ErrorState,
  LoadingState,
  StatusDot,
  Table,
} from '../../components'
import { Page } from '../pages'
import { useAgents, flattenAgents, type Agent } from '../../api/agents'
import { useSecretsHealth, type SecretBackendHealth } from '../../api/secrets'
import { RemediationCard, KeysCard } from './AdminCards'
import { LifecycleCard, SupportCard, EditionsCard } from './LifecycleCards'
import { IdentityCard } from './IdentityCard'

// --- Admin & Settings: the agent fleet (live /v1/agents) + secret-backend
// health (S41, live /v1/secrets/health) ---

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
