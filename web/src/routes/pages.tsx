import { useState, type ReactNode } from 'react'
import styles from './pages.module.css'
import { NAV } from '../nav/ia'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  ChartShell,
  Column,
  EmptyState,
  ErrorState,
  Field,
  Icon,
  LoadingState,
  Modal,
  Select,
  Sparkline,
  StatusDot,
  Table,
  useToast,
} from '../components'
import { useCreateTest, useDeleteTest, useTests, type Test } from '../api/tests'
import { AuthoringPanel } from './AuthoringPanel'
import { useAgents, type Agent } from '../api/agents'

export function Page({
  title,
  subtitle,
  actions,
  children,
}: {
  title: string
  subtitle?: string
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div>
          <h1 className={styles.title}>{title}</h1>
          {subtitle ? <p className={styles.subtitle}>{subtitle}</p> : null}
        </div>
        {actions ? <div className={styles.actions}>{actions}</div> : null}
      </header>
      {children}
    </div>
  )
}

/** PlaceholderPage stands in for an IA section until its sprint lands. */
export function PlaceholderPage({ to }: { to: string }) {
  const item = NAV.find((n) => n.to === to)
  const label = item?.label ?? 'Page'
  return (
    <Page title={label} subtitle="This surface is part of the probectl information architecture.">
      <Card>
        <CardBody>
          <EmptyState
            icon={item?.icon}
            title={`${label} lands in a later sprint`}
            description="The app shell, navigation, and design system are ready — feature screens build on this foundation."
          />
        </CardBody>
      </Card>
    </Page>
  )
}

export function NotFoundPage() {
  return (
    <Page title="Not found">
      <Card>
        <CardBody>
          <ErrorState title="404 — page not found" description="That route does not exist." />
        </CardBody>
      </Card>
    </Page>
  )
}

// --- Targets & Tests (live /v1/tests CRUD) ---

const TEST_TYPES = ['icmp', 'tcp', 'udp', 'dns', 'http', 'a2a', 'noop']

function CreateTestModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { push } = useToast()
  const create = useCreateTest()
  const [name, setName] = useState('')
  const [type, setType] = useState('icmp')
  const [target, setTarget] = useState('')
  const [interval, setInterval] = useState(60)

  function reset() {
    setName('')
    setType('icmp')
    setTarget('')
    setInterval(60)
  }

  function submit() {
    create.mutate(
      { name, type, target, interval_seconds: interval, timeout_seconds: 3, enabled: true },
      {
        onSuccess: () => {
          push({ tone: 'success', title: 'Test created', message: name })
          reset()
          onClose()
        },
        onError: (e) => push({ tone: 'danger', title: 'Create failed', message: (e as Error).message }),
      },
    )
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Create test"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} disabled={create.isPending || !name}>
            {create.isPending ? 'Creating…' : 'Create'}
          </Button>
        </>
      }
    >
      <div className={styles.form}>
        <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="edge-dns" />
        <Select
          label="Type"
          value={type}
          onChange={(e) => setType(e.target.value)}
          options={TEST_TYPES.map((t) => ({ value: t, label: t }))}
        />
        <Field
          label="Target"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder={type === 'tcp' || type === 'udp' ? 'host:port' : '1.1.1.1'}
          hint={type === 'noop' ? 'Not required for noop.' : undefined}
        />
        <Field
          label="Interval (seconds)"
          type="number"
          value={interval}
          onChange={(e) => setInterval(Number(e.target.value))}
        />
      </div>
    </Modal>
  )
}

export function TargetsPage() {
  const { data, isPending, isError, error } = useTests()
  const del = useDeleteTest()
  const { push } = useToast()
  const [creating, setCreating] = useState(false)

  function remove(t: Test) {
    del.mutate(t.id, {
      onSuccess: () => push({ tone: 'success', title: 'Test deleted', message: t.name }),
      onError: (e) => push({ tone: 'danger', title: 'Delete failed', message: (e as Error).message }),
    })
  }

  const columns: Column<Test>[] = [
    { key: 'name', header: 'Test', render: (t) => <strong>{t.name}</strong> },
    { key: 'type', header: 'Type', render: (t) => <Badge tone="neutral">{t.type}</Badge> },
    { key: 'target', header: 'Target', render: (t) => <code>{t.target || '—'}</code> },
    { key: 'interval', header: 'Interval', numeric: true, render: (t) => `${t.interval_seconds}s` },
    {
      key: 'status',
      header: 'Status',
      render: (t) =>
        t.enabled ? <StatusDot tone="success" label="Enabled" /> : <StatusDot tone="neutral" label="Disabled" />,
    },
    {
      key: 'actions',
      header: <span className="sr-only">Actions</span>,
      align: 'end',
      render: (t) => (
        <Button variant="ghost" size="sm" onClick={() => remove(t)} aria-label={`Delete ${t.name}`}>
          Delete
        </Button>
      ),
    },
  ]

  return (
    <Page
      title="Targets & Tests"
      subtitle="Active synthetic tests across your network."
      actions={
        <Button variant="primary" onClick={() => setCreating(true)}>
          <Icon name="targets" size={16} /> New test
        </Button>
      }
    >
      <div className={styles.statRow}>
        <ChartShell title="Avg RTT (24h)" height={120} toolbar={<Badge tone="neutral">sample</Badge>}>
          <Sparkline label="Average round-trip time, last 24 hours" data={[20, 18, 22, 19, 24, 30, 26, 21, 23, 19, 17, 20]} />
        </ChartShell>
        <ChartShell title="Packet loss (24h)" height={120} toolbar={<Badge tone="neutral">sample</Badge>}>
          <Sparkline label="Packet loss, last 24 hours" data={[0, 0, 0, 1, 0, 0, 3, 8, 2, 0, 0, 0]} />
        </ChartShell>
      </div>

      <AuthoringPanel />

      <Card>
        <CardHeader title="Tests" description="Live results land here once the metrics API ships (S23)." />
        <CardBody>
          {isPending ? (
            <LoadingState label="Loading tests…" />
          ) : isError ? (
            <ErrorState description={(error as Error)?.message ?? 'Could not load tests.'} />
          ) : (
            <Table
              caption="Synthetic tests"
              columns={columns}
              rows={data ?? []}
              rowKey={(t) => t.id}
              empty={
                <EmptyState
                  title="No tests yet"
                  description="Create your first test to begin monitoring."
                  action={
                    <Button variant="primary" onClick={() => setCreating(true)}>
                      New test
                    </Button>
                  }
                />
              }
            />
          )}
        </CardBody>
      </Card>

      <CreateTestModal open={creating} onClose={() => setCreating(false)} />
    </Page>
  )
}

// --- Admin & Settings: the agent fleet (live /v1/agents) ---

export function AdminPage() {
  const { data, isPending, isError } = useAgents()

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
        <CardHeader title="Agents" description="Agents register over mTLS; identity is certificate-derived." />
        <CardBody>
          {isPending ? (
            <LoadingState label="Loading agents…" />
          ) : isError ? (
            <ErrorState description="Could not load agents." />
          ) : (
            <Table
              caption="Registered agents"
              columns={columns}
              rows={data ?? []}
              rowKey={(a) => a.id}
              empty={<EmptyState icon="admin" title="No agents registered" description="Deploy a probectl agent to begin." />}
            />
          )}
        </CardBody>
      </Card>
    </Page>
  )
}
