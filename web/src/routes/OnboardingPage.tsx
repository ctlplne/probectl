import { useMemo, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  Field,
  Icon,
  Select,
  StatusDot,
} from '../components'
import { useAuth } from '../auth/useAuth'
import {
  flattenAgents,
  useAgents,
  useMintAgentEnrollToken,
  type AgentEnrollToken,
} from '../api/agents'
import { useCreateScimToken, type CreatedScimToken, useScimTokens } from '../api/identity'
import { useCreateTest, useTests, type Test } from '../api/tests'
import { Page } from './pages'
import { agentEnrollCommand, defaultControlPlaneURL } from './enrollment'
import styles from './onboarding.module.css'

const FIRST_TEST_TYPES = ['http', 'dns', 'icmp', 'tcp']

function firstTestTargetPlaceholder(type: string): string {
  switch (type) {
    case 'http':
      return 'https://app.example.test/health'
    case 'dns':
      return 'app.example.test'
    case 'tcp':
      return 'app.example.test:443'
    default:
      return '1.1.1.1'
  }
}

function ProgressItem({ label, detail, done }: { label: string; detail: string; done: boolean }) {
  return (
    <li className={styles.progressItem}>
      <StatusDot tone={done ? 'success' : 'neutral'} label={done ? `${label} ready` : label} />
      <span>{detail}</span>
    </li>
  )
}

export function OnboardingPage() {
  const navigate = useNavigate()
  const { tenant, user } = useAuth()
  const agentsQuery = useAgents()
  const testsQuery = useTests()
  const scimQuery = useScimTokens()
  const mintAgent = useMintAgentEnrollToken()
  const createTest = useCreateTest()
  const createInvite = useCreateScimToken()

  const [agentLabel, setAgentLabel] = useState('edge-canary-1')
  const [agentTTLMinutes, setAgentTTLMinutes] = useState('60')
  const [controlURL, setControlURL] = useState(defaultControlPlaneURL)
  const [agentToken, setAgentToken] = useState<AgentEnrollToken | null>(null)

  const [testName, setTestName] = useState('first-http-check')
  const [testType, setTestType] = useState('http')
  const [testTarget, setTestTarget] = useState('https://app.example.test/health')
  const [testInterval, setTestInterval] = useState('60')
  const [createdTest, setCreatedTest] = useState<Test | null>(null)

  const [inviteName, setInviteName] = useState('first-run-teammates')
  const [inviteToken, setInviteToken] = useState<CreatedScimToken | null>(null)

  const agents = flattenAgents(agentsQuery.data?.pages)
  const tests = testsQuery.data ?? []
  const scimTokens = scimQuery.data ?? []
  const command = agentToken
    ? agentEnrollCommand(agentToken, controlURL.trim() || defaultControlPlaneURL())
    : ''

  const progress = useMemo(
    () => [
      {
        label: 'Session',
        done: true,
        detail: `${user.email} in tenant ${tenant.slug || tenant.id}`,
      },
      {
        label: 'Agent',
        done: agents.length > 0 || agentToken !== null,
        detail:
          agents.length > 0
            ? `${agents.length} agent${agents.length === 1 ? '' : 's'} visible`
            : agentToken
              ? 'enrollment token minted'
              : 'waiting for an enrollment token',
      },
      {
        label: 'First test',
        done: tests.length > 0 || createdTest !== null,
        detail:
          tests.length > 0
            ? `${tests.length} test${tests.length === 1 ? '' : 's'} configured`
            : createdTest
              ? `${createdTest.name} created`
              : 'waiting for a synthetic target',
      },
      {
        label: 'Teammates',
        done: scimTokens.length > 0 || inviteToken !== null,
        detail:
          scimTokens.length > 0
            ? `${scimTokens.length} SCIM token${scimTokens.length === 1 ? '' : 's'} active`
            : inviteToken
              ? `${inviteToken.name} token created`
              : 'waiting for an invite/provisioning token',
      },
    ],
    [
      agentToken,
      agents.length,
      createdTest,
      inviteToken,
      scimTokens.length,
      tenant.id,
      tenant.slug,
      tests.length,
      user.email,
    ],
  )

  function submitAgent(e: FormEvent) {
    e.preventDefault()
    const ttl = Number(agentTTLMinutes)
    mintAgent.mutate(
      {
        ...(agentLabel.trim() ? { name: agentLabel.trim() } : {}),
        ...(Number.isFinite(ttl) && ttl > 0 ? { ttl_seconds: Math.round(ttl * 60) } : {}),
      },
      { onSuccess: setAgentToken },
    )
  }

  function submitTest(e: FormEvent) {
    e.preventDefault()
    const interval = Number(testInterval)
    createTest.mutate(
      {
        name: testName.trim(),
        type: testType,
        target: testTarget.trim(),
        interval_seconds: Number.isFinite(interval) && interval > 0 ? Math.round(interval) : 60,
        timeout_seconds: 3,
        params: {},
        enabled: true,
      },
      { onSuccess: setCreatedTest },
    )
  }

  function submitInvite(e: FormEvent) {
    e.preventDefault()
    createInvite.mutate(
      { name: inviteName.trim() || 'first-run-teammates' },
      { onSuccess: setInviteToken },
    )
  }

  return (
    <Page
      title="First-run setup"
      subtitle="Bring one tenant online from the browser: agent token, first test, and teammate provisioning."
      actions={
        <Button variant="secondary" onClick={() => navigate('/admin')}>
          <Icon name="admin" /> Admin
        </Button>
      }
    >
      <section className={styles.progress} aria-label="First-run progress">
        <ul className={styles.progressList} role="list">
          {progress.map((item) => (
            <ProgressItem key={item.label} {...item} />
          ))}
        </ul>
      </section>

      <div className={styles.grid}>
        <Card>
          <CardHeader
            title="Enroll an agent"
            description="Mint a tenant-scoped, one-time token and run the command from the agent host."
            actions={agentToken ? <Badge tone="success">token ready</Badge> : null}
          />
          <CardBody>
            <form className={styles.form} onSubmit={submitAgent}>
              <Field
                label="Agent label"
                value={agentLabel}
                onChange={(e) => setAgentLabel(e.target.value)}
                placeholder="edge-canary-1"
              />
              <Field
                label="Token TTL minutes"
                type="number"
                min={1}
                value={agentTTLMinutes}
                onChange={(e) => setAgentTTLMinutes(e.target.value)}
              />
              <Field
                label="Control plane URL"
                value={controlURL}
                onChange={(e) => setControlURL(e.target.value)}
              />
              <Button type="submit" variant="primary" disabled={mintAgent.isPending}>
                <Icon name="admin" /> {mintAgent.isPending ? 'Minting...' : 'Mint enrollment token'}
              </Button>
              {mintAgent.isError ? (
                <p className={styles.error} role="alert">
                  {mintAgent.error.message}
                </p>
              ) : null}
            </form>
            {agentToken ? (
              <div className={styles.receipt}>
                <Field label="Enrollment token" value={agentToken.token} readOnly />
                <Field label="Enrollment command" value={command} readOnly />
                <Button
                  variant="secondary"
                  onClick={() => void navigator.clipboard?.writeText(command)}
                >
                  <Icon name="check" /> Copy command
                </Button>
              </div>
            ) : null}
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Create the first test"
            description="Start with one synthetic target so the tenant has a live signal to inspect."
            actions={createdTest ? <Badge tone="success">test created</Badge> : null}
          />
          <CardBody>
            <form className={styles.form} onSubmit={submitTest}>
              <Field
                label="Test name"
                value={testName}
                onChange={(e) => setTestName(e.target.value)}
              />
              <Select
                label="Type"
                value={testType}
                onChange={(e) => {
                  const next = e.target.value
                  setTestType(next)
                  setTestTarget(firstTestTargetPlaceholder(next))
                }}
                options={FIRST_TEST_TYPES.map((type) => ({ value: type, label: type }))}
              />
              <Field
                label="Target"
                value={testTarget}
                onChange={(e) => setTestTarget(e.target.value)}
                placeholder={firstTestTargetPlaceholder(testType)}
              />
              <Field
                label="Interval seconds"
                type="number"
                min={10}
                value={testInterval}
                onChange={(e) => setTestInterval(e.target.value)}
              />
              <Button
                type="submit"
                variant="primary"
                disabled={createTest.isPending || !testName.trim() || !testTarget.trim()}
              >
                <Icon name="targets" /> {createTest.isPending ? 'Creating...' : 'Create first test'}
              </Button>
              {createTest.isError ? (
                <p className={styles.error} role="alert">
                  {createTest.error.message}
                </p>
              ) : null}
            </form>
            {createdTest ? (
              <div className={styles.receipt}>
                <StatusDot tone="success" label={`${createdTest.name} is enabled`} />
                <code>{createdTest.target}</code>
                <Button variant="secondary" onClick={() => navigate('/targets')}>
                  <Icon name="targets" /> Open tests
                </Button>
              </div>
            ) : null}
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Invite teammates"
            description="Create the SCIM provisioning token your IdP uses to add users and groups."
            actions={inviteToken ? <Badge tone="success">token ready</Badge> : null}
          />
          <CardBody>
            <form className={styles.form} onSubmit={submitInvite}>
              <Field
                label="Invite token name"
                value={inviteName}
                onChange={(e) => setInviteName(e.target.value)}
              />
              <Button type="submit" variant="primary" disabled={createInvite.isPending}>
                <Icon name="admin" /> {createInvite.isPending ? 'Creating...' : 'Create SCIM token'}
              </Button>
              {createInvite.isError ? (
                <p className={styles.error} role="alert">
                  {createInvite.error.message}
                </p>
              ) : null}
            </form>
            {inviteToken ? (
              <div className={styles.receipt}>
                <Field label="SCIM bearer token" value={inviteToken.token} readOnly />
                <Button
                  variant="secondary"
                  onClick={() => void navigator.clipboard?.writeText(inviteToken.token)}
                >
                  <Icon name="check" /> Copy token
                </Button>
              </div>
            ) : null}
          </CardBody>
        </Card>
      </div>
    </Page>
  )
}
