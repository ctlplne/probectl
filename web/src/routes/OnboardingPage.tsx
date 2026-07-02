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
  useOnboardingProgress,
  type AgentEnrollToken,
  type CollectorPlane,
} from '../api/agents'
import { useCreateScimToken, type CreatedScimToken, useScimTokens } from '../api/identity'
import { useCreateTest, useTests, type Test } from '../api/tests'
import { Page } from './pages'
import { agentEnrollCommand, defaultControlPlaneURL } from './enrollment'
import styles from './onboarding.module.css'
import { useI18n } from '../i18n/useI18n'
import { formatCount } from '../i18n/number'
import type { MessageKey } from '../i18n/messages'

const FIRST_TEST_TYPES = ['http', 'dns', 'icmp', 'tcp']

type ProducerPlane = {
  id: 'synthetic' | CollectorPlane
  titleKey: MessageKey
  producerKey: MessageKey
  prerequisitesKey: MessageKey
  firstSignalKey: MessageKey
  actionKey: MessageKey
}

const PRODUCER_PLANES: ProducerPlane[] = [
  {
    id: 'synthetic',
    titleKey: 'onboarding.producer.synthetic.title',
    producerKey: 'onboarding.producer.synthetic.producer',
    prerequisitesKey: 'onboarding.producer.synthetic.prerequisites',
    firstSignalKey: 'onboarding.producer.synthetic.firstSignal',
    actionKey: 'onboarding.producer.synthetic.action',
  },
  {
    id: 'flow',
    titleKey: 'onboarding.producer.flow.title',
    producerKey: 'onboarding.producer.flow.producer',
    prerequisitesKey: 'onboarding.producer.flow.prerequisites',
    firstSignalKey: 'onboarding.producer.flow.firstSignal',
    actionKey: 'onboarding.producer.flow.action',
  },
  {
    id: 'bgp',
    titleKey: 'onboarding.producer.bgp.title',
    producerKey: 'onboarding.producer.bgp.producer',
    prerequisitesKey: 'onboarding.producer.bgp.prerequisites',
    firstSignalKey: 'onboarding.producer.bgp.firstSignal',
    actionKey: 'onboarding.producer.bgp.action',
  },
  {
    id: 'device',
    titleKey: 'onboarding.producer.device.title',
    producerKey: 'onboarding.producer.device.producer',
    prerequisitesKey: 'onboarding.producer.device.prerequisites',
    firstSignalKey: 'onboarding.producer.device.firstSignal',
    actionKey: 'onboarding.producer.device.action',
  },
  {
    id: 'ebpf',
    titleKey: 'onboarding.producer.ebpf.title',
    producerKey: 'onboarding.producer.ebpf.producer',
    prerequisitesKey: 'onboarding.producer.ebpf.prerequisites',
    firstSignalKey: 'onboarding.producer.ebpf.firstSignal',
    actionKey: 'onboarding.producer.ebpf.action',
  },
  {
    id: 'endpoint',
    titleKey: 'onboarding.producer.endpoint.title',
    producerKey: 'onboarding.producer.endpoint.producer',
    prerequisitesKey: 'onboarding.producer.endpoint.prerequisites',
    firstSignalKey: 'onboarding.producer.endpoint.firstSignal',
    actionKey: 'onboarding.producer.endpoint.action',
  },
]

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

function ProgressItem({
  label,
  detail,
  done,
  readyLabel,
}: {
  label: string
  detail: string
  done: boolean
  readyLabel: string
}) {
  return (
    <li className={styles.progressItem}>
      <StatusDot tone={done ? 'success' : 'neutral'} label={done ? readyLabel : label} />
      <span>{detail}</span>
    </li>
  )
}

export function OnboardingPage() {
  const navigate = useNavigate()
  const { locale, t } = useI18n()
  const { tenant, user } = useAuth()
  const agentsQuery = useAgents()
  const testsQuery = useTests()
  const scimQuery = useScimTokens()
  const onboardingProgress = useOnboardingProgress()
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
  const persistedProgress = onboardingProgress.data
  const command = agentToken
    ? agentEnrollCommand(agentToken, controlURL.trim() || defaultControlPlaneURL())
    : ''

  const progress = useMemo(() => {
    const agentDone =
      agents.length > 0 ||
      agentToken !== null ||
      Boolean(persistedProgress?.agent_registered || persistedProgress?.agent_enroll_token_created)
    const testDone =
      tests.length > 0 || createdTest !== null || Boolean(persistedProgress?.first_test_created)
    const teammatesDone =
      scimTokens.length > 0 ||
      inviteToken !== null ||
      Boolean(persistedProgress?.scim_token_created)
    return [
      {
        label: t('onboarding.progress.session'),
        done: true,
        detail: t('onboarding.progress.session.detail', {
          email: user.email,
          tenant: tenant.slug || tenant.id,
        }),
      },
      {
        label: t('onboarding.progress.agent'),
        done: agentDone,
        detail:
          agents.length > 0
            ? t('onboarding.progress.agent.visible', {
                count: formatCount(
                  agents.length,
                  t('onboarding.unit.agent'),
                  t('onboarding.unit.agents'),
                  locale,
                ),
              })
            : agentToken
              ? t('onboarding.progress.agent.tokenMinted')
              : persistedProgress?.agent_registered
                ? t('onboarding.progress.agent.registered')
                : persistedProgress?.agent_enroll_token_created
                  ? t('onboarding.progress.agent.tokenAlreadyMinted')
                  : t('onboarding.progress.agent.waiting'),
      },
      {
        label: t('onboarding.progress.firstTest'),
        done: testDone,
        detail:
          tests.length > 0
            ? t('onboarding.progress.firstTest.configured', {
                count: formatCount(
                  tests.length,
                  t('onboarding.unit.test'),
                  t('onboarding.unit.tests'),
                  locale,
                ),
              })
            : createdTest
              ? t('onboarding.progress.firstTest.created', { name: createdTest.name })
              : persistedProgress?.first_test_created
                ? t('onboarding.progress.firstTest.alreadyConfigured')
                : t('onboarding.progress.firstTest.waiting'),
      },
      {
        label: t('onboarding.progress.teammates'),
        done: teammatesDone,
        detail:
          scimTokens.length > 0
            ? t('onboarding.progress.teammates.active', {
                count: formatCount(
                  scimTokens.length,
                  t('onboarding.unit.scimToken'),
                  t('onboarding.unit.scimTokens'),
                  locale,
                ),
              })
            : inviteToken
              ? t('onboarding.progress.teammates.created', { name: inviteToken.name })
              : persistedProgress?.scim_token_created
                ? t('onboarding.progress.teammates.alreadyCreated')
                : t('onboarding.progress.teammates.waiting'),
      },
    ]
  }, [
    agentToken,
    agents.length,
    createdTest,
    inviteToken,
    locale,
    persistedProgress?.agent_enroll_token_created,
    persistedProgress?.agent_registered,
    persistedProgress?.first_test_created,
    persistedProgress?.scim_token_created,
    scimTokens.length,
    t,
    tenant.id,
    tenant.slug,
    tests.length,
    user.email,
  ])

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

  function choosePlane(plane: ProducerPlane) {
    if (plane.id === 'synthetic') {
      const target = document.getElementById('first-run-agent')
      target?.scrollIntoView({ block: 'start', behavior: 'smooth' })
      target?.querySelector<HTMLButtonElement | HTMLInputElement>('input, button')?.focus()
      return
    }
    navigate(`/admin?register_collector=${plane.id}`)
  }

  return (
    <Page
      title={t('onboarding.page.title')}
      subtitle={t('onboarding.page.subtitle')}
      actions={
        <Button variant="secondary" onClick={() => navigate('/admin')}>
          <Icon name="admin" /> {t('onboarding.action.admin')}
        </Button>
      }
    >
      <section className={styles.progress} aria-label={t('onboarding.progress.aria')}>
        <ul className={styles.progressList} role="list">
          {progress.map((item) => (
            <ProgressItem
              key={item.label}
              {...item}
              readyLabel={t('onboarding.progress.ready', { label: item.label })}
            />
          ))}
        </ul>
      </section>

      <section className={styles.planeChooser} aria-labelledby="plane-chooser-title">
        <div className={styles.sectionIntro}>
          <h2 id="plane-chooser-title">{t('onboarding.planeChooser.title')}</h2>
          <p>{t('onboarding.planeChooser.description')}</p>
        </div>
        <div className={styles.planeGrid}>
          {PRODUCER_PLANES.map((plane) => (
            <Card key={plane.id} className={styles.planeCard}>
              <CardHeader
                title={t(plane.titleKey)}
                description={t(plane.producerKey)}
                actions={
                  <Badge tone={plane.id === 'synthetic' ? 'info' : 'warning'}>
                    {plane.id === 'synthetic' ? 'gRPC' : 'bus'}
                  </Badge>
                }
              />
              <CardBody className={styles.planeBody}>
                <dl className={styles.planeFacts}>
                  <dt>{t('onboarding.field.prerequisites')}</dt>
                  <dd>{t(plane.prerequisitesKey)}</dd>
                  <dt>{t('onboarding.field.firstSignal')}</dt>
                  <dd>{t(plane.firstSignalKey)}</dd>
                </dl>
                <Button
                  variant={plane.id === 'synthetic' ? 'primary' : 'secondary'}
                  onClick={() => choosePlane(plane)}
                >
                  <Icon name={plane.id === 'synthetic' ? 'targets' : 'admin'} />{' '}
                  {t(plane.actionKey)}
                </Button>
              </CardBody>
            </Card>
          ))}
        </div>
      </section>

      <div className={styles.grid}>
        <Card id="first-run-agent">
          <CardHeader
            title={t('onboarding.agent.title')}
            description={t('onboarding.agent.description')}
            actions={
              agentToken ? <Badge tone="success">{t('onboarding.agent.tokenReady')}</Badge> : null
            }
          />
          <CardBody>
            <form className={styles.form} onSubmit={submitAgent}>
              <Field
                label={t('onboarding.agent.label')}
                value={agentLabel}
                onChange={(e) => setAgentLabel(e.target.value)}
                placeholder="edge-canary-1"
              />
              <Field
                label={t('onboarding.agent.ttl')}
                type="number"
                min={1}
                value={agentTTLMinutes}
                onChange={(e) => setAgentTTLMinutes(e.target.value)}
              />
              <Field
                label={t('onboarding.agent.controlURL')}
                value={controlURL}
                onChange={(e) => setControlURL(e.target.value)}
              />
              <Button type="submit" variant="primary" disabled={mintAgent.isPending}>
                <Icon name="admin" />{' '}
                {mintAgent.isPending ? t('onboarding.agent.minting') : t('onboarding.agent.mint')}
              </Button>
              {mintAgent.isError ? (
                <p className={styles.error} role="alert">
                  {mintAgent.error.message}
                </p>
              ) : null}
            </form>
            {agentToken ? (
              <div className={styles.receipt}>
                <Field label={t('onboarding.agent.token')} value={agentToken.token} readOnly />
                <Field label={t('onboarding.agent.command')} value={command} readOnly />
                <Button
                  variant="secondary"
                  onClick={() => void navigator.clipboard?.writeText(command)}
                >
                  <Icon name="check" /> {t('onboarding.agent.copyCommand')}
                </Button>
              </div>
            ) : null}
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title={t('onboarding.test.title')}
            description={t('onboarding.test.description')}
            actions={
              createdTest ? <Badge tone="success">{t('onboarding.test.createdBadge')}</Badge> : null
            }
          />
          <CardBody>
            <form className={styles.form} onSubmit={submitTest}>
              <Field
                label={t('onboarding.test.name')}
                value={testName}
                onChange={(e) => setTestName(e.target.value)}
              />
              <Select
                label={t('onboarding.test.type')}
                value={testType}
                onChange={(e) => {
                  const next = e.target.value
                  setTestType(next)
                  setTestTarget(firstTestTargetPlaceholder(next))
                }}
                options={FIRST_TEST_TYPES.map((type) => ({ value: type, label: type }))}
              />
              <Field
                label={t('onboarding.test.target')}
                value={testTarget}
                onChange={(e) => setTestTarget(e.target.value)}
                placeholder={firstTestTargetPlaceholder(testType)}
              />
              <Field
                label={t('onboarding.test.interval')}
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
                <Icon name="targets" />{' '}
                {createTest.isPending ? t('onboarding.test.creating') : t('onboarding.test.create')}
              </Button>
              {createTest.isError ? (
                <p className={styles.error} role="alert">
                  {createTest.error.message}
                </p>
              ) : null}
            </form>
            {createdTest ? (
              <div className={styles.receipt}>
                <StatusDot
                  tone="success"
                  label={t('onboarding.test.enabled', { name: createdTest.name })}
                />
                <code>{createdTest.target}</code>
                <Button variant="secondary" onClick={() => navigate('/targets')}>
                  <Icon name="targets" /> {t('onboarding.test.openTests')}
                </Button>
              </div>
            ) : null}
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title={t('onboarding.invite.title')}
            description={t('onboarding.invite.description')}
            actions={
              inviteToken ? <Badge tone="success">{t('onboarding.agent.tokenReady')}</Badge> : null
            }
          />
          <CardBody>
            <form className={styles.form} onSubmit={submitInvite}>
              <Field
                label={t('onboarding.invite.name')}
                value={inviteName}
                onChange={(e) => setInviteName(e.target.value)}
              />
              <Button type="submit" variant="primary" disabled={createInvite.isPending}>
                <Icon name="admin" />{' '}
                {createInvite.isPending
                  ? t('onboarding.invite.creating')
                  : t('onboarding.invite.create')}
              </Button>
              {createInvite.isError ? (
                <p className={styles.error} role="alert">
                  {createInvite.error.message}
                </p>
              ) : null}
            </form>
            {inviteToken ? (
              <div className={styles.receipt}>
                <Field label={t('onboarding.invite.token')} value={inviteToken.token} readOnly />
                <Button
                  variant="secondary"
                  onClick={() => void navigator.clipboard?.writeText(inviteToken.token)}
                >
                  <Icon name="check" /> {t('onboarding.invite.copyToken')}
                </Button>
              </div>
            ) : null}
          </CardBody>
        </Card>
      </div>
    </Page>
  )
}
