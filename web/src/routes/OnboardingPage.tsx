// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMemo, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  Icon,
  Select,
  StatusDot,
} from '../components'
import {
  useMintAgentEnrollToken,
  useOnboardingProgress,
  type AgentEnrollToken,
  type CollectorPlane,
  type OnboardingReadiness,
} from '../api/agents'
import { useCreateScimToken, type CreatedScimToken } from '../api/identity'
import { useCreateTest, type Test } from '../api/tests'
import { Page } from './RoutePage'
import { agentEnrollCommand, defaultControlPlaneURL } from './enrollment'
import styles from './onboarding.module.css'
import { useI18n } from '../i18n/useI18n'
import type { MessageKey } from '../i18n/messages'
import type { BadgeTone } from '../components'
import { useTime } from '../time/useTime'

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

function agentCanaryYAML(test: Test): string {
  const lines = [
    'canaries:',
    `  - test_id: ${JSON.stringify(test.id)}`,
    `    type: ${JSON.stringify(test.type)}`,
    `    target: ${JSON.stringify(test.target)}`,
    `    interval: ${test.interval_seconds}s`,
    `    timeout: ${test.timeout_seconds}s`,
  ]
  const params = Object.entries(test.params ?? {}).sort(([left], [right]) =>
    left.localeCompare(right),
  )
  if (params.length > 0) {
    lines.push('    params:')
    for (const [key, value] of params) lines.push(`      ${key}: ${JSON.stringify(value)}`)
  }
  return lines.join('\n')
}

type ReadinessStepID = 'credential' | 'connected' | 'healthy' | 'result' | 'finding'

interface ReadinessStep {
  id: ReadinessStepID
  label: string
  detail: string
  done: boolean
}

function ProgressItem({
  id,
  label,
  detail,
  done,
  active,
  readyLabel,
}: {
  id: ReadinessStepID
  label: string
  detail: string
  done: boolean
  /** The first not-done step — "you are here". */
  active: boolean
  readyLabel: string
}) {
  return (
    <li
      className={`${styles.progressItem} ${active ? styles.progressActive : ''}`}
      data-readiness-step={id}
    >
      <StatusDot
        tone={done ? 'success' : active ? 'warning' : 'neutral'}
        label={done ? readyLabel : label}
      />
      <span>{detail}</span>
    </li>
  )
}

function readinessTone(state: OnboardingReadiness['state']): BadgeTone {
  if (state === 'ready') return 'success'
  if (state === 'quiet') return 'info'
  return 'warning'
}

export function OnboardingPage() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const time = useTime()
  const onboardingProgress = useOnboardingProgress()
  const mintAgent = useMintAgentEnrollToken()
  const createTest = useCreateTest()
  const createInvite = useCreateScimToken()

  const [agentLabel, setAgentLabel] = useState('edge-canary-1')
  const [agentTTLMinutes, setAgentTTLMinutes] = useState('60')
  const [controlURL, setControlURL] = useState(defaultControlPlaneURL)
  const [agentToken, setAgentToken] = useState<AgentEnrollToken | null>(null)

  const [testName, setTestName] = useState('first-loopback-check')
  const [testType, setTestType] = useState('icmp')
  const [testTarget, setTestTarget] = useState('127.0.0.1')
  const [testInterval, setTestInterval] = useState('60')
  // The sovereign first-run default is loopback, so its existing per-test SSRF
  // exception starts selected and visible. Changing probe type resets the
  // exception: a public target must not inherit privileged access silently.
  const [allowPrivateTargets, setAllowPrivateTargets] = useState(true)
  const [createdTest, setCreatedTest] = useState<Test | null>(null)

  const [inviteName, setInviteName] = useState('first-run-teammates')
  const [inviteToken, setInviteToken] = useState<CreatedScimToken | null>(null)

  const persistedProgress = onboardingProgress.data
  const command = agentToken
    ? agentEnrollCommand(agentToken, controlURL.trim() || defaultControlPlaneURL())
    : ''

  const progress = useMemo<ReadinessStep[]>(() => {
    const tokenCreated =
      agentToken !== null || Boolean(persistedProgress?.agent_enroll_token_created)
    return [
      {
        id: 'credential',
        label: t('onboarding.progress.credential'),
        done: tokenCreated,
        detail: tokenCreated
          ? t('onboarding.progress.credential.created')
          : t('onboarding.progress.credential.waiting'),
      },
      {
        id: 'connected',
        label: t('onboarding.progress.connected'),
        done: Boolean(persistedProgress?.agent_connected),
        detail: persistedProgress?.agent_connected
          ? t('onboarding.progress.connected.ready')
          : t('onboarding.progress.connected.waiting'),
      },
      {
        id: 'healthy',
        label: t('onboarding.progress.healthy'),
        done: Boolean(persistedProgress?.producer_healthy),
        detail: persistedProgress?.producer_healthy
          ? t('onboarding.progress.healthy.ready')
          : t('onboarding.progress.healthy.waiting'),
      },
      {
        id: 'result',
        label: t('onboarding.progress.result'),
        done: Boolean(persistedProgress?.first_result_received),
        detail: persistedProgress?.first_result_received
          ? t('onboarding.progress.result.ready')
          : t('onboarding.progress.result.waiting'),
      },
      {
        id: 'finding',
        label: t('onboarding.progress.finding'),
        done: Boolean(persistedProgress?.first_finding_visible),
        detail: persistedProgress?.first_finding_visible
          ? t('onboarding.progress.finding.ready')
          : t('onboarding.progress.finding.waiting'),
      },
    ]
  }, [
    agentToken,
    persistedProgress?.agent_enroll_token_created,
    persistedProgress?.agent_connected,
    persistedProgress?.first_finding_visible,
    persistedProgress?.first_result_received,
    persistedProgress?.producer_healthy,
    t,
  ])

  // The enrollment token is intentionally setup-only. Keep it visible in the
  // checklist, but use the server's operational milestone count so minting a
  // credential can never inflate readiness before a producer connects.
  const operationalProgress = progress.filter((item) => item.id !== 'credential')
  const progressTotal = persistedProgress?.readiness_steps_total ?? operationalProgress.length
  const progressComplete =
    persistedProgress?.readiness_steps_complete ??
    operationalProgress.filter((item) => item.done).length
  const activeProgressIndex = progress.findIndex((item) => !item.done)

  function submitAgent(e: FormEvent) {
    e.preventDefault()
    const ttl = Number(agentTTLMinutes)
    mintAgent.mutate(
      {
        ...(agentLabel.trim() ? { name: agentLabel.trim() } : {}),
        ...(Number.isFinite(ttl) && ttl > 0 ? { ttl_seconds: Math.round(ttl * 60) } : {}),
      },
      {
        onSuccess: (token) => {
          setAgentToken(token)
          void onboardingProgress.refetch()
        },
      },
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
        params: allowPrivateTargets ? { allow_private_targets: 'true' } : {},
        enabled: true,
      },
      {
        onSuccess: (test) => {
          setCreatedTest(test)
          void onboardingProgress.refetch()
        },
      },
    )
  }

  function submitInvite(e: FormEvent) {
    e.preventDefault()
    createInvite.mutate(
      { name: inviteName.trim() || 'first-run-teammates' },
      {
        onSuccess: (token) => {
          setInviteToken(token)
          void onboardingProgress.refetch()
        },
      },
    )
  }

  function choosePlane(plane: ProducerPlane) {
    const nextAction = persistedProgress?.producers.find(
      (item) => item.id === plane.id,
    )?.next_action
    if (nextAction === '/onboarding') return
    if (nextAction && nextAction !== '/onboarding#first-run-agent') {
      void navigate(nextAction)
      return
    }
    if (plane.id === 'synthetic' || nextAction === '/onboarding#first-run-agent') {
      const target = document.getElementById('first-run-agent')
      target?.scrollIntoView({ block: 'start', behavior: 'smooth' })
      target?.querySelector<HTMLButtonElement | HTMLInputElement>('input, button')?.focus()
      return
    }
    void navigate(`/admin?register_collector=${plane.id}`)
  }

  return (
    <Page
      title={t('onboarding.page.title')}
      subtitle={t('onboarding.page.subtitle')}
      actions={
        <Button variant="secondary" onClick={() => void navigate('/admin')}>
          <Icon name="admin" /> {t('onboarding.action.admin')}
        </Button>
      }
    >
      <section className={styles.progress} aria-label={t('onboarding.progress.aria')}>
        <div className={styles.progressHeader}>
          <h2>{t('onboarding.progress.title')}</h2>
          {/* The API excludes setup artifacts from operational readiness. */}
          <Badge tone={progressComplete === progressTotal ? 'success' : 'info'}>
            {t('onboarding.progress.count', {
              complete: progressComplete,
              total: progressTotal,
            })}
          </Badge>
        </div>
        <ul className={styles.progressList} role="list">
          {progress.map((item, index) => (
            <ProgressItem
              key={item.id}
              {...item}
              active={index === activeProgressIndex}
              readyLabel={t('onboarding.progress.ready', { label: item.label })}
            />
          ))}
        </ul>
      </section>

      {onboardingProgress.isError ? (
        <ErrorState
          title="Onboarding progress unavailable"
          description="Could not load tenant producer readiness. Setup actions remain available below."
        />
      ) : null}

      {persistedProgress?.first_finding ? (
        <Card className={styles.findingReceipt}>
          <CardHeader
            title={t('onboarding.finding.title')}
            description={t('onboarding.finding.description')}
            actions={
              <Badge tone={persistedProgress.first_finding.success ? 'success' : 'danger'}>
                {persistedProgress.first_finding.success
                  ? t('onboarding.finding.healthy')
                  : t('onboarding.finding.failed')}
              </Badge>
            }
          />
          <CardBody className={styles.findingBody}>
            <strong>{persistedProgress.first_finding.title}</strong>
            <code>{persistedProgress.first_finding.target}</code>
            <time dateTime={persistedProgress.first_finding.observed_at}>
              {time.format(persistedProgress.first_finding.observed_at).text}
            </time>
            <Button
              variant="primary"
              onClick={() => void navigate(persistedProgress.first_finding!.href)}
            >
              <Icon name="targets" /> {t('onboarding.finding.open')}
            </Button>
          </CardBody>
        </Card>
      ) : null}

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
                  <Badge
                    tone={readinessTone(
                      persistedProgress?.producers.find((item) => item.id === plane.id)?.state ??
                        'blocked',
                    )}
                  >
                    {persistedProgress?.producers.find((item) => item.id === plane.id)?.state ??
                      'blocked'}
                  </Badge>
                }
              />
              <CardBody className={styles.planeBody}>
                {persistedProgress?.producers.find((item) => item.id === plane.id) ? (
                  <StatusDot
                    tone={readinessTone(
                      persistedProgress.producers.find((item) => item.id === plane.id)!.state,
                    )}
                    label={persistedProgress.producers.find((item) => item.id === plane.id)!.detail}
                  />
                ) : null}
                <dl className={styles.planeFacts}>
                  <dt>{t('onboarding.field.prerequisites')}</dt>
                  <dd>{t(plane.prerequisitesKey)}</dd>
                  <dt>{t('onboarding.field.firstSignal')}</dt>
                  <dd>{t(plane.firstSignalKey)}</dd>
                </dl>
                <Button
                  variant={plane.id === 'synthetic' ? 'primary' : 'secondary'}
                  onClick={() => choosePlane(plane)}
                  disabled={
                    persistedProgress?.producers.find((item) => item.id === plane.id)
                      ?.next_action === '/onboarding'
                  }
                >
                  <Icon name={plane.id === 'synthetic' ? 'targets' : 'admin'} />{' '}
                  {persistedProgress?.producers.find((item) => item.id === plane.id)?.state ===
                  'ready'
                    ? t('onboarding.producer.open')
                    : t(plane.actionKey)}
                </Button>
              </CardBody>
            </Card>
          ))}
        </div>
      </section>

      <section className={styles.engineReadiness} aria-labelledby="engine-readiness-title">
        <div className={styles.sectionIntro}>
          <h2 id="engine-readiness-title">{t('onboarding.engines.title')}</h2>
          <p>{t('onboarding.engines.description')}</p>
        </div>
        <ul className={styles.engineList} role="list">
          {(persistedProgress?.engines ?? []).map((engine) => (
            <li key={engine.id} className={styles.engineItem}>
              <div>
                <strong>{engine.id}</strong>
                <span>{engine.detail}</span>
              </div>
              <Badge tone={readinessTone(engine.state)}>{engine.state}</Badge>
              <Button variant="secondary" onClick={() => void navigate(engine.next_action)}>
                {t('onboarding.engines.nextAction')}
              </Button>
            </li>
          ))}
        </ul>
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
                  setAllowPrivateTargets(false)
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
                hint={t('onboarding.test.intervalHint')}
              />
              <label className={styles.checkboxLabel}>
                <input
                  type="checkbox"
                  checked={allowPrivateTargets}
                  onChange={(e) => setAllowPrivateTargets(e.target.checked)}
                />
                <span>{t('onboarding.test.allowPrivate')}</span>
              </label>
              <p className={styles.fieldHint}>{t('onboarding.test.allowPrivateHint')}</p>
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
                <p className={styles.configIntro}>{t('onboarding.test.configHint')}</p>
                <pre className={styles.configSnippet}>
                  <code>{agentCanaryYAML(createdTest)}</code>
                </pre>
                <Button
                  variant="secondary"
                  onClick={() => void navigator.clipboard?.writeText(agentCanaryYAML(createdTest))}
                >
                  <Icon name="check" /> {t('onboarding.test.copyConfig')}
                </Button>
                <code>probectl-agent -config /etc/probectl/agent.yml</code>
                <Button variant="secondary" onClick={() => void navigate('/targets')}>
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
