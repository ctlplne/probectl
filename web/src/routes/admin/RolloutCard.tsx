// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useMemo, useState, type FormEvent } from 'react'
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
  Modal,
  StatusDot,
  Table,
} from '../../components'
import {
  useRolloutAction,
  useRollouts,
  type Rollout,
  type RolloutAction,
  type RolloutWave,
  type RolloutWaveStatus,
} from '../../api/rollouts'
import { useI18n } from '../../i18n/useI18n'
import type { MessageKey } from '../../i18n/messages'
import styles from '../pages.module.css'

type TFn = (key: MessageKey, vars?: Record<string, string | number>) => string
const EMPTY_ROLLOUTS: Rollout[] = []

function rolloutState(rollout: Rollout, t: TFn) {
  if (rollout.halted) return <StatusDot tone="danger" label={t('admin.rollout.state.halted')} />
  if (rollout.done) return <StatusDot tone="success" label={t('admin.rollout.state.complete')} />
  return <StatusDot tone="warning" label={t('admin.rollout.state.active')} />
}

function waveTone(status: RolloutWaveStatus) {
  if (status === 'complete') return 'success' as const
  if (status === 'applying') return 'warning' as const
  if (status === 'halted') return 'danger' as const
  return 'neutral' as const
}

function waveStatusLabel(status: RolloutWaveStatus, t: TFn) {
  const labels: Record<RolloutWaveStatus, MessageKey> = {
    pending: 'admin.rollout.wave.pending',
    applying: 'admin.rollout.wave.applying',
    complete: 'admin.rollout.wave.complete',
    halted: 'admin.rollout.wave.halted',
  }
  return t(labels[status])
}

function actionLabel(action: RolloutAction, t: TFn) {
  const labels: Record<RolloutAction, MessageKey> = {
    advance: 'admin.rollout.action.advance',
    verify: 'admin.rollout.action.verify',
    halt: 'admin.rollout.action.halt',
    resume: 'admin.rollout.action.resume',
  }
  return t(labels[action])
}

function currentWave(rollout: Rollout): RolloutWave | undefined {
  return rollout.waves.find((wave) => wave.status !== 'complete')
}

function RolloutActionDialog({
  rollout,
  action,
  onClose,
  onReceipt,
}: {
  rollout: Rollout
  action: RolloutAction | null
  onClose: () => void
  onReceipt: (receipt: string) => void
}) {
  const { t } = useI18n()
  const mutate = useRolloutAction()
  const [reason, setReason] = useState('')
  const wave = currentWave(rollout)
  const needsReason = action === 'halt' || action === 'resume'

  useEffect(() => {
    setReason('')
    mutate.reset()
    // `mutate` is deliberately omitted: its object identity changes as the
    // mutation state changes, which would erase a reason while the user types.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [action, rollout.id])

  if (!action) return null
  const confirmedAction = action

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (needsReason && !reason.trim()) return
    try {
      const updated = await mutate.mutateAsync({ id: rollout.id, action: confirmedAction, reason })
      onReceipt(
        t('admin.rollout.receipt.success', {
          action: actionLabel(confirmedAction, t),
          progress: updated.progress,
        }),
      )
      onClose()
    } catch {
      // TanStack exposes the typed error below without duplicating state.
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={t('admin.rollout.dialog.title', { action: actionLabel(action, t) })}
    >
      <form
        className={styles.form}
        onSubmit={(event) => {
          void submit(event)
        }}
      >
        <p className={styles.fleetSafety}>{t('admin.rollout.dialog.guardrail')}</p>
        <dl className={styles.fleetEvidence}>
          <div>
            <dt>{t('admin.rollout.detail.id')}</dt>
            <dd>
              <code>{rollout.id}</code>
            </dd>
          </div>
          <div>
            <dt>{t('admin.rollout.detail.target')}</dt>
            <dd>
              <code>{rollout.target}</code>
            </dd>
          </div>
          <div>
            <dt>{t('admin.rollout.dialog.currentWave')}</dt>
            <dd>
              {wave
                ? t('admin.rollout.wave.summary', {
                    cohort: wave.cohort,
                    agents: wave.agents,
                    status: waveStatusLabel(wave.status, t),
                  })
                : t('admin.rollout.wave.none')}
            </dd>
          </div>
        </dl>
        {needsReason ? (
          <Field
            label={t('admin.rollout.dialog.reason')}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            hint={t('admin.rollout.dialog.reasonHint')}
            required
          />
        ) : null}
        {mutate.isError ? (
          <p role="alert" className={styles.fleetNotice}>
            {mutate.error.message}
          </p>
        ) : null}
        <span className={styles.actions}>
          <Button
            type="submit"
            variant={action === 'halt' ? 'danger' : 'primary'}
            disabled={mutate.isPending || (needsReason && !reason.trim())}
          >
            {mutate.isPending
              ? t('admin.rollout.dialog.pending')
              : t('admin.rollout.dialog.confirm', { action: actionLabel(action, t) })}
          </Button>
          <Button variant="ghost" onClick={onClose} disabled={mutate.isPending}>
            {t('admin.cancel')}
          </Button>
        </span>
      </form>
    </Modal>
  )
}

/**
 * Human-gated rollout console. The controls mutate only the audited rollout
 * state machine. Actual digest deployment remains outside probectl, and the
 * health gate verifies live tenant-scoped registry evidence before completion.
 */
export function RolloutCard({ available }: { available: boolean | undefined }) {
  const { t } = useI18n()
  const { data, isPending, isError } = useRollouts(available === true)
  const [selectedID, setSelectedID] = useState('')
  const [dialogAction, setDialogAction] = useState<RolloutAction | null>(null)
  const [receipt, setReceipt] = useState<{ rolloutID: string; text: string } | null>(null)
  const rollouts = data?.items ?? EMPTY_ROLLOUTS

  const selected = useMemo(
    () => rollouts.find((rollout) => rollout.id === selectedID) ?? rollouts[0],
    [rollouts, selectedID],
  )

  if (available !== true) return null

  const columns: Column<Rollout>[] = [
    {
      key: 'target',
      header: t('admin.rollout.column.target'),
      render: (rollout) => (
        <span className={styles.fleetCell}>
          <strong>{rollout.target}</strong>
          <code>{rollout.id}</code>
        </span>
      ),
    },
    {
      key: 'waves',
      header: t('admin.rollout.column.waves'),
      render: (rollout) => (
        <span className={styles.fleetBadges}>
          {rollout.waves.map((wave) => (
            <Badge key={wave.cohort} tone={waveTone(wave.status)}>
              {wave.cohort} {wave.agents} · {waveStatusLabel(wave.status, t)}
            </Badge>
          ))}
        </span>
      ),
    },
    {
      key: 'state',
      header: t('admin.rollout.column.state'),
      render: (rollout) => rolloutState(rollout, t),
    },
    {
      key: 'action',
      header: t('admin.rollout.column.action'),
      render: (rollout) => (
        <Button size="sm" variant="secondary" onClick={() => setSelectedID(rollout.id)}>
          {t('admin.rollout.action.review')}
        </Button>
      ),
    },
  ]

  const wave = selected ? currentWave(selected) : undefined
  const canAdvance = Boolean(
    selected && !selected.halted && !selected.done && wave?.status === 'pending',
  )
  const canVerify = Boolean(
    selected && !selected.halted && !selected.done && wave?.status === 'applying',
  )

  return (
    <Card>
      <CardHeader title={t('admin.rollout.title')} description={t('admin.rollout.description')} />
      <CardBody>
        {isPending ? (
          <LoadingState label={t('admin.rollout.loading')} />
        ) : isError ? (
          <ErrorState description={t('admin.rollout.error')} />
        ) : rollouts.length === 0 ? (
          <EmptyState
            icon="admin"
            title={t('admin.rollout.empty.title')}
            description={t('admin.rollout.empty.description')}
          />
        ) : (
          <div className={styles.form}>
            <Table
              caption={t('admin.rollout.table.caption')}
              columns={columns}
              rows={rollouts}
              rowKey={(rollout) => rollout.id}
            />
            {selected ? (
              <section className={styles.rolloutDetail} aria-labelledby="selected-rollout-title">
                <div className={styles.rolloutHeader}>
                  <div>
                    <h3 id="selected-rollout-title">
                      {t('admin.rollout.detail.title', { target: selected.target })}
                    </h3>
                    <p>{selected.progress}</p>
                  </div>
                  {rolloutState(selected, t)}
                </div>
                <ol className={styles.rolloutWaves} aria-label={t('admin.rollout.wave.aria')}>
                  {selected.waves.map((item) => (
                    <li key={item.cohort} data-state={item.status}>
                      <span>{item.cohort}</span>
                      <strong>{item.agents}</strong>
                      <StatusDot
                        tone={waveTone(item.status)}
                        label={waveStatusLabel(item.status, t)}
                      />
                    </li>
                  ))}
                </ol>
                <dl className={styles.fleetEvidence}>
                  <div>
                    <dt>{t('admin.rollout.detail.digest')}</dt>
                    <dd className={styles.rolloutDigest}>
                      <code>{selected.digest}</code>
                    </dd>
                  </div>
                  <div>
                    <dt>{t('admin.rollout.gate.title')}</dt>
                    <dd>{t('admin.rollout.gate.description', { target: selected.target })}</dd>
                  </div>
                  {selected.halt_reason ? (
                    <div>
                      <dt>{t('admin.rollout.detail.haltReason')}</dt>
                      <dd>{selected.halt_reason}</dd>
                    </div>
                  ) : null}
                  {selected.stragglers && selected.stragglers.length > 0 ? (
                    <div>
                      <dt>{t('admin.rollout.detail.stragglers')}</dt>
                      <dd>
                        <ul
                          className={styles.rolloutAgentList}
                          aria-label={t('admin.rollout.detail.stragglers')}
                        >
                          {selected.stragglers.map((item) => (
                            <li key={item}>
                              <code>{item}</code>
                            </li>
                          ))}
                        </ul>
                      </dd>
                    </div>
                  ) : null}
                  {selected.skipped_offline && selected.skipped_offline.length > 0 ? (
                    <div>
                      <dt>{t('admin.rollout.detail.skippedOffline')}</dt>
                      <dd>
                        <ul
                          className={styles.rolloutAgentList}
                          aria-label={t('admin.rollout.detail.skippedOffline')}
                        >
                          {selected.skipped_offline.map((item) => (
                            <li key={item}>
                              <code>{item}</code>
                            </li>
                          ))}
                        </ul>
                      </dd>
                    </div>
                  ) : null}
                  <div>
                    <dt>{t('admin.rollout.detail.receipt')}</dt>
                    <dd>
                      <span role="status">
                        {receipt?.rolloutID === selected.id
                          ? receipt.text
                          : t('admin.rollout.gate.noReceipt')}
                      </span>
                    </dd>
                  </div>
                </dl>
                <p className={styles.fleetSafety}>{t('admin.rollout.safety')}</p>
                <div className={styles.actions}>
                  <Button
                    variant="primary"
                    disabled={!canAdvance}
                    onClick={() => setDialogAction('advance')}
                  >
                    {t('admin.rollout.action.advance')}
                  </Button>
                  <Button
                    variant="secondary"
                    disabled={!canVerify}
                    onClick={() => setDialogAction('verify')}
                  >
                    {t('admin.rollout.action.verify')}
                  </Button>
                  {selected.halted ? (
                    <Button variant="primary" onClick={() => setDialogAction('resume')}>
                      {t('admin.rollout.action.resume')}
                    </Button>
                  ) : (
                    <Button
                      variant="danger"
                      disabled={selected.done}
                      onClick={() => setDialogAction('halt')}
                    >
                      {t('admin.rollout.action.halt')}
                    </Button>
                  )}
                </div>
                <RolloutActionDialog
                  rollout={selected}
                  action={dialogAction}
                  onClose={() => setDialogAction(null)}
                  onReceipt={(text) => setReceipt({ rolloutID: selected.id, text })}
                />
              </section>
            ) : null}
          </div>
        )}
      </CardBody>
    </Card>
  )
}
