// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import {
  useDeviceCollectionOutcomes,
  type DeviceCollectionOutcome,
  type DeviceCollectionOutcomeState,
} from '../api/planes'
import { useI18n } from '../i18n/useI18n'
import type { MessageKey } from '../i18n/messages'
import { DateTime } from '../time/DateTime'
import { Badge, StatusDot, type BadgeTone } from './Badge'
import { Card, CardBody, CardHeader } from './Card'
import { EmptyState, ErrorState, LoadingState } from './States'
import styles from './DeviceCollectionOutcomesCard.module.css'

const stateLabels: Record<DeviceCollectionOutcomeState, MessageKey> = {
  ok_with_rows: 'device.outcomes.state.okWithRows',
  healthy_empty: 'device.outcomes.state.healthyEmpty',
  unsupported: 'device.outcomes.state.unsupported',
  failed: 'device.outcomes.state.failed',
  never_observed: 'device.outcomes.state.neverObserved',
}

const reasonLabels: Record<DeviceCollectionOutcome['reason'], MessageKey> = {
  rows_observed: 'device.outcomes.reason.rowsObserved',
  no_rows_observed: 'device.outcomes.reason.noRowsObserved',
  mib_unsupported: 'device.outcomes.reason.mibUnsupported',
  poll_failed: 'device.outcomes.reason.pollFailed',
  credential_unavailable: 'device.outcomes.reason.credentialUnavailable',
  transport_unreachable: 'device.outcomes.reason.transportUnreachable',
  base_poll_failed: 'device.outcomes.reason.basePollFailed',
  never_attempted: 'device.outcomes.reason.neverAttempted',
}

const actionLabels: Record<DeviceCollectionOutcome['next_action'], MessageKey> = {
  review_neighbor_evidence: 'device.outcomes.action.reviewEvidence',
  review_target_neighbor_configuration: 'device.outcomes.action.reviewConfiguration',
  enable_protocol_on_configured_target: 'device.outcomes.action.enableProtocol',
  verify_configured_target_access: 'device.outcomes.action.verifyAccess',
  wait_for_first_collection: 'device.outcomes.action.wait',
}

function stateTone(state: DeviceCollectionOutcomeState): BadgeTone {
  if (state === 'ok_with_rows') return 'success'
  if (state === 'healthy_empty') return 'info'
  if (state === 'unsupported') return 'warning'
  if (state === 'failed') return 'danger'
  return 'neutral'
}

export function DeviceCollectionOutcomesCard() {
  const { t } = useI18n()
  const outcomes = useDeviceCollectionOutcomes(100)
  const rows = outcomes.data?.items ?? []

  return (
    <Card>
      <CardHeader
        title={t('device.outcomes.title')}
        description={t('device.outcomes.description')}
        actions={
          outcomes.data?.truncated ? (
            <Badge tone="warning">{t('device.outcomes.truncated')}</Badge>
          ) : null
        }
      />
      <CardBody>
        {outcomes.isPending ? (
          <LoadingState label={t('device.outcomes.loading')} />
        ) : outcomes.isError ? (
          <ErrorState description={t('device.outcomes.error')} />
        ) : outcomes.data?.collection_running === false ? (
          <EmptyState
            icon="admin"
            title={t('device.outcomes.unavailable.title')}
            description={t('device.outcomes.unavailable.description')}
          />
        ) : rows.length === 0 ? (
          <EmptyState
            icon="admin"
            title={t('device.outcomes.empty.title')}
            description={t('device.outcomes.empty.description')}
          />
        ) : (
          <ul className={styles.receiptList} aria-label={t('device.outcomes.caption')}>
            {rows.map((row) => (
              <li
                className={styles.receipt}
                key={`${row.agent_id}:${row.configured_target}:${row.protocol}`}
              >
                <div className={styles.receiptHeader}>
                  <div className={styles.identity}>
                    <span className={styles.label}>{t('device.outcomes.column.target')}</span>
                    <strong className={styles.target}>{row.configured_target}</strong>
                    <code className={styles.agent}>{row.agent_id}</code>
                  </div>
                  <div className={styles.protocol}>
                    <span className={styles.label}>{t('device.outcomes.column.protocol')}</span>
                    <Badge tone="info">{row.protocol.toUpperCase()}</Badge>
                  </div>
                </div>
                <dl className={styles.facts}>
                  <div className={`${styles.fact} ${styles.outcome}`}>
                    <dt>{t('device.outcomes.column.outcome')}</dt>
                    <dd className={styles.outcomeValue}>
                      <StatusDot tone={stateTone(row.state)} label={t(stateLabels[row.state])} />
                      <span className={styles.reason}>{t(reasonLabels[row.reason])}</span>
                    </dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('device.outcomes.column.rows')}</dt>
                    <dd className={styles.numeric}>{row.row_count}</dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('device.outcomes.column.lastAttempt')}</dt>
                    <dd>
                      {row.last_attempt_at ? (
                        <DateTime value={row.last_attempt_at} />
                      ) : (
                        t('device.outcomes.value.never')
                      )}
                    </dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('device.outcomes.column.lastSuccess')}</dt>
                    <dd>
                      {row.last_success_at ? (
                        <DateTime value={row.last_success_at} />
                      ) : (
                        t('device.outcomes.value.never')
                      )}
                    </dd>
                  </div>
                  <div className={`${styles.fact} ${styles.nextAction}`}>
                    <dt>{t('device.outcomes.column.nextAction')}</dt>
                    <dd>{t(actionLabels[row.next_action])}</dd>
                  </div>
                </dl>
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  )
}
