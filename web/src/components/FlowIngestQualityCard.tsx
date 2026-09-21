// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import {
  useFlowIngestQuality,
  type FlowIngestQualityReceipt,
  type FlowIngestQualityState,
} from '../api/planes'
import { useI18n } from '../i18n/useI18n'
import type { MessageKey } from '../i18n/messages'
import { formatInteger } from '../i18n/number'
import { DateTime } from '../time/DateTime'
import { Badge, StatusDot, type BadgeTone } from './Badge'
import { Card, CardBody, CardHeader } from './Card'
import { EmptyState, ErrorState, LoadingState } from './States'
import styles from './FlowIngestQualityCard.module.css'

const stateLabels: Record<FlowIngestQualityState, MessageKey> = {
  healthy: 'flow.quality.state.healthy',
  degraded: 'flow.quality.state.degraded',
  stale: 'flow.quality.state.stale',
}

const reasonLabels: Record<FlowIngestQualityReceipt['reason'], MessageKey> = {
  receiving_valid_records: 'flow.quality.reason.receiving',
  waiting_for_templates: 'flow.quality.reason.waitingTemplates',
  template_missing: 'flow.quality.reason.templateMissing',
  decode_errors: 'flow.quality.reason.decodeErrors',
  queue_loss: 'flow.quality.reason.queueLoss',
  emit_loss: 'flow.quality.reason.emitLoss',
  no_valid_records: 'flow.quality.reason.noValidRecords',
  no_recent_packets: 'flow.quality.reason.noRecentPackets',
}

const actionLabels: Record<FlowIngestQualityReceipt['next_action'], MessageKey> = {
  continue_monitoring: 'flow.quality.action.monitor',
  verify_exporter_templates: 'flow.quality.action.templates',
  verify_exporter_protocol: 'flow.quality.action.protocol',
  reduce_local_ingest_pressure: 'flow.quality.action.pressure',
  verify_local_bus_delivery: 'flow.quality.action.bus',
  verify_exporter_delivery: 'flow.quality.action.delivery',
}

function stateTone(state: FlowIngestQualityState): BadgeTone {
  if (state === 'healthy') return 'success'
  if (state === 'degraded') return 'warning'
  return 'danger'
}

export function FlowIngestQualityCard() {
  const { locale, t } = useI18n()
  const quality = useFlowIngestQuality(100)
  const rows = quality.data?.items ?? []

  return (
    <Card>
      <CardHeader
        title={t('flow.quality.title')}
        description={t('flow.quality.description')}
        actions={
          quality.data?.truncated ? (
            <Badge tone="warning">{t('flow.quality.truncated')}</Badge>
          ) : null
        }
      />
      <CardBody>
        {quality.isPending ? (
          <LoadingState label={t('flow.quality.loading')} />
        ) : quality.isError ? (
          <ErrorState description={t('flow.quality.error')} />
        ) : quality.data?.ingest_running === false ? (
          <EmptyState
            icon="path"
            title={t('flow.quality.unavailable.title')}
            description={t('flow.quality.unavailable.description')}
          />
        ) : rows.length === 0 ? (
          <EmptyState
            icon="path"
            title={t('flow.quality.empty.title')}
            description={t('flow.quality.empty.description')}
          />
        ) : (
          <ul className={styles.receiptList} aria-label={t('flow.quality.caption')}>
            {rows.map((row) => (
              <li
                className={styles.receipt}
                key={`${row.agent_id}:${row.exporter_address}:${row.protocol}`}
              >
                <div className={styles.receiptHeader}>
                  <div className={styles.identity}>
                    <span className={styles.label}>{t('flow.quality.column.exporter')}</span>
                    <strong className={styles.exporter}>{row.exporter_address}</strong>
                    <code className={styles.agent}>{row.agent_id}</code>
                  </div>
                  <div className={styles.protocol}>
                    <span className={styles.label}>{t('flow.quality.column.protocol')}</span>
                    <Badge tone="info">{row.protocol.toUpperCase()}</Badge>
                  </div>
                </div>
                <dl className={styles.facts}>
                  <div className={`${styles.fact} ${styles.outcome}`}>
                    <dt>{t('flow.quality.column.outcome')}</dt>
                    <dd className={styles.outcomeValue}>
                      <StatusDot tone={stateTone(row.state)} label={t(stateLabels[row.state])} />
                      <span className={styles.reason}>{t(reasonLabels[row.reason])}</span>
                    </dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('flow.quality.column.packets')}</dt>
                    <dd className={styles.numeric}>
                      {formatInteger(row.packets_received, locale)}
                    </dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('flow.quality.column.records')}</dt>
                    <dd className={styles.numeric}>{formatInteger(row.records_decoded, locale)}</dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('flow.quality.column.decodeErrors')}</dt>
                    <dd className={styles.numeric}>
                      {formatInteger(row.decode_error_packets, locale)}
                    </dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('flow.quality.column.templateMisses')}</dt>
                    <dd className={styles.numeric}>{formatInteger(row.template_misses, locale)}</dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('flow.quality.column.queueDrops')}</dt>
                    <dd className={styles.numeric}>
                      {formatInteger(row.queue_dropped_records, locale)}
                    </dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('flow.quality.column.emitDrops')}</dt>
                    <dd className={styles.numeric}>
                      {formatInteger(row.emit_dropped_records, locale)}
                    </dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('flow.quality.column.template')}</dt>
                    <dd>{row.template_state.replace('_', ' ')}</dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('flow.quality.column.sampling')}</dt>
                    <dd>{row.sampling_state}</dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('flow.quality.column.lastPacket')}</dt>
                    <dd>
                      <DateTime value={row.last_packet_at} />
                    </dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('flow.quality.column.lastValid')}</dt>
                    <dd>
                      {row.last_valid_record_at ? (
                        <DateTime value={row.last_valid_record_at} />
                      ) : (
                        t('flow.quality.value.never')
                      )}
                    </dd>
                  </div>
                  <div className={styles.fact}>
                    <dt>{t('flow.quality.column.window')}</dt>
                    <dd>
                      <DateTime value={row.window_started_at} /> –{' '}
                      <DateTime value={row.window_ended_at} />
                    </dd>
                  </div>
                  <div
                    className={`${styles.fact} ${styles.nextAction}`}
                    data-action-tone={row.state}
                  >
                    <dt>{t('flow.quality.column.nextAction')}</dt>
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
