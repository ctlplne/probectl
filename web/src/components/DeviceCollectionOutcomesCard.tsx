// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
import { Table, type Column } from './Table'

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
  const columns: Column<DeviceCollectionOutcome>[] = [
    {
      key: 'target',
      header: t('device.outcomes.column.target'),
      render: (row) => (
        <span>
          <strong>{row.configured_target}</strong>
          <div>
            <code>{row.agent_id}</code>
          </div>
        </span>
      ),
    },
    {
      key: 'protocol',
      header: t('device.outcomes.column.protocol'),
      render: (row) => <Badge tone="info">{row.protocol.toUpperCase()}</Badge>,
    },
    {
      key: 'outcome',
      header: t('device.outcomes.column.outcome'),
      render: (row) => (
        <span>
          <StatusDot tone={stateTone(row.state)} label={t(stateLabels[row.state])} />
          <div>{t(reasonLabels[row.reason])}</div>
        </span>
      ),
    },
    {
      key: 'rows',
      header: t('device.outcomes.column.rows'),
      numeric: true,
      render: (row) => String(row.row_count),
    },
    {
      key: 'attempt',
      header: t('device.outcomes.column.lastAttempt'),
      render: (row) =>
        row.last_attempt_at ? (
          <DateTime value={row.last_attempt_at} />
        ) : (
          t('device.outcomes.value.never')
        ),
    },
    {
      key: 'success',
      header: t('device.outcomes.column.lastSuccess'),
      render: (row) =>
        row.last_success_at ? (
          <DateTime value={row.last_success_at} />
        ) : (
          t('device.outcomes.value.never')
        ),
    },
    {
      key: 'action',
      header: t('device.outcomes.column.nextAction'),
      render: (row) => t(actionLabels[row.next_action]),
    },
  ]

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
        ) : (
          <Table
            caption={t('device.outcomes.caption')}
            columns={columns}
            rows={rows}
            rowKey={(row) => `${row.agent_id}:${row.configured_target}:${row.protocol}`}
            empty={
              <EmptyState
                icon="admin"
                title={t('device.outcomes.empty.title')}
                description={t('device.outcomes.empty.description')}
              />
            }
          />
        )}
      </CardBody>
    </Card>
  )
}
