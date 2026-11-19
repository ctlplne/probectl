// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { getAlertFieldReceipt } from '../api/alerts'
import type { Signal } from '../api/incidents'
import { useAuth } from '../auth/useAuth'
import { Button, Card, CardBody, CardHeader, ErrorState, LoadingState } from '../components'
import { FieldComparisonResults } from './FlowFieldComparisonCard'

const digest = /^[a-f0-9]{64}$/

export function IncidentFieldReceipt({
  signal,
  incidentID,
}: {
  signal?: Signal
  incidentID: string
}) {
  if (signal?.kind !== 'alert.field_change' || signal.plane !== 'flow') return null
  const rule = signal.attributes?.rule_id
  const fingerprint = signal.attributes?.['probectl.alert.field.receipt_fingerprint']
  const episode = signal.attributes?.['probectl.alert.field.episode_id']
  if (!rule || !fingerprint || !episode || !digest.test(fingerprint) || !digest.test(episode))
    return null
  return (
    <FieldReceipt
      key={episode}
      rule={rule}
      fingerprint={fingerprint}
      episode={episode}
      incidentID={incidentID}
    />
  )
}

function FieldReceipt({
  rule,
  fingerprint,
  episode,
  incidentID,
}: {
  rule: string
  fingerprint: string
  episode: string
  incidentID: string
}) {
  const [open, setOpen] = useState(false)
  const { tenant, user, permissions } = useAuth()
  const canRead = ['alert.read', 'ai.query', 'flow.read'].every((permission) =>
    permissions.includes(permission),
  )
  const receipt = useQuery({
    queryKey: ['alert-field-receipt', tenant.id, user.id, permissions.join(','), rule, fingerprint],
    queryFn: ({ signal }) => getAlertFieldReceipt(tenant.id, rule, fingerprint, signal),
    enabled: canRead && open,
    gcTime: 0,
  })
  if (!canRead) return null
  const result = receipt.isSuccess && !receipt.isFetching ? receipt.data : undefined
  const link = result?.signals.find(
    (link) => link.episode_id === episode && link.incident_id === incidentID,
  )
  const change = result?.comparison.changes.find((change) => change.key === link?.change_key)
  return (
    <Card>
      <CardHeader title="Field comparison receipt" />
      <CardBody>
        {!open && <Button onClick={() => setOpen(true)}>Show exact field evidence</Button>}
        {open && receipt.isFetching && <LoadingState label="Loading original field evidence" />}
        {open && receipt.isError && (
          <ErrorState title="Field evidence unavailable" description={receipt.error.message} />
        )}
        {open && result && change && (
          <FieldComparisonResults result={{ ...result.comparison, changes: [change] }} />
        )}
        {open && result && !change && (
          <ErrorState title="Field evidence does not match this incident" />
        )}
      </CardBody>
    </Card>
  )
}
