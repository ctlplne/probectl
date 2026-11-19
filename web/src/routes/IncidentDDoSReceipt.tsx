// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { getAlertDDoSReceipt } from '../api/alerts'
import type { Signal } from '../api/incidents'
import { useAuth } from '../auth/useAuth'
import { Button, Card, CardBody, CardHeader, ErrorState, LoadingState } from '../components'
import { DDoSAssessmentEvidence } from './FlowDDoSAssessmentCard'

const digest = /^[a-f0-9]{64}$/

export function IncidentDDoSReceipt({
  signal,
  incidentID,
}: {
  signal?: Signal
  incidentID: string
}) {
  if (signal?.kind !== 'alert.ddos_assessment' || signal.plane !== 'flow') return null
  const rule = signal.attributes?.rule_id
  const fingerprint = signal.attributes?.['probectl.alert.ddos.receipt_fingerprint']
  const episode = signal.attributes?.['probectl.alert.ddos.episode_id']
  if (!rule || !fingerprint || !episode || !digest.test(episode) || !digest.test(fingerprint))
    return null
  return (
    <DDoSReceipt
      key={episode}
      rule={rule}
      fingerprint={fingerprint}
      episode={episode}
      incidentID={incidentID}
    />
  )
}

function DDoSReceipt({
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
    queryKey: ['alert-ddos-receipt', tenant.id, user.id, permissions.join(','), rule, fingerprint],
    queryFn: ({ signal }) => getAlertDDoSReceipt(tenant.id, rule, fingerprint, signal),
    enabled: canRead && open,
    gcTime: 0,
  })
  if (!canRead) return null
  const result = receipt.isSuccess && !receipt.isFetching ? receipt.data : undefined
  const matched = result?.incident_id === incidentID && result.episode_id === episode
  return (
    <Card>
      <CardHeader title="Traffic pressure receipt" />
      <CardBody>
        {!open && <Button onClick={() => setOpen(true)}>Show original traffic evidence</Button>}
        {open && receipt.isFetching && <LoadingState label="Loading original traffic evidence" />}
        {open && receipt.isError && (
          <ErrorState title="Traffic evidence unavailable" description={receipt.error.message} />
        )}
        {open && result && matched && (
          <>
            <h3>First qualifying window</h3>
            <DDoSAssessmentEvidence result={result.previous} />
            <h3>Second qualifying window</h3>
            <DDoSAssessmentEvidence result={result.current} />
          </>
        )}
        {open && result && !matched && (
          <ErrorState title="Traffic evidence does not match this incident" />
        )}
      </CardBody>
    </Card>
  )
}
