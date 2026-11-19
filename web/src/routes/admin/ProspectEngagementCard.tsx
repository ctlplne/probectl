// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import { apiDownloadURL } from '../../api/client'
import { useDashboards, useReportSchedules } from '../../api/dashboardReporting'
import { useProspectEngagement, useProspectEngagementAction } from '../../api/lifecycle'
import type { ProspectEngagement } from '../../api/sdk.gen'
import { useAuth } from '../../auth/useAuth'
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  LoadingState,
  Select,
} from '../../components'
import { DateTime } from '../../time/DateTime'
import styles from './EntityRegistryCard.module.css'

export function ProspectEngagementCard() {
  const { tenant, user, permissions } = useAuth()
  if (!permissions.includes('lifecycle.erase')) return null
  const identity = `${tenant.id}:${user.id}`
  return (
    <Card data-prospect-engagement>
      <CardHeader title="Prospect engagement" />
      <CardBody>
        <ProspectEngagementContents
          key={identity}
          identity={identity}
          ownerID={user.id}
          tenantSlug={tenant.slug}
          mayScheduleErasure={permissions.includes('lifecycle.export')}
        />
      </CardBody>
    </Card>
  )
}

function ProspectEngagementContents({
  identity,
  ownerID,
  tenantSlug,
  mayScheduleErasure,
}: {
  identity: string
  ownerID: string
  tenantSlug: string
  mayScheduleErasure: boolean
}) {
  const engagement = useProspectEngagement(identity)
  if (engagement.isPending) return <LoadingState label="Loading prospect engagement…" />
  if (engagement.isError)
    return <ErrorState description="Could not load the prospect engagement." />
  if (engagement.data) return <CurrentProspect identity={identity} engagement={engagement.data} />
  return (
    <StartProspect
      identity={identity}
      ownerID={ownerID}
      tenantSlug={tenantSlug}
      mayScheduleErasure={mayScheduleErasure}
    />
  )
}

function StartProspect({
  identity,
  ownerID,
  tenantSlug,
  mayScheduleErasure,
}: {
  identity: string
  ownerID: string
  tenantSlug: string
  mayScheduleErasure: boolean
}) {
  const views = useDashboards(identity)
  const action = useProspectEngagementAction(identity)
  const [viewID, setViewID] = useState('')
  const [preparer, setPreparer] = useState('')
  const [end, setEnd] = useState('')
  const [consent, setConsent] = useState(false)
  const [destinationID, setDestinationID] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  const schedules = useReportSchedules(identity, consent && mayScheduleErasure)
  const eligibleViews = (views.data?.items ?? []).filter(
    (view) => view.owner_id === ownerID && view.definition.client_report,
  )
  const destinations = (schedules.data?.destinations ?? []).filter(
    (destination) => destination.outbound && destination.ready,
  )
  const ownsView = eligibleViews.find((view) => view.id === viewID)
  const destination = destinations.find((item) => item.id === destinationID)
  const approved = mayScheduleErasure && consent

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    const endsAt = end ? new Date(`${end}Z`) : null
    if (endsAt && (!Number.isFinite(endsAt.getTime()) || endsAt.getTime() <= Date.now())) {
      setError('Choose a future engagement end in UTC.')
      return
    }
    if (
      !ownsView ||
      !preparer.trim() ||
      (approved && (!endsAt || !destination || !tenantSlug || confirmation !== tenantSlug))
    )
      return
    try {
      await action.mutateAsync({
        action: 'start',
        input: {
          assessment_view_id: ownsView.id,
          assessment_view_revision: ownsView.updated_at,
          preparer: preparer.trim(),
          ends_at: endsAt?.toISOString(),
          ...(approved && destination
            ? { destination_id: destination.id, confirm_tenant: confirmation }
            : {}),
        },
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to start the prospect engagement.')
    }
  }

  if (views.isPending) return <LoadingState label="Loading saved client reports…" />
  if (views.isError) return <ErrorState description="Could not load the saved client reports." />
  if (eligibleViews.length === 0)
    return <p>Save a client report you own in Dashboards to start a prospect engagement.</p>
  return (
    <form className={styles.stack} onSubmit={(event) => void submit(event)}>
      <div className={styles.row}>
        <Select
          label="Assessment report"
          value={viewID}
          onChange={(event) => setViewID(event.target.value)}
          options={[
            { value: '', label: 'Choose an owned report' },
            ...eligibleViews.map((view) => ({ value: view.id, label: view.name })),
          ]}
        />
        <Field
          label="Assessment preparer"
          value={preparer}
          onChange={(event) => setPreparer(event.target.value)}
          required
        />
        <Field
          type="datetime-local"
          label="Engagement end in UTC"
          hint={
            approved
              ? 'Required for scheduled erasure.'
              : 'Leave blank for an engagement of 14 days.'
          }
          value={end}
          onChange={(event) => setEnd(event.target.value)}
          required={approved}
        />
      </div>
      {mayScheduleErasure ? (
        <label>
          <input
            type="checkbox"
            checked={consent}
            onChange={(event) => {
              setConsent(event.target.checked)
              setConfirmation('')
              setDestinationID('')
            }}
          />{' '}
          Authorize verifiable deletion after the completed assessment is delivered
        </label>
      ) : null}
      {approved ? (
        <div className={styles.row}>
          <Select
            label="Delivery destination"
            value={destinationID}
            onChange={(event) => setDestinationID(event.target.value)}
            options={[
              { value: '', label: 'Choose a configured destination' },
              ...destinations.map((item) => ({ value: item.id, label: item.name })),
            ]}
          />
          <Field
            label="Confirm tenant slug"
            hint={`Type ${tenantSlug} to authorize this tenant’s deletion.`}
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
            required
          />
          {schedules.isError ? <p role="alert">Could not load delivery destinations.</p> : null}
          {schedules.isSuccess && destinations.length === 0 ? (
            <p>No durable report destination is configured.</p>
          ) : null}
        </div>
      ) : null}
      {error ? <p role="alert">{error}</p> : null}
      <Button
        type="submit"
        variant="primary"
        disabled={
          action.isPending ||
          !ownsView ||
          !preparer.trim() ||
          (approved && (!end || !destination || !tenantSlug || confirmation !== tenantSlug))
        }
      >
        {action.isPending ? 'Starting engagement…' : 'Start prospect engagement'}
      </Button>
    </form>
  )
}

function CurrentProspect({
  identity,
  engagement,
}: {
  identity: string
  engagement: ProspectEngagement
}) {
  const action = useProspectEngagementAction(identity)
  const [error, setError] = useState('')
  const converted = Boolean(engagement.converted_at)
  const consent = Boolean(engagement.consented_at && !engagement.consent_revoked_at && !converted)
  const state = converted
    ? 'Converted to client'
    : engagement.assessment_artifact_id
      ? 'Assessment filed'
      : Date.parse(engagement.ends_at) > Date.now()
        ? 'Collecting evidence'
        : 'Preparing assessment'

  async function decide(decision: 'convert' | 'revoke-consent') {
    setError('')
    try {
      await action.mutateAsync({ action: decision, revision: engagement.revision })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update the prospect engagement.')
    }
  }

  return (
    <div className={styles.stack}>
      <p role="status">{state}</p>
      <p>
        Engagement end <DateTime value={engagement.ends_at} />
      </p>
      <p>Assessment preparer {engagement.preparer}</p>
      <p>
        {consent
          ? 'Scheduled erasure consent recorded'
          : engagement.consent_revoked_at
            ? 'Scheduled erasure consent withdrawn'
            : 'Scheduled erasure is off'}
      </p>
      {engagement.assessment_delivery_state === 'pending' ? (
        <p>Assessment delivery is queued.</p>
      ) : null}
      {engagement.assessment_delivery_state === 'retrying' ? (
        <p>Assessment delivery is pending after an attempt.</p>
      ) : null}
      {engagement.assessment_delivery_state === 'sent' ? (
        <p>Assessment delivered to the configured archive.</p>
      ) : null}
      {engagement.assessment_delivery_state === 'withdrawn' ? (
        <p>Assessment delivery was withdrawn.</p>
      ) : null}
      {engagement.assessment_artifact_id ? (
        <a
          href={apiDownloadURL(
            `/dashboard-report-artifacts/${encodeURIComponent(engagement.assessment_artifact_id)}`,
          )}
          download
        >
          Download assessment PDF
        </a>
      ) : null}
      {error ? <p role="alert">{error}</p> : null}
      {!converted ? (
        <div className={styles.row}>
          {consent ? (
            <Button
              variant="secondary"
              onClick={() => void decide('revoke-consent')}
              disabled={action.isPending}
            >
              Withdraw scheduled erasure
            </Button>
          ) : null}
          <Button
            variant="secondary"
            onClick={() => void decide('convert')}
            disabled={action.isPending}
          >
            Convert to client
          </Button>
        </div>
      ) : null}
    </div>
  )
}
