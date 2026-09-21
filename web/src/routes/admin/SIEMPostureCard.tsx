// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import styles from '../pages.module.css'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  Column,
  HonestDataState,
  LoadingState,
  StatusDot,
  Table,
  classifySurfaceTruth,
} from '../../components'
import { useSIEMStatus, type SIEMReason, type SIEMStatus } from '../../api/siem'

/**
 * SIEMPostureCard (F26, DPR-254): the native surface for SIEM delivery posture
 * and tenant-routed forwarding. `GET /v1/siem/status` and `probectl siem status`
 * have always served this, and there was no screen — so an operator could not
 * see whether their audit and threat streams were actually leaving the
 * deployment without dropping to a terminal.
 *
 * Everything here is posture, never a value: the server returns "is an endpoint
 * configured" and "is a token configured" as booleans plus scheme-free
 * `host:port`, and never the path, query or ingest token (§7 guardrail 6). This
 * card renders exactly that and adds nothing.
 */

/** One posture row: the setting, what the server says, and why it matters. */
interface PostureRow {
  id: string
  setting: string
  value: JSX.Element | string
  meaning: string
}

/**
 * Why the exporter is not delivering, in the server's own words. `configured`
 * is the only reason that is not a problem, and a missing reason on a
 * configured exporter is reported as such rather than guessed at.
 */
const REASONS: Record<
  SIEMReason,
  { label: string; detail: string; tone: 'danger' | 'warning' | 'success' }
> = {
  disabled: {
    label: 'Disabled',
    detail: 'PROBECTL_SIEM_ENABLED is off, so no stream is forwarded anywhere.',
    tone: 'warning',
  },
  missing_endpoint: {
    label: 'No endpoint',
    detail: 'The exporter is enabled but has no destination, so events accumulate nowhere.',
    tone: 'danger',
  },
  insecure_endpoint: {
    label: 'Endpoint refused (not TLS)',
    detail:
      'The configured endpoint is not HTTPS and TLS is required, so the exporter fails closed rather than sending audit records in the clear.',
    tone: 'danger',
  },
  invalid_format: {
    label: 'Format not recognized',
    detail:
      'The configured format is not one this build can emit; the raw configured value is shown below.',
    tone: 'danger',
  },
  configured: {
    label: 'Configured',
    detail: 'The exporter has a destination it is willing to deliver to.',
    tone: 'success',
  },
}

/**
 * `reason` is optional in the API. When the server omits it, the card must say
 * so rather than pick the most likely cause — inferring "disabled" from silence
 * would send an operator to check an environment variable the server never
 * mentioned.
 */
function reasonFor(status: SIEMStatus): { label: string; detail: string } {
  if (status.reason) return REASONS[status.reason]
  return status.configured
    ? {
        label: 'Configured',
        detail: 'The server reported no reason code, so no further detail is claimed here.',
      }
    : {
        label: 'Not delivering, reason not reported',
        detail:
          'The server reports configured=false and sent no reason code, so why it is not delivering is not known from this response.',
      }
}

function yesNo(on: boolean, yes: string, no: string) {
  return <StatusDot tone={on ? 'success' : 'neutral'} label={on ? yes : no} />
}

function postureRows(status: SIEMStatus): PostureRow[] {
  return [
    {
      id: 'delivery',
      setting: 'Delivery',
      value: yesNo(status.siem_running, 'Exporter running', 'Exporter not running'),
      meaning: status.summary,
    },
    {
      id: 'streams',
      setting: 'Streams forwarded',
      value:
        status.streams.length === 0 ? (
          <Badge tone="warning">None</Badge>
        ) : (
          <span className={styles.actions}>
            {status.streams.map((stream) => (
              <Badge key={stream} tone="info">
                {stream}
              </Badge>
            ))}
          </span>
        ),
      meaning:
        status.streams.length === 0
          ? 'No stream is routed off this deployment, so the SIEM sees nothing from this tenant.'
          : 'Each stream is read with its own tenant-scoped cursor, so one tenant’s records never reach another’s destination.',
    },
    {
      id: 'preset',
      setting: 'Preset and format',
      value: (
        <span>
          <Badge tone="info">{status.preset}</Badge> <code>{status.format}</code>
        </span>
      ),
      meaning:
        status.reason === 'invalid_format'
          ? 'This is the RAW configured value, not a format this build emits.'
          : 'The resolved wire format the destination will receive.',
    },
    {
      id: 'endpoint',
      setting: 'Endpoint',
      value: status.endpoint_configured ? (
        <span>
          {yesNo(status.endpoint_tls_configured, 'Configured over TLS', 'Configured WITHOUT TLS')}
          {status.endpoint_host ? (
            <>
              {' '}
              <code>{status.endpoint_host}</code>
            </>
          ) : null}
        </span>
      ) : (
        <StatusDot tone="neutral" label="Not configured" />
      ),
      meaning:
        'Host and port only. The path, query string and credentials are never returned by the API, so they cannot be shown here.',
    },
    {
      id: 'token',
      setting: 'Ingest credential',
      value: yesNo(status.token_configured, 'Configured', 'Not configured'),
      meaning:
        'Whether a credential exists, never its value. An unauthenticated destination is a delivery that any listener can accept.',
    },
    {
      id: 'tls-required',
      setting: 'TLS required',
      value: yesNo(status.tls_required, 'Required', 'Not required'),
      meaning:
        'When required, a plaintext endpoint is refused outright instead of downgraded (§7 guardrail 12).',
    },
    {
      id: 'no-drop',
      setting: 'Back-pressure policy',
      value: status.no_drop_delivery ? (
        <StatusDot tone="success" label="Never drop" />
      ) : (
        <StatusDot tone="warning" label="Drop oldest when full" />
      ),
      meaning: status.no_drop_delivery
        ? 'Ingest slows rather than silently discarding audit records the SIEM is expected to hold.'
        : `The ${status.buffer_size}-event buffer discards the oldest record when the destination cannot keep up, so the SIEM's copy can be incomplete.`,
    },
    {
      id: 'cadence',
      setting: 'Poll cadence and buffer',
      value: (
        <span>
          <code>{status.audit_poll_interval}</code> · {status.buffer_size} events
        </span>
      ),
      meaning: 'How often the cursor advances, and how much the exporter holds while delivering.',
    },
    {
      id: 'redaction',
      setting: 'Redaction keys',
      value: (
        <Badge tone={status.redact_key_count > 0 ? 'success' : 'neutral'}>
          {status.redact_key_count}
        </Badge>
      ),
      meaning:
        status.redact_key_count > 0
          ? 'Fields stripped from every forwarded record before it leaves the deployment.'
          : 'No field is stripped, so forwarded records carry whatever the source event carried.',
    },
  ]
}

export function SIEMPostureCard() {
  const { data, isPending, isError, error, refetch } = useSIEMStatus()

  const columns: Column<PostureRow>[] = [
    { key: 'setting', header: 'Setting', render: (row) => <strong>{row.setting}</strong> },
    { key: 'value', header: 'Server reports', render: (row) => row.value },
    { key: 'meaning', header: 'What it means', render: (row) => row.meaning },
  ]

  const retry = (
    <Button variant="secondary" onClick={() => void refetch()}>
      Recheck SIEM posture
    </Button>
  )

  return (
    <Card>
      <CardHeader
        title="SIEM export posture"
        description="Whether the audit and threat streams are actually leaving this deployment, and to what. Posture only — the endpoint path and the ingest token are never returned by the API, so they are never shown."
      />
      <CardBody>
        {isPending ? (
          <LoadingState label="Loading SIEM posture…" />
        ) : isError ? (
          <HonestDataState
            state={classifySurfaceTruth({ error })}
            producer="SIEM exporter"
            producerReadiness="The tenant-scoped exporter status is unavailable"
            lastSuccessfulIngest={null}
            coverageLimitation="No delivery posture is shown because the server did not answer. Absence here is not evidence that forwarding is working."
            action={retry}
          />
        ) : !data.configured ? (
          <HonestDataState
            state="blocked"
            icon="admin"
            title={`SIEM forwarding is not delivering — ${reasonFor(data).label}`}
            producer="SIEM exporter"
            producerReadiness={`Server reports configured=false${data.reason ? `, reason=${data.reason}` : ''}`}
            lastSuccessfulIngest={null}
            coverageLimitation={`${reasonFor(data).detail} Until it is configured, this tenant's audit and threat records exist only inside this deployment.`}
            action={retry}
          />
        ) : (
          <>
            <p className={styles.subtitle} role="note">
              <strong>{reasonFor(data).label}.</strong> {reasonFor(data).detail} Delivery posture is
              what the server reports right now; it is not a receipt that any particular record
              arrived.
            </p>
            <Table
              caption="SIEM delivery posture"
              columns={columns}
              rows={postureRows(data)}
              rowKey={(row) => row.id}
            />
          </>
        )}
      </CardBody>
    </Card>
  )
}
