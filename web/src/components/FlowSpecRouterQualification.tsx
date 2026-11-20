// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { Fragment, useState, type FormEvent } from 'react'
import { useQualifyFlowSpec } from '../api/remediation'
import type {
  RemediationFlowSpecHandoffInput,
  RemediationFlowSpecRouterQualification,
  RemediationFlowSpecRouterQualificationInput,
} from '../api/sdk.gen'
import { Button, Field, Select } from './index'

const profiles = [
  { value: '', label: 'Choose a router profile' },
  { value: 'junos_standard', label: 'Junos standard flow' },
  { value: 'ios_xr_asr9000_7_11', label: 'Cisco ASR 9000 IOS XR 7.11' },
  { value: 'eos_4_36_2f', label: 'Arista EOS 4.36.2F' },
  { value: 'frr_10_7_1', label: 'FRRouting 10.7.1' },
] satisfies { value: RemediationFlowSpecRouterQualificationInput['profile'] | ''; label: string }[]

export function FlowSpecRouterQualification({
  proposalID,
  fingerprint,
  prepared,
  onPrepare,
}: {
  proposalID: string
  fingerprint: string
  prepared: boolean
  onPrepare: (input?: RemediationFlowSpecHandoffInput) => void
}) {
  const [profile, setProfile] = useState<
    RemediationFlowSpecRouterQualificationInput['profile'] | ''
  >('')
  const [routingTable, setRoutingTable] = useState<'default' | 'vrf'>('default')
  const [available, setAvailable] = useState('')
  const [duration, setDuration] = useState('60')
  const check = useQualifyFlowSpec(proposalID)
  const validCount =
    available === '' || (/^[0-9]{1,10}$/.test(available) && Number(available) <= 4294967295)
  const result = check.data?.review_fingerprint === fingerprint ? check.data : undefined
  const validDuration = /^[1-9][0-9]{0,2}$/.test(duration) && Number(duration) <= 600
  const input = profile
    ? {
        profile,
        routing_table: routingTable,
        available_entries: available === '' ? undefined : Number(available),
      }
    : undefined

  function validate(event: FormEvent) {
    event.preventDefault()
    if (!input || !validCount || check.isPending) return
    onPrepare()
    check.mutate(input)
  }

  return (
    <>
      <form onSubmit={validate}>
        <Select
          label="Router profile"
          name="flowspec-router-profile"
          value={profile}
          disabled={check.isPending}
          options={profiles}
          onChange={(event) => {
            check.reset()
            onPrepare()
            setProfile(profiles.find((option) => option.value === event.target.value)?.value ?? '')
          }}
        />
        <Select
          label="Routing table"
          options={[
            { value: 'default', label: 'Default' },
            { value: 'vrf', label: 'VRF' },
          ]}
          value={routingTable}
          disabled={check.isPending}
          onChange={(event) => {
            check.reset()
            onPrepare()
            setRoutingTable(event.target.value === 'vrf' ? 'vrf' : 'default')
          }}
        />
        <Field
          label="Available entries (optional)"
          name="flowspec-available-entries"
          inputMode="numeric"
          value={available}
          disabled={check.isPending}
          onChange={(event) => {
            check.reset()
            onPrepare()
            setAvailable(event.target.value)
          }}
        />
        <Button type="submit" variant="ghost" disabled={!profile || !validCount || check.isPending}>
          Check router profile
        </Button>
      </form>
      {check.isError ? <p role="alert">{check.error.message}</p> : null}
      {result ? <FlowSpecProfileResult result={result} /> : null}
      {input && result?.syntax_compatible && result.capacity.fits_declared ? (
        <>
          <Field
            label="Handoff duration in seconds"
            inputMode="numeric"
            value={duration}
            onChange={(event) => {
              onPrepare()
              setDuration(event.target.value)
            }}
          />
          <Button
            type="button"
            variant="ghost"
            disabled={!validDuration || prepared}
            onClick={() =>
              onPrepare({
                qualification: input,
                qualification_fingerprint: result.qualification_fingerprint,
                duration_seconds: Number(duration),
              })
            }
          >
            Attach time-limited handoff
          </Button>
          {prepared ? <p role="status">Handoff attached to this approval.</p> : null}
        </>
      ) : null}
    </>
  )
}

export function FlowSpecProfileResult({
  result,
}: {
  result: RemediationFlowSpecRouterQualification
}) {
  const { capacity } = result
  const capacityLabel =
    capacity.fits_declared === undefined
      ? 'Available entries unreported'
      : capacity.fits_declared
        ? 'Declared entries meet the minimum'
        : 'Declared entries below the minimum'
  return (
    <>
      <dl aria-label="Router profile checks">
        <dt>Documented rule support</dt>
        <dd>{result.syntax_compatible ? 'Compatible' : 'Unsupported'}</dd>
        <dt>Address family</dt>
        <dd>{result.address_family}</dd>
        <dt>Minimum entries</dt>
        <dd>{capacity.minimum_entries}</dd>
        <dt>Capacity</dt>
        <dd>{capacityLabel}</dd>
      </dl>
      {result.findings.length > 0 ? (
        <ul>
          {result.findings.map((finding) => (
            <li key={finding}>{finding}</li>
          ))}
        </ul>
      ) : null}
      {result.template ? (
        <dl aria-label="FlowSpec rule template">
          {result.template.components.map((component) => (
            <Fragment key={component.type}>
              <dt>{component.field.replace(/_/g, ' ')}</dt>
              <dd>{component.value}</dd>
            </Fragment>
          ))}
          <dt>Proposed action</dt>
          <dd>{result.template.action}</dd>
        </dl>
      ) : null}
      <a href={result.documentation}>Router profile reference</a>
    </>
  )
}
