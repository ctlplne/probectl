// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import { useCanonicalEntities, useEntityContexts } from '../api/entities'
import { useFlowQueryViews } from '../api/flowViews'
import {
  usePreviewDiversion,
  usePreviewFlowSpec,
  usePreviewRTBH,
  useProposeDiversion,
  useProposeFlowSpec,
  useProposeRTBH,
} from '../api/remediation'
import { FlowSpecEvidence } from '../components/FlowSpecEvidence'
import { useAuth } from '../auth/useAuth'
import { Button, Field, Select } from '../components'
import { DateTime } from '../time/DateTime'
import styles from './incidentRoom.module.css'

export function IncidentRoutingProposal({
  rule,
  receipt,
  prefix,
  windowSeconds,
}: {
  rule: string
  receipt: string
  prefix: string
  windowSeconds: number
}) {
  const { tenant, user } = useAuth()
  const identity = `${tenant.id}:${user.id}`
  const contexts = useEntityContexts(identity)
  const [contextID, setContextID] = useState('')
  const [protectedID, setProtectedID] = useState('')
  const [benignID, setBenignID] = useState('')
  const [viewID, setViewID] = useState('')
  const [search, setSearch] = useState('')
  const [method, setMethod] = useState<'rtbh' | 'flowspec' | 'diversion'>('rtbh')
  const [community, setCommunity] = useState('')
  const [protocol, setProtocol] = useState<'tcp' | 'udp'>('tcp')
  const [sourcePort, setSourcePort] = useState('')
  const [destinationPort, setDestinationPort] = useState('')
  const flowSpec = method === 'flowspec'
  const diversion = method === 'diversion'
  const [confirmed, setConfirmed] = useState(false)
  const [maximum, setMaximum] = useState('')
  const entities = useCanonicalEntities(identity, contextID)
  const views = useFlowQueryViews({ search, limit: 50 }, identity)
  const inventory = entities.data?.pages.flatMap((page) => page.items) ?? []
  const prefixes = inventory.filter((item) => item.kind === 'prefix' && item.network_prefix)
  const eligibleViews = (views.data?.items ?? []).filter(
    (view) =>
      view.definition.time?.mode === 'lookback' &&
      view.definition.time.lookback_seconds === windowSeconds &&
      !view.definition.plan?.filter &&
      !view.definition.comparison,
  )
  const view = eligibleViews.find((item) => item.id === viewID)
  const valid = Boolean(
    contextID &&
    protectedID &&
    benignID &&
    protectedID !== benignID &&
    view &&
    (flowSpec
      ? validOptionalPort(sourcePort) && validOptionalPort(destinationPort)
      : diversion || community.trim()) &&
    confirmed,
  )
  const rtbhPreview = usePreviewRTBH()
  const rtbhFile = useProposeRTBH()
  const flowSpecPreview = usePreviewFlowSpec()
  const flowSpecFile = useProposeFlowSpec()
  const diversionPreview = usePreviewDiversion()
  const diversionFile = useProposeDiversion()
  const preview = diversion ? diversionPreview : flowSpec ? flowSpecPreview : rtbhPreview
  const file = diversion ? diversionFile : flowSpec ? flowSpecFile : rtbhFile
  const busy = preview.isPending || file.isPending

  function previewRouting(event: FormEvent) {
    event.preventDefault()
    if (busy || !valid || !view) return
    file.reset()
    const scope = {
      rule_id: rule,
      receipt_fingerprint: receipt,
      context_id: contextID,
      protected_entity_id: protectedID,
      benign_entity_id: benignID,
      whole_view_id: view.id,
      whole_view_version: view.version,
    }
    if (diversion) {
      diversionPreview.mutate({ action: 'start', observation: scope })
    } else if (flowSpec) {
      flowSpecPreview.mutate({
        ...scope,
        routing_policy_agreed: confirmed,
        transport: {
          protocol,
          source_port: sourcePort ? Number(sourcePort) : undefined,
          destination_port: destinationPort ? Number(destinationPort) : undefined,
        },
      })
    } else {
      rtbhPreview.mutate({
        ...scope,
        community: community.trim(),
        routing_policy_agreed: confirmed,
      })
    }
  }

  function clearPreview() {
    preview.reset()
    file.reset()
  }

  function fileProposal() {
    if (diversion && diversionPreview.data) {
      const { input, assessment } = diversionPreview.data
      if (!assessment.impact) return
      diversionFile.mutate({
        selection: input,
        observed_to: assessment.impact.to,
        preview_fingerprint: assessment.preview_fingerprint,
        max_known_benign_packets: maximum,
      })
    } else if (flowSpec && flowSpecPreview.data) {
      const { input, assessment } = flowSpecPreview.data
      flowSpecFile.mutate({
        preview: input,
        observed_to: assessment.matching.to,
        preview_fingerprint: assessment.preview_fingerprint,
        max_known_benign_packets: maximum,
      })
    } else if (method === 'rtbh' && rtbhPreview.data) {
      const { input, assessment } = rtbhPreview.data
      if (!assessment.preview_fingerprint) return
      rtbhFile.mutate({
        preview: input,
        observed_to: assessment.impact.to,
        preview_fingerprint: assessment.preview_fingerprint,
        max_known_benign_packets: maximum,
      })
    }
  }

  const contextOptions = (contexts.data?.pages.flatMap((page) => page.items) ?? []).map((item) => ({
    value: item.context_id,
    label: `${item.site_label} / ${item.vrf_label}`,
  }))
  const options = prefixes.map((item) => ({
    value: item.id,
    label: `${item.network_prefix} · ${item.label}`,
    prefix: item.network_prefix,
  }))
  const rtbhAssessment = method === 'rtbh' ? rtbhPreview.data?.assessment : undefined
  const flowSpecAssessment = flowSpec ? flowSpecPreview.data?.assessment : undefined
  const diversionAssessment = diversion ? diversionPreview.data?.assessment : undefined
  const evidence =
    rtbhAssessment?.preview_fingerprint ??
    flowSpecAssessment?.preview_fingerprint ??
    diversionAssessment?.preview_fingerprint

  return (
    <>
      <h3>Prepare routing mitigation proposal</h3>
      <form onSubmit={previewRouting}>
        <Select
          label="Proposal method"
          value={method}
          disabled={busy}
          options={[
            { value: 'rtbh', label: 'RTBH' },
            { value: 'flowspec', label: 'FlowSpec' },
            { value: 'diversion', label: 'Diversion (local preview)' },
          ]}
          onChange={(event) => {
            clearPreview()
            const next = event.target.value
            setMethod(next === 'flowspec' || next === 'diversion' ? next : 'rtbh')
            setConfirmed(false)
            setMaximum('')
          }}
        />
        <Select
          label="Routing context"
          value={contextID}
          disabled={busy}
          options={[{ value: '', label: 'Choose a routing context' }, ...contextOptions]}
          onChange={(event) => {
            clearPreview()
            setContextID(event.target.value)
            setProtectedID('')
            setBenignID('')
          }}
        />
        {contexts.hasNextPage ? (
          <Button type="button" variant="ghost" onClick={() => void contexts.fetchNextPage()}>
            Load more routing contexts
          </Button>
        ) : null}
        <Select
          label="Protected prefix"
          value={protectedID}
          disabled={busy || !contextID}
          options={[
            { value: '', label: 'Choose the cited prefix' },
            ...options.filter((item) => item.prefix === prefix),
          ]}
          onChange={(event) => {
            clearPreview()
            setProtectedID(event.target.value)
          }}
        />
        <Select
          label="Known benign source prefix"
          value={benignID}
          disabled={busy || !contextID}
          options={[
            { value: '', label: 'Choose a known benign source' },
            ...options.filter((item) => item.value !== protectedID),
          ]}
          onChange={(event) => {
            clearPreview()
            setBenignID(event.target.value)
          }}
        />
        {entities.hasNextPage ? (
          <Button type="button" variant="ghost" onClick={() => void entities.fetchNextPage()}>
            Load more configured prefixes
          </Button>
        ) : null}
        <Field
          label="Search saved whole-prefix views"
          value={search}
          disabled={busy}
          onChange={(event) => {
            clearPreview()
            setSearch(event.target.value)
            setViewID('')
          }}
        />
        <Select
          label="Whole-prefix flow view"
          value={viewID}
          disabled={busy}
          options={[
            { value: '', label: 'Choose an unfiltered saved view' },
            ...eligibleViews.map((item) => ({ value: item.id, label: item.definition.name })),
          ]}
          onChange={(event) => {
            clearPreview()
            setViewID(event.target.value)
          }}
        />
        {flowSpec ? (
          <>
            <Select
              label="Transport protocol"
              value={protocol}
              disabled={busy}
              options={[
                { value: 'tcp', label: 'TCP' },
                { value: 'udp', label: 'UDP' },
              ]}
              onChange={(event) => {
                clearPreview()
                setProtocol(event.target.value === 'udp' ? 'udp' : 'tcp')
              }}
            />
            <Field
              label="Exact source port (optional)"
              inputMode="numeric"
              value={sourcePort}
              disabled={busy}
              onChange={(event) => {
                clearPreview()
                setSourcePort(event.target.value)
              }}
            />
            <Field
              label="Exact destination port (optional)"
              inputMode="numeric"
              value={destinationPort}
              disabled={busy}
              onChange={(event) => {
                clearPreview()
                setDestinationPort(event.target.value)
              }}
            />
          </>
        ) : diversion ? null : (
          <Field
            label="Community from your routing policy"
            value={community}
            disabled={busy}
            onChange={(event) => {
              clearPreview()
              setCommunity(event.target.value)
            }}
          />
        )}
        <label>
          <input
            type="checkbox"
            checked={confirmed}
            disabled={busy}
            onChange={(event) => {
              clearPreview()
              setConfirmed(event.target.checked)
            }}
          />{' '}
          {diversion
            ? 'I reviewed the protected scope for the local diversion preview'
            : flowSpec
              ? 'I checked this FlowSpec match against the selected routing context’s policy'
              : 'I checked this community against the selected routing context’s policy'}
        </label>
        <div className={styles.actions}>
          <Button type="submit" disabled={!valid || busy}>
            Preview scoped collateral
          </Button>
        </div>
      </form>
      {contexts.isError || entities.isError || views.isError ? (
        <p role="alert">Could not load current routing sources.</p>
      ) : null}
      {preview.isError ? <p role="alert">{preview.error.message}</p> : null}
      {evidence ? (
        <>
          <dl aria-label="Scoped routing preview">
            {flowSpecAssessment ? <FlowSpecEvidence preview={flowSpecAssessment} /> : null}
            {diversionAssessment?.impact ? (
              <>
                <dt>Local preview prefix</dt>
                <dd>{diversionAssessment.prefix}</dd>
                <dt>Known benign traffic</dt>
                <dd>{diversionAssessment.impact.known_benign.packets} packets</dd>
                <dt>Unclassified traffic</dt>
                <dd>{diversionAssessment.impact.unclassified.packets} packets</dd>
              </>
            ) : null}
            {rtbhAssessment ? (
              <>
                <dt>Proposed prefix and community</dt>
                <dd>
                  {rtbhAssessment.announcement.prefix} · {rtbhAssessment.announcement.community}
                </dd>
                <dt>Window ended</dt>
                <dd>
                  <DateTime value={rtbhAssessment.impact.to} />
                </dd>
                <dt>Known benign traffic</dt>
                <dd>{rtbhAssessment.impact.known_benign.packets} packets</dd>
                <dt>Unclassified traffic</dt>
                <dd>{rtbhAssessment.impact.unclassified.packets} packets</dd>
              </>
            ) : null}
          </dl>
          <Field
            label="Maximum known benign packets"
            inputMode="numeric"
            value={maximum}
            onChange={(event) => setMaximum(event.target.value)}
            disabled={busy || file.isSuccess}
          />
          <Button
            type="button"
            disabled={busy || file.isSuccess || !/^[0-9]{1,64}$/.test(maximum)}
            onClick={fileProposal}
          >
            File exact routing proposal
          </Button>
        </>
      ) : null}
      {file.isError ? <p role="alert">{file.error.message}</p> : null}
      {file.isSuccess ? (
        <p role="status">Routing proposal filed for independent review in Admin.</p>
      ) : null}
    </>
  )
}

function validOptionalPort(port: string) {
  return port === '' || (/^[1-9][0-9]{0,4}$/.test(port) && Number(port) <= 65535)
}
