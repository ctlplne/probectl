// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import { useCanonicalEntities, useEntityContexts } from '../api/entities'
import { useFlowQueryViews } from '../api/flowViews'
import { usePreviewRTBH, useProposeRTBH } from '../api/remediation'
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
  const [community, setCommunity] = useState('')
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
    community.trim() &&
    confirmed,
  )
  const preview = usePreviewRTBH()
  const file = useProposeRTBH()
  const busy = preview.isPending || file.isPending

  function previewRouting(event: FormEvent) {
    event.preventDefault()
    if (busy || !valid || !view) return
    file.reset()
    preview.mutate({
      rule_id: rule,
      receipt_fingerprint: receipt,
      context_id: contextID,
      protected_entity_id: protectedID,
      benign_entity_id: benignID,
      whole_view_id: view.id,
      whole_view_version: view.version,
      community: community.trim(),
      routing_policy_agreed: confirmed,
    })
  }

  function clearPreview() {
    preview.reset()
    file.reset()
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
  const assessment = preview.data?.assessment
  const evidence = assessment?.preview_fingerprint

  return (
    <>
      <h3>Prepare routing mitigation proposal</h3>
      <form onSubmit={previewRouting}>
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
        <Field
          label="Community from your routing policy"
          value={community}
          disabled={busy}
          onChange={(event) => {
            clearPreview()
            setCommunity(event.target.value)
          }}
        />
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
          I checked this community against the selected routing context’s policy
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
      {assessment && evidence ? (
        <>
          <dl aria-label="Scoped routing preview">
            <dt>Proposed prefix and community</dt>
            <dd>
              {assessment.announcement.prefix} · {assessment.announcement.community}
            </dd>
            <dt>Window ended</dt>
            <dd>
              <DateTime value={assessment.impact.to} />
            </dd>
            <dt>Known benign traffic</dt>
            <dd>{assessment.impact.known_benign.packets} packets</dd>
            <dt>Unclassified traffic</dt>
            <dd>{assessment.impact.unclassified.packets} packets</dd>
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
            onClick={() => {
              if (!preview.data) return
              file.mutate({
                preview: preview.data.input,
                observed_to: assessment.impact.to,
                preview_fingerprint: evidence,
                max_known_benign_packets: maximum,
              })
            }}
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
