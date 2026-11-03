// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/useAuth'
import { useEntityContexts } from '../../api/entities'
import { useApplyNetBoxTag, useNetBoxTagPreview, useTagDefinitions } from '../../api/tags'
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  LoadingState,
  Modal,
  Select,
  Table,
  type Column,
} from '../../components'
import { TagValue } from './TagValue'
import styles from './EntityRegistryCard.module.css'

const importKinds = ['exporter', 'device', 'interface', 'prefix', 'agent', 'test'] as const
type ImportKind = (typeof importKinds)[number]
const importReadGrant: Record<ImportKind, string> = {
  exporter: 'flow.read',
  device: 'metrics.read',
  interface: 'metrics.read',
  prefix: 'entities.read',
  agent: 'agent.read',
  test: 'test.read',
}

export function NetBoxTagPreviewCard() {
  const { permissions, tenant, user } = useAuth()
  if (!permissions.includes('tags.read') || !permissions.includes('cmdb.read')) return null
  return (
    <NetBoxTagPreviewContents
      key={`${tenant.id}:${user.id}`}
      tenantID={tenant.id}
      canListContexts={permissions.includes('entities.read')}
      canWrite={permissions.includes('tags.write')}
      readKinds={importKinds.filter((kind) => permissions.includes(importReadGrant[kind]))}
    />
  )
}

function NetBoxTagPreviewContents({
  tenantID,
  canListContexts,
  canWrite,
  readKinds,
}: {
  tenantID: string
  canListContexts: boolean
  canWrite: boolean
  readKinds: ImportKind[]
}) {
  const contexts = useEntityContexts(tenantID, canListContexts)
  const definitions = useTagDefinitions(tenantID)
  const [contextID, setContextID] = useState('')
  const [tagID, setTagID] = useState('')
  const allContexts = contexts.data?.pages.flatMap((page) => page.items) ?? []
  const selectedTag = definitions.data?.items.find((item) => item.id === tagID)

  useEffect(() => {
    if (!definitions.data) return
    if (!definitions.data.items.some((item) => item.id === tagID)) {
      setTagID(definitions.data.items[0]?.id ?? '')
    }
  }, [definitions.data, tagID])

  return (
    <Card data-tenant-netbox-tag-preview>
      <CardHeader
        title="NetBox tag preview"
        description="Preview a fresh role or site for an owned device, interface, prefix, agent, test or exporter. No assignment is written."
      />
      <CardBody>
        <div className={styles.stack}>
          {canListContexts ? (
            <>
              {contexts.isPending ? <LoadingState label="Loading preview contexts…" /> : null}
              {contexts.isError ? (
                <ErrorState description="Preview routing contexts could not be loaded." />
              ) : null}
              <div className={styles.row}>
                <Select
                  label="NetBox preview routing context"
                  value={contextID}
                  onChange={(event) => setContextID(event.target.value)}
                  options={[
                    { value: '', label: 'Choose a site and VRF' },
                    ...allContexts.map((item) => ({
                      value: item.context_id,
                      label: `${item.site_label} / ${item.vrf_label}`,
                    })),
                  ]}
                />
                {contexts.hasNextPage ? (
                  <Button
                    onClick={() => void contexts.fetchNextPage()}
                    disabled={contexts.isFetchingNextPage}
                  >
                    Load more preview contexts
                  </Button>
                ) : null}
              </div>
            </>
          ) : (
            <Field
              label="NetBox preview routing context ID"
              hint="Enter a context you are authorized to read. Inventory discovery requires entities.read."
              maxLength={36}
              value={contextID}
              onChange={(event) => setContextID(event.target.value.trim())}
            />
          )}
          {definitions.isPending ? <LoadingState label="Loading preview tag keys…" /> : null}
          {definitions.isError ? (
            <ErrorState description="Preview tag keys could not be loaded." />
          ) : null}
          <Select
            label="NetBox preview tag key"
            value={tagID}
            onChange={(event) => setTagID(event.target.value)}
            options={[
              { value: '', label: 'Choose a tag key' },
              ...(definitions.data?.items.map((item) => ({ value: item.id, label: item.key })) ??
                []),
            ]}
          />
          {contextID && selectedTag ? (
            <NetBoxPreviewForm
              key={`${contextID}:${selectedTag.id}:${selectedTag.key}:${readKinds.join(',')}`}
              tenantID={tenantID}
              contextID={contextID}
              tagID={selectedTag.id}
              tagKey={selectedTag.key}
              canWrite={canWrite}
              readKinds={readKinds}
            />
          ) : null}
        </div>
      </CardBody>
    </Card>
  )
}

function NetBoxPreviewForm({
  tenantID,
  contextID,
  tagID,
  tagKey,
  canWrite,
  readKinds,
}: {
  tenantID: string
  contextID: string
  tagID: string
  tagKey: string
  canWrite: boolean
  readKinds: ImportKind[]
}) {
  const preview = useNetBoxTagPreview(tenantID, contextID)
  const apply = useApplyNetBoxTag(tenantID, contextID)
  const [reviewing, setReviewing] = useState(false)
  const [kind, setKind] = useState<ImportKind>(readKinds[0] ?? 'exporter')
  const [targetID, setTargetID] = useState('')
  const [sourceID, setSourceID] = useState('')
  const [agentID, setAgentID] = useState('')
  const [sourceRef, setSourceRef] = useState('')
  const [field, setField] = useState<'role' | 'site'>('site')

  function clearResult() {
    preview.reset()
    apply.reset()
    setReviewing(false)
  }

  async function onPreview(event: FormEvent) {
    event.preventDefault()
    if (
      !readKinds.includes(kind) ||
      (kind === 'exporter' ? !agentID.trim() || !sourceRef.trim() : !targetID.trim())
    )
      return
    apply.reset()
    try {
      await preview.mutateAsync({
        tag_id: tagID,
        ...(kind === 'exporter'
          ? { exporter_agent_id: agentID.trim(), exporter_source_ref: sourceRef.trim() }
          : { target_kind: kind, target_id: targetID.trim() }),
        ...(sourceID.trim() ? { source_id: sourceID.trim() } : {}),
        field,
      })
    } catch {
      // Keep the source refusal visible; a cached enrichment is never a preview.
    }
  }

  const result = preview.data
  const matchesInput =
    result &&
    result.target.context_id === contextID &&
    result.target.tag_id === tagID &&
    result.target.tag_key === tagKey &&
    readKinds.includes(kind) &&
    result.target.target_kind === kind &&
    (kind === 'exporter'
      ? result.target.exporter_agent_id === agentID.trim() &&
        result.target.exporter_source_ref === sourceRef.trim()
      : result.target.target_id === targetID.trim()) &&
    result.candidate.field === field
  const columns: Column<{ label: string; value: string }>[] = [
    { key: 'label', header: 'Field', render: (row) => row.label },
    {
      key: 'value',
      header: 'Value',
      render: (row) => <TagValue value={row.value} />,
    },
  ]
  const rows =
    matchesInput && result
      ? [
          { label: 'Tag key', value: result.target.tag_key },
          { label: 'Proposed value', value: result.candidate.value },
          { label: 'Source field', value: result.candidate.field },
          { label: 'Source name', value: result.candidate.name },
          { label: 'Source CI ID', value: result.candidate.ci_id },
          { label: 'Lookup CI ID', value: result.candidate.lookup_ci_id },
          { label: 'NetBox tenant ID', value: result.candidate.netbox_tenant_id },
          { label: 'Source reference', value: result.candidate.source_ref },
          { label: 'Tag revision', value: result.target.tag_revision },
        ]
      : []

  return (
    <div className={styles.stack}>
      <form className={styles.form} onSubmit={(event) => void onPreview(event)}>
        <Select
          label="NetBox target kind"
          value={kind}
          disabled={preview.isPending || apply.isPending || readKinds.length === 0}
          options={readKinds.map((value) => ({ value, label: value }))}
          onChange={(event) => {
            clearResult()
            setKind(event.target.value as ImportKind)
            setSourceID('')
          }}
        />
        {readKinds.length === 0 ? (
          <ErrorState description="A subject read permission is required to preview NetBox tags." />
        ) : null}
        {kind === 'exporter' ? (
          <>
            <Field
              label="NetBox exporter agent ID"
              required
              maxLength={128}
              disabled={preview.isPending || apply.isPending}
              value={agentID}
              onChange={(event) => {
                clearResult()
                setAgentID(event.target.value)
              }}
            />
            <Field
              label="NetBox exporter address"
              hint="The current registered exporter IP address in this routing context."
              required
              maxLength={45}
              disabled={preview.isPending || apply.isPending}
              value={sourceRef}
              onChange={(event) => {
                clearResult()
                setSourceRef(event.target.value)
              }}
            />
          </>
        ) : (
          <Field
            label="NetBox target ID"
            hint="The exact owned subject ID in this routing context; labels never select inventory."
            required
            maxLength={36}
            disabled={preview.isPending || apply.isPending}
            value={targetID}
            onChange={(event) => {
              clearResult()
              setTargetID(event.target.value)
            }}
          />
        )}
        <Field
          label="NetBox source object ID"
          hint={
            kind === 'prefix'
              ? 'Optional exact NetBox prefix ID to select an overlapping range or VRF.'
              : 'Optional exact NetBox IP-address CI ID when automatic matching is ambiguous.'
          }
          maxLength={19}
          inputMode="numeric"
          disabled={preview.isPending || apply.isPending}
          value={sourceID}
          onChange={(event) => {
            clearResult()
            setSourceID(event.target.value)
          }}
        />
        <Select
          label="NetBox source field"
          value={field}
          disabled={preview.isPending || apply.isPending}
          onChange={(event) => {
            clearResult()
            setField(event.target.value as 'role' | 'site')
          }}
          options={[
            { value: 'site', label: 'Site' },
            { value: 'role', label: 'Role' },
          ]}
        />
        <Button
          type="submit"
          disabled={
            preview.isPending ||
            apply.isPending ||
            !readKinds.includes(kind) ||
            (kind === 'exporter' ? !agentID.trim() || !sourceRef.trim() : !targetID.trim())
          }
        >
          Preview NetBox value
        </Button>
      </form>
      {preview.isPending ? <LoadingState label="Reading fresh NetBox metadata…" /> : null}
      {preview.isError ? <ErrorState description={preview.error.message} /> : null}
      {result && !matchesInput ? (
        <ErrorState description="The preview no longer matches this selection. Request it again." />
      ) : null}
      {matchesInput ? (
        <Table
          caption="Fresh NetBox tag preview"
          columns={columns}
          rows={rows}
          rowKey={(row) => row.label}
        />
      ) : null}
      {matchesInput && canWrite ? (
        <Button disabled={apply.isPending || apply.isSuccess} onClick={() => setReviewing(true)}>
          Review NetBox import
        </Button>
      ) : null}
      {apply.isSuccess ? (
        <p role="status">NetBox tag imported. Manual assignments retain precedence.</p>
      ) : null}
      {reviewing && canWrite && matchesInput && result ? (
        <Modal
          open
          title="Apply reviewed NetBox tag?"
          onClose={() => {
            if (!apply.isPending) setReviewing(false)
          }}
        >
          <div className={styles.stack}>
            <p>
              Import {result.target.tag_key} = {result.candidate.value} for this {kind}?
            </p>
            <p>
              Source {result.candidate.source_ref}; reviewed tag revision{' '}
              {result.target.tag_revision}. The server will read the source again and refuse any
              changed candidate or target.
            </p>
            {apply.isError ? <ErrorState description={apply.error.message} /> : null}
            <Button
              disabled={apply.isPending}
              onClick={() => {
                void apply
                  .mutateAsync({ confirmed: true, preview: result })
                  .then(() => setReviewing(false))
                  .catch(() => {
                    /* Keep the source refusal and review visible. */
                  })
              }}
            >
              Apply reviewed NetBox tag
            </Button>
          </div>
        </Modal>
      ) : null}
    </div>
  )
}
