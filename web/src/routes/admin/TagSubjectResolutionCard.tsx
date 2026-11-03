// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/useAuth'
import { useEntityContexts } from '../../api/entities'
import {
  resolveSubjectTags,
  type TagSubjectResolution,
  type TagResolutionItem,
} from '../../api/tags'
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  LoadingState,
  Select,
  Table,
  type Column,
} from '../../components'
import { TagValue } from './TagValue'
import styles from './EntityRegistryCard.module.css'

const kinds = ['device', 'interface', 'prefix', 'agent', 'test', 'exporter'] as const
const columns: Column<TagResolutionItem>[] = [
  { key: 'key', header: 'Key', render: (item) => item.key },
  { key: 'value', header: 'Value', render: (item) => <TagValue value={item.value} /> },
  { key: 'source', header: 'Source', render: (item) => item.source },
]

export function TagSubjectResolutionCard() {
  const { tenant, user, permissions } = useAuth()
  if (!permissions.includes('tags.read')) return null
  return (
    <TagSubjectContents
      key={`${tenant.id}:${user.id}`}
      tenantID={tenant.id}
      canList={permissions.includes('entities.read')}
    />
  )
}

function TagSubjectContents({ tenantID, canList }: { tenantID: string; canList: boolean }) {
  const contexts = useEntityContexts(tenantID, canList)
  const [contextID, setContextID] = useState('')
  const allContexts = contexts.data?.pages.flatMap((page) => page.items) ?? []
  return (
    <Card data-tag-subject-resolution>
      <CardHeader
        title="Effective subject tags"
        description="Preview effective tags from current rules, manual values and reviewed imports for one owned subject. Tag and subject read permissions are required."
      />
      <CardBody>
        <div className={styles.stack}>
          {canList ? (
            <>
              {contexts.isPending ? <LoadingState label="Loading effective-tag contexts…" /> : null}
              {contexts.isError ? (
                <ErrorState description="Effective-tag contexts could not be loaded." />
              ) : null}
              <Select
                label="Effective-tag routing context"
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
                  Load more effective-tag contexts
                </Button>
              ) : null}
            </>
          ) : (
            <Field
              label="Effective-tag routing context ID"
              hint="Enter a context you can read. Listing inventory requires entities.read."
              maxLength={36}
              value={contextID}
              onChange={(event) => setContextID(event.target.value.trim())}
            />
          )}
          {contextID ? (
            <TagSubjectForm key={contextID} tenantID={tenantID} contextID={contextID} />
          ) : null}
        </div>
      </CardBody>
    </Card>
  )
}

function TagSubjectForm({ tenantID, contextID }: { tenantID: string; contextID: string }) {
  const [kind, setKind] = useState<(typeof kinds)[number]>('device')
  const [targetID, setTargetID] = useState('')
  const [agentID, setAgentID] = useState('')
  const [sourceRef, setSourceRef] = useState('')
  const [result, setResult] = useState<TagSubjectResolution | null>(null)
  const [pending, setPending] = useState(false)
  const [failed, setFailed] = useState(false)
  const generation = useRef(0)
  const request = useRef<AbortController | null>(null)
  useEffect(
    () => () => {
      generation.current++
      request.current?.abort()
    },
    [],
  )
  function clear() {
    generation.current++
    request.current?.abort()
    setResult(null)
    setFailed(false)
    setPending(false)
  }
  async function submit(event: FormEvent) {
    event.preventDefault()
    clear()
    const current = generation.current
    const controller = new AbortController()
    request.current = controller
    setPending(true)
    try {
      const resolved = await resolveSubjectTags(
        tenantID,
        {
          contextId: contextID,
          targetKind: kind,
          ...(kind === 'exporter'
            ? { exporterAgentId: agentID.trim(), exporterSourceRef: sourceRef.trim() }
            : { targetId: targetID.trim() }),
        },
        controller.signal,
      )
      if (generation.current !== current) return
      if (
        resolved.context_id.toLowerCase() !== contextID.toLowerCase() ||
        resolved.target_kind !== kind
      )
        throw new Error('Subject scope changed')
      setResult(resolved)
    } catch {
      if (generation.current === current) setFailed(true)
    } finally {
      if (generation.current === current) setPending(false)
    }
  }
  const ready =
    kind === 'exporter' ? Boolean(agentID.trim() && sourceRef.trim()) : Boolean(targetID.trim())
  return (
    <div className={styles.stack}>
      {kind === 'agent' || kind === 'prefix' ? (
        <p>
          {kind === 'agent' ? 'Agent address' : 'Live prefix CIDR'} matching is not available yet;
          manual and name rules remain usable.
        </p>
      ) : null}
      <form onSubmit={(event) => void submit(event)} className={styles.stack}>
        <Select
          label="Effective-tag subject kind"
          value={kind}
          options={kinds.map((value) => ({ value, label: value }))}
          onChange={(event) => {
            clear()
            setKind(event.target.value as typeof kind)
          }}
        />
        {kind === 'exporter' ? (
          <>
            <Field
              label="Effective-tag exporter agent ID"
              maxLength={128}
              value={agentID}
              onChange={(event) => {
                clear()
                setAgentID(event.target.value)
              }}
            />
            <Field
              label="Effective-tag exporter source reference"
              maxLength={128}
              value={sourceRef}
              onChange={(event) => {
                clear()
                setSourceRef(event.target.value)
              }}
            />
          </>
        ) : (
          <Field
            label="Effective-tag subject ID"
            maxLength={128}
            value={targetID}
            onChange={(event) => {
              clear()
              setTargetID(event.target.value)
            }}
          />
        )}
        <div className={styles.row}>
          <Button type="submit" disabled={!ready || pending}>
            Resolve effective tags
          </Button>
        </div>
      </form>
      {pending ? <LoadingState label="Resolving current subject tags…" /> : null}
      {failed ? (
        <ErrorState description="Effective tags could not be resolved. Check the owned subject, context permission and current source facts, then retry." />
      ) : null}
      {result ? (
        <div className={styles.stack} aria-live="polite">
          <p>
            Tag revision {result.tag_revision}. Snapshot{' '}
            <time dateTime={result.as_of}>{result.as_of}</time>.
          </p>
          <p>
            Fresh queries apply current rules to retained history. Resolve again to read later rule
            or source changes.
          </p>
          {result.items.length ? (
            <Table
              caption="Effective subject tags"
              columns={columns}
              rows={result.items}
              rowKey={(item) => item.tag_id}
            />
          ) : (
            <p>No effective tags match this owned subject.</p>
          )}
        </div>
      ) : null}
    </div>
  )
}
