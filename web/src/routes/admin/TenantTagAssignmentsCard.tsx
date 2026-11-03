// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/useAuth'
import { useEntityContexts } from '../../api/entities'
import {
  MAX_TAG_VALUE_INPUT_UNITS,
  tagValueTooLong,
  useCreateTagAssignment,
  useDeleteTagAssignment,
  useTagAssignments,
  useTagDefinitions,
  useUpdateTagAssignment,
  type ManualTagAssignmentInput,
  type TagAssignment,
} from '../../api/tags'
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

const targetKinds = ['device', 'interface', 'prefix', 'exporter', 'agent', 'test'] as const
type TargetKind = (typeof targetKinds)[number]

export function TenantTagAssignmentsCard() {
  const { permissions, tenant } = useAuth()
  if (!permissions.includes('tags.read')) return null
  return (
    <TenantTagAssignmentsContents
      key={tenant.id}
      tenantID={tenant.id}
      canWrite={permissions.includes('tags.write')}
    />
  )
}

function TenantTagAssignmentsContents({
  tenantID,
  canWrite,
}: {
  tenantID: string
  canWrite: boolean
}) {
  const contexts = useEntityContexts(tenantID)
  const allContexts = useMemo(
    () => contexts.data?.pages.flatMap((page) => page.items) ?? [],
    [contexts.data],
  )
  const definitions = useTagDefinitions(tenantID)
  const [contextID, setContextID] = useState('')
  const [pageIndex, setPageIndex] = useState(0)
  const assignments = useTagAssignments(tenantID, contextID)
  const create = useCreateTagAssignment(tenantID, contextID)
  const update = useUpdateTagAssignment(tenantID, contextID)
  const remove = useDeleteTagAssignment(tenantID, contextID)
  const [editing, setEditing] = useState<TagAssignment | null>(null)
  const [deleting, setDeleting] = useState<TagAssignment | null>(null)
  const [tagID, setTagID] = useState('')
  const [targetKind, setTargetKind] = useState<TargetKind>('device')
  const [targetID, setTargetID] = useState('')
  const [exporterAgentID, setExporterAgentID] = useState('')
  const [exporterSourceRef, setExporterSourceRef] = useState('')
  const [value, setValue] = useState('')

  useEffect(() => {
    if (!contextID && allContexts.length > 0) setContextID(allContexts[0].context_id)
  }, [allContexts, contextID])
  useEffect(() => {
    if (!definitions.data) return
    if (!definitions.data.items.some((item) => item.id === tagID)) {
      setTagID(definitions.data.items[0]?.id ?? '')
    }
  }, [definitions.data, tagID])

  function chooseContext(id: string) {
    setContextID(id)
    setPageIndex(0)
    setEditing(null)
  }

  function editAssignment(item: TagAssignment) {
    if (item.source !== 'manual') return
    setEditing(item)
    setTagID(item.tag_id)
    setTargetKind(item.target_kind)
    setTargetID(item.target_kind === 'exporter' ? '' : item.target_id)
    setExporterAgentID(item.exporter_agent_id ?? '')
    setExporterSourceRef(item.exporter_source_ref ?? '')
    setValue(item.value)
  }

  function input(): ManualTagAssignmentInput {
    const base: ManualTagAssignmentInput = {
      tag_id: tagID,
      target_kind: targetKind,
      value: value.trim(),
    }
    if (targetKind === 'exporter')
      return {
        ...base,
        exporter_agent_id: exporterAgentID.trim(),
        exporter_source_ref: exporterSourceRef.trim(),
      }
    return { ...base, target_id: targetID.trim() }
  }

  async function onSave(event: FormEvent) {
    event.preventDefault()
    if (definitions.isPending || definitions.isError) return
    if (!contextID || !tagID || !value.trim() || tagValueTooLong(value)) return
    if (
      targetKind === 'exporter'
        ? !exporterAgentID.trim() || !exporterSourceRef.trim()
        : !targetID.trim()
    )
      return
    try {
      const body = input()
      if (editing) await update.mutateAsync({ id: editing.id, input: body })
      else await create.mutateAsync(body)
      setEditing(null)
      setPageIndex(0)
      setTargetID('')
      setExporterAgentID('')
      setExporterSourceRef('')
      setValue('')
    } catch {
      // Keep the form and show the exact server error.
    }
  }

  async function onDelete() {
    if (!deleting) return
    try {
      await remove.mutateAsync(deleting.id)
      setDeleting(null)
      setPageIndex(0)
    } catch {
      // Keep confirmation visible with the error.
    }
  }

  const rows = assignments.data?.pages[pageIndex]?.items ?? []
  const keyByID = new Map<string, string>(
    definitions.data?.items.map((definition): [string, string] => [
      definition.id,
      definition.key,
    ]) ?? [],
  )
  const columns: Column<TagAssignment>[] = [
    {
      key: 'tag',
      header: 'Tag',
      render: (row) => <code>{keyByID.get(row.tag_id) ?? row.tag_id}</code>,
    },
    { key: 'target', header: 'Target', render: (row) => `${row.target_kind}: ${row.target_id}` },
    {
      key: 'value',
      header: 'Value',
      render: (row) => <TagValue value={row.value} />,
    },
    { key: 'source', header: 'Source', render: (row) => row.source },
    {
      key: 'provenance',
      header: 'Provenance',
      render: (row) =>
        row.source === 'netbox' ? (
          <span>
            {row.source_ref ?? 'Unknown source'}
            {row.reviewed_at ? ` · reviewed ${row.reviewed_at}` : ''}
          </span>
        ) : (
          'Operator'
        ),
    },
    {
      key: 'actions',
      header: 'Actions',
      render: (row) =>
        canWrite && row.source === 'manual' ? (
          <div className={styles.row}>
            <Button
              size="sm"
              onClick={() => editAssignment(row)}
              aria-label={`Edit assignment ${row.id}`}
            >
              Edit
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setDeleting(row)}
              aria-label={`Delete assignment ${row.id}`}
            >
              Delete
            </Button>
          </div>
        ) : (
          'Read only'
        ),
    },
  ]

  return (
    <Card data-tenant-tag-assignments>
      <CardHeader
        title="Manual tag assignments"
        description="Assign a tag to a tenant-owned subject in one routing context. Manual values take precedence over rules and reviewed imports."
      />
      <CardBody>
        <div className={styles.stack}>
          {definitions.isPending ? <LoadingState label="Loading assignment tag keys…" /> : null}
          {definitions.isError ? (
            <ErrorState description="Assignment tag keys could not be loaded." />
          ) : null}
          {contexts.isPending ? <LoadingState label="Loading routing contexts…" /> : null}
          {contexts.isError ? (
            <ErrorState description="Routing contexts could not be loaded." />
          ) : null}
          {contexts.data ? (
            <div className={styles.row}>
              <Select
                label="Assignment routing context"
                value={contextID}
                onChange={(event) => chooseContext(event.target.value)}
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
                  Load more contexts
                </Button>
              ) : null}
            </div>
          ) : null}
          {contextID ? (
            <>
              {assignments.isPending ? <LoadingState label="Loading tag assignments…" /> : null}
              {assignments.isError ? (
                <ErrorState description="Tag assignments could not be loaded." />
              ) : null}
              {assignments.data ? (
                <>
                  <Table
                    caption="Tag assignments in selected routing context"
                    columns={columns}
                    rows={rows}
                    rowKey={(row) => row.id}
                    empty="No tag assignments in this context."
                  />
                  <div className={styles.row}>
                    <Button disabled={pageIndex === 0} onClick={() => setPageIndex(pageIndex - 1)}>
                      Previous page
                    </Button>
                    <span aria-live="polite">Page {pageIndex + 1}</span>
                    <Button
                      disabled={
                        assignments.isFetchingNextPage ||
                        (pageIndex + 1 >= assignments.data.pages.length && !assignments.hasNextPage)
                      }
                      onClick={() => {
                        if (pageIndex + 1 < assignments.data.pages.length)
                          setPageIndex(pageIndex + 1)
                        else
                          void assignments.fetchNextPage().then(() => setPageIndex(pageIndex + 1))
                      }}
                    >
                      Next page
                    </Button>
                  </div>
                </>
              ) : null}
              {canWrite && !definitions.isError && definitions.data?.items.length ? (
                <form className={styles.form} onSubmit={(event) => void onSave(event)}>
                  <h3>{editing ? 'Edit manual assignment' : 'Create manual assignment'}</h3>
                  <div className={styles.row}>
                    <Select
                      label="Assignment tag key"
                      value={tagID}
                      onChange={(event) => setTagID(event.target.value)}
                      options={definitions.data.items.map((item) => ({
                        value: item.id,
                        label: item.key,
                      }))}
                    />
                    <Select
                      label="Assignment target kind"
                      value={targetKind}
                      onChange={(event) => {
                        setTargetKind(event.target.value as TargetKind)
                        setTargetID('')
                        setExporterAgentID('')
                        setExporterSourceRef('')
                      }}
                      options={targetKinds.map((kind) => ({ value: kind, label: kind }))}
                    />
                  </div>
                  <div className={styles.row}>
                    {targetKind === 'exporter' ? (
                      <>
                        <Field
                          label="Exporter agent ID"
                          required
                          value={exporterAgentID}
                          onChange={(event) => setExporterAgentID(event.target.value)}
                        />
                        <Field
                          label="Owned exporter source reference"
                          required
                          value={exporterSourceRef}
                          onChange={(event) => setExporterSourceRef(event.target.value)}
                        />
                      </>
                    ) : (
                      <Field
                        label="Owned target ID"
                        required
                        value={targetID}
                        hint="Use the ID of a subject already bound to this routing context."
                        onChange={(event) => setTargetID(event.target.value)}
                      />
                    )}
                    <Field
                      label="Assignment value"
                      required
                      maxLength={MAX_TAG_VALUE_INPUT_UNITS}
                      hint="Up to 24,000 Unicode characters."
                      error={tagValueTooLong(value) ? 'Use at most 24,000 characters.' : undefined}
                      value={value}
                      onChange={(event) => setValue(event.target.value)}
                    />
                    <Button
                      type="submit"
                      disabled={
                        create.isPending ||
                        update.isPending ||
                        !tagID ||
                        !value.trim() ||
                        tagValueTooLong(value)
                      }
                    >
                      {editing ? 'Save assignment' : 'Create assignment'}
                    </Button>
                    {editing ? <Button onClick={() => setEditing(null)}>Cancel edit</Button> : null}
                  </div>
                  {create.isError ? <p role="alert">{create.error.message}</p> : null}
                  {update.isError ? <p role="alert">{update.error.message}</p> : null}
                </form>
              ) : null}
            </>
          ) : (
            <p>Choose a routing context to inspect tag assignments.</p>
          )}
        </div>
      </CardBody>
      <Modal
        open={Boolean(deleting)}
        onClose={() => setDeleting(null)}
        title="Delete manual assignment?"
        footer={
          <>
            <Button onClick={() => setDeleting(null)}>Cancel</Button>
            <Button variant="danger" disabled={remove.isPending} onClick={() => void onDelete()}>
              Delete assignment
            </Button>
          </>
        }
      >
        <p>
          The current tag value for matching retained history may change after this assignment is
          removed.
        </p>
        {remove.isError ? <p role="alert">{remove.error.message}</p> : null}
      </Modal>
    </Card>
  )
}
