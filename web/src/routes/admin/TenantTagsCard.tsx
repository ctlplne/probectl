// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/useAuth'
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  LoadingState,
  Modal,
  Table,
  type Column,
} from '../../components'
import {
  useCreateTagDefinition,
  useDeleteTagDefinition,
  useRenameTagDefinition,
  useTagDefinitions,
  type TagDefinition,
} from '../../api/tags'
import styles from './EntityRegistryCard.module.css'

export function TenantTagsCard() {
  const { permissions, tenant } = useAuth()
  if (!permissions.includes('tags.read')) return null
  return (
    <TenantTagsContents
      key={tenant.id}
      tenantID={tenant.id}
      canWrite={permissions.includes('tags.write')}
    />
  )
}

function TenantTagsContents({ tenantID, canWrite }: { tenantID: string; canWrite: boolean }) {
  const definitions = useTagDefinitions(tenantID)
  const create = useCreateTagDefinition(tenantID)
  const rename = useRenameTagDefinition(tenantID)
  const remove = useDeleteTagDefinition(tenantID)
  const [newKey, setNewKey] = useState('')
  const [renameTarget, setRenameTarget] = useState<TagDefinition | null>(null)
  const [renameKey, setRenameKey] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<TagDefinition | null>(null)

  async function onCreate(event: FormEvent) {
    event.preventDefault()
    if (!newKey.trim()) return
    try {
      await create.mutateAsync(newKey.trim())
      setNewKey('')
    } catch {
      // The mutation error is shown next to the form.
    }
  }

  async function onRename(event: FormEvent) {
    event.preventDefault()
    if (!renameTarget || !renameKey.trim()) return
    try {
      await rename.mutateAsync({ id: renameTarget.id, key: renameKey.trim() })
      setRenameTarget(null)
      setRenameKey('')
    } catch {
      // The mutation error is shown next to the form.
    }
  }

  async function onDelete() {
    if (!deleteTarget) return
    try {
      await remove.mutateAsync(deleteTarget.id)
      setDeleteTarget(null)
    } catch {
      // Keep the dialog open so the operator can read the error.
    }
  }

  const columns: Column<TagDefinition>[] = [
    { key: 'key', header: 'Tag key', render: (row) => <code>{row.key}</code> },
    { key: 'id', header: 'Stable ID', render: (row) => <code>{row.id}</code> },
    {
      key: 'actions',
      header: 'Actions',
      render: (row) =>
        canWrite ? (
          <div className={styles.row}>
            <Button
              size="sm"
              onClick={() => {
                setRenameTarget(row)
                setRenameKey(row.key)
                rename.reset()
              }}
              aria-label={`Rename tag ${row.key}`}
            >
              Rename
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setDeleteTarget(row)}
              aria-label={`Delete tag ${row.key}`}
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
    <Card data-tenant-tags>
      <CardHeader
        title="Tenant tags"
        description="Name reusable keys for your tenant. Rules and assignments use these stable IDs; current rules label retained history when you query it."
      />
      <CardBody>
        <div className={styles.stack}>
          {definitions.isPending ? <LoadingState label="Loading tenant tags…" /> : null}
          {definitions.isError ? (
            <ErrorState description="Tenant tags could not be loaded." />
          ) : null}
          {definitions.data ? (
            <Table
              caption="Tenant tag definitions"
              columns={columns}
              rows={definitions.data.items}
              rowKey={(row) => row.id}
              empty="No tenant tag keys have been created."
            />
          ) : null}
          {canWrite ? (
            <form className={styles.form} onSubmit={(event) => void onCreate(event)}>
              <h3>Create tag key</h3>
              <div className={styles.row}>
                <Field
                  label="Key"
                  required
                  maxLength={64}
                  value={newKey}
                  onChange={(event) => setNewKey(event.target.value)}
                />
                <Button type="submit" disabled={create.isPending || !newKey.trim()}>
                  Create key
                </Button>
              </div>
              {create.isError ? <p role="alert">{create.error.message}</p> : null}
              {create.isSuccess ? <p role="status">Tag key created.</p> : null}
            </form>
          ) : null}
          {canWrite && renameTarget ? (
            <form className={styles.form} onSubmit={(event) => void onRename(event)}>
              <h3>Rename {renameTarget.key}</h3>
              <p>Saved flow views using this key will need review after a rename.</p>
              <div className={styles.row}>
                <Field
                  label="New key"
                  required
                  maxLength={64}
                  value={renameKey}
                  onChange={(event) => setRenameKey(event.target.value)}
                />
                <Button type="submit" disabled={rename.isPending || !renameKey.trim()}>
                  Save name
                </Button>
                <Button onClick={() => setRenameTarget(null)}>Cancel</Button>
              </div>
              {rename.isError ? <p role="alert">{rename.error.message}</p> : null}
            </form>
          ) : null}
        </div>
      </CardBody>
      <Modal
        open={Boolean(deleteTarget)}
        onClose={() => setDeleteTarget(null)}
        title={`Delete tag ${deleteTarget?.key ?? ''}?`}
        footer={
          <>
            <Button onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="danger" disabled={remove.isPending} onClick={() => void onDelete()}>
              Delete key and assignments
            </Button>
          </>
        }
      >
        <p>
          Deleting this key also removes its tenant rules and assignments. Saved flow views using it
          will refuse to run.
        </p>
        {remove.isError ? <p role="alert">{remove.error.message}</p> : null}
      </Modal>
    </Card>
  )
}
