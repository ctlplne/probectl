// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/useAuth'
import { useEntityContexts } from '../../api/entities'
import {
  advanceImportPlan,
  configureImportSource,
  finalizeImportReview,
  importDiff,
  importRows,
  setImportReviewChoices,
  startImportPlan,
  type ImportChoice,
  type ImportDiffItem,
  type ImportDiffPage,
  type ImportRow,
  type ImportRowsPage,
} from '../../api/nmsImport'
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  Field,
  Select,
  Table,
  type Column,
} from '../../components'
import styles from '../pages.module.css'

type ChoiceAction = ImportChoice['action'] | ''
type PendingChoice = { action: ChoiceAction; target_entity_id: string }

export function NMSImportCard() {
  const { tenant, permissions } = useAuth()
  if (!permissions.includes('nms.import.read')) return null
  return (
    <ImportContents
      key={tenant.id}
      tenantID={tenant.id}
      canWrite={permissions.includes('nms.import.write')}
    />
  )
}

function ImportContents({ tenantID, canWrite }: { tenantID: string; canWrite: boolean }) {
  const contexts = useEntityContexts(tenantID)
  const available = useMemo(
    () => contexts.data?.pages.flatMap((page) => page.items) ?? [],
    [contexts.data],
  )
  const [contextID, setContextID] = useState('')
  const selectedContext = available.find((item) => item.context_id === contextID)
  const [instanceRef, setInstanceRef] = useState('')
  const [origin, setOrigin] = useState('')
  const [credentialRef, setCredentialRef] = useState('')
  const [planID, setPlanID] = useState('')
  const [snapshotHash, setSnapshotHash] = useState('')
  const [reviewHash, setReviewHash] = useState('')
  const [page, setPage] = useState<ImportRowsPage | null>(null)
  const [diffPage, setDiffPage] = useState<ImportDiffPage | null>(null)
  const [choices, setChoices] = useState<Record<number, PendingChoice>>({})
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    if (!contextID && available.length > 0) setContextID(available[0].context_id)
  }, [available, contextID])

  function chooseContext(next: string) {
    setContextID(next)
    setInstanceRef('')
    setOrigin('')
    setPlanID('')
    setSnapshotHash('')
    setReviewHash('')
    setPage(null)
    setDiffPage(null)
    setChoices({})
    setCredentialRef('')
    setMessage('')
    setError('')
  }

  async function run(action: () => Promise<void>) {
    setBusy(true)
    setError('')
    setMessage('')
    try {
      await action()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Import request failed.')
    } finally {
      setBusy(false)
    }
  }

  function showPage(next: ImportRowsPage) {
    setPage(next)
    setSnapshotHash(next.snapshot_hash)
    setChoices(
      Object.fromEntries(
        next.items.map((row) => [
          row.row_number,
          {
            action: row.reviewed ? (row.action as ChoiceAction) : '',
            target_entity_id: row.target_entity_id ?? '',
          },
        ]),
      ),
    )
  }

  function configure(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    void run(async () => {
      await configureImportSource({
        context_id: contextID,
        instance_ref: instanceRef,
        https_origin: origin,
        credential_ref: credentialRef,
      })
      setOrigin('')
      setCredentialRef('')
      setMessage('Source configured in this routing context. Start a new inert plan when ready.')
    })
  }

  function start() {
    void run(async () => {
      const result = await startImportPlan(contextID, instanceRef)
      setPlanID(result.plan_id)
      setSnapshotHash('')
      setReviewHash('')
      setPage(null)
      setDiffPage(null)
      setChoices({})
      setMessage('Inert capture plan started. Advance one source endpoint per request.')
    })
  }

  function advance() {
    void run(async () => {
      const result = await advanceImportPlan(contextID, planID)
      setMessage(`${result.completed_stage} complete; next stage: ${result.next_stage}.`)
      if (result.snapshot_hash) {
        setSnapshotHash(result.snapshot_hash)
        showPage(await importRows(contextID, planID))
      }
    })
  }

  function load(cursor?: number) {
    void run(async () => {
      showPage(await importRows(contextID, planID, cursor))
      setMessage('Redacted source rows loaded. Review every row before finalizing.')
    })
  }

  function setChoice(row: ImportRow, patch: Partial<PendingChoice>) {
    setChoices((current) => ({
      ...current,
      [row.row_number]: {
        action: current[row.row_number]?.action ?? '',
        target_entity_id: current[row.row_number]?.target_entity_id ?? '',
        ...patch,
      },
    }))
  }

  function saveChoices() {
    if (!page) return
    const batch: ImportChoice[] = page.items.flatMap((row) => {
      const choice = choices[row.row_number]
      if (
        !choice?.action ||
        (row.reviewed &&
          row.action === choice.action &&
          (row.target_entity_id ?? '') === choice.target_entity_id)
      )
        return []
      return [
        {
          row_number: row.row_number,
          action: choice.action,
          ...(choice.action === 'update' ? { target_entity_id: choice.target_entity_id } : {}),
        },
      ]
    })
    if (batch.length === 0) {
      setMessage('Choose an action for at least one row on this page.')
      return
    }
    void run(async () => {
      await setImportReviewChoices(contextID, planID, snapshotHash, batch)
      const cursor = page.items.length > 0 ? page.items[0].row_number - 1 : undefined
      showPage(await importRows(contextID, planID, cursor))
      setMessage(
        `${batch.length} explicit choice${batch.length === 1 ? '' : 's'} saved. No destination changed.`,
      )
    })
  }

  function finalize() {
    void run(async () => {
      const result = await finalizeImportReview(contextID, planID, snapshotHash)
      setReviewHash(result.review_hash)
      setDiffPage(await importDiff(contextID, planID, result.review_hash))
      setMessage(`Dry run frozen: ${result.review_hash}. No destination changed.`)
      const cursor = page && page.items.length > 0 ? page.items[0].row_number - 1 : undefined
      showPage(await importRows(contextID, planID, cursor))
    })
  }

  function loadDiff(cursor?: number) {
    void run(async () => {
      setDiffPage(await importDiff(contextID, planID, reviewHash, cursor))
      setMessage('Frozen destination comparison loaded. No destination changed.')
    })
  }

  const diffColumns: Column<ImportDiffItem>[] = [
    {
      key: 'source',
      header: 'Source identity',
      render: (row) => `${row.object_kind} ${row.external_id}`,
    },
    { key: 'action', header: 'Decision', render: (row) => row.action },
    {
      key: 'destination',
      header: 'Exact destination',
      render: (row) =>
        row.target_entity_id ? <code>{row.target_entity_id}</code> : 'New or unchanged',
    },
    {
      key: 'labels',
      header: 'Label change',
      render: (row) =>
        row.proposed_label ? `${row.current_label || 'New'} → ${row.proposed_label}` : 'No change',
    },
    {
      key: 'residual',
      header: 'Still unmapped',
      render: (row) => (row.unmapped_codes.length > 0 ? row.unmapped_codes.join(', ') : 'None'),
    },
  ]

  const columns: Column<ImportRow>[] = [
    {
      key: 'source',
      header: 'Source row',
      render: (row) => (
        <span className={styles.stack}>
          <strong>
            {row.object_kind}: {row.label || row.external_id}
          </strong>
          <small>
            <code>{row.external_id}</code>
            {row.address ? ` · ${row.address}` : ''}
          </small>
        </span>
      ),
    },
    {
      key: 'unmapped',
      header: 'Unmapped fields',
      render: (row) => (row.unmapped_codes.length > 0 ? row.unmapped_codes.join(', ') : 'None'),
    },
    {
      key: 'choice',
      header: 'Explicit choice',
      render: (row) =>
        canWrite && !reviewHash ? (
          <Select
            label={`Choice for ${row.object_kind} ${row.external_id}`}
            value={choices[row.row_number]?.action ?? ''}
            onChange={(event) =>
              setChoice(row, { action: event.target.value as ChoiceAction, target_entity_id: '' })
            }
            options={[
              { value: '', label: 'Choose action' },
              ...((row.object_kind === 'device' || row.object_kind === 'site') &&
              row.unmapped_codes.length === 0
                ? [
                    { value: 'create', label: 'Create' },
                    { value: 'update', label: 'Update exact ID' },
                  ]
                : []),
              { value: 'skip', label: 'Skip' },
              ...(row.unmapped_codes.length > 0 ? [{ value: 'unmapped', label: 'Unmapped' }] : []),
            ]}
          />
        ) : row.reviewed ? (
          row.action
        ) : (
          'Awaiting review'
        ),
    },
    {
      key: 'target',
      header: 'Update target',
      render: (row) =>
        canWrite && !reviewHash && choices[row.row_number]?.action === 'update' ? (
          <Field
            label={`Exact target entity ID for ${row.external_id}`}
            value={choices[row.row_number]?.target_entity_id ?? ''}
            onChange={(event) => setChoice(row, { target_entity_id: event.target.value })}
          />
        ) : row.target_entity_id ? (
          <code>{row.target_entity_id}</code>
        ) : (
          '—'
        ),
    },
  ]

  return (
    <Card data-nms-import>
      <CardHeader
        title="Incumbent NMS import"
        description="Capture redacted source inventory per tenant and routing context. Review every action before a destination can change."
      />
      <CardBody>
        <div className={styles.stack}>
          <div className={styles.row}>
            <Select
              label="Import routing context"
              value={contextID}
              onChange={(event) => chooseContext(event.target.value)}
              options={[
                { value: '', label: 'Choose a site and VRF' },
                ...available.map((item) => ({
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
          {contexts.isError ? <p role="alert">Routing contexts could not be loaded.</p> : null}
          {selectedContext ? (
            <p>
              Selected routing context:{' '}
              <strong>
                {selectedContext.site_label} / {selectedContext.vrf_label}
              </strong>
            </p>
          ) : null}
          {canWrite && contextID ? (
            <form className={styles.form} onSubmit={configure}>
              <h3>Configure LibreNMS source</h3>
              <p>
                Live access requires deployment-approved HTTPS egress and a tenant-scoped secret
                reference.
              </p>
              <div className={styles.row}>
                <Field
                  label="Source instance"
                  required
                  value={instanceRef}
                  onChange={(event) => setInstanceRef(event.target.value)}
                />
                <Field
                  label="HTTPS origin"
                  required
                  value={origin}
                  onChange={(event) => setOrigin(event.target.value)}
                />
                <Field
                  label="Credential reference"
                  required
                  value={credentialRef}
                  onChange={(event) => setCredentialRef(event.target.value)}
                />
                <Button type="submit" disabled={busy}>
                  Configure source
                </Button>
              </div>
            </form>
          ) : null}
          {canWrite && contextID ? (
            <Button onClick={start} disabled={busy || !instanceRef}>
              Start inert plan
            </Button>
          ) : null}
          {contextID ? (
            <div className={styles.row}>
              <Field
                label="Import plan ID"
                value={planID}
                onChange={(event) => {
                  setPlanID(event.target.value)
                  setPage(null)
                  setSnapshotHash('')
                  setReviewHash('')
                  setDiffPage(null)
                }}
              />
              <Button onClick={() => load()} disabled={busy || !planID}>
                Load redacted rows
              </Button>
              {canWrite ? (
                <Button onClick={advance} disabled={busy || !planID}>
                  Advance one endpoint
                </Button>
              ) : null}
            </div>
          ) : null}
          {error ? <p role="alert">{error}</p> : null}
          {message ? <p role="status">{message}</p> : null}
          {page ? (
            <div className={styles.stack}>
              <p>
                {page.row_count} source rows · snapshot <code>{snapshotHash}</code>. Unsupported
                fields remain visible; no action is automatic.
              </p>
              <Table
                caption="Import source rows"
                rows={page.items}
                rowKey={(row) => String(row.row_number)}
                columns={columns}
              />
              <div className={styles.row}>
                {canWrite && !reviewHash ? (
                  <Button onClick={saveChoices} disabled={busy || page.items.length === 0}>
                    Save page choices
                  </Button>
                ) : null}
                {page.next_cursor !== undefined ? (
                  <Button onClick={() => load(page.next_cursor)} disabled={busy}>
                    Next source page
                  </Button>
                ) : null}
                {canWrite && !reviewHash ? (
                  <Button onClick={finalize} disabled={busy}>
                    Finalize dry run
                  </Button>
                ) : null}
              </div>
            </div>
          ) : null}
          {planID ? (
            <div className={styles.row}>
              <Field
                label="Frozen review hash"
                value={reviewHash}
                onChange={(event) => {
                  setReviewHash(event.target.value)
                  setDiffPage(null)
                }}
              />
              <Button onClick={() => loadDiff()} disabled={busy || !reviewHash}>
                Load destination comparison
              </Button>
            </div>
          ) : null}
          {diffPage ? (
            <div className={styles.stack}>
              <p>
                {diffPage.row_count} reviewed rows. This comparison makes no destination changes.
              </p>
              <Table
                caption="Import destination comparison"
                rows={diffPage.items}
                rowKey={(row) => String(row.row_number)}
                columns={diffColumns}
              />
              {diffPage.next_cursor !== undefined ? (
                <Button onClick={() => loadDiff(diffPage.next_cursor)} disabled={busy}>
                  Next comparison page
                </Button>
              ) : null}
            </div>
          ) : null}
        </div>
      </CardBody>
    </Card>
  )
}
