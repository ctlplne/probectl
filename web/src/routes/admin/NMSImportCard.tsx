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
  applyImportAlertTarget,
  applyImportReview,
  configureImportSource,
  finalizeImportReview,
  importDiff,
  importPollProposals,
  importRows,
  previewImportPollTarget,
  previewImportAlertTarget,
  setImportReviewChoices,
  startImportPlan,
  verifyImportBeforeApply,
  type ImportChoice,
  type ImportDiffItem,
  type ImportDiffPage,
  type ImportRow,
  type ImportRowsPage,
  type ImportPollProposalsPage,
  type ImportPollTargetPreview,
  type ImportAlertTargetPreview,
  type ImportAlertTargetApplyResult,
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

function canCreateImportRow(row: ImportRow): boolean {
  if (row.object_kind === 'device' || row.object_kind === 'site')
    return row.unmapped_codes.length === 0
  if (row.object_kind === 'group')
    return (
      Boolean(row.label) &&
      row.unmapped_codes.includes('group_unmapped') &&
      row.unmapped_codes.every(
        (code) => code === 'group_unmapped' || code === 'dynamic_predicate_unmapped',
      )
    )
  if (row.object_kind === 'membership')
    return row.unmapped_codes.length === 1 && row.unmapped_codes[0] === 'group_unmapped'
  if (row.object_kind === 'poll_setting')
    return (
      Boolean(row.parent_external_id) &&
      (row.poll_seconds ?? 0) >= 15 &&
      (row.poll_seconds ?? 0) <= 86400 &&
      row.unmapped_codes.length === 1 &&
      row.unmapped_codes[0] === 'poll_proposal'
    )
  return false
}

function canRemoveImportMember(row: ImportRow): boolean {
  return (
    row.object_kind === 'membership' &&
    row.unmapped_codes.length === 1 &&
    row.unmapped_codes[0] === 'member_removal_candidate'
  )
}

export function NMSImportCard() {
  const { tenant, permissions } = useAuth()
  if (!permissions.includes('nms.import.read')) return null
  return (
    <ImportContents
      key={tenant.id}
      tenantID={tenant.id}
      canWrite={permissions.includes('nms.import.write')}
      canPreviewTarget={permissions.includes('entities.read')}
      canApplyAlert={
        permissions.includes('nms.import.write') &&
        permissions.includes('entities.read') &&
        permissions.includes('alert.write')
      }
    />
  )
}

function ImportContents({
  tenantID,
  canWrite,
  canPreviewTarget,
  canApplyAlert,
}: {
  tenantID: string
  canWrite: boolean
  canPreviewTarget: boolean
  canApplyAlert: boolean
}) {
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
  const [proofReady, setProofReady] = useState(false)
  const [applyComplete, setApplyComplete] = useState(false)
  const [page, setPage] = useState<ImportRowsPage | null>(null)
  const [diffPage, setDiffPage] = useState<ImportDiffPage | null>(null)
  const [pollItemID, setPollItemID] = useState('')
  const [pollAgentID, setPollAgentID] = useState('')
  const [pollAddress, setPollAddress] = useState('')
  const [pollPreview, setPollPreview] = useState<ImportPollTargetPreview | null>(null)
  const [pollProposals, setPollProposals] = useState<ImportPollProposalsPage | null>(null)
  const [alertRuleID, setAlertRuleID] = useState('')
  const [alertAgentID, setAlertAgentID] = useState('')
  const [alertAddress, setAlertAddress] = useState('')
  const [alertPreview, setAlertPreview] = useState<ImportAlertTargetPreview | null>(null)
  const [alertResult, setAlertResult] = useState<ImportAlertTargetApplyResult | null>(null)
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
    setProofReady(false)
    setApplyComplete(false)
    setPage(null)
    setDiffPage(null)
    setPollPreview(null)
    setPollProposals(null)
    setAlertPreview(null)
    setAlertResult(null)
    setAlertRuleID('')
    setAlertAgentID('')
    setAlertAddress('')
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
    setPollPreview(null)
    setPollProposals(null)
    setAlertPreview(null)
    setAlertResult(null)
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
      setProofReady(false)
      setApplyComplete(false)
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

  function previewPollTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!page) return
    void run(async () => {
      const preview = await previewImportPollTarget({
        context_id: contextID,
        source_id: page.source_id,
        item_external_id: pollItemID,
        agent_id: pollAgentID,
        target_address: pollAddress,
      })
      setPollPreview(preview)
      setMessage('Current source item and assigned device-agent target verified. No agent changed.')
    })
  }

  function loadPollProposals(cursor?: string) {
    if (!page) return
    void run(async () => {
      setPollProposals(await importPollProposals(contextID, page.source_id, cursor))
      setMessage('Applied source cadence proposals loaded. Agent configuration is still separate.')
    })
  }

  function previewAlertTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!page) return
    void run(async () => {
      const preview = await previewImportAlertTarget({
        context_id: contextID,
        source_id: page.source_id,
        rule_external_id: alertRuleID,
        agent_id: alertAgentID,
        target_address: alertAddress,
      })
      setAlertPreview(preview)
      setAlertResult(null)
      setMessage(
        'Finite source rule and current operator-owned agent target verified. No alert changed.',
      )
    })
  }

  function applyAlertTarget() {
    if (!alertPreview) return
    void run(async () => {
      const result = await applyImportAlertTarget(alertPreview)
      setAlertResult(result)
      setMessage(
        result.created
          ? 'Disabled, channel-free native alert created. Enable it separately after review.'
          : 'Existing native alert unchanged. Its enabled state was not changed.',
      )
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
      setProofReady(false)
      setApplyComplete(false)
      setDiffPage(await importDiff(contextID, planID, result.review_hash))
      setMessage(`Dry run frozen: ${result.review_hash}. No destination changed.`)
      const cursor = page && page.items.length > 0 ? page.items[0].row_number - 1 : undefined
      showPage(await importRows(contextID, planID, cursor))
    })
  }

  function loadDiff(cursor?: number) {
    void run(async () => {
      const next = await importDiff(contextID, planID, reviewHash, cursor)
      setDiffPage(next)
      setSnapshotHash(next.snapshot_hash)
      setMessage('Pending reviewed choices loaded. Reading this page made no destination change.')
    })
  }

  function verifySource() {
    void run(async () => {
      setProofReady(false)
      const result = await verifyImportBeforeApply(contextID, planID, snapshotHash, reviewHash)
      setProofReady(result.ready)
      setMessage(
        result.ready
          ? 'Source recheck complete. Apply one reviewed chunk within 60 seconds.'
          : `${result.verified_stage} rechecked; next source endpoint: ${result.next_stage}.`,
      )
    })
  }

  function applyChunk() {
    void run(async () => {
      const result = await applyImportReview(contextID, planID, snapshotHash, reviewHash)
      setProofReady(false)
      setApplyComplete(result.state === 'applied')
      if (page) {
        const cursor = page.items.length > 0 ? page.items[0].row_number - 1 : undefined
        showPage(await importRows(contextID, planID, cursor))
      }
      setMessage(
        `${result.applied} applied, ${result.skipped} skipped; ${result.remaining} rows remain. ` +
          (result.state === 'applied'
            ? 'Import complete.'
            : 'Recheck the source before the next chunk.'),
      )
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
      key: 'changes',
      header: 'Destination change',
      render: (row) => (row.changed_fields.length > 0 ? row.changed_fields.join(', ') : 'None'),
    },
    {
      key: 'destination',
      header: 'Exact destination',
      render: (row) =>
        row.target_entity_id ? <code>{row.target_entity_id}</code> : 'New or unchanged',
    },
    {
      key: 'labels',
      header: 'Reviewed value',
      render: (row) => {
        if (row.object_kind === 'poll_setting' && row.proposed_poll_seconds)
          return `${row.current_poll_seconds ? `${row.current_poll_seconds}s` : 'New'} → ${row.proposed_poll_seconds}s`
        return row.proposed_label
          ? `${row.current_label || 'New'} → ${row.proposed_label}`
          : 'No change'
      },
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
            {row.object_kind === 'poll_setting' && row.poll_seconds
              ? ` · ${row.poll_seconds}s proposal for host ${row.parent_external_id}`
              : ''}
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
      key: 'applied',
      header: 'Apply status and source binding',
      render: (row) => (
        <span className={styles.stack}>
          <strong>{row.state}</strong>
          {row.applied_at ? <time dateTime={row.applied_at}>{row.applied_at}</time> : null}
          {row.bound_entity_id ? (
            <small>
              Bound entity <code>{row.bound_entity_id}</code>
              {row.binding_plan_id ? (
                <>
                  {' '}
                  via plan <code>{row.binding_plan_id}</code>
                </>
              ) : null}
            </small>
          ) : null}
        </span>
      ),
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
              ...(canCreateImportRow(row)
                ? [
                    { value: 'create', label: 'Create' },
                    ...(row.object_kind === 'device' || row.object_kind === 'site'
                      ? [{ value: 'update', label: 'Update exact ID' }]
                      : row.object_kind === 'group'
                        ? [{ value: 'update', label: 'Update source group' }]
                        : row.object_kind === 'poll_setting'
                          ? [{ value: 'update', label: 'Update source proposal' }]
                          : []),
                  ]
                : []),
              ...(canRemoveImportMember(row)
                ? [{ value: 'remove', label: 'Remove exact member' }]
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
        canWrite &&
        !reviewHash &&
        choices[row.row_number]?.action === 'update' &&
        (row.object_kind === 'device' || row.object_kind === 'site') ? (
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
                  setProofReady(false)
                  setApplyComplete(false)
                  setDiffPage(null)
                  setPollPreview(null)
                  setPollProposals(null)
                  setAlertPreview(null)
                  setAlertResult(null)
                  setAlertRuleID('')
                  setAlertAgentID('')
                  setAlertAddress('')
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
                {page.row_count} source rows · source <code>{page.source_id}</code> · snapshot{' '}
                <code>{snapshotHash}</code>. Unsupported fields remain visible; no action is
                automatic.
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
          {page ? (
            <div className={styles.stack}>
              <Button onClick={() => loadPollProposals()} disabled={busy}>
                List applied polling proposals
              </Button>
              {pollProposals ? (
                <div>
                  <h3>Inert source cadences</h3>
                  {pollProposals.items.length === 0 ? (
                    <p>No applied cadence proposals on this page.</p>
                  ) : null}
                  <ul>
                    {pollProposals.items.map((proposal) => (
                      <li key={proposal.item_external_id}>
                        Item <code>{proposal.item_external_id}</code> for source host{' '}
                        <code>{proposal.host_external_id}</code>: {proposal.poll_seconds}s, revision{' '}
                        {proposal.revision}.{' '}
                        {canPreviewTarget ? (
                          <Button
                            onClick={() => {
                              setPollItemID(proposal.item_external_id)
                              setPollPreview(null)
                            }}
                          >
                            Select item
                          </Button>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                  {pollProposals.next_cursor ? (
                    <Button
                      onClick={() => loadPollProposals(pollProposals.next_cursor)}
                      disabled={busy}
                    >
                      Next proposal page
                    </Button>
                  ) : null}
                </div>
              ) : null}
            </div>
          ) : null}
          {canPreviewTarget && page ? (
            <form className={styles.form} onSubmit={previewPollTarget}>
              <h3>Preview an applied polling proposal</h3>
              <p>
                Select the exact source item and current assigned agent target. This view contains
                no device credential and does not change the running agent.
              </p>
              <div className={styles.row}>
                <Field
                  label="Source item UUID"
                  required
                  value={pollItemID}
                  onChange={(event) => setPollItemID(event.target.value)}
                />
                <Field
                  label="Assigned agent ID"
                  required
                  value={pollAgentID}
                  onChange={(event) => setPollAgentID(event.target.value)}
                />
                <Field
                  label="Assigned target address"
                  required
                  value={pollAddress}
                  onChange={(event) => setPollAddress(event.target.value)}
                />
                <Button type="submit" disabled={busy}>
                  Verify current target
                </Button>
              </div>
              {pollPreview ? (
                <p role="status">
                  Canonical device <code>{pollPreview.entity_id}</code> on agent{' '}
                  <code>{pollPreview.agent_id}</code> at <code>{pollPreview.target_address}</code>:{' '}
                  {pollPreview.poll_seconds}s, revision {pollPreview.revision}. Apply a separately
                  reviewed device-agent configuration to activate it.
                </p>
              ) : null}
            </form>
          ) : null}
          {canPreviewTarget && page ? (
            <form className={styles.form} onSubmit={previewAlertTarget}>
              <h3>Review a LibreNMS port-down alert</h3>
              <p>
                Enter the exact source rule and assigned agent target. The source address cannot
                choose a target. Preview never creates or enables an alert.
              </p>
              <div className={styles.row}>
                <Field
                  label="Source rule ID"
                  required
                  value={alertRuleID}
                  onChange={(event) => {
                    setAlertRuleID(event.target.value)
                    setAlertPreview(null)
                    setAlertResult(null)
                  }}
                />
                <Field
                  label="Alert agent ID"
                  required
                  value={alertAgentID}
                  onChange={(event) => {
                    setAlertAgentID(event.target.value)
                    setAlertPreview(null)
                    setAlertResult(null)
                  }}
                />
                <Field
                  label="Alert target address"
                  required
                  value={alertAddress}
                  onChange={(event) => {
                    setAlertAddress(event.target.value)
                    setAlertPreview(null)
                    setAlertResult(null)
                  }}
                />
                <Button type="submit" disabled={busy}>
                  Verify alert target
                </Button>
              </div>
              {alertPreview ? (
                <div className={styles.stack} role="status">
                  <p>
                    {alertPreview.name} ({alertPreview.severity}) on canonical device{' '}
                    <code>{alertPreview.entity_id}</code>. Native rule: interface operational status
                    equals down, limited to agent <code>{alertPreview.agent_id}</code> and device{' '}
                    <code>{alertPreview.target_address}</code>. It will be disabled with no
                    notification channels.
                  </p>
                  {canApplyAlert ? (
                    <Button type="button" onClick={applyAlertTarget} disabled={busy}>
                      Create disabled alert
                    </Button>
                  ) : null}
                  {alertResult ? (
                    <p>
                      Native alert <code>{alertResult.alert_rule_id}</code>:
                      {alertResult.created ? ' created disabled' : ' unchanged'}.
                    </p>
                  ) : null}
                </div>
              ) : null}
            </form>
          ) : null}
          {planID ? (
            <div className={styles.row}>
              <Field
                label="Frozen review hash"
                value={reviewHash}
                onChange={(event) => {
                  setReviewHash(event.target.value)
                  setProofReady(false)
                  setApplyComplete(false)
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
                {diffPage.row_count} reviewed source rows. Pending choices are shown here; reading
                this comparison makes no destination change.
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
              {canWrite && !applyComplete ? (
                <div className={styles.row}>
                  <Button onClick={verifySource} disabled={busy || !snapshotHash || !reviewHash}>
                    Recheck next source endpoint
                  </Button>
                  <Button onClick={applyChunk} disabled={busy || !proofReady}>
                    Apply one reviewed chunk
                  </Button>
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      </CardBody>
    </Card>
  )
}
