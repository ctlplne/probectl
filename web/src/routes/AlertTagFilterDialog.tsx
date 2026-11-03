// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAuth } from '../auth/useAuth'
import {
  clearAlertTagFilter,
  getAlertTagFilter,
  putAlertTagFilter,
  type AlertRule,
  type AlertTagFilterState,
} from '../api/alerts'
import type { FlowQueryFilterGroup } from '../api/flowExplorer'
import { Button, ConfirmDialog, EmptyState, ErrorState, LoadingState, Modal } from '../components'
import { DateTime } from '../time/DateTime'
import { FlowFilterGroupEditor } from './FlowPlanBuilder'
import styles from './alerts.module.css'

type State =
  | { kind: 'idle' | 'loading' | 'error' | 'cleared' }
  | { kind: 'ready'; value: AlertTagFilterState; filter: FlowQueryFilterGroup }

export function AlertTagFilterDialog({ rule, onClose }: { rule: AlertRule; onClose: () => void }) {
  const { tenant, user, permissions } = useAuth()
  if (rule.tenant_id !== tenant.id) return null
  const identity = JSON.stringify([tenant.id, user.id, permissions.slice().sort(), rule.id])
  return (
    <AlertTagContents
      key={identity}
      rule={rule}
      tenantID={tenant.id}
      canRead={['alert.read', 'tags.read', 'test.read', 'metrics.read'].every((key) =>
        permissions.includes(key),
      )}
      canWrite={permissions.includes('alert.write')}
      onClose={onClose}
    />
  )
}

function AlertTagContents({
  rule,
  tenantID,
  canRead,
  canWrite,
  onClose,
}: {
  rule: AlertRule
  tenantID: string
  canRead: boolean
  canWrite: boolean
  onClose: () => void
}) {
  const [state, setState] = useState<State>({ kind: 'idle' })
  const [confirmClear, setConfirmClear] = useState(false)
  const request = useRef<AbortController | undefined>(undefined)
  const client = useQueryClient()
  useEffect(() => () => request.current?.abort(), [])

  const perform = async (method: 'GET' | 'PUT' | 'DELETE') => {
    if ((method !== 'GET' && !canWrite) || (method !== 'DELETE' && !canRead)) return
    if (method === 'PUT' && state.kind !== 'ready') return
    const filter = state.kind === 'ready' ? state.filter : undefined
    request.current?.abort()
    const controller = new AbortController()
    request.current = controller
    setState({ kind: 'loading' })
    try {
      if (method === 'DELETE') {
        await clearAlertTagFilter(tenantID, rule.id, controller.signal)
        if (!controller.signal.aborted) {
          setState({ kind: 'cleared' })
          setConfirmClear(false)
        }
      } else {
        if (method === 'PUT' && filter) {
          await putAlertTagFilter(tenantID, rule.id, filter, controller.signal)
        }
        if (controller.signal.aborted) return
        const value = await getAlertTagFilter(tenantID, rule.id, controller.signal)
        if (controller.signal.aborted) return
        if (!value.editor || value.rule_id !== rule.id)
          throw new Error('current schema unavailable')
        setState({
          kind: 'ready',
          value,
          filter: value.tag_filter?.filter ?? { match: 'all', mode: 'include' },
        })
      }
      if (method !== 'GET') void client.invalidateQueries({ queryKey: ['alerts', 'rules'] })
    } catch {
      if (!controller.signal.aborted) {
        setState({ kind: 'error' })
        setConfirmClear(false)
      }
    }
  }

  return (
    <>
      <Modal open title={`Current test tags: ${rule.name}`} onClose={onClose}>
        <p>
          Preview: rules and annotations select current owned tests over retained metrics. Tag edits
          cover history on the next evaluation; metric labels and alert fingerprints stay unchanged.
          Current owner grants are checked again on each evaluation. MFA is not delegated.
        </p>
        {!canRead ? (
          <p>Reading criteria requires alert.read, tags.read, test.read and metrics.read.</p>
        ) : (
          <Button disabled={state.kind === 'loading'} onClick={() => void perform('GET')}>
            {state.kind === 'idle' ? 'Load current criteria' : 'Refresh current criteria'}
          </Button>
        )}
        {state.kind === 'loading' ? <LoadingState label="Loading current alert criteria…" /> : null}
        {state.kind === 'error' ? (
          <ErrorState description="Current criteria are unavailable. Refresh after checking current grants, source availability or stale tag definitions. Previous criteria have been cleared from this view." />
        ) : null}
        {state.kind === 'cleared' ? (
          <p role="status">Tag filter cleared. The rule uses its ordinary metric selection.</p>
        ) : null}
        {state.kind === 'ready' && state.value.editor ? (
          <div className={styles.formGrid}>
            <dl className={styles.kv}>
              <dt>Current vocabulary revision</dt>
              <dd>{state.value.editor.tag_revision}</dd>
              <dt>Current as of</dt>
              <dd>
                <DateTime value={state.value.editor.as_of} />
              </dd>
              {state.value.tag_filter ? (
                <>
                  <dt>Saved binding revision</dt>
                  <dd>{state.value.tag_filter.tag_revision}</dd>
                  <dt>Current owner</dt>
                  <dd>{state.value.tag_filter.owner_user_id}</dd>
                </>
              ) : null}
            </dl>
            {state.value.editor.fields.length === 0 ? (
              <EmptyState
                title="No test tag keys"
                description="Create a tenant tag key before adding criteria."
              />
            ) : null}
            <fieldset className={styles.metadataEditor} disabled={!canWrite}>
              <legend>Current test-tag criteria</legend>
              <FlowFilterGroupEditor
                value={state.filter}
                schema={{
                  fields: state.value.editor.fields,
                  limits: { ...state.value.editor.limits },
                }}
                filters={[]}
                allowSaved={false}
                onChange={(filter) => setState({ ...state, filter })}
              />
            </fieldset>
            <p>
              Saving explicitly binds these fields to their current tag IDs under your current
              grants.
            </p>
            <Button
              disabled={!canWrite || state.value.editor.fields.length === 0}
              onClick={() => void perform('PUT')}
            >
              Save current criteria
            </Button>
          </div>
        ) : null}
        <div className={styles.actionsRow}>
          <Button
            disabled={!canWrite || state.kind === 'loading'}
            onClick={() => setConfirmClear(true)}
          >
            Clear tag filter
          </Button>
        </div>
      </Modal>
      <ConfirmDialog
        open={confirmClear}
        title="Clear tag filter"
        confirmLabel="Clear criteria"
        pending={state.kind === 'loading'}
        onClose={() => setConfirmClear(false)}
        onConfirm={() => void perform('DELETE')}
      >
        Remove this rule's metadata criteria and resume its ordinary metric selection. Other
        settings remain unchanged. This action requires current alert.write and reads no previous
        criteria.
      </ConfirmDialog>
    </>
  )
}
