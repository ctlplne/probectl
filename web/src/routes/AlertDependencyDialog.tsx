// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAuth } from '../auth/useAuth'
import type { AlertRule } from '../api/alerts'
import {
  alertDependencyContexts,
  getAlertDependencyPolicy,
  putAlertDependencyPolicy,
  clearAlertDependencyPolicy,
  parseDependencyGraph,
  type AlertDependencyPolicyState,
  type EntityContext,
} from '../api/alertDependencies'
import {
  Button,
  ConfirmDialog,
  ErrorState,
  Field,
  LoadingState,
  Modal,
  Select,
  TextArea,
} from '../components'
import { DateTime } from '../time/DateTime'
import styles from './alerts.module.css'

type State =
  | { kind: 'idle' | 'loading' | 'error' | 'cleared' }
  | { kind: 'ready'; value: AlertDependencyPolicyState }

export function AlertDependencyDialog({ rule, onClose }: { rule: AlertRule; onClose: () => void }) {
  const { tenant, user, permissions } = useAuth()
  if (rule.tenant_id !== tenant.id) return null
  const identity = JSON.stringify([tenant.id, user.id, permissions.slice().sort(), rule.id])
  const canRead = ['alert.read', 'entities.read', 'topology.read'].every((key) =>
    permissions.includes(key),
  )
  return (
    <DependencyContents
      key={identity}
      tenantID={tenant.id}
      rule={rule}
      onClose={onClose}
      canRead={canRead}
      canSave={
        canRead &&
        ['alert.write', 'test.read', 'metrics.read'].every((key) => permissions.includes(key))
      }
      canClear={permissions.includes('alert.write')}
    />
  )
}

function DependencyContents({
  tenantID,
  rule,
  onClose,
  canRead,
  canSave,
  canClear,
}: {
  tenantID: string
  rule: AlertRule
  onClose: () => void
  canRead: boolean
  canSave: boolean
  canClear: boolean
}) {
  const [state, setState] = useState<State>({ kind: 'idle' })
  const [contexts, setContexts] = useState<EntityContext[]>([])
  const [cursor, setCursor] = useState('')
  const [paging, setPaging] = useState(false)
  const [contextID, setContextID] = useState('')
  const [freshness, setFreshness] = useState('300')
  const [graphText, setGraphText] = useState('')
  const [confirmClear, setConfirmClear] = useState(false)
  const request = useRef<AbortController | undefined>(undefined)
  const pageRequest = useRef<AbortController | undefined>(undefined)
  const form = useRef<HTMLFormElement | null>(null)
  const restoreFormFocus = useRef(false)
  const client = useQueryClient()
  useEffect(() => {
    if (state.kind === 'ready' && restoreFormFocus.current) {
      form.current?.focus()
      restoreFormFocus.current = false
    }
  }, [state])
  useEffect(
    () => () => {
      request.current?.abort()
      pageRequest.current?.abort()
    },
    [],
  )
  const reset = () => {
    setContexts([])
    setCursor('')
    setContextID('')
    setFreshness('300')
    setGraphText('')
  }
  const owned = (items: EntityContext[]) => {
    if (items.some((item) => item.tenant_id !== tenantID || !item.context_id))
      throw new Error('current context identity unavailable')
    return items
  }
  const seconds = Number(freshness)
  const knownContext =
    contexts.some((item) => item.context_id === contextID) ||
    (state.kind === 'ready' && state.value.policy?.context_id === contextID)
  let graph: ReturnType<typeof parseDependencyGraph>
  let graphError: string | undefined
  try {
    graph = parseDependencyGraph(graphText)
  } catch {
    graphError =
      'Enter the complete graph with canonical device, agent and ICMP test IDs and parent arrays.'
  }
  const valid = Boolean(
    contextID && knownContext && Number.isSafeInteger(seconds) && seconds > 0 && !graphError,
  )

  const perform = async (method: 'GET' | 'PUT' | 'DELETE') => {
    if (method === 'GET' ? !canRead : method === 'PUT' ? !canSave || !valid : !canClear) return
    request.current?.abort()
    pageRequest.current?.abort()
    const controller = new AbortController()
    request.current = controller
    restoreFormFocus.current = method === 'PUT'
    setPaging(false)
    setState({ kind: 'loading' })
    try {
      const value =
        method === 'GET'
          ? await getAlertDependencyPolicy(tenantID, rule.id, controller.signal)
          : method === 'PUT'
            ? await putAlertDependencyPolicy(
                tenantID,
                rule.id,
                { context_id: contextID, freshness_seconds: seconds, ...(graph ? { graph } : {}) },
                controller.signal,
              )
            : await clearAlertDependencyPolicy(tenantID, rule.id, controller.signal)
      if (controller.signal.aborted) return
      if (value.rule_id !== rule.id || value.configured !== Boolean(value.policy))
        throw new Error('current rule identity unavailable')
      if (method === 'GET') {
        const page = await alertDependencyContexts(tenantID, '', controller.signal)
        if (controller.signal.aborted) return
        setContexts(owned(page.items))
        setCursor(page.next_cursor ?? '')
      }
      if (method === 'DELETE') reset()
      else {
        setContextID(value.policy?.context_id ?? '')
        setFreshness(String(value.policy?.freshness_seconds ?? 300))
        setGraphText(value.policy?.graph ? JSON.stringify(value.policy.graph, null, 2) : '')
      }
      setState(method === 'DELETE' ? { kind: 'cleared' } : { kind: 'ready', value })
      setConfirmClear(false)
      if (method !== 'GET') void client.invalidateQueries({ queryKey: ['alerts', 'rules'] })
    } catch {
      if (!controller.signal.aborted) {
        restoreFormFocus.current = false
        reset()
        setState({ kind: 'error' })
        setConfirmClear(false)
      }
    }
  }
  const more = async () => {
    if (!canRead || !cursor || paging || state.kind !== 'ready') return
    pageRequest.current?.abort()
    const controller = new AbortController()
    pageRequest.current = controller
    setPaging(true)
    try {
      const page = await alertDependencyContexts(tenantID, cursor, controller.signal)
      if (controller.signal.aborted) return
      const items = owned(page.items)
      if (page.next_cursor === cursor) throw new Error('context page did not advance')
      setContexts((previous) => [
        ...new Map(
          [...previous, ...items].map((item) => [item.context_id, item] as const),
        ).values(),
      ])
      setCursor(page.next_cursor ?? '')
    } catch {
      if (!controller.signal.aborted) {
        reset()
        setState({ kind: 'error' })
      }
    } finally {
      if (!controller.signal.aborted) setPaging(false)
    }
  }
  const currentPolicy = state.kind === 'ready' ? state.value.policy : undefined
  const contextOptions = [
    { value: '', label: 'Choose an owned context' },
    ...contexts.map((item) => ({
      value: item.context_id,
      label: `${item.site_label || item.site_id} · ${item.vrf_label || item.vrf_id} · ${item.context_id}`,
    })),
  ]
  if (currentPolicy && !contexts.some((item) => item.context_id === currentPolicy.context_id)) {
    contextOptions.splice(1, 0, {
      value: currentPolicy.context_id,
      label: `${currentPolicy.context_id} · current policy`,
    })
  }
  const submit = (event: FormEvent) => {
    event.preventDefault()
    void perform('PUT')
  }
  return (
    <>
      <Modal open title={`Dependency context: ${rule.name}`} onClose={onClose}>
        <p>
          Preview: choose the routing context, source freshness and optional directed dependencies.
          Verified upstream failures can hold downstream reachability notifications. Collection and
          detection keep running.
        </p>
        {canRead ? (
          <Button disabled={state.kind === 'loading'} onClick={() => void perform('GET')}>
            Load current dependency settings
          </Button>
        ) : (
          <p>
            Reading settings needs current alert, entity and topology read access. You can remove
            settings with alert write access without reading the old configuration.
          </p>
        )}
        {state.kind === 'loading' ? (
          <LoadingState label="Checking current dependency settings…" />
        ) : null}
        {state.kind === 'error' ? (
          <ErrorState description="Dependency settings are unavailable. Refresh or check your current source permissions." />
        ) : null}
        {state.kind === 'cleared' ? (
          <p role="status">Dependency settings cleared. Detection keeps running.</p>
        ) : null}
        {state.kind === 'ready' ? (
          <form
            ref={form}
            tabIndex={-1}
            aria-label="Dependency settings"
            onSubmit={submit}
            className={styles.formGrid}
          >
            <p>
              {state.value.configured
                ? 'Dependency context configured'
                : 'No dependency context configured'}{' '}
              · checked <DateTime value={state.value.rule_updated_at} />
            </p>
            <Select
              label="Dependency routing context"
              value={contextID}
              onChange={(event) => {
                setContextID(event.target.value)
                setGraphText('')
              }}
              disabled={!canSave}
              options={contextOptions}
            />
            {cursor ? (
              <Button type="button" disabled={paging} onClick={() => void more()}>
                {paging ? 'Loading contexts…' : 'Load more contexts'}
              </Button>
            ) : null}
            <Field
              label="Source freshness in seconds"
              type="number"
              min="1"
              step="1"
              value={freshness}
              onChange={(event) => setFreshness(event.target.value)}
              disabled={!canSave}
            />
            <TextArea
              label="Directed dependency graph (JSON)"
              value={graphText}
              onChange={(event) => setGraphText(event.target.value)}
              disabled={!canSave}
              rows={8}
              error={graphError}
              hint={
                'Optional: {"nodes":[{"entity_id":"device UUID","agent_id":"agent UUID","test_id":"ICMP test UUID","parents":[]}]}. Use device IDs from Entities and assigned source IDs from its evidence. Parents name other devices in this graph; connected probes must share an agent vantage. Leave blank for context-only settings. Changing context clears the graph.'
              }
            />
            <Button type="submit" disabled={!canSave || !valid || paging}>
              Save dependency settings
            </Button>
          </form>
        ) : null}
        <div className={styles.actionsRow}>
          <Button
            disabled={!canClear || state.kind === 'loading'}
            onClick={() => setConfirmClear(true)}
          >
            Clear dependency settings
          </Button>
        </div>
      </Modal>
      <ConfirmDialog
        open={confirmClear}
        title="Clear dependency settings"
        confirmLabel="Clear settings"
        pending={state.kind === 'loading'}
        onClose={() => setConfirmClear(false)}
        onConfirm={() => void perform('DELETE')}
      >
        Remove this rule's dependency settings. Detection keeps running. This action reads no old
        configuration.
      </ConfirmDialog>
    </>
  )
}
