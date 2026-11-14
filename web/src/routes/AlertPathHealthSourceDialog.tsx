// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAuth } from '../auth/useAuth'
import {
  clearAlertPathHealthSource,
  createPathHealthAlert,
  getAlertPathHealthSource,
  putAlertPathHealthSource,
  type AlertRule,
  type AlertPathHealthSourceInput,
  type AlertPathHealthSourceState,
} from '../api/alerts'
import {
  Button,
  ConfirmDialog,
  ErrorState,
  Field,
  LoadingState,
  Modal,
  Select,
} from '../components'
import styles from './alerts.module.css'
import { alertRuleAsCode } from './codeExport'
import { CodeExportPanel } from './CodeExportPanel'

const emptySource: AlertPathHealthSourceInput = {
  test_id: '',
  interface_id: '',
  metric: 'probectl.device.if.in.errors',
  lookback_seconds: 86400,
  poll_gap_seconds: 300,
}
const metrics = [
  ['probectl.device.if.in.errors', 'Input errors'],
  ['probectl.device.if.out.errors', 'Output errors'],
  ['probectl.device.if.in.discards', 'Input discards'],
  ['probectl.device.if.out.discards', 'Output discards'],
  ['probectl.device.if.in.fcs.errors', 'Input FCS errors'],
  ['probectl.device.if.in.alignment.errors', 'Input alignment errors'],
] as const

type Props = { rule?: AlertRule; initialSource?: AlertPathHealthSourceInput; onClose: () => void }
type State =
  | { kind: 'idle' | 'loading' | 'error' | 'cleared' }
  | { kind: 'ready'; value: AlertPathHealthSourceState }

export function AlertPathHealthSourceDialog(props: Props) {
  const { tenant, user, permissions } = useAuth()
  if (props.rule && props.rule.tenant_id !== tenant.id) return null
  const identity = JSON.stringify([
    tenant.id,
    user.id,
    permissions.slice().sort(),
    props.rule?.id,
    props.initialSource,
  ])
  return (
    <PathHealthSourceContents
      key={identity}
      {...props}
      tenantID={tenant.id}
      canRead={
        ['test.read', 'entities.read', 'metrics.read'].every((key) => permissions.includes(key)) &&
        (!props.rule || permissions.includes('alert.read'))
      }
      canWrite={permissions.includes('alert.write')}
    />
  )
}

function PathHealthSourceContents({
  rule,
  initialSource,
  tenantID,
  canRead,
  canWrite,
  onClose,
}: Props & { tenantID: string; canRead: boolean; canWrite: boolean }) {
  const [state, setState] = useState<State>(
    rule
      ? { kind: 'idle' }
      : { kind: 'ready', value: { rule_id: '', rule_updated_at: '', configured: false } },
  )
  const [input, setInput] = useState<AlertPathHealthSourceInput>(initialSource ?? emptySource)
  const [name, setName] = useState('')
  const [confirmClear, setConfirmClear] = useState(false)
  const request = useRef<AbortController | undefined>(undefined)
  const client = useQueryClient()
  useEffect(() => () => request.current?.abort(), [])
  const perform = async (method: 'GET' | 'PUT' | 'DELETE') => {
    if ((method !== 'GET' && !canWrite) || (method !== 'DELETE' && !canRead)) return
    request.current?.abort()
    const controller = new AbortController()
    request.current = controller
    setState({ kind: 'loading' })
    try {
      if (!rule) {
        if (method !== 'PUT') return
        const created = await createPathHealthAlert(tenantID, name.trim(), input, controller.signal)
        if (controller.signal.aborted) return
        if (created.tenant_id !== tenantID) throw new Error('source identity unavailable')
        void client.invalidateQueries({ queryKey: ['alerts', 'rules'] })
        onClose()
        return
      }
      const value =
        method === 'GET'
          ? await getAlertPathHealthSource(tenantID, rule.id, controller.signal)
          : method === 'PUT'
            ? await putAlertPathHealthSource(tenantID, rule.id, input, controller.signal)
            : await clearAlertPathHealthSource(tenantID, rule.id, controller.signal)
      if (controller.signal.aborted) return
      if (value.rule_id !== rule.id) throw new Error('source identity unavailable')
      setInput(value.source ?? emptySource)
      setState(method === 'DELETE' ? { kind: 'cleared' } : { kind: 'ready', value })
      setConfirmClear(false)
      if (method !== 'GET') void client.invalidateQueries({ queryKey: ['alerts', 'rules'] })
    } catch {
      if (!controller.signal.aborted) {
        setInput(emptySource)
        setState({ kind: 'error' })
        setConfirmClear(false)
      }
    }
  }
  const submit = (event: FormEvent) => {
    event.preventDefault()
    void perform('PUT')
  }
  return (
    <>
      <Modal
        open
        title={rule ? `Path-error source: ${rule.name}` : 'Create path-error alert'}
        onClose={onClose}
      >
        <p>
          Compare the current port's observed minimum error rates with its local baseline. A
          complete climb fires one episode through the existing notification channels. Missing,
          reset, ambiguous or unauthorized evidence holds evaluation; it never resolves an episode
          as a healthy zero.
        </p>
        <p>
          The selected interface must be on the current owned path. Current user and source grants
          are checked on every evaluation. Check evaluator status before relying on delivery.
        </p>
        {!canRead ? (
          <p>
            Current test.read, entities.read and metrics.read grants are required to inspect or bind
            a source. alert.write can still clear it.
          </p>
        ) : null}
        {rule && canRead ? (
          <Button disabled={state.kind === 'loading'} onClick={() => void perform('GET')}>
            Read current path source
          </Button>
        ) : null}
        {state.kind === 'loading' ? (
          <LoadingState label="Checking complete current path source…" />
        ) : null}
        {state.kind === 'error' ? (
          <ErrorState description="The complete current source is unavailable under your present authority. Refresh the source and try again." />
        ) : null}
        {state.kind === 'cleared' ? <p role="status">Source cleared and rule disabled.</p> : null}
        {canRead && state.kind === 'ready' ? (
          <form onSubmit={submit} className={styles.formGrid}>
            {!rule ? (
              <Field
                label="Rule name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            ) : null}
            <Field
              label="Owned path test ID"
              value={input.test_id}
              disabled={!canWrite}
              onChange={(e) => setInput({ ...input, test_id: e.target.value })}
              required
            />
            <Field
              label="Canonical interface ID"
              value={input.interface_id}
              disabled={!canWrite}
              onChange={(e) => setInput({ ...input, interface_id: e.target.value })}
              required
            />
            <Select
              label="Original error counter"
              value={input.metric}
              options={metrics.map(([value, label]) => ({ value, label }))}
              disabled={!canWrite}
              onChange={(e) =>
                setInput({
                  ...input,
                  metric: e.target.value as AlertPathHealthSourceInput['metric'],
                })
              }
            />
            <Field
              label="Lookback seconds"
              type="number"
              min={1}
              step={1}
              value={input.lookback_seconds ?? 86400}
              disabled={!canWrite}
              onChange={(e) => setInput({ ...input, lookback_seconds: Number(e.target.value) })}
              required
            />
            <Field
              label="Maximum contiguous poll gap seconds"
              type="number"
              min={1}
              step={1}
              value={input.poll_gap_seconds ?? 300}
              disabled={!canWrite}
              onChange={(e) => setInput({ ...input, poll_gap_seconds: Number(e.target.value) })}
              required
            />
            <Button type="submit" disabled={!canWrite || !input.test_id || !input.interface_id}>
              {rule ? 'Save current path source' : 'Create path-error alert'}
            </Button>
          </form>
        ) : null}
        {rule ? (
          <div className={styles.actionsRow}>
            <Button
              disabled={!canWrite || state.kind === 'loading'}
              onClick={() => setConfirmClear(true)}
            >
              Clear source and disable rule
            </Button>
          </div>
        ) : null}
      </Modal>
      {rule && state.kind === 'ready' && state.value.source ? (
        <details>
          <summary>Export current source as code</summary>
          <CodeExportPanel title="View as YAML" code={alertRuleAsCode(rule, state.value.source)} />
        </details>
      ) : null}
      {rule ? (
        <ConfirmDialog
          open={confirmClear}
          title="Clear path-error source"
          confirmLabel="Clear and disable"
          pending={state.kind === 'loading'}
          onClose={() => setConfirmClear(false)}
          onConfirm={() => void perform('DELETE')}
        >
          Clear this rule's source and disable evaluation. This requires current alert.write and
          reads no previous criteria.
        </ConfirmDialog>
      ) : null}
    </>
  )
}
