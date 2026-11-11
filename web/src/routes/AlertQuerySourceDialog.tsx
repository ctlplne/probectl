// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAuth } from '../auth/useAuth'
import {
  clearAlertQuerySource,
  createSavedQueryAlert,
  getAlertQuerySource,
  putAlertQuerySource,
  type AlertRule,
  type AlertQuerySourceInput,
  type AlertQuerySourceState,
} from '../api/alerts'
import { useFlowQueryViews } from '../api/flowViews'
import {
  Button,
  ConfirmDialog,
  ErrorState,
  Field,
  LoadingState,
  Modal,
  Select,
} from '../components'
import { DateTime } from '../time/DateTime'
import styles from './alerts.module.css'

type State =
  | { kind: 'idle' | 'loading' | 'error' | 'cleared' }
  | { kind: 'ready'; value: AlertQuerySourceState }
const emptySource: AlertQuerySourceInput = {
  view_id: '',
  view_version: '',
  every_seconds: 60,
  condition: { mode: 'new_group' },
}

export function AlertQuerySourceDialog({
  rule,
  onClose,
}: {
  rule?: AlertRule
  onClose: () => void
}) {
  const { tenant, user, permissions } = useAuth()
  if (rule && rule.tenant_id !== tenant.id) return null
  const identity = JSON.stringify([tenant.id, user.id, permissions.slice().sort(), rule?.id])
  const sourceRead = ['ai.query', 'flow.read'].every((key) => permissions.includes(key))
  return (
    <QuerySourceContents
      key={identity}
      identity={identity}
      tenantID={tenant.id}
      rule={rule}
      canRead={sourceRead && (!rule || permissions.includes('alert.read'))}
      canWrite={permissions.includes('alert.write')}
      onClose={onClose}
    />
  )
}

function QuerySourceContents({
  rule,
  tenantID,
  identity,
  canRead,
  canWrite,
  onClose,
}: {
  rule?: AlertRule
  tenantID: string
  identity: string
  canRead: boolean
  canWrite: boolean
  onClose: () => void
}) {
  const [state, setState] = useState<State>(
    rule
      ? { kind: 'idle' }
      : {
          kind: 'ready',
          value: { rule_id: '', rule_updated_at: '', configured: false, stale_revision: false },
        },
  )
  const [input, setInput] = useState<AlertQuerySourceInput>(emptySource)
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
        await createSavedQueryAlert(tenantID, name.trim(), input, controller.signal)
        if (!controller.signal.aborted) {
          void client.invalidateQueries({ queryKey: ['alerts', 'rules'] })
          onClose()
        }
        return
      }
      const value =
        method === 'GET'
          ? await getAlertQuerySource(tenantID, rule.id, controller.signal)
          : method === 'PUT'
            ? await putAlertQuerySource(tenantID, rule.id, input, controller.signal)
            : await clearAlertQuerySource(tenantID, rule.id, controller.signal)
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
        title={rule ? `Saved-query source: ${rule.name}` : 'Create saved-query alert'}
        onClose={onClose}
      >
        <p>
          Preview: each complete saved-query group is evaluated inside Explorer resource limits.
          Source revisions and current owner permissions are checked on every read. A changed or
          unavailable source withholds evaluation and never invents a resolution.
        </p>
        {!canRead ? (
          <p>
            Reading a source requires ai.query, flow.read and alert.read. A private saved query also
            requires its current owner.
          </p>
        ) : rule ? (
          <Button disabled={state.kind === 'loading'} onClick={() => void perform('GET')}>
            Load current source
          </Button>
        ) : null}
        {state.kind === 'loading' ? (
          <LoadingState label="Checking complete source and current grants…" />
        ) : null}
        {state.kind === 'error' ? (
          <ErrorState description="The current source is unavailable. Check current permissions, saved revision, coverage and Explorer cost admission, then load it again." />
        ) : null}
        {state.kind === 'error' && !rule && canRead ? (
          <Button
            onClick={() =>
              setState({
                kind: 'ready',
                value: {
                  rule_id: '',
                  rule_updated_at: '',
                  configured: false,
                  stale_revision: false,
                },
              })
            }
          >
            Choose another source
          </Button>
        ) : null}
        {state.kind === 'cleared' ? (
          <p role="status">Source and baseline cleared. The rule is disabled.</p>
        ) : null}
        {state.kind === 'ready' && canRead ? (
          <form className={styles.formGrid} onSubmit={submit}>
            {!rule ? (
              <Field
                label="Rule name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            ) : null}
            {state.value.stale_revision ? (
              <p role="status">
                The saved query changed. Choose its current revision and explicitly save to resume.
              </p>
            ) : null}
            {state.value.next_at ? (
              <p>
                Next admitted read no earlier than <DateTime value={state.value.next_at} />.
              </p>
            ) : null}
            <QuerySourceEditor
              identity={identity}
              value={input}
              disabled={!canWrite}
              onChange={setInput}
            />
            <p>
              New-group mode warms the initial complete top set without firing, then alerts on newly
              selected groups. The schedule is a minimum separation; actual evaluation follows the
              configured alert tick.
            </p>
            <Button type="submit" disabled={!canWrite || !input.view_id || !input.view_version}>
              {rule ? 'Save current source' : 'Create query alert'}
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
      {rule ? (
        <ConfirmDialog
          open={confirmClear}
          title="Clear saved-query source"
          confirmLabel="Clear and disable"
          pending={state.kind === 'loading'}
          onClose={() => setConfirmClear(false)}
          onConfirm={() => void perform('DELETE')}
        >
          Clear this rule's source and baseline and disable evaluation. This requires current
          alert.write and reads no previous source criteria.
        </ConfirmDialog>
      ) : null}
    </>
  )
}

function QuerySourceEditor({
  identity,
  value,
  disabled,
  onChange,
}: {
  identity: string
  value: AlertQuerySourceInput
  disabled: boolean
  onChange: (value: AlertQuerySourceInput) => void
}) {
  const [after, setAfter] = useState<string | undefined>(undefined)
  const [search, setSearch] = useState('')
  const views = useFlowQueryViews({ after, search, sort: 'name' }, identity)
  const selected = views.data?.items.find((item) => item.id === value.view_id)
  const options = [
    { value: '', label: 'Choose a saved Explorer query' },
    ...(views.data?.items ?? []).map((item) => ({
      value: item.id,
      label: `${item.definition.name} · revision ${item.version}`,
    })),
  ]
  if (value.view_id && !selected)
    options.push({
      value: value.view_id,
      label: `Selected query ${value.view_id} · revision ${value.view_version}`,
    })
  const condition = value.condition
  return (
    <fieldset className={styles.metadataEditor} disabled={disabled}>
      <legend>Saved Explorer source and grouped condition</legend>
      <Field
        label="Find saved queries"
        value={search}
        onChange={(e) => {
          setSearch(e.target.value)
          setAfter(undefined)
        }}
      />
      {views.isLoading ? <LoadingState label="Loading saved queries…" /> : null}
      {views.isError ? (
        <ErrorState description="Saved queries are unavailable under your current grants." />
      ) : null}
      <Select
        label="Saved query"
        value={value.view_id}
        options={options}
        onChange={(e) => {
          const item = views.data?.items.find((item) => item.id === e.target.value)
          if (item) onChange({ ...value, view_id: item.id, view_version: item.version })
        }}
        required
      />
      <p>Bound revision: {value.view_version || 'choose a query'}</p>
      <div className={styles.actionsRow}>
        <Button type="button" disabled={!after} onClick={() => setAfter(undefined)}>
          First page
        </Button>
        <Button
          type="button"
          disabled={!views.data?.next}
          onClick={() => setAfter(views.data?.next)}
        >
          Next page
        </Button>
      </div>
      <Select
        label="Condition"
        value={condition.mode}
        options={[
          { value: 'new_group', label: 'New group in the selected top set' },
          { value: 'threshold', label: 'Metric threshold for each group' },
        ]}
        onChange={(e) =>
          onChange({
            ...value,
            condition:
              e.target.value === 'new_group'
                ? { mode: 'new_group' }
                : { mode: 'threshold', metric: 'bytes:total', comparison: 'gt', threshold: '0' },
          })
        }
      />
      {condition.mode === 'threshold' ? (
        <>
          <Field
            label="Exact saved-plan metric key"
            value={condition.metric ?? ''}
            onChange={(e) =>
              onChange({ ...value, condition: { ...condition, metric: e.target.value } })
            }
            hint="Use a metric present in the saved query, for example bytes:total."
            required
          />
          <Select
            label="Comparison"
            value={condition.comparison ?? 'gt'}
            options={['gt', 'gte', 'lt', 'lte', 'eq', 'neq'].map((key) => ({
              value: key,
              label: key,
            }))}
            onChange={(e) =>
              onChange({
                ...value,
                condition: {
                  ...condition,
                  comparison: e.target.value as NonNullable<typeof condition.comparison>,
                },
              })
            }
          />
          <Field
            label="Exact decimal threshold"
            value={condition.threshold ?? ''}
            onChange={(e) =>
              onChange({ ...value, condition: { ...condition, threshold: e.target.value } })
            }
            hint="Wide counters remain exact; no floating-point rounding."
            inputMode="decimal"
            required
          />
        </>
      ) : null}
      <Field
        label="Minimum seconds between reads"
        type="number"
        min={1}
        max={9223372036}
        step={1}
        value={String(value.every_seconds ?? 60)}
        onChange={(e) => onChange({ ...value, every_seconds: Number(e.target.value) })}
        required
      />
    </fieldset>
  )
}
