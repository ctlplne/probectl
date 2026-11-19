// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import {
  createSeasonalFlowAlert,
  seasonalAlertSource,
  seasonalFlowAlertMetric,
  type AlertRule,
  type AlertSeasonalCadence,
  type AlertSeasonalDirection,
  type AlertSeasonalFlowInput,
} from '../api/alerts'
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
import { useAuth } from '../auth/useAuth'
import { AlertSeasonalFlowPicker } from './AlertSeasonalFlowPicker'
import styles from './alerts.module.css'

export function AlertSeasonalSourceDialog({
  rule,
  onClose,
}: {
  rule?: AlertRule
  onClose: () => void
}) {
  const { tenant, user, permissions } = useAuth()
  const client = useQueryClient()
  const flow = !rule || rule.metric === seasonalFlowAlertMetric
  const sourceRead = flow
    ? ['ai.query', 'flow.read'].every((permission) => permissions.includes(permission))
    : permissions.includes('metrics.read')
  const canRead = sourceRead && (!rule || permissions.includes('alert.read'))
  const canWrite = permissions.includes('alert.write')
  const [configured, setConfigured] = useState(rule?.has_seasonal_source === true)
  const [name, setName] = useState('')
  const [flowSource, setFlowSource] = useState<AlertSeasonalFlowInput>({
    view_id: '',
    view_version: '',
    measure: '',
  })
  const [cadence, setCadence] = useState<AlertSeasonalCadence>('weekly')
  const [direction, setDirection] = useState<AlertSeasonalDirection>('both')
  const [timezone, setTimezone] = useState('UTC')
  const [minimum, setMinimum] = useState('')
  const [holidays, setHolidays] = useState('')
  const [testID, setTestID] = useState('')
  const [ready, setReady] = useState(!rule)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [confirmClear, setConfirmClear] = useState(false)
  const edit = useRef<AbortController | null>(null)

  useEffect(() => {
    if (!canRead || !rule || rule.tenant_id !== tenant.id) return
    const load = new AbortController()
    void seasonalAlertSource(tenant.id, rule.id, 'GET', load.signal)
      .then((state) => {
        if (load.signal.aborted) return
        if (state.rule_id !== rule.id) throw new Error('Rule identity changed')
        setConfigured(state.configured)
        setCadence(state.source?.cadence ?? 'weekly')
        setDirection(state.source?.direction ?? 'both')
        setTimezone(state.source?.timezone ?? 'UTC')
        setMinimum(state.source ? String(state.source.minimum_change) : '')
        setHolidays(state.source?.holidays?.join('\n') ?? '')
        setTestID(state.source?.test_id ?? '')
        if (state.source?.flow) setFlowSource(state.source.flow)
        setReady(true)
      })
      .catch(() => {
        if (!load.signal.aborted) setError('Could not read the current seasonal source.')
      })
    return () => load.abort()
  }, [canRead, rule, tenant.id])

  useEffect(() => () => edit.current?.abort(), [])

  async function save(method: 'PUT' | 'DELETE') {
    if (busy || !canWrite || (method === 'PUT' && (!canRead || !ready))) return
    const current = new AbortController()
    edit.current = current
    setBusy(true)
    setError('')
    try {
      const input = {
        ...(cadence === 'weekly' ? {} : { cadence }),
        ...(direction === 'both' ? {} : { direction }),
        timezone: timezone.trim(),
        minimum_change: Number(minimum),
        holidays: holidays
          .split('\n')
          .map((line) => line.trim())
          .filter(Boolean),
        ...(flow ? { flow: flowSource } : { test_id: testID.trim() || undefined }),
      }
      if (rule) {
        const state = await seasonalAlertSource(tenant.id, rule.id, method, current.signal, input)
        if (current.signal.aborted) return
        if (state.rule_id !== rule.id || state.configured !== (method === 'PUT')) {
          throw new Error('Rule identity changed')
        }
      } else {
        const created = await createSeasonalFlowAlert(tenant.id, name.trim(), input, current.signal)
        if (current.signal.aborted) return
        if (!created.has_seasonal_source || created.tenant_id !== tenant.id) {
          throw new Error('Rule identity changed')
        }
      }
      void client.invalidateQueries({ queryKey: ['alerts', 'rules'] })
      onClose()
    } catch {
      if (!current.signal.aborted) setError('Could not update the seasonal source.')
    } finally {
      if (!current.signal.aborted) {
        setBusy(false)
        setConfirmClear(false)
      }
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    if (!timezone.trim() || !Number.isFinite(Number(minimum)) || Number(minimum) <= 0) {
      setError('Enter a timezone and a minimum change greater than zero.')
      return
    }
    if (flow && (!flowSource.view_id || !flowSource.view_version || !flowSource.measure)) {
      setError('Choose a saved flow view and one measure.')
      return
    }
    void save('PUT')
  }

  if (rule && rule.tenant_id !== tenant.id) return null
  const scope = JSON.stringify([tenant.id, user.id, permissions.slice().sort(), rule?.id])
  return (
    <>
      <Modal
        open
        onClose={onClose}
        title={rule ? `Seasonal baseline for ${rule.name}` : 'Create seasonal flow alert'}
      >
        {error ? <ErrorState description={error} /> : null}
        {!canRead ? (
          <p>
            {flow
              ? 'Current flow and Explorer query permissions are required to choose a source.'
              : 'Current alert and metric read permissions are required to inspect the source.'}
          </p>
        ) : null}
        {canRead && !ready && !error ? (
          <LoadingState label="Reading current seasonal source…" />
        ) : null}
        {ready && canRead ? (
          <form className={styles.formGrid} onSubmit={submit}>
            {!rule ? (
              <Field
                label="Name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                disabled={!canWrite || busy}
              />
            ) : null}
            {flow ? (
              <AlertSeasonalFlowPicker
                key={scope}
                identity={scope}
                value={flowSource}
                onChange={setFlowSource}
                disabled={!canWrite || busy}
              />
            ) : null}
            <Select
              label="Learning cadence"
              value={cadence}
              options={[
                { value: 'weekly', label: 'Weekly (same weekday and hour)' },
                { value: 'weekly_early', label: 'Weekly (early band)' },
                { value: 'daily', label: 'Daily (same local hour)' },
                { value: 'hourly', label: 'Hourly (same local minute)' },
              ]}
              onChange={(e) => setCadence(e.target.value as AlertSeasonalCadence)}
              disabled={!canWrite || busy}
            />
            <Select
              label="Alert when values go"
              value={direction}
              options={[
                { value: 'both', label: 'Above or below the band' },
                { value: 'above', label: 'Above the band' },
                { value: 'below', label: 'Below the band' },
              ]}
              onChange={(e) => setDirection(e.target.value as AlertSeasonalDirection)}
              disabled={!canWrite || busy}
            />
            <Field
              label="Timezone"
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
              hint="Enter an IANA timezone such as America/New_York."
              required
              disabled={!canWrite || busy}
            />
            <Field
              label="Minimum change"
              type="number"
              step="any"
              value={minimum}
              onChange={(e) => setMinimum(e.target.value)}
              hint={
                flow
                  ? 'Use the unit of the chosen flow measure.'
                  : 'Use the same unit as the rule metric.'
              }
              required
              disabled={!canWrite || busy}
            />
            <TextArea
              label="Holiday dates"
              value={holidays}
              onChange={(e) => setHolidays(e.target.value)}
              hint="Enter local dates as YYYY-MM-DD, one per line."
              disabled={!canWrite || busy}
            />
            {!flow && permissions.includes('test.read') ? (
              <Field
                label="Test ID"
                value={testID}
                onChange={(e) => setTestID(e.target.value)}
                hint="Optional. Restrict this metric to one owned test."
                disabled={!canWrite || busy}
              />
            ) : null}
            {canWrite ? (
              <Button type="submit" disabled={busy}>
                {rule ? 'Save seasonal baseline' : 'Create seasonal flow alert'}
              </Button>
            ) : null}
          </form>
        ) : null}
        {configured && canWrite ? (
          <Button variant="ghost" disabled={busy} onClick={() => setConfirmClear(true)}>
            Clear seasonal baseline
          </Button>
        ) : null}
      </Modal>
      <ConfirmDialog
        open={confirmClear}
        title="Clear the seasonal baseline and disable this rule?"
        confirmLabel="Clear and disable"
        busyLabel="Clearing…"
        pending={busy}
        onClose={() => setConfirmClear(false)}
        onConfirm={() => void save('DELETE')}
      >
        {flow
          ? 'Choose a saved flow view before enabling this rule again.'
          : 'You can enable the rule with its rolling baseline later.'}
      </ConfirmDialog>
    </>
  )
}
