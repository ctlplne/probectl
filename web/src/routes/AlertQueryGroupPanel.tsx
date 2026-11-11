// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { Fragment, useEffect, useRef, useState } from 'react'
import { useAuth } from '../auth/useAuth'
import { getAlertQueryGroup, type ActiveAlert, type AlertQueryGroupInspection } from '../api/alerts'
import { Button, ErrorState, LoadingState } from '../components'
import { DateTime } from '../time/DateTime'
import styles from './alerts.module.css'

type State =
  | { kind: 'idle' | 'loading' | 'error' }
  | { kind: 'ready'; value: AlertQueryGroupInspection }
export function AlertQueryGroupPanel({ alert }: { alert: ActiveAlert }) {
  const { tenant, user, permissions } = useAuth()
  const key = JSON.stringify([
    tenant.id,
    user.id,
    permissions.slice().sort(),
    alert.rule_id,
    alert.labels?.query_group,
  ])
  return (
    <GroupContents
      key={key}
      alert={alert}
      tenantID={tenant.id}
      canRead={['alert.read', 'ai.query', 'flow.read'].every((key) => permissions.includes(key))}
    />
  )
}
function GroupContents({
  alert,
  tenantID,
  canRead,
}: {
  alert: ActiveAlert
  tenantID: string
  canRead: boolean
}) {
  const [state, setState] = useState<State>({ kind: 'idle' })
  const request = useRef<AbortController | undefined>(undefined)
  useEffect(() => () => request.current?.abort(), [])
  const load = async () => {
    const group = alert.labels?.query_group
    if (!canRead || !group) return
    request.current?.abort()
    const controller = new AbortController()
    request.current = controller
    setState({ kind: 'loading' })
    try {
      const value = await getAlertQueryGroup(tenantID, alert.rule_id, group, controller.signal)
      if (controller.signal.aborted) return
      if (
        value.kind !== 'current_query_group' ||
        value.rule_id !== alert.rule_id ||
        value.group_key !== group
      )
        throw new Error('current group unavailable')
      setState({ kind: 'ready', value })
    } catch {
      if (!controller.signal.aborted) setState({ kind: 'error' })
    }
  }
  return (
    <section aria-label="Current saved-query group" className={styles.evaluations}>
      <h3>Current query group</h3>
      <p>
        This is a fresh source query under your current grants, not a historical firing receipt. It
        does not change the alert baseline or schedule.
      </p>
      {canRead ? (
        <Button disabled={state.kind === 'loading'} onClick={() => void load()}>
          Inspect current group
        </Button>
      ) : (
        <p>
          Inspecting source facts requires alert.read, ai.query, flow.read and the saved query's
          current source permissions.
        </p>
      )}
      {state.kind === 'loading' ? <LoadingState label="Reading complete current source…" /> : null}
      {state.kind === 'error' ? (
        <ErrorState description="Current group facts are unavailable. Check source revision, current grants and complete coverage. Previous details have been cleared." />
      ) : null}
      {state.kind === 'ready' ? (
        <>
          <dl className={styles.kv}>
            <dt>Current query time</dt>
            <dd>
              <DateTime value={state.value.at} />
            </dd>
            <dt>Selected window</dt>
            <dd>
              <DateTime value={state.value.from} /> to <DateTime value={state.value.to} />
            </dd>
            <dt>Saved revision</dt>
            <dd>{state.value.view_version}</dd>
            <dt>Current selection</dt>
            <dd>
              {state.value.present
                ? 'Group is present'
                : 'Group is absent from the current complete selection'}
            </dd>
            {Object.entries(state.value.dimensions ?? {}).map(([key, value]) => (
              <Fragment key={key}>
                <dt>{key}</dt>
                <dd>{value}</dd>
              </Fragment>
            ))}
            {state.value.exact_value !== undefined ? (
              <>
                <dt>Exact current value</dt>
                <dd>{state.value.exact_value}</dd>
              </>
            ) : null}
            <dt>Current condition</dt>
            <dd>
              {state.value.condition.mode === 'threshold'
                ? `${state.value.condition.metric} ${state.value.condition.comparison} ${state.value.condition.threshold}`
                : 'New group in the selected top set'}
            </dd>
            <dt>Current condition met</dt>
            <dd>
              {state.value.condition_met ? 'Yes' : 'No'}
              {!state.value.baseline_initialized && state.value.condition.mode === 'new_group'
                ? ' (initial baseline warming)'
                : ''}
            </dd>
          </dl>
        </>
      ) : null}
    </section>
  )
}
