// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import type { AlertSeasonalFlowInput } from '../api/alerts'
import { useFlowQueryView, useFlowQueryViews } from '../api/flowViews'
import { Button, ErrorState, Field, LoadingState, Select } from '../components'
import styles from './alerts.module.css'

export function AlertSeasonalFlowPicker({
  identity,
  value,
  disabled,
  onChange,
}: {
  identity: string
  value: AlertSeasonalFlowInput
  disabled: boolean
  onChange: (value: AlertSeasonalFlowInput) => void
}) {
  const [after, setAfter] = useState<string | undefined>(undefined)
  const [search, setSearch] = useState('')
  const list = useFlowQueryViews({ after, search, sort: 'name' }, identity)
  const current = useFlowQueryView(value.view_id || undefined, identity)
  const eligible = (list.data?.items ?? []).filter(
    (row) => row.definition.time?.mode === 'lookback',
  )
  const selected = eligible.find((row) => row.id === value.view_id)
  const source = current.data?.id === value.view_id ? current.data : selected
  const metrics = (source?.definition.plan?.metrics ?? []).map((item) => ({
    value: `${item.measure}:${item.calculation}`,
    label: `${item.measure} · ${item.calculation}`,
  }))
  const views = eligible.map((row) => ({ value: row.id, label: row.definition.name }))
  if (value.view_id && !selected) views.push({ value: value.view_id, label: 'Selected saved view' })
  if (value.measure && !metrics.some((row) => row.value === value.measure)) {
    metrics.push({ value: value.measure, label: `Previously selected ${value.measure}` })
  }
  const changed = source && source.version !== value.view_version

  return (
    <fieldset className={styles.metadataEditor} disabled={disabled}>
      <legend>Saved flow view</legend>
      <Field
        label="Find saved flow views"
        value={search}
        hint="Choose an Explorer view with a moving lookback."
        onChange={(e) => {
          setSearch(e.target.value)
          setAfter(undefined)
        }}
      />
      {list.isLoading ? <LoadingState label="Loading saved flow views…" /> : null}
      {list.isError || current.isError ? (
        <ErrorState description="The saved flow view is unavailable under your current grants." />
      ) : null}
      <Select
        label="Saved flow view"
        value={value.view_id}
        options={[{ value: '', label: 'Choose a view' }, ...views]}
        onChange={(e) => {
          const row = eligible.find((item) => item.id === e.target.value)
          onChange({ view_id: row?.id ?? '', view_version: row?.version ?? '', measure: '' })
        }}
        required
      />
      {list.data?.next || after ? (
        <div className={styles.actionsRow}>
          <Button type="button" disabled={!after} onClick={() => setAfter(undefined)}>
            First page
          </Button>
          <Button
            type="button"
            disabled={!list.data?.next}
            onClick={() => setAfter(list.data?.next)}
          >
            Next page
          </Button>
        </div>
      ) : null}
      {value.view_version ? <p>Saved view revision {value.view_version}</p> : null}
      {changed && source.definition.time?.mode === 'lookback' ? (
        <Button
          type="button"
          onClick={() => onChange({ ...value, view_version: source.version, measure: '' })}
        >
          Select current revision {source.version}
        </Button>
      ) : null}
      <Select
        label="Flow measure"
        value={value.measure}
        options={[{ value: '', label: 'Choose a measure' }, ...metrics]}
        onChange={(e) => onChange({ ...value, measure: e.target.value })}
        disabled={!value.view_id || Boolean(changed)}
        required
      />
    </fieldset>
  )
}
