// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type ReactNode } from 'react'
import styles from './listControls.module.css'
import { Button, Field, Select, useToast } from '../components'
import { useCreateSavedView, useSavedViews, type SavedViewSurface } from '../api/savedViews'
import { useI18n } from '../i18n/useI18n'
import { useAuth } from '../auth/useAuth'

export function FilterBar({ children }: { children: ReactNode }) {
  return (
    <form className={styles.filterBar} onSubmit={(e) => e.preventDefault()}>
      {children}
    </form>
  )
}

export function SavedViews({
  surface,
  filters,
  onApply,
  placeholder = 'Named view',
}: {
  surface: SavedViewSurface
  filters: Record<string, string>
  onApply: (filters: Record<string, string>) => void
  placeholder?: string
}) {
  const { t } = useI18n()
  const { permissions } = useAuth()
  const canCreate = permissions.includes('agent.write')
  const { push } = useToast()
  const saved = useSavedViews(surface)
  const create = useCreateSavedView(surface)
  const [name, setName] = useState('')

  const save = () => {
    if (!canCreate) return
    const cleanName = name.trim()
    if (!cleanName) {
      push({ tone: 'warning', title: 'Name required', message: 'Saved views need a label.' })
      return
    }
    create.mutate(
      { name: cleanName, filters: cleanFilters(filters) },
      {
        onSuccess: (view) => {
          setName('')
          push({ tone: 'success', title: 'View saved', message: view.name })
        },
        onError: (err) => push({ tone: 'danger', title: 'Save failed', message: err.message }),
      },
    )
  }

  return (
    <>
      <Select
        label="Saved views"
        value=""
        onChange={(e) => {
          const view = saved.data?.items.find((v) => v.id === e.target.value)
          if (view) onApply(view.filters)
        }}
        options={[
          {
            value: '',
            // Honest states: an error is not the same as "none saved yet".
            label: saved.isError
              ? 'Saved views unavailable'
              : saved.isPending
                ? 'Loading views…'
                : (saved.data?.items?.length ?? 0) === 0
                  ? 'No saved views yet'
                  : 'Choose view',
          },
          ...(saved.data?.items ?? []).map((v) => ({ value: v.id, label: v.name })),
        ]}
      />
      <div
        className={styles.savedViewComposer}
        role="group"
        aria-label={t('savedViews.createGroup')}
        data-saved-view-composer
      >
        <Field
          label="View name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={placeholder}
          disabled={!canCreate}
        />
        <Button type="button" onClick={save} disabled={create.isPending || !canCreate}>
          Save view
        </Button>
        {!canCreate ? (
          <small className={styles.permissionHint}>Requires agent.write permission.</small>
        ) : null}
      </div>
    </>
  )
}

function cleanFilters(filters: Record<string, string>) {
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(filters)) {
    const v = value.trim()
    if (v && v !== 'all') out[key] = v
  }
  return out
}
