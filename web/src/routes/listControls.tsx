import { useState, type ReactNode } from 'react'
import styles from './listControls.module.css'
import { Button, Field, Select, useToast } from '../components'
import {
  useCreateSavedView,
  useSavedViews,
  type SavedViewSurface,
} from '../api/savedViews'

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
  const { push } = useToast()
  const saved = useSavedViews(surface)
  const create = useCreateSavedView(surface)
  const [name, setName] = useState('')

  const save = () => {
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
          { value: '', label: saved.isError ? 'Views unavailable' : 'Choose view' },
          ...(saved.data?.items ?? []).map((v) => ({ value: v.id, label: v.name })),
        ]}
      />
      <Field
        label="View name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder={placeholder}
      />
      <Button type="button" onClick={save} disabled={create.isPending}>
        Save view
      </Button>
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
