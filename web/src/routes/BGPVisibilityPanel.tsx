// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '../api/client'
import type {
  BGPVisibilityHistory,
  BGPVisibilityMonitor,
  BGPVisibilityMonitorInput,
  BGPVisibilityMonitorList,
  BGPVisibilityObservation,
} from '../api/sdk.gen'
import { useAuth } from '../auth/useAuth'
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  LoadingState,
  Modal,
  Select,
  Table,
  type Column,
} from '../components'
import { DateTime } from '../time/DateTime'
import { BGPASPathHistory } from './BGPASPathHistory'
import { BGPRPKIPosture } from './BGPRPKIPosture'
import styles from './planes.module.css'

const historyColumns: Column<BGPVisibilityObservation>[] = [
  { key: 'time', header: 'Observed', render: (item) => <DateTime value={item.observed_at} /> },
  { key: 'collector', header: 'Collector', render: (item) => item.collector },
  {
    key: 'visible',
    header: 'Visibility',
    render: (item) => {
      if (item.counts)
        return `${item.counts.visible_peers} of ${item.counts.eligible_peers} eligible peers`
      switch (item.availability) {
        case 'archive_gap':
          return 'Archive gap'
        case 'session_change':
          return 'Collector session changed'
        case 'empty_cohort':
          return 'No eligible peers'
        default:
          return 'Unavailable'
      }
    },
  },
  {
    key: 'origins',
    header: 'Observed origins',
    render: (item) =>
      item.counts?.origins.length
        ? item.counts.origins.map((origin) => `AS${origin.asn} (${origin.peers})`).join(', ')
        : '—',
  },
]

export function BGPVisibilityPanel() {
  const { tenant, permissions } = useAuth()
  const [open, setOpen] = useState(false)
  if (!permissions.includes('events.read')) return null
  return (
    <Card>
      <CardHeader title="Public prefix visibility" />
      <CardBody>
        {open ? (
          <VisibilityControls
            tenant={tenant.id}
            allowEdits={permissions.includes('alert.write')}
            allowPosture={permissions.includes('entities.read')}
          />
        ) : (
          <Button variant="secondary" onClick={() => setOpen(true)}>
            Open prefix visibility
          </Button>
        )}
      </CardBody>
    </Card>
  )
}

function VisibilityControls({
  tenant,
  allowEdits,
  allowPosture,
}: {
  tenant: string
  allowEdits: boolean
  allowPosture: boolean
}) {
  const cache = useQueryClient()
  const [selected, setSelected] = useState('')
  const [editing, setEditing] = useState(false)
  const [removing, setRemoving] = useState<BGPVisibilityMonitor | null>(null)
  const [openPaths, setOpenPaths] = useState(false)
  const [openPosture, setOpenPosture] = useState(false)
  const key = ['bgp', 'visibility', tenant] as const
  const monitors = useQuery({
    queryKey: key,
    queryFn: () => apiFetch<BGPVisibilityMonitorList>('/bgp/visibility'),
  })
  const entries = monitors.data?.items ?? []
  const monitor = entries.find((item) => item.id === selected) ?? entries[0]
  const monitorId = monitor?.id ?? ''
  const history = useInfiniteQuery({
    queryKey: [...key, monitorId],
    enabled: monitorId !== '',
    initialPageParam: '',
    queryFn: ({ pageParam }) => {
      const path = `/bgp/visibility/${encodeURIComponent(monitorId)}`
      return apiFetch<BGPVisibilityHistory>(
        pageParam ? `${path}?cursor=${encodeURIComponent(pageParam)}` : path,
      )
    },
    getNextPageParam: (page) => page.next_cursor,
  })
  const save = useMutation({
    mutationFn: (input: BGPVisibilityMonitorInput) =>
      apiFetch<BGPVisibilityMonitor>('/bgp/visibility', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: (item) => {
      setSelected(item.id)
      setEditing(false)
      void cache.invalidateQueries({ queryKey: key })
    },
  })
  const remove = useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(`/bgp/visibility/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    onSuccess: () => {
      setRemoving(null)
      void cache.invalidateQueries({ queryKey: key })
    },
  })
  if (monitors.isLoading) return <LoadingState label="Loading monitored prefixes…" />
  if (monitors.isError) return <ErrorState description="Could not load monitored prefixes." />
  return (
    <div className={styles.visualStack}>
      {entries.length > 0 ? (
        <Select
          label="Monitored prefix"
          value={monitorId}
          onChange={(e) => setSelected(e.target.value)}
          options={entries.map((item) => ({ value: item.id, label: item.prefix }))}
        />
      ) : (
        <p>No monitored prefixes yet.</p>
      )}
      {allowEdits && (
        <Button
          variant="secondary"
          onClick={() => {
            save.reset()
            setEditing(true)
          }}
        >
          Set up monitoring
        </Button>
      )}
      {allowEdits && monitor && (
        <Button
          variant="secondary"
          onClick={() => {
            remove.reset()
            setRemoving(monitor)
          }}
        >
          Remove monitor
        </Button>
      )}
      {monitor && history.isLoading && <LoadingState label="Loading visibility history…" />}
      {monitor && (
        <Button
          variant="secondary"
          aria-expanded={openPaths}
          onClick={() => setOpenPaths(!openPaths)}
        >
          {openPaths ? 'Close AS-path history' : 'Open AS-path history'}
        </Button>
      )}
      {monitor && openPaths && (
        <BGPASPathHistory
          key={monitor.id}
          tenant={tenant}
          monitorID={monitor.id}
          prefix={monitor.prefix}
        />
      )}
      {monitor && allowPosture && (
        <Button
          variant="secondary"
          aria-expanded={openPosture}
          onClick={() => setOpenPosture(!openPosture)}
        >
          {openPosture ? 'Close RPKI posture' : 'Open RPKI posture'}
        </Button>
      )}
      {monitor && allowPosture && openPosture && (
        <BGPRPKIPosture key={`${tenant}/${monitor.id}`} tenant={tenant} monitor={monitor} />
      )}
      {history.isError && <ErrorState description="Could not load visibility history." />}
      {history.data && monitor && (
        <>
          <Table
            caption={`Collector coverage for ${monitor.prefix}`}
            columns={historyColumns}
            rows={history.data.pages.flatMap((page) => page.items)}
            rowKey={(item) => `${item.source}/${item.collector}/${item.observed_at}`}
            empty="Waiting for a complete collector archive."
          />
          {history.hasNextPage && (
            <Button
              variant="secondary"
              disabled={history.isFetchingNextPage}
              onClick={() => void history.fetchNextPage()}
            >
              Load earlier observations
            </Button>
          )}
          <p>Collector data from the University of Oregon RouteViews Project.</p>
        </>
      )}
      {editing && (
        <Modal open onClose={() => setEditing(false)} title="Set up prefix monitoring">
          <VisibilityMonitorForm
            onSave={(input) => save.mutate(input)}
            pending={save.isPending}
            failed={save.isError}
          />
        </Modal>
      )}
      {removing && (
        <Modal open onClose={() => setRemoving(null)} title="Remove prefix monitor">
          <div className={styles.visualStack}>
            <p>This removes {removing.prefix} and its visibility history from this tenant.</p>
            {remove.isError && <ErrorState description="Could not remove this monitor." />}
            <Button
              variant="danger"
              disabled={remove.isPending}
              onClick={() => remove.mutate(removing.id)}
            >
              Remove monitor and history
            </Button>
          </div>
        </Modal>
      )}
    </div>
  )
}

function VisibilityMonitorForm({
  onSave,
  pending,
  failed,
}: {
  onSave: (input: BGPVisibilityMonitorInput) => void
  pending: boolean
  failed: boolean
}) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values = new FormData(event.currentTarget)
    const prefix = values.get('prefix')
    if (typeof prefix !== 'string') return
    onSave({
      prefix: prefix.trim(),
      minimum_visible_basis_points: Math.round(Number(values.get('percent')) * 100),
      alert_on_partial: values.has('alert_on_partial'),
      alert_on_loss: values.has('alert_on_loss'),
    })
  }
  return (
    <form className={styles.visualStack} onSubmit={submit}>
      <Field label="Prefix" name="prefix" required placeholder="192.0.2.0/24" />
      <Field
        label="Minimum visible peers (%)"
        name="percent"
        type="number"
        min="0.01"
        max="100"
        step="0.01"
        defaultValue="95"
        required
      />
      <label>
        <input type="checkbox" name="alert_on_partial" defaultChecked /> Alert on partial visibility
      </label>
      <label>
        <input type="checkbox" name="alert_on_loss" defaultChecked /> Alert on lost visibility
      </label>
      {failed && (
        <ErrorState description="Could not save this prefix monitor. Check the CIDR and alert threshold." />
      )}
      <Button type="submit" disabled={pending}>
        Save monitor
      </Button>
    </form>
  )
}
