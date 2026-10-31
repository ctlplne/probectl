// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'
import {
  useDeleteFlowQueryView,
  useFlowQueryView,
  useFlowQueryViewFavorite,
  useFlowQueryViews,
  type FlowQueryViewList,
  type SavedFlowQueryView,
} from '../api/flowViews'
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  LoadingState,
  Select,
  Table,
} from '../components'
import styles from './flowExplorer.module.css'

export function FlowViewLibrary({
  identity,
  selectedID,
  onSelect,
}: {
  identity: string
  selectedID?: string
  onSelect: (view: SavedFlowQueryView) => void
}) {
  const { user, permissions } = useAuth()
  const [filters, setFilters] = useState<FlowQueryViewList>({ limit: 100, sort: 'name' })
  const [error, setError] = useState('')
  const list = useFlowQueryViews(filters, identity)
  const selected = useFlowQueryView(selectedID, identity)
  const favorite = useFlowQueryViewFavorite()
  const remove = useDeleteFlowQueryView()
  const opened = useRef<string>()
  const selectRef = useRef(onSelect)
  selectRef.current = onSelect
  useEffect(() => {
    if (selected.data && selectedID !== opened.current) {
      opened.current = selectedID
      selectRef.current(selected.data)
    }
  }, [selected.data, selectedID])
  const change = (patch: Partial<FlowQueryViewList>) =>
    setFilters({ ...filters, after: undefined, ...patch })
  const pending = favorite.isPending || remove.isPending
  return (
    <Card>
      <CardHeader
        title="Saved flow queries"
        description="Private queries are visible only to their owner. Shared queries stay inside this tenant; only the owner can change or delete them."
      />
      <CardBody className={styles.stack}>
        <div className={styles.grid}>
          <Field
            label="Search saved flow queries"
            value={filters.search ?? ''}
            onChange={(event) => change({ search: event.target.value })}
          />
          <Field
            label="Saved query label"
            value={filters.label ?? ''}
            onChange={(event) => change({ label: event.target.value })}
          />
          <Field
            label="Saved query owner ID"
            value={filters.owner ?? ''}
            onChange={(event) => change({ owner: event.target.value })}
          />
          <Select
            label="Saved query visibility filter"
            value={filters.visibility ?? ''}
            options={[
              { value: '', label: 'Any visibility' },
              { value: 'private', label: 'Private' },
              { value: 'tenant', label: 'Tenant shared' },
            ]}
            onChange={(event) =>
              change({ visibility: event.target.value as FlowQueryViewList['visibility'] })
            }
          />
          <Select
            label="Saved query collection"
            value={filters.tab ?? 'all'}
            options={[
              { value: 'all', label: 'All accessible' },
              { value: 'favorites', label: 'Favorites' },
              { value: 'recents', label: 'Recently opened' },
            ]}
            onChange={(event) => change({ tab: event.target.value as FlowQueryViewList['tab'] })}
          />
          <Select
            label="Saved query sort"
            value={filters.sort ?? 'name'}
            options={['name', 'created_at', 'updated_at'].map((value) => ({
              value,
              label: value.replace(/_/g, ' '),
            }))}
            onChange={(event) => change({ sort: event.target.value as FlowQueryViewList['sort'] })}
          />
        </div>
        {(error || list.isError || selected.isError) && (
          <ErrorState
            title="Saved query request failed"
            description={error || list.error?.message || selected.error?.message}
          />
        )}
        {list.isPending ? (
          <LoadingState label="Loading saved flow queries" />
        ) : (
          <Table
            caption="Saved flow queries"
            rows={list.data?.items ?? []}
            rowKey={(item) => item.id}
            columns={[
              {
                key: 'name',
                header: 'Query',
                render: (item) => (
                  <>
                    <Button
                      onClick={() => {
                        opened.current = item.id
                        onSelect(item)
                      }}
                    >
                      Open {item.definition.name}
                    </Button>
                    <p>{item.definition.description}</p>
                  </>
                ),
              },
              {
                key: 'owner',
                header: 'Owner / visibility',
                render: (item) => `${item.owner_id} / ${item.definition.visibility ?? 'private'}`,
              },
              {
                key: 'labels',
                header: 'Labels',
                render: (item) => item.definition.labels?.join(', '),
              },
              {
                key: 'actions',
                header: 'Actions',
                render: (item) => (
                  <div className={styles.actions}>
                    <Button
                      disabled={pending}
                      onClick={() => {
                        setError('')
                        favorite.mutate(
                          { id: item.id, favorite: !item.favorite },
                          { onError: (cause) => setError(cause.message) },
                        )
                      }}
                    >
                      {item.favorite ? 'Unfavorite' : 'Favorite'} {item.definition.name}
                    </Button>
                    <Link
                      className={styles.link}
                      to={`/explore?native_flow=1&flow_view=${encodeURIComponent(item.id)}`}
                    >
                      Authenticated link to {item.definition.name}
                    </Link>
                    {permissions.includes('flow.views.write') && item.owner_id === user.id && (
                      <Button
                        disabled={pending}
                        onClick={() => {
                          setError('')
                          remove.mutate(
                            { id: item.id, version: item.version },
                            { onError: (cause) => setError(cause.message) },
                          )
                        }}
                      >
                        Delete {item.definition.name}
                      </Button>
                    )}
                  </div>
                ),
              },
            ]}
          />
        )}
        <div className={styles.actions}>
          <Button
            disabled={!filters.after || list.isFetching}
            onClick={() => change({ after: undefined })}
          >
            First saved query page
          </Button>
          <Button
            disabled={!list.data?.next || list.isFetching}
            onClick={() => setFilters({ ...filters, after: list.data?.next })}
          >
            Next saved query page
          </Button>
        </div>
      </CardBody>
    </Card>
  )
}
