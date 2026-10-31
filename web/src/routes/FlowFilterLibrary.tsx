// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { useAuth } from '../auth/useAuth'
import {
  useDeleteFlowFilter,
  useSaveFlowFilter,
  type FlowFilterPage,
  type SavedFlowFilter,
} from '../api/flowFilters'
import type { FlowQueryFilterGroup } from '../api/flowExplorer'
import type { UseQueryResult } from '@tanstack/react-query'
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  LoadingState,
  Table,
} from '../components'
import styles from './flowExplorer.module.css'

export function FlowFilterLibrary({
  page,
  after,
  setAfter,
  expression,
  onApply,
}: {
  identity: string
  page: UseQueryResult<FlowFilterPage>
  after: string
  setAfter: (after: string) => void
  expression: FlowQueryFilterGroup
  onApply: (expression: FlowQueryFilterGroup) => void
}) {
  const { permissions } = useAuth()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [selected, setSelected] = useState<SavedFlowFilter>()
  const [error, setError] = useState('')
  const save = useSaveFlowFilter()
  const remove = useDeleteFlowFilter()
  const canWrite = permissions.includes('flow.filters.write')
  const pending = save.isPending || remove.isPending
  return (
    <Card>
      <CardHeader
        title="Reusable flow filters"
        description="Save the current condition tree for reuse in other flow queries. Updates use the revision you opened."
      />
      <CardBody className={styles.stack}>
        {error && <ErrorState title="Filter request failed" description={error} />}
        {page.isPending ? (
          <LoadingState label="Loading reusable flow filters" />
        ) : page.isError ? (
          <ErrorState title="Reusable filters unavailable" description={page.error.message} />
        ) : (
          <Table
            caption="Reusable flow filters"
            rows={page.data.items}
            rowKey={(item) => item.id}
            columns={[
              { key: 'name', header: 'Name', render: (item) => item.name },
              { key: 'version', header: 'Revision', render: (item) => item.version_text },
              { key: 'description', header: 'Description', render: (item) => item.description },
              {
                key: 'actions',
                header: 'Actions',
                render: (item) => (
                  <div className={styles.actions}>
                    <Button onClick={() => onApply({ saved: [{ id: item.id }] })}>
                      Use {item.name}
                    </Button>
                    {canWrite && (
                      <>
                        <Button
                          onClick={() => {
                            setSelected(item)
                            setName(item.name)
                            setDescription(item.description)
                            onApply(item.expression)
                          }}
                        >
                          Edit {item.name}
                        </Button>
                        <Button
                          disabled={pending}
                          onClick={() => {
                            setError('')
                            remove.mutate(
                              { id: item.id, version_text: item.version_text },
                              {
                                onError: (cause) => setError(cause.message),
                                onSuccess: () => {
                                  if (selected?.id === item.id) setSelected(undefined)
                                },
                              },
                            )
                          }}
                        >
                          Delete {item.name}
                        </Button>
                      </>
                    )}
                  </div>
                ),
              },
            ]}
          />
        )}
        <div className={styles.actions}>
          <Button disabled={!after || page.isFetching} onClick={() => setAfter('')}>
            First reusable filter page
          </Button>
          <Button
            disabled={!page.data?.next || page.isFetching}
            onClick={() => setAfter(page.data?.next ?? '')}
          >
            Next reusable filter page
          </Button>
        </div>
        {canWrite && (
          <>
            <div className={styles.grid}>
              <Field
                label="Reusable filter name"
                value={name}
                onChange={(event) => setName(event.target.value)}
              />
              <Field
                label="Reusable filter description"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
              />
            </div>
            <div className={styles.actions}>
              <Button
                disabled={pending || !name.trim()}
                onClick={() => {
                  setError('')
                  save.mutate(
                    { name, description, expression },
                    {
                      onError: (cause) => setError(cause.message),
                      onSuccess: (item) => setSelected(item),
                    },
                  )
                }}
              >
                Save current conditions as new filter
              </Button>
              <Button
                disabled={pending || !selected || !name.trim()}
                onClick={() => {
                  setError('')
                  save.mutate(
                    {
                      id: selected!.id,
                      version_text: selected!.version_text,
                      name,
                      description,
                      expression,
                    },
                    {
                      onError: (cause) => setError(cause.message),
                      onSuccess: (item) => setSelected(item),
                    },
                  )
                }}
              >
                Update selected reusable filter
              </Button>
            </div>
          </>
        )}
      </CardBody>
    </Card>
  )
}
