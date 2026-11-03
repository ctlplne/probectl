// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState } from 'react'
import { useAuth } from '../auth/useAuth'
import type { LatestResult } from '../api/results'
import {
  resolveTestTagContext,
  type TestTagContextResolution,
  type TagResolutionItem,
} from '../api/tags'
import { Button, EmptyState, ErrorState, LoadingState, Table, type Column } from '../components'
import { DateTime } from '../time/DateTime'
import { TagValue } from './admin/TagValue'
import styles from './results.module.css'

const columns: Column<TagResolutionItem>[] = [
  { key: 'key', header: 'Key', render: (item) => item.key },
  { key: 'value', header: 'Value', render: (item) => <TagValue value={item.value} /> },
  { key: 'source', header: 'Source', render: (item) => item.source },
]

type State =
  | { kind: 'idle' | 'loading' | 'error' }
  | { kind: 'ready'; value: TestTagContextResolution }

export function TestResultTagContext({ results }: { results: LatestResult[] }) {
  const ids = results
    .map((result) => result.attributes?.['probectl.test.id'])
    .filter(Boolean) as string[]
  return <CurrentTestTagContext ids={ids} />
}

// The references are lookup inputs, never ownership evidence. The server
// reloads current tenant ownership, source grants and context policy each time.
export function CurrentTestTagContext({ ids, answerID }: { ids: string[]; answerID?: string }) {
  const { tenant, user, permissions } = useAuth()
  const references = Array.from(new Set(ids)).sort()
  if (
    !permissions.includes('tags.read') ||
    !permissions.includes('test.read') ||
    references.length === 0
  )
    return null
  return (
    <TestTagContents
      key={JSON.stringify([tenant.id, user.id, permissions.slice().sort(), references, answerID])}
      tenantID={tenant.id}
      ids={references}
      isAnswer={answerID !== undefined}
    />
  )
}

function TestTagContents({
  tenantID,
  ids,
  isAnswer,
}: {
  tenantID: string
  ids: string[]
  isAnswer: boolean
}) {
  const [state, setState] = useState<State>({ kind: 'idle' })
  const request = useRef<AbortController | undefined>(undefined)
  useEffect(
    () => () => {
      request.current?.abort()
      request.current = undefined
    },
    [],
  )
  const load = async () => {
    request.current?.abort()
    const controller = new AbortController()
    request.current = controller
    setState({ kind: 'loading' })
    try {
      const value = await resolveTestTagContext(tenantID, ids, controller.signal)
      if (!controller.signal.aborted) setState({ kind: 'ready', value })
    } catch {
      if (!controller.signal.aborted) setState({ kind: 'error' })
    }
  }
  return (
    <section className={styles.agentBlock} aria-label="Current test tags">
      <Button onClick={() => void load()} disabled={state.kind === 'loading'}>
        {state.kind === 'idle' ? 'Show current test tags' : 'Refresh current test tags'}
      </Button>
      {state.kind === 'loading' ? <LoadingState label="Loading current test tags…" /> : null}
      {state.kind === 'error' ? (
        <ErrorState description="Current test tag context could not be loaded. Refresh after checking your current permissions or source availability." />
      ) : null}
      {state.kind === 'ready' ? (
        <>
          <p>
            {isAnswer
              ? 'Preview: current tags for cited test metrics, loaded separately after this answer. Its citations and confidence describe the original evidence.'
              : 'Preview: current rules and annotations apply to older results. Probe data is unchanged.'}
          </p>
          <dl className={styles.kv}>
            <dt>Tag revision</dt>
            <dd>{state.value.tag_revision}</dd>
            <dt>Current as of</dt>
            <dd>
              <DateTime value={state.value.as_of} />
            </dd>
          </dl>
          {state.value.items.length === 0 ? (
            <EmptyState
              title="No current tag context"
              description="No current tag context is available for these result IDs."
            />
          ) : (
            state.value.items.map((subject) => (
              <div key={subject.target_id}>
                <p>Test {subject.target_id}</p>
                <Table
                  columns={columns}
                  rows={subject.items}
                  rowKey={(item) => item.tag_id}
                  caption="Current test tag values"
                />
              </div>
            ))
          )}
        </>
      ) : null}
    </section>
  )
}
