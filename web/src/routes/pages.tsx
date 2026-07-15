// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import styles from './pages.module.css'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  Column,
  EmptyState,
  Field,
  HonestDataState,
  Icon,
  LoadingState,
  Modal,
  Select,
  StatusDot,
  Table,
  useToast,
} from '../components'
import { classifySurfaceTruth } from '../components'
import { useCreateTest, useDeleteTest, useTests, type Test } from '../api/tests'
import { AuthoringPanel } from './AuthoringPanel'
import { ResultDetail } from './ResultDetail'
import { FilterBar, SavedViews } from './listControls'
import { filterValue, filtersForSave, setURLFilters } from './urlFilters'
import { CodeExportPanel } from './CodeExportPanel'
import { testAsCode } from './codeExport'
import { Page } from './RoutePage'

// --- Targets & Tests (live /v1/tests CRUD) ---

const TEST_TYPES = ['icmp', 'tcp', 'udp', 'dns', 'http', 'browser', 'voice', 'a2a', 'noop']
const CREATE_TEST_TYPES = [
  ...TEST_TYPES.filter((type) => type !== 'browser').map((type) => ({ value: type, label: type })),
  { value: 'browser-http', label: 'HTTP transaction (no rendering)' },
  { value: 'browser-rendered', label: 'Rendered browser (Playwright)' },
]

function browserDriver(selection: string): 'http' | 'browser' | null {
  if (selection === 'browser-http') return 'http'
  if (selection === 'browser-rendered') return 'browser'
  return null
}

function testTypeLabel(test: Test): string {
  if (test.type !== 'browser') return test.type
  return test.params?.browser_driver === 'browser' ? 'Rendered browser' : 'HTTP transaction'
}

function defaultBrowserScript(name: string, target: string): string {
  return JSON.stringify({
    name: name || 'browser',
    start_url: target,
    steps: [
      { name: 'open', action: 'goto' },
      { name: 'status', action: 'assert_status', status: 200 },
    ],
  })
}

function CreateTestModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { push } = useToast()
  const create = useCreateTest()
  const [name, setName] = useState('')
  const [type, setType] = useState('icmp')
  const [target, setTarget] = useState('')
  const [interval, setInterval] = useState(60)

  function reset() {
    setName('')
    setType('icmp')
    setTarget('')
    setInterval(60)
  }

  function submit() {
    const driver = browserDriver(type)
    const params = driver
      ? { script: defaultBrowserScript(name, target), browser_driver: driver }
      : undefined
    create.mutate(
      {
        name,
        type: driver ? 'browser' : type,
        target,
        interval_seconds: interval,
        timeout_seconds: driver ? 60 : 3,
        params,
        enabled: true,
      },
      {
        onSuccess: () => {
          push({ tone: 'success', title: 'Test created', message: name })
          reset()
          onClose()
        },
        onError: (e) => push({ tone: 'danger', title: 'Create failed', message: e.message }),
      },
    )
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Create test"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} disabled={create.isPending || !name}>
            {create.isPending ? 'Creating…' : 'Create'}
          </Button>
        </>
      }
    >
      <div className={styles.form}>
        <Field
          label="Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="edge-dns"
        />
        <Select
          label="Type"
          value={type}
          onChange={(e) => setType(e.target.value)}
          options={CREATE_TEST_TYPES}
        />
        <Field
          label="Target"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder={
            browserDriver(type)
              ? 'https://app.example/login'
              : type === 'tcp' || type === 'udp' || type === 'voice'
                ? 'host:port'
                : '1.1.1.1'
          }
          hint={
            type === 'noop'
              ? 'Not required for noop.'
              : type === 'browser-http'
                ? 'Runs a multi-step HTTP transaction without rendering a DOM.'
                : type === 'browser-rendered'
                  ? 'Requires a browser-configured agent and runs the transaction in Chromium.'
                  : undefined
          }
        />
        <Field
          label="Interval (seconds)"
          type="number"
          value={interval}
          onChange={(e) => setInterval(Number(e.target.value))}
        />
      </div>
    </Modal>
  )
}

export function TargetsPage() {
  const {
    data,
    isPending,
    isError,
    error,
    hasNextPage,
    fetchNextPage,
    isFetchingNextPage,
    refetch,
  } = useTests()
  const del = useDeleteTest()
  const { push } = useToast()
  const [creating, setCreating] = useState(false)
  const [resultsFor, setResultsFor] = useState<Test | null>(null)
  const [codeFor, setCodeFor] = useState<Test | null>(null)
  const [params, setParams] = useSearchParams()
  const defaults = { q: '', type: 'all', enabled: 'all' }
  const q = filterValue(params, 'q')
  const type = filterValue(params, 'type', 'all')
  const enabled = filterValue(params, 'enabled', 'all')
  const setFilter = (patch: Record<string, string>) =>
    setURLFilters(params, setParams, defaults, patch)

  useEffect(() => {
    if (params.get('create') !== 'test') return
    setCreating(true)
    const next = new URLSearchParams(params)
    next.delete('create')
    setParams(next, { replace: true })
  }, [params, setParams])

  const filteredTests = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return (data ?? []).filter((t) => {
      const haystack = [t.name, t.type, t.target ?? ''].join(' ').toLowerCase()
      return (
        (!needle || haystack.includes(needle)) &&
        (type === 'all' || t.type === type) &&
        (enabled === 'all' || (enabled === 'enabled' ? t.enabled : !t.enabled))
      )
    })
  }, [data, enabled, q, type])

  function remove(t: Test) {
    del.mutate(t.id, {
      onSuccess: () => push({ tone: 'success', title: 'Test deleted', message: t.name }),
      onError: (e) => push({ tone: 'danger', title: 'Delete failed', message: e.message }),
    })
  }

  const columns: Column<Test>[] = [
    { key: 'name', header: 'Test', render: (t) => <strong>{t.name}</strong> },
    {
      key: 'type',
      header: 'Type',
      render: (t) => <Badge tone="neutral">{testTypeLabel(t)}</Badge>,
    },
    { key: 'target', header: 'Target', render: (t) => <code>{t.target || '—'}</code> },
    { key: 'interval', header: 'Interval', numeric: true, render: (t) => `${t.interval_seconds}s` },
    {
      key: 'status',
      header: 'Status',
      render: (t) =>
        t.enabled ? (
          <StatusDot tone="success" label="Enabled" />
        ) : (
          <StatusDot tone="neutral" label="Disabled" />
        ),
    },
    {
      key: 'actions',
      header: <span className="sr-only">Actions</span>,
      align: 'end',
      render: (t) => (
        <>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setResultsFor(t)}
            aria-label={`Results for ${t.name}`}
          >
            Results
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setCodeFor(t)}
            aria-label={`View YAML for ${t.name}`}
          >
            View as YAML
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => remove(t)}
            aria-label={`Delete ${t.name}`}
          >
            Delete
          </Button>
        </>
      ),
    },
  ]

  return (
    <Page
      title="Targets & Tests"
      subtitle="Active synthetic tests across your network."
      actions={
        <Button variant="primary" onClick={() => setCreating(true)}>
          <Icon name="targets" size={16} /> New test
        </Button>
      }
    >
      <AuthoringPanel />

      <Card>
        <CardHeader
          title="Tests"
          description="Open Results on any test for its per-type latest result detail."
          actions={
            <FilterBar>
              <Field
                label="Find"
                value={q}
                onChange={(e) => setFilter({ q: e.target.value })}
                placeholder="dns, edge, 1.1.1.1"
              />
              <Select
                label="Type"
                value={type}
                onChange={(e) => setFilter({ type: e.target.value })}
                options={[
                  { value: 'all', label: 'All types' },
                  ...TEST_TYPES.map((t) => ({ value: t, label: t })),
                ]}
              />
              <Select
                label="State"
                value={enabled}
                onChange={(e) => setFilter({ enabled: e.target.value })}
                options={[
                  { value: 'all', label: 'All states' },
                  { value: 'enabled', label: 'Enabled' },
                  { value: 'disabled', label: 'Disabled' },
                ]}
              />
              <SavedViews
                surface="targets"
                filters={filtersForSave(params, defaults)}
                onApply={(filters) =>
                  setURLFilters(params, setParams, defaults, {
                    q: filters.q ?? '',
                    type: filters.type ?? 'all',
                    enabled: filters.enabled ?? 'all',
                  })
                }
                placeholder="DNS tests"
              />
            </FilterBar>
          }
        />
        <CardBody>
          {isPending ? (
            <LoadingState label="Loading tests…" />
          ) : isError ? (
            <HonestDataState
              state={classifySurfaceTruth({ error })}
              producer="Control-plane test registry"
              producerReadiness={`The server did not return an authoritative tenant-scoped result: ${error?.message ?? 'request failed'}`}
              lastSuccessfulIngest={null}
              coverageLimitation="Synthetic definitions and their measurements are not shown while this request is unavailable."
              action={
                <Button variant="secondary" onClick={() => void refetch()}>
                  Retry tenant-scoped request
                </Button>
              }
            />
          ) : (
            <>
              <Table
                caption="Synthetic tests"
                columns={columns}
                rows={filteredTests}
                rowKey={(t) => t.id}
                empty={
                  (data?.length ?? 0) > 0 ? (
                    <EmptyState
                      title="No tests match these filters"
                      description="The server returned tests, but none match the current local filter."
                      action={
                        <Button
                          variant="secondary"
                          onClick={() => setURLFilters(params, setParams, defaults, {})}
                        >
                          Clear filters
                        </Button>
                      }
                    />
                  ) : (
                    <HonestDataState
                      state="ready-no-data"
                      producer="Control-plane test registry"
                      producerReadiness="Ready; the tenant has no test definitions"
                      lastSuccessfulIngest={null}
                      coverageLimitation="No targets are configured, so no synthetic RTT, loss, DNS, HTTP, or path evidence exists yet."
                      action={
                        <Button variant="primary" onClick={() => setCreating(true)}>
                          New test
                        </Button>
                      }
                    />
                  )
                }
              />
              {hasNextPage ? (
                <div className={styles.pagination}>
                  <span>{data?.length ?? 0} tests loaded</span>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      void fetchNextPage()
                    }}
                    disabled={isFetchingNextPage}
                  >
                    {isFetchingNextPage ? 'Loading…' : 'Load more tests'}
                  </Button>
                </div>
              ) : null}
            </>
          )}
        </CardBody>
      </Card>

      <CreateTestModal open={creating} onClose={() => setCreating(false)} />
      {codeFor ? (
        <Modal open onClose={() => setCodeFor(null)} title={`Export as code: ${codeFor.name}`}>
          <CodeExportPanel title="Test YAML" code={testAsCode(codeFor)} />
        </Modal>
      ) : null}
      {resultsFor ? <ResultDetail test={resultsFor} onClose={() => setResultsFor(null)} /> : null}
    </Page>
  )
}
