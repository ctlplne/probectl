// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, apiFetch } from '../api/client'
import type {
  CapacityAgreement,
  CapacityAgreementDefinition,
  CapacityAgreementPage,
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
  Select,
  Table,
} from '../components'
import { Page } from './RoutePage'
import styles from './flowExplorer.module.css'

const base = '/flows/capacity/agreements'

function emptyDefinition(): CapacityAgreementDefinition {
  return {
    name: '',
    reference: '',
    valid_from: '',
    target: { kind: 'interface' },
    billing_day: 1,
    timezone: 'UTC',
    direction: 'max_directional_percentiles',
    currency: '',
    commit_bps: '',
    unit_bps: '1000000',
    unit_price: '',
  }
}

export function CapacityAgreementsPage() {
  const { tenant, user, permissions, hasScopedGrants } = useAuth()
  const identity = JSON.stringify([
    tenant.id,
    user.id,
    [...permissions].sort(),
    Boolean(hasScopedGrants),
  ])
  return (
    <Page
      title="Capacity agreements"
      subtitle="Record commercial terms separately from telemetry and physical link capacity."
    >
      {permissions.includes('flow.agreements.read') ? (
        <AgreementWorkspace
          key={identity}
          canWrite={permissions.includes('flow.agreements.write')}
        />
      ) : (
        <Card>
          <CardBody>
            <p>Financial read permission is required to view capacity agreements.</p>
          </CardBody>
        </Card>
      )}
    </Page>
  )
}

// Terms live only in this identity-keyed component. No shared query cache or
// browser storage retains prices, and old in-flight responses cannot repopulate
// a different tenant/user or a withdrawn permission set.
function AgreementWorkspace({ canWrite }: { canWrite: boolean }) {
  const [page, setPage] = useState<CapacityAgreementPage>()
  const [cursor, setCursor] = useState('')
  const [previous, setPrevious] = useState<string[]>([])
  const [refresh, setRefresh] = useState(0)
  const [selected, setSelected] = useState<CapacityAgreement>()
  const [draft, setDraft] = useState(emptyDefinition)
  const [history, setHistory] = useState<CapacityAgreementPage>()
  const [readVersion, setReadVersion] = useState('')
  const [effectiveAt, setEffectiveAt] = useState('')
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const lifetime = useRef({
    active: true,
    epoch: 0,
    request: undefined as AbortController | undefined,
  })
  useEffect(() => {
    const current = lifetime.current
    current.active = true
    return () => {
      current.active = false
      current.epoch++
      current.request?.abort()
    }
  }, [])
  const clearTerms = useCallback(() => {
    setPage(undefined)
    setSelected(undefined)
    setDraft(emptyDefinition())
    setHistory(undefined)
    setReadVersion('')
    setEffectiveAt('')
    setConfirmDelete(false)
  }, [])
  const execute = useCallback(
    async <T,>(path: string, init: RequestInit | undefined, accept: (value: T) => void) => {
      const current = lifetime.current
      const epoch = ++current.epoch
      current.request?.abort()
      const request = new AbortController()
      current.request = request
      setBusy(true)
      setError('')
      try {
        const value = await apiFetch<T>(path, { ...init, signal: request.signal })
        if (current.active && current.epoch === epoch) accept(value)
      } catch (cause) {
        if (current.active && current.epoch === epoch) {
          if (cause instanceof ApiError && (cause.status === 401 || cause.status === 403))
            clearTerms()
          setError(
            cause instanceof Error ? cause.message : 'Financial configuration is unavailable.',
          )
        }
      } finally {
        if (current.active && current.epoch === epoch) setBusy(false)
      }
    },
    [clearTerms],
  )
  useEffect(() => {
    clearTerms()
    void execute<CapacityAgreementPage>(
      `${base}?limit=20&after=${encodeURIComponent(cursor)}`,
      undefined,
      setPage,
    )
  }, [cursor, refresh, execute, clearTerms])

  function open(id: string, query = '') {
    void execute<CapacityAgreement>(
      `${base}/${encodeURIComponent(id)}${query}`,
      undefined,
      (item) => {
        setSelected(item)
        setDraft({ ...item.definition, target: { ...item.definition.target } })
        setHistory(undefined)
        setConfirmDelete(false)
      },
    )
  }
  function change<K extends keyof CapacityAgreementDefinition>(
    key: K,
    value: CapacityAgreementDefinition[K],
  ) {
    setDraft((old) => ({ ...old, [key]: value }))
    setConfirmDelete(false)
  }
  function revisions(after = '') {
    if (!selected) return
    setHistory(undefined)
    void execute<CapacityAgreementPage>(
      `${base}/${encodeURIComponent(selected.id)}/revisions?limit=20&after=${encodeURIComponent(after)}`,
      undefined,
      setHistory,
    )
  }
  function save(event: FormEvent) {
    event.preventDefault()
    const path = selected ? `${base}/${encodeURIComponent(selected.id)}` : base
    void execute<CapacityAgreement>(
      path,
      {
        method: selected ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          definition: draft,
          ...(selected ? { version: selected.current_version } : {}),
        }),
      },
      () => {
        clearTerms()
        setRefresh((old) => old + 1)
      },
    )
  }
  function remove() {
    if (!selected) return
    void execute<void>(
      `${base}/${encodeURIComponent(selected.id)}?version=${encodeURIComponent(selected.current_version)}`,
      { method: 'DELETE' },
      () => {
        clearTerms()
        setRefresh((old) => old + 1)
      },
    )
  }
  return (
    <div className={styles.stack}>
      {error && <ErrorState title="Agreement request failed" description={error} />}
      {busy && <LoadingState label="Reading or saving financial terms" />}
      <Card>
        <CardHeader
          title="Recorded terms"
          description="Prices and revisions are operator configuration. They do not prove measured traffic or a bill."
        />
        <CardBody className={styles.stack}>
          <div className={styles.actions}>
            <Button
              disabled={busy}
              onClick={() => {
                clearTerms()
                setRefresh((old) => old + 1)
              }}
            >
              Refresh agreements
            </Button>
            {canWrite && (
              <Button
                disabled={busy}
                onClick={() => {
                  setSelected(undefined)
                  setDraft(emptyDefinition())
                  setHistory(undefined)
                  setConfirmDelete(false)
                }}
              >
                New agreement
              </Button>
            )}
          </div>
          {page && (
            <>
              <Table
                caption="Capacity agreement catalog"
                rows={page.items}
                rowKey={(item) => item.id}
                columns={[
                  { key: 'name', header: 'Agreement', render: (item) => item.definition.name },
                  { key: 'revision', header: 'Revision', render: (item) => item.current_version },
                  {
                    key: 'currency',
                    header: 'Currency',
                    render: (item) => item.definition.currency,
                  },
                  {
                    key: 'price',
                    header: 'Unit price',
                    render: (item) => item.definition.unit_price,
                  },
                  {
                    key: 'inventory',
                    header: 'Inventory',
                    render: (item) => (item.target_present ? 'Linked' : 'Retired reference'),
                  },
                  {
                    key: 'open',
                    header: 'Details',
                    render: (item) => (
                      <Button disabled={busy} onClick={() => open(item.id)}>
                        Open {item.definition.name}
                      </Button>
                    ),
                  },
                ]}
              />
              {page.items.length === 0 && <p>No agreements are recorded on this page.</p>}
              <div className={styles.actions}>
                <Button
                  disabled={busy || previous.length === 0}
                  onClick={() => {
                    setCursor(previous[previous.length - 1])
                    setPrevious(previous.slice(0, -1))
                  }}
                >
                  Previous agreements
                </Button>
                <Button
                  disabled={busy || !page.has_more || !page.next}
                  onClick={() => {
                    setPrevious([...previous, cursor])
                    setCursor(page.next ?? '')
                  }}
                >
                  Next agreements
                </Button>
              </div>
            </>
          )}
        </CardBody>
      </Card>
      {selected && (
        <Card>
          <CardHeader
            title={`${selected.definition.name} · revision ${selected.version}`}
            description={
              selected.target_present
                ? 'Current tenant inventory reference retained.'
                : 'Inventory reference retired. Recorded terms remain available.'
            }
          />
          <CardBody className={styles.stack}>
            <AgreementTerms definition={selected.definition} />
            <div className={styles.grid}>
              <Field
                label="Recorded revision to read"
                inputMode="numeric"
                value={readVersion}
                onChange={(e) => setReadVersion(e.target.value)}
              />
              <Field
                label="Effective instant to read"
                hint="RFC3339 with timezone; fractional seconds are preserved."
                value={effectiveAt}
                onChange={(e) => setEffectiveAt(e.target.value)}
              />
            </div>
            <div className={styles.actions}>
              <Button disabled={busy} onClick={() => open(selected.id)}>
                Read current terms
              </Button>
              <Button
                disabled={busy || !readVersion}
                onClick={() => open(selected.id, `?version=${encodeURIComponent(readVersion)}`)}
              >
                Read exact revision
              </Button>
              <Button
                disabled={busy || !effectiveAt}
                onClick={() => open(selected.id, `?at=${encodeURIComponent(effectiveAt)}`)}
              >
                Read effective terms
              </Button>
            </div>
            <div className={styles.actions}>
              <Button disabled={busy} onClick={() => revisions()}>
                Read recorded revisions
              </Button>
              {canWrite && (
                <Button disabled={busy} onClick={() => setConfirmDelete(true)}>
                  Delete agreement
                </Button>
              )}
            </div>
            {confirmDelete && (
              <div className={styles.stack}>
                <p>
                  Delete this agreement and all recorded terms at revision{' '}
                  {selected.current_version}? This cannot be undone.
                </p>
                <div className={styles.actions}>
                  <Button disabled={busy} onClick={remove}>
                    Confirm deletion
                  </Button>
                  <Button disabled={busy} onClick={() => setConfirmDelete(false)}>
                    Keep agreement
                  </Button>
                </div>
              </div>
            )}
            {history && (
              <>
                <Table
                  caption="Recorded agreement revisions"
                  rows={history.items}
                  rowKey={(item) => item.version}
                  columns={[
                    { key: 'revision', header: 'Revision', render: (item) => item.version },
                    {
                      key: 'effective',
                      header: 'Effective from',
                      render: (item) => item.definition.valid_from,
                    },
                    {
                      key: 'terms',
                      header: 'Complete terms',
                      render: (item) => <AgreementTerms definition={item.definition} />,
                    },
                  ]}
                />
                <div className={styles.actions}>
                  <Button disabled={busy} onClick={() => revisions()}>
                    Latest revisions
                  </Button>
                  <Button
                    disabled={busy || !history.has_more || !history.next}
                    onClick={() => revisions(history.next)}
                  >
                    Older revisions
                  </Button>
                </div>
              </>
            )}
          </CardBody>
        </Card>
      )}
      {canWrite && (
        <Card>
          <CardHeader
            title={selected ? 'Append revised terms' : 'New agreement'}
            description={
              selected
                ? `Saving compares current revision ${selected.current_version}; earlier terms stay immutable.`
                : 'Enter the complete contract and its canonical tenant inventory reference.'
            }
          />
          <CardBody>
            <form className={styles.stack} onSubmit={save}>
              <div className={styles.grid}>
                <Field
                  label="Agreement name"
                  required
                  value={draft.name}
                  onChange={(e) => change('name', e.target.value)}
                />
                <Field
                  label="Contract reference"
                  value={draft.reference}
                  onChange={(e) => change('reference', e.target.value)}
                />
                <Field
                  label="Effective from"
                  hint="RFC3339, including timezone and any recorded fractional seconds."
                  required
                  value={draft.valid_from}
                  onChange={(e) => change('valid_from', e.target.value)}
                />
                <Select
                  label="Agreement target"
                  value={draft.target.kind}
                  onChange={(e) =>
                    change(
                      'target',
                      e.target.value === 'interface' ? { kind: 'interface' } : { kind: 'circuit' },
                    )
                  }
                >
                  <option value="interface">Interface</option>
                  <option value="circuit">Tagged circuit</option>
                </Select>
                {draft.target.kind === 'interface' ? (
                  <>
                    <Field
                      label="Routing context ID"
                      required
                      value={draft.target.context_id ?? ''}
                      onChange={(e) =>
                        change('target', { ...draft.target, context_id: e.target.value })
                      }
                    />
                    <Field
                      label="Canonical interface ID"
                      required
                      value={draft.target.interface_id ?? ''}
                      onChange={(e) =>
                        change('target', { ...draft.target, interface_id: e.target.value })
                      }
                    />
                  </>
                ) : (
                  <>
                    <Field
                      label="Circuit tag ID"
                      required
                      value={draft.target.tag_id ?? ''}
                      onChange={(e) =>
                        change('target', { ...draft.target, tag_id: e.target.value })
                      }
                    />
                    <Field
                      label="Complete circuit tag value"
                      required
                      value={draft.target.tag_value ?? ''}
                      onChange={(e) =>
                        change('target', { ...draft.target, tag_value: e.target.value })
                      }
                    />
                  </>
                )}
                <Field
                  label="Billing day"
                  type="number"
                  min={1}
                  max={31}
                  required
                  value={draft.billing_day}
                  onChange={(e) => change('billing_day', Number(e.target.value))}
                />
                <Field
                  label="Billing timezone"
                  required
                  value={draft.timezone}
                  onChange={(e) => change('timezone', e.target.value)}
                />
                <Select
                  label="Billing direction"
                  value={draft.direction}
                  onChange={(e) =>
                    change('direction', e.target.value as CapacityAgreementDefinition['direction'])
                  }
                >
                  <option value="in">Inbound</option>
                  <option value="out">Outbound</option>
                  <option value="max_directional_percentiles">Larger directional percentile</option>
                  <option value="interval_max">Larger direction per interval</option>
                  <option value="interval_sum">Sum directions per interval</option>
                </Select>
                <Field
                  label="Currency"
                  required
                  value={draft.currency}
                  onChange={(e) => change('currency', e.target.value)}
                />
                <Field
                  label="Recorded commit (bps)"
                  inputMode="decimal"
                  required
                  value={draft.commit_bps}
                  onChange={(e) => change('commit_bps', e.target.value)}
                />
                <Field
                  label="Price unit (bps)"
                  inputMode="decimal"
                  required
                  value={draft.unit_bps}
                  onChange={(e) => change('unit_bps', e.target.value)}
                />
                <Field
                  label="Recorded unit price"
                  inputMode="decimal"
                  required
                  value={draft.unit_price}
                  onChange={(e) => change('unit_price', e.target.value)}
                />
              </div>
              <div className={styles.actions}>
                <Button type="submit" variant="primary" disabled={busy}>
                  {selected ? 'Save revised terms' : 'Record agreement'}
                </Button>
              </div>
            </form>
          </CardBody>
        </Card>
      )}
    </div>
  )
}

function AgreementTerms({ definition: d }: { definition: CapacityAgreementDefinition }) {
  const target =
    d.target.kind === 'interface'
      ? `Interface ${d.target.interface_id} in ${d.target.context_id}`
      : `Circuit ${d.target.tag_id}: ${d.target.tag_value}`
  const values = [
    ['Name', d.name],
    ['Reference', d.reference],
    ['Effective from', d.valid_from],
    ['Target', target],
    ['Billing day', String(d.billing_day)],
    ['Timezone', d.timezone],
    ['Direction', d.direction],
    ['Currency', d.currency],
    ['Commit (bps)', d.commit_bps],
    ['Price unit (bps)', d.unit_bps],
    ['Unit price', d.unit_price],
  ]
  return (
    <dl className={styles.summary}>
      {values.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  )
}
