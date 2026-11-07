// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/useAuth'
import { useEntityContexts } from '../../api/entities'
import {
  readBGPRoutingBindings,
  replaceBGPRoutingBindings,
  type BGPRoutingBinding,
  type BGPRoutingBindingConfiguration,
} from '../../api/bgpRoutingBindings'
import {
  Button,
  Card,
  CardHeader,
  CardBody,
  Field,
  Select,
  LoadingState,
  ErrorState,
  Modal,
  TextArea,
} from '../../components'
import styles from './EntityRegistryCard.module.css'

export function BGPRoutingBindingsCard() {
  const { tenant, permissions } = useAuth()
  if (!permissions.includes('entities.read')) return null
  return (
    <RoutingBindingsScope
      key={tenant.id}
      tenant={tenant.id}
      canWrite={permissions.includes('agent.write')}
    />
  )
}

function RoutingBindingsScope({ tenant, canWrite }: { tenant: string; canWrite: boolean }) {
  const contexts = useEntityContexts(tenant)
  const [context, setContext] = useState('')
  const [collector, setCollector] = useState('')
  const [source, setSource] = useState('')
  const [current, setCurrent] = useState<BGPRoutingBindingConfiguration>()
  const [draft, setDraft] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [confirmWithdraw, setConfirmWithdraw] = useState(false)
  const pending = useRef<AbortController | null>(null)
  const generation = useRef<object>({})
  useEffect(
    () => () => {
      generation.current = {}
      pending.current?.abort()
    },
    [],
  )

  function resetScope() {
    generation.current = {}
    pending.current?.abort()
    setCurrent(undefined)
    setDraft('')
    setError('')
    setBusy(false)
    setConfirmWithdraw(false)
  }
  async function perform(write?: BGPRoutingBinding[]) {
    if (write !== undefined && (!canWrite || !current)) return
    pending.current?.abort()
    const controller = new AbortController()
    pending.current = controller
    const token = {}
    generation.current = token
    setBusy(true)
    setError('')
    if (!write) {
      setCurrent(undefined)
      setDraft('')
    }
    try {
      const result =
        write && current
          ? await replaceBGPRoutingBindings(context, current, write, controller.signal)
          : await readBGPRoutingBindings(context, collector, source, controller.signal)
      if (generation.current !== token) return
      if (
        result.context_id !== context ||
        result.collector_agent_id !== collector ||
        result.source_ref !== source
      ) {
        throw new Error(
          'Routing configuration does not match the requested source. Reload it before saving.',
        )
      }
      setCurrent(result)
      setDraft(JSON.stringify(result.manifest?.bindings ?? [], null, 2))
    } catch (failure) {
      if (generation.current !== token) return
      setCurrent(undefined)
      setDraft('')
      setError(
        failure instanceof Error
          ? failure.message
          : 'Cannot load the complete routing configuration.',
      )
    } finally {
      if (generation.current === token) setBusy(false)
    }
  }
  function save(event: FormEvent) {
    event.preventDefault()
    if (!canWrite || !current || busy) return
    try {
      const bindings: unknown = JSON.parse(draft)
      if (!Array.isArray(bindings)) throw new Error('Bindings must be a complete JSON array.')
      if (bindings.length === 0) {
        setConfirmWithdraw(true)
        return
      }
      void perform(bindings as BGPRoutingBinding[])
    } catch (failure) {
      setError(
        failure instanceof Error ? failure.message : 'Cannot parse the complete binding array.',
      )
    }
  }
  const options =
    contexts.data?.pages
      .flatMap((page) => page.items)
      .filter((row) => row.tenant_id === tenant)
      .map((row) => ({ value: row.context_id, label: `${row.site_label} / ${row.vrf_label}` })) ??
    []
  return (
    <Card data-bgp-routing-bindings>
      <CardHeader
        title="Routing source bindings"
        description="Map an authenticated BMP source to owned router contexts. A configuration does not assert a live source, a complete RIB or forwarding state."
      />
      <CardBody>
        <div className={styles.stack}>
          {contexts.isPending ? <LoadingState label="Loading routing binding contexts" /> : null}
          {contexts.isError ? (
            <ErrorState title="Cannot load routing contexts" description={contexts.error.message} />
          ) : null}
          <Select
            label="Routing binding base context"
            value={context}
            onChange={(event) => {
              resetScope()
              setContext(event.target.value)
            }}
            options={[{ value: '', label: 'Choose a routing context' }, ...options]}
          />
          {contexts.hasNextPage ? (
            <Button
              disabled={contexts.isFetchingNextPage}
              onClick={() => void contexts.fetchNextPage()}
            >
              Load more routing binding contexts
            </Button>
          ) : null}
          <Field
            label="Routing collector identity"
            value={collector}
            onChange={(event) => {
              resetScope()
              setCollector(event.target.value)
            }}
            hint="Use the current registered BMP evidence collector identity."
          />
          <Field
            label="Routing origin identity"
            value={source}
            onChange={(event) => {
              resetScope()
              setSource(event.target.value)
            }}
            hint="Use the authenticated router origin from the existing source assignment."
          />
          <Button
            disabled={busy || !context || !collector || !source || contexts.isError}
            onClick={() => void perform()}
          >
            Read current routing bindings
          </Button>
          {busy ? <LoadingState label="Reading or replacing complete routing bindings" /> : null}
          {error ? (
            <ErrorState title="Routing configuration unavailable" description={error} />
          ) : null}
          {current ? (
            <form onSubmit={save} className={styles.form}>
              <h3>Complete source selector configuration</h3>
              <p>
                Current base router: <code>{current.router_id}</code>.{' '}
                {current.manifest
                  ? `Epoch ${current.manifest.epoch}.`
                  : 'Strict global default; no explicit selector manifest.'}
              </p>
              <TextArea
                label="Complete routing binding array"
                rows={12}
                spellCheck={false}
                value={draft}
                readOnly={!canWrite || busy}
                onChange={(event) => setDraft(event.target.value)}
                hint="Each binding needs context_id, router_id, the 16-hex-digit distinguisher, bgp_identifier and complete families (1 IPv4, 2 IPv6). source_format is empty for strict capability validation or frr_loc_rib_v1 for the known FRR selected-RIB serializer. IDs are assigned by the server. An empty array withdraws every selector."
              />
              <p>
                Saving replaces the whole manifest at the displayed epoch and retires its former
                routing generations. A stale epoch requires a fresh read; no partial replacement is
                published.
              </p>
              {canWrite ? (
                <Button type="submit" disabled={busy}>
                  Replace complete routing bindings
                </Button>
              ) : (
                <p>
                  Replacing bindings requires agent.write for every current and proposed context.
                </p>
              )}
            </form>
          ) : null}
          <Modal
            open={confirmWithdraw && canWrite && Boolean(current) && !busy}
            onClose={() => setConfirmWithdraw(false)}
            title="Withdraw all routing bindings?"
            footer={
              <>
                <Button onClick={() => setConfirmWithdraw(false)}>Keep current bindings</Button>
                <Button
                  onClick={() => {
                    setConfirmWithdraw(false)
                    void perform([])
                  }}
                >
                  Withdraw all routing bindings
                </Button>
              </>
            }
          >
            <p>
              This retires the source’s routing generations. It does not restore a legacy fallback.
              Fresh operator bindings and authenticated complete source views are required before
              attribution resumes.
            </p>
          </Modal>
        </div>
      </CardBody>
    </Card>
  )
}
