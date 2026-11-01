// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/useAuth'
import {
  useAssignEntitySource,
  useCanonicalEntities,
  useCanonicalEntity,
  useCanonicalEvidence,
  useCanonicalLinks,
  useCreateCanonicalEntity,
  useCreateEntityContext,
  useEntityContexts,
  useEntityResolution,
  type EntityContext,
  type EntityRecord,
  type EntitySourceAssignment,
} from '../../api/entities'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  LoadingState,
  Select,
  Table,
  type Column,
} from '../../components'
import styles from './EntityRegistryCard.module.css'

const entityKinds = [
  'device',
  'interface',
  'address',
  'prefix',
  'service',
  'site',
  'customer',
] as const
const sourceKinds = [
  'device_target',
  'flow_exporter',
  'path_agent',
  'bmp_peer',
  'agent_site',
] as const
const aliasKinds = [
  'address',
  'prefix',
  'snmp_device_id',
  'snmp_interface_id',
  'physical_neighbor_id',
  'flow_exporter_id',
  'bmp_peer_id',
  'path_hop_id',
  'agent_site_id',
  'site_key',
  'customer_key',
  'service_key',
] as const

export function EntityRegistryCard() {
  const { permissions, tenant } = useAuth()
  if (!permissions.includes('entities.read')) return null
  return (
    <EntityRegistryContents
      key={tenant.id}
      tenantID={tenant.id}
      canWrite={permissions.includes('agent.write')}
    />
  )
}

function EntityRegistryContents({ tenantID, canWrite }: { tenantID: string; canWrite: boolean }) {
  const contexts = useEntityContexts(tenantID)
  const allContexts = useMemo(
    () => contexts.data?.pages.flatMap((page) => page.items) ?? [],
    [contexts.data],
  )
  const [createdContext, setCreatedContext] = useState<EntityContext | null>(null)
  const selectableContexts = useMemo(
    () =>
      createdContext && !allContexts.some((item) => item.context_id === createdContext.context_id)
        ? [createdContext, ...allContexts]
        : allContexts,
    [allContexts, createdContext],
  )
  const [contextID, setContextID] = useState('')
  const [entityPage, setEntityPage] = useState(0)
  const [selectedID, setSelectedID] = useState('')
  const entities = useCanonicalEntities(tenantID, contextID)
  const rows = entities.data?.pages[entityPage]?.items ?? []
  const selected = useCanonicalEntity(tenantID, contextID, selectedID)
  const evidence = useCanonicalEvidence(tenantID, contextID, selectedID)
  const links = useCanonicalLinks(tenantID, contextID, selectedID)
  const createContext = useCreateEntityContext(tenantID)
  const createEntity = useCreateCanonicalEntity(tenantID)
  const assignSource = useAssignEntitySource(tenantID)
  const [siteLabel, setSiteLabel] = useState('')
  const [vrfLabel, setVRFLabel] = useState('')
  const [entityLabel, setEntityLabel] = useState('')
  const [entityKind, setEntityKind] = useState<(typeof entityKinds)[number]>('device')
  const [agentID, setAgentID] = useState('')
  const [sourceKind, setSourceKind] =
    useState<EntitySourceAssignment['source_kind']>('device_target')
  const [sourceRef, setSourceRef] = useState('')
  const [anchorID, setAnchorID] = useState('')
  const [aliasKind, setAliasKind] = useState<(typeof aliasKinds)[number]>('address')
  const [aliasValue, setAliasValue] = useState('')
  const [lookup, setLookup] = useState({ kind: '', value: '' })
  const resolution = useEntityResolution(tenantID, contextID, lookup.kind, lookup.value)

  useEffect(() => {
    if (!contextID && allContexts.length > 0) setContextID(allContexts[0].context_id)
  }, [allContexts, contextID])

  function chooseContext(id: string) {
    setContextID(id)
    setEntityPage(0)
    setSelectedID('')
    setLookup({ kind: '', value: '' })
    setAnchorID('')
  }

  async function onCreateContext(event: FormEvent) {
    event.preventDefault()
    try {
      const created = await createContext.mutateAsync({
        site_label: siteLabel.trim(),
        vrf_label: vrfLabel.trim(),
      })
      setCreatedContext(created)
      chooseContext(created.context_id)
      setSiteLabel('')
      setVRFLabel('')
    } catch {
      /* mutation state shows the server's failure */
    }
  }

  async function onCreateEntity(event: FormEvent) {
    event.preventDefault()
    if (!contextID) return
    try {
      const created = await createEntity.mutateAsync({
        context_id: contextID,
        kind: entityKind,
        label: entityLabel.trim(),
      })
      setEntityLabel('')
      setSelectedID(created.id)
      setAnchorID(created.id)
    } catch {
      /* mutation state shows the server's failure */
    }
  }

  async function onAssignSource(event: FormEvent) {
    event.preventDefault()
    if (!contextID) return
    try {
      await assignSource.mutateAsync({
        agent_id: agentID.trim(),
        source_kind: sourceKind,
        source_ref: sourceRef.trim(),
        context_id: contextID,
        ...(anchorID ? { anchor_entity_id: anchorID } : {}),
      })
    } catch {
      /* mutation state shows the server's failure */
    }
  }

  const columns: Column<EntityRecord>[] = [
    {
      key: 'entity',
      header: 'Canonical entity',
      render: (row) => (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setSelectedID(row.id)}
          aria-label={`Inspect ${row.kind} ${row.label}`}
        >
          {row.label}
        </Button>
      ),
    },
    { key: 'kind', header: 'Kind', render: (row) => row.kind },
    { key: 'id', header: 'Stable ID', render: (row) => <code>{row.id}</code> },
  ]

  return (
    <Card data-entity-registry>
      <CardHeader
        title="Canonical entity registry"
        description="Choose a tenant routing context before connecting SNMP, flow, path or BMP evidence. Ambiguous identifiers stay unresolved."
      />
      <CardBody>
        {contexts.isPending ? <LoadingState label="Loading routing contexts…" /> : null}
        {contexts.isError ? (
          <ErrorState description="Routing contexts could not be loaded." />
        ) : null}
        {!contexts.isPending && !contexts.isError ? (
          <div className={styles.stack}>
            <div className={styles.row}>
              <Select
                label="Routing context"
                value={contextID}
                onChange={(event) => chooseContext(event.target.value)}
                options={[
                  { value: '', label: 'Choose a site and VRF' },
                  ...selectableContexts.map((item) => ({
                    value: item.context_id,
                    label: `${item.site_label} / ${item.vrf_label}`,
                  })),
                ]}
              />
              {contexts.hasNextPage ? (
                <Button
                  onClick={() => void contexts.fetchNextPage()}
                  disabled={contexts.isFetchingNextPage}
                >
                  {contexts.isFetchingNextPage ? 'Loading contexts…' : 'Load more contexts'}
                </Button>
              ) : null}
            </div>
            {canWrite ? (
              <form className={styles.form} onSubmit={(event) => void onCreateContext(event)}>
                <h3>Create routing context</h3>
                <div className={styles.row}>
                  <Field
                    label="Site name"
                    required
                    value={siteLabel}
                    onChange={(event) => setSiteLabel(event.target.value)}
                  />
                  <Field
                    label="VRF name"
                    required
                    value={vrfLabel}
                    onChange={(event) => setVRFLabel(event.target.value)}
                  />
                  <Button type="submit" disabled={createContext.isPending}>
                    Create context
                  </Button>
                </div>
                {createContext.isError ? <p role="alert">{createContext.error.message}</p> : null}
                {createContext.isSuccess ? <p role="status">Routing context created.</p> : null}
              </form>
            ) : null}
            {contextID ? (
              <>
                <div className={styles.stack}>
                  <h3>Entities in this context</h3>
                  {entities.isPending ? <LoadingState label="Loading entities…" /> : null}
                  {entities.isError ? (
                    <ErrorState description="Entities could not be loaded." />
                  ) : null}
                  {!entities.isPending && !entities.isError ? (
                    <>
                      <Table
                        caption="Canonical entities in selected routing context"
                        columns={columns}
                        rows={rows}
                        rowKey={(row) => row.id}
                        empty="No canonical entities in this context."
                      />
                      <div className={styles.row}>
                        <Button
                          disabled={entityPage === 0}
                          onClick={() => setEntityPage(entityPage - 1)}
                        >
                          Previous page
                        </Button>
                        <span aria-live="polite">Page {entityPage + 1}</span>
                        <Button
                          disabled={
                            entities.isFetchingNextPage ||
                            (entityPage + 1 >= (entities.data?.pages.length ?? 0) &&
                              !entities.hasNextPage)
                          }
                          onClick={() => {
                            if (entityPage + 1 < (entities.data?.pages.length ?? 0))
                              setEntityPage(entityPage + 1)
                            else
                              void entities
                                .fetchNextPage()
                                .then(() => setEntityPage(entityPage + 1))
                          }}
                        >
                          Next page
                        </Button>
                      </div>
                    </>
                  ) : null}
                </div>
                {selectedID ? (
                  <div className={styles.stack} aria-live="polite">
                    <h3>Selected entity</h3>
                    {selected.isPending ? <LoadingState label="Loading entity…" /> : null}
                    {selected.isError ? (
                      <ErrorState description="Selected entity could not be loaded in this context." />
                    ) : null}
                    {selected.data ? (
                      <p>
                        <strong>{selected.data.label}</strong> · {selected.data.kind} ·{' '}
                        <code>{selected.data.id}</code>
                      </p>
                    ) : null}
                    {evidence.isPending ? <LoadingState label="Loading entity evidence…" /> : null}
                    {evidence.isError ? (
                      <ErrorState description="Evidence could not be loaded. Access to every source on the page is required." />
                    ) : null}
                    {evidence.data ? (
                      <div className={styles.stack}>
                        <h4>Original evidence and current mapping</h4>
                        {evidence.data.pages.flatMap((page) => page.items).length === 0 ? (
                          <p>No evidence is attached to this entity.</p>
                        ) : (
                          <ul>
                            {evidence.data.pages
                              .flatMap((page) => page.items)
                              .map((item) => (
                                <li key={item.id}>
                                  <code>{String(item.alias['kind'])}</code>:{' '}
                                  <code>{String(item.alias['value'])}</code> · {item.source} ·{' '}
                                  <code>{item.source_ref}</code> ·{' '}
                                  {item.interface_name ? (
                                    <>
                                      ifName <code>{item.interface_name}</code> ·{' '}
                                    </>
                                  ) : null}
                                  {item.interface_description ? (
                                    <>
                                      ifDescr <code>{item.interface_description}</code> ·{' '}
                                    </>
                                  ) : null}
                                  {item.neighbor_protocol ? (
                                    <>
                                      {item.neighbor_protocol.toUpperCase()} local ifIndex{' '}
                                      <code>{item.neighbor_local_if_index}</code> port{' '}
                                      <code>{item.neighbor_local_port_id}</code> → remote port{' '}
                                      <code>{item.neighbor_remote_port_id}</code>
                                      {item.neighbor_chassis_id ? (
                                        <>
                                          {' '}
                                          · chassis <code>{item.neighbor_chassis_id}</code>
                                        </>
                                      ) : null}
                                      {item.neighbor_device_name ? (
                                        <>
                                          {' '}
                                          · name <code>{item.neighbor_device_name}</code>
                                        </>
                                      ) : null}
                                      {item.neighbor_management_address ? (
                                        <>
                                          {' '}
                                          · management IP{' '}
                                          <code>{item.neighbor_management_address}</code>
                                        </>
                                      ) : null}
                                      {' · '}
                                    </>
                                  ) : null}
                                  {item.origin_serial ? (
                                    <>
                                      router certificate <code>{item.origin_serial}</code> ·{' '}
                                    </>
                                  ) : null}
                                  {item.support_evidence_id ? (
                                    <>
                                      inferred from SNMP evidence{' '}
                                      <code>{item.support_evidence_id}</code> ·{' '}
                                    </>
                                  ) : null}
                                  {item.current ? 'Current' : 'Historical'}
                                  {item.neighbor_protocol ? ' local source mapping' : ''} ·{' '}
                                  <time dateTime={item.observed_at}>
                                    {new Date(item.observed_at).toLocaleString()}
                                  </time>
                                </li>
                              ))}
                          </ul>
                        )}
                        {evidence.hasNextPage ? (
                          <Button
                            onClick={() => void evidence.fetchNextPage()}
                            disabled={evidence.isFetchingNextPage}
                          >
                            {evidence.isFetchingNextPage
                              ? 'Loading evidence…'
                              : 'Load more evidence'}
                          </Button>
                        ) : null}
                      </div>
                    ) : null}
                    {links.isPending ? <LoadingState label="Loading entity links…" /> : null}
                    {links.isError ? (
                      <ErrorState description="Links could not be loaded. Access to every source on the page is required." />
                    ) : null}
                    {links.data ? (
                      <div className={styles.stack}>
                        <h4>Observed links (history included)</h4>
                        {links.data.pages.flatMap((page) => page.items).length === 0 ? (
                          <p>No links are attached to this entity.</p>
                        ) : (
                          <ul>
                            {links.data.pages
                              .flatMap((page) => page.items)
                              .map((item) => (
                                <li key={item.id}>
                                  {item.kind}: <code>{item.from_entity_id}</code> →{' '}
                                  <code>{item.to_entity_id}</code> · evidence{' '}
                                  <code>{item.evidence_id}</code> ·{' '}
                                  <time dateTime={item.observed_at}>
                                    {new Date(item.observed_at).toLocaleString()}
                                  </time>
                                </li>
                              ))}
                          </ul>
                        )}
                        {links.hasNextPage ? (
                          <Button
                            onClick={() => void links.fetchNextPage()}
                            disabled={links.isFetchingNextPage}
                          >
                            {links.isFetchingNextPage ? 'Loading links…' : 'Load more links'}
                          </Button>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                ) : null}
                {canWrite ? (
                  <div className={styles.formGrid}>
                    <form className={styles.form} onSubmit={(event) => void onCreateEntity(event)}>
                      <h3>Create canonical entity</h3>
                      <Select
                        label="Kind"
                        value={entityKind}
                        onChange={(event) => setEntityKind(event.target.value as typeof entityKind)}
                        options={entityKinds.map((kind) => ({ value: kind, label: kind }))}
                      />
                      <Field
                        label="Label"
                        required
                        value={entityLabel}
                        onChange={(event) => setEntityLabel(event.target.value)}
                      />
                      <Button type="submit" disabled={createEntity.isPending}>
                        Create entity
                      </Button>
                      {createEntity.isError ? (
                        <p role="alert">{createEntity.error.message}</p>
                      ) : null}
                      {createEntity.isSuccess ? (
                        <p role="status">Canonical entity created.</p>
                      ) : null}
                    </form>
                    <form className={styles.form} onSubmit={(event) => void onAssignSource(event)}>
                      <h3>Assign configured evidence source</h3>
                      <Field
                        label="Registered agent UUID"
                        required
                        value={agentID}
                        onChange={(event) => setAgentID(event.target.value)}
                      />
                      <Select
                        label="Source kind"
                        value={sourceKind}
                        onChange={(event) =>
                          setSourceKind(event.target.value as EntitySourceAssignment['source_kind'])
                        }
                        options={sourceKinds.map((kind) => ({ value: kind, label: kind }))}
                      />
                      <Field
                        label="Configured source reference"
                        required
                        value={sourceRef}
                        onChange={(event) => setSourceRef(event.target.value)}
                      />
                      <Field
                        label="Canonical anchor UUID (optional; unanchored flow/BMP needs unique current SNMP evidence)"
                        value={anchorID}
                        onChange={(event) => setAnchorID(event.target.value)}
                      />
                      <Button type="submit" disabled={assignSource.isPending}>
                        Assign source
                      </Button>
                      {assignSource.isError ? (
                        <p role="alert">{assignSource.error.message}</p>
                      ) : null}
                      {assignSource.isSuccess ? (
                        <p role="status">Source assignment audited.</p>
                      ) : null}
                    </form>
                  </div>
                ) : null}
                <form
                  className={styles.form}
                  onSubmit={(event) => {
                    event.preventDefault()
                    setLookup({ kind: aliasKind, value: aliasValue.trim() })
                  }}
                >
                  <h3>Resolve an observed identifier</h3>
                  <div className={styles.row}>
                    <Select
                      label="Identifier kind"
                      value={aliasKind}
                      onChange={(event) => setAliasKind(event.target.value as typeof aliasKind)}
                      options={aliasKinds.map((kind) => ({ value: kind, label: kind }))}
                    />
                    <Field
                      label="Observed value"
                      required
                      value={aliasValue}
                      onChange={(event) => setAliasValue(event.target.value)}
                    />
                    <Button type="submit">Resolve</Button>
                  </div>
                  {resolution.isPending && lookup.value ? (
                    <LoadingState label="Resolving identifier…" />
                  ) : null}
                  {resolution.isError ? (
                    <ErrorState description="Identifier could not be resolved with your current permissions." />
                  ) : null}
                  {resolution.data ? (
                    <div className={styles.stack} role="status">
                      <Badge
                        tone={
                          resolution.data.status === 'resolved'
                            ? 'success'
                            : resolution.data.status === 'conflict'
                              ? 'warning'
                              : 'neutral'
                        }
                      >
                        {resolution.data.status}
                      </Badge>
                      {resolution.data.entity_id ? <code>{resolution.data.entity_id}</code> : null}
                      {resolution.data.candidates?.map((candidate) => (
                        <p key={candidate.evidence_id}>
                          <code>{candidate.evidence_id}</code> · {candidate.source} ·{' '}
                          {candidate.source_ref}
                        </p>
                      ))}
                      {resolution.data.more_candidates ? (
                        <p>More candidates exist; no winner was selected.</p>
                      ) : null}
                    </div>
                  ) : null}
                </form>
              </>
            ) : (
              <p role="status">Create or choose a routing context to browse entities.</p>
            )}
          </div>
        ) : null}
      </CardBody>
    </Card>
  )
}
