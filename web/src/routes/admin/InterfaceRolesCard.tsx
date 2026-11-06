// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/useAuth'
import { useEntityContexts, useCanonicalEntities } from '../../api/entities'
import {
  useInterfaceRolePolicy,
  useSaveInterfaceRolePolicy,
  useInterfaceRoleOverride,
  useSaveInterfaceRoleOverride,
  useResetInterfaceRoleOverride,
  useInterfaceRoleExplanation,
  type InterfaceRole,
  type InterfaceRoleDescriptionRule,
  type InterfaceRolePolicy,
  type InterfaceRoleOverride,
} from '../../api/interfaceRoles'
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
} from '../../components'
import styles from './EntityRegistryCard.module.css'

const roles: InterfaceRole[] = [
  'transit',
  'ix_peering',
  'private_peering',
  'customer',
  'backbone',
  'other',
]
const roleOptions = roles.map((role) => ({ value: role, label: role.replaceAll('_', ' ') }))
const RULE_PAGE_SIZE = 25

function parseASNs(text: string): number[] {
  if (!text.trim()) return []
  return text
    .trim()
    .split(/[\s,]+/)
    .map((value) => {
      if (!/^[0-9]+$/.test(value))
        throw new Error('ASNs must be positive decimal integers separated by commas or spaces.')
      const number = Number(value)
      if (!Number.isInteger(number) || number < 1 || number > 4294967295)
        throw new Error('Use ASNs from 1 through 4294967295.')
      return number
    })
}

export function InterfaceRolesCard() {
  const { tenant, permissions } = useAuth()
  if (!permissions.includes('entities.read')) return null
  return (
    <InterfaceRoleContexts
      key={tenant.id}
      tenant={tenant.id}
      canWrite={permissions.includes('agent.write')}
    />
  )
}

function InterfaceRoleContexts({ tenant, canWrite }: { tenant: string; canWrite: boolean }) {
  const contexts = useEntityContexts(tenant)
  const [context, setContext] = useState('')
  const options =
    contexts.data?.pages
      .flatMap((page) => page.items)
      .map((row) => ({ value: row.context_id, label: `${row.site_label} / ${row.vrf_label}` })) ??
    []
  return (
    <Card data-interface-roles>
      <CardHeader
        title="Interface roles"
        description="Declare providers, customers and ordered description rules. Manual overrides stay until you reset them. Automatic labels require current authorized source evidence."
      />
      <CardBody>
        <div className={styles.stack}>
          {contexts.isPending ? <LoadingState label="Loading role routing contexts" /> : null}
          {contexts.isError ? (
            <ErrorState title="Cannot load role contexts" message={contexts.error.message} />
          ) : null}
          <Select
            label="Interface role routing context"
            value={context}
            onChange={(event) => setContext(event.target.value)}
            options={[{ value: '', label: 'Choose a routing context' }, ...options]}
          />
          {contexts.hasNextPage ? (
            <Button
              disabled={contexts.isFetchingNextPage}
              onClick={() => void contexts.fetchNextPage()}
            >
              Load more role contexts
            </Button>
          ) : null}
          {context ? (
            <InterfaceRoleConfiguration
              key={context}
              tenant={tenant}
              context={context}
              canWrite={canWrite}
            />
          ) : null}
        </div>
      </CardBody>
    </Card>
  )
}

function InterfaceRoleConfiguration({
  tenant,
  context,
  canWrite,
}: {
  tenant: string
  context: string
  canWrite: boolean
}) {
  const policy = useInterfaceRolePolicy(tenant, context)
  const entities = useCanonicalEntities(tenant, context)
  const [subject, setSubject] = useState('')
  const interfaces =
    entities.data?.pages
      .flatMap((page) => page.items)
      .filter((item) => item.kind === 'interface') ?? []
  return (
    <div className={styles.stack}>
      {policy.isPending ? <LoadingState label="Loading interface role policy" /> : null}
      {policy.isError ? (
        <ErrorState title="Cannot load interface role policy" message={policy.error.message} />
      ) : null}
      {policy.data && !policy.isError ? (
        <InterfaceRolePolicyEditor
          tenant={tenant}
          context={context}
          current={policy.data}
          canWrite={canWrite}
        />
      ) : null}
      {entities.isError ? (
        <ErrorState title="Cannot load owned interfaces" message={entities.error.message} />
      ) : null}
      <Select
        label="Interface for role explanation and override"
        value={subject}
        onChange={(event) => setSubject(event.target.value)}
        options={[
          { value: '', label: 'Choose an owned interface' },
          ...interfaces.map((item) => ({ value: item.id, label: `${item.label} (${item.id})` })),
        ]}
      />
      {entities.hasNextPage ? (
        <Button
          disabled={entities.isFetchingNextPage}
          onClick={() => void entities.fetchNextPage()}
        >
          Load more owned interfaces
        </Button>
      ) : null}
      {subject ? (
        <InterfaceRoleCurrent tenant={tenant} context={context} subject={subject} />
      ) : null}
      {subject ? (
        <InterfaceRoleOverrideEditor
          key={subject}
          tenant={tenant}
          context={context}
          subject={subject}
          canWrite={canWrite}
        />
      ) : null}
    </div>
  )
}

function InterfaceRoleCurrent({
  tenant,
  context,
  subject,
}: {
  tenant: string
  context: string
  subject: string
}) {
  const { permissions } = useAuth()
  const canRead = permissions.includes('metrics.read') && permissions.includes('events.read')
  const explanation = useInterfaceRoleExplanation(tenant, context, subject, canRead)
  if (!canRead) return <p>Current role explanations require metrics and events read access.</p>
  return (
    <section aria-label="Current interface role" className={styles.stack}>
      {explanation.isPending ? (
        <LoadingState label="Explaining the current interface role" />
      ) : null}
      {explanation.isError ? (
        <ErrorState title="Cannot explain the current role" message={explanation.error.message} />
      ) : null}
      {explanation.data && !explanation.isError ? (
        <>
          <p>
            <strong>{explanation.data.role.replaceAll('_', ' ')}</strong> —{' '}
            {explanation.data.reason.replaceAll('_', ' ')}
          </p>
          <p>
            As of {explanation.data.as_of}.{' '}
            {explanation.data.snmp_current
              ? 'Current interface evidence.'
              : 'Interface evidence unavailable.'}{' '}
            {explanation.data.prefix_current
              ? 'Complete current prefixes.'
              : 'Prefix association unavailable.'}
          </p>
          {explanation.data.sources.length ? (
            <ul aria-label="Contributing role sources" className={styles.sourceList}>
              {explanation.data.sources.map((source) => (
                <li key={source}>{source}</li>
              ))}
            </ul>
          ) : (
            <p>No current contributing source.</p>
          )}
        </>
      ) : null}
      <Button disabled={explanation.isFetching} onClick={() => void explanation.refetch()}>
        Refresh role explanation
      </Button>
    </section>
  )
}

function InterfaceRolePolicyEditor({
  tenant,
  context,
  current,
  canWrite,
}: {
  tenant: string
  context: string
  current: InterfaceRolePolicy
  canWrite: boolean
}) {
  const save = useSaveInterfaceRolePolicy(tenant, context)
  const [baseline, setBaseline] = useState(current)
  const [providers, setProviders] = useState(current.definition.provider_asns.join(', '))
  const [customers, setCustomers] = useState(current.definition.customer_asns.join(', '))
  const [rules, setRules] = useState<InterfaceRoleDescriptionRule[]>(
    current.definition.description_rules,
  )
  const [page, setPage] = useState(0)
  const [error, setError] = useState('')
  const stale = baseline.id !== current.id || baseline.revision !== current.revision
  function load(value: InterfaceRolePolicy) {
    setBaseline(value)
    setProviders(value.definition.provider_asns.join(', '))
    setCustomers(value.definition.customer_asns.join(', '))
    setRules(value.definition.description_rules)
    setPage(0)
    setError('')
  }
  function change(index: number, patch: Partial<InterfaceRoleDescriptionRule>) {
    setRules((old) => old.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)))
  }
  function move(index: number, delta: number) {
    setRules((old) => {
      const next = [...old]
      ;[next[index], next[index + delta]] = [next[index + delta], next[index]]
      return next
    })
  }
  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    try {
      const result = await save.mutateAsync({
        expected_id: baseline.id,
        expected_revision: baseline.revision,
        definition: {
          provider_asns: parseASNs(providers),
          customer_asns: parseASNs(customers),
          description_rules: rules,
        },
      })
      load(result)
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Cannot save complete role policy.')
    }
  }
  const lastPage = Math.max(0, Math.ceil(rules.length / RULE_PAGE_SIZE) - 1)
  const selectedPage = Math.min(page, lastPage)
  return (
    <form className={styles.form} onSubmit={(event) => void submit(event)}>
      <h3>Classification policy</h3>
      <p>
        Rules run in the listed order; the first description match wins. These rules configure
        future classification and do not assert that a peer session is up.
      </p>
      {stale ? (
        <p role="alert">Configuration changed. Reload the current policy before saving.</p>
      ) : null}
      <Button onClick={() => load(current)}>Reload current role policy</Button>
      <Field
        label="Provider ASNs"
        value={providers}
        readOnly={!canWrite}
        onChange={(event) => setProviders(event.target.value)}
        hint="Separate complete ASN sets with commas or spaces."
      />
      <Field
        label="Customer ASNs"
        value={customers}
        readOnly={!canWrite}
        onChange={(event) => setCustomers(event.target.value)}
      />
      <p role="status">
        {rules.length} description rules; page {selectedPage + 1} of {lastPage + 1}.
      </p>
      {rules
        .slice(selectedPage * RULE_PAGE_SIZE, (selectedPage + 1) * RULE_PAGE_SIZE)
        .map((rule, offset) => {
          const index = selectedPage * RULE_PAGE_SIZE + offset
          return (
            <div className={styles.form} key={rule.id || `new-${index}`}>
              <Field
                label={`Description pattern ${index + 1}`}
                value={rule.pattern}
                readOnly={!canWrite}
                onChange={(event) => change(index, { pattern: event.target.value })}
              />
              <Select
                label={`Role for description rule ${index + 1}`}
                value={rule.role}
                disabled={!canWrite}
                onChange={(event) => change(index, { role: event.target.value as InterfaceRole })}
                options={roleOptions}
              />
              {canWrite ? (
                <div className={styles.row}>
                  <Button disabled={index === 0} onClick={() => move(index, -1)}>
                    Move rule {index + 1} earlier
                  </Button>
                  <Button disabled={index === rules.length - 1} onClick={() => move(index, 1)}>
                    Move rule {index + 1} later
                  </Button>
                  <Button onClick={() => setRules((old) => old.filter((_, i) => i !== index))}>
                    Remove rule {index + 1}
                  </Button>
                </div>
              ) : null}
            </div>
          )
        })}
      <div className={styles.row}>
        <Button disabled={selectedPage === 0} onClick={() => setPage(selectedPage - 1)}>
          Previous role rules
        </Button>
        <Button disabled={selectedPage === lastPage} onClick={() => setPage(selectedPage + 1)}>
          Next role rules
        </Button>
        {canWrite ? (
          <Button
            onClick={() => {
              setRules((old) => [...old, { id: '', pattern: '', role: 'other' }])
              setPage(Math.floor(rules.length / RULE_PAGE_SIZE))
            }}
          >
            Add description rule
          </Button>
        ) : null}
      </div>
      {canWrite ? (
        <Button type="submit" disabled={save.isPending || stale}>
          Save complete role policy
        </Button>
      ) : null}
      {error ? <p role="alert">{error}</p> : null}
      {save.isSuccess && !error ? <p role="status">Complete role policy saved.</p> : null}
    </form>
  )
}

function InterfaceRoleOverrideEditor({
  tenant,
  context,
  subject,
  canWrite,
}: {
  tenant: string
  context: string
  subject: string
  canWrite: boolean
}) {
  const query = useInterfaceRoleOverride(tenant, context, subject)
  return (
    <div className={styles.stack}>
      {query.isPending ? <LoadingState label="Loading manual role override" /> : null}
      {query.isError ? (
        <ErrorState title="Cannot load manual role override" message={query.error.message} />
      ) : null}
      {query.data && !query.isError ? (
        <InterfaceRoleOverrideForm
          tenant={tenant}
          context={context}
          subject={subject}
          canWrite={canWrite}
          current={query.data}
        />
      ) : null}
    </div>
  )
}

function InterfaceRoleOverrideForm({
  tenant,
  context,
  subject,
  canWrite,
  current,
}: {
  tenant: string
  context: string
  subject: string
  canWrite: boolean
  current: InterfaceRoleOverride
}) {
  const save = useSaveInterfaceRoleOverride(tenant, context, subject)
  const reset = useResetInterfaceRoleOverride(tenant, context, subject)
  const [baseline, setBaseline] = useState(current)
  const [role, setRole] = useState<InterfaceRole>(current.role || 'other')
  const [confirm, setConfirm] = useState<InterfaceRoleOverride | null>(null)
  const stale = current.id !== baseline.id || current.revision !== baseline.revision
  async function submit(event: FormEvent) {
    event.preventDefault()
    try {
      const result = await save.mutateAsync({
        expected_id: baseline.id,
        expected_revision: baseline.revision,
        role,
      })
      setBaseline(result)
    } catch {
      /* Shown below. */
    }
  }
  async function remove() {
    if (!confirm) return
    try {
      await reset.mutateAsync({
        expected_id: confirm.id,
        expected_revision: confirm.revision,
        confirmed: true,
      })
      setConfirm(null)
    } catch {
      /* Keep the captured confirmation open on refusal. */
    }
  }
  return (
    <div className={styles.stack}>
      <form className={styles.form} onSubmit={(event) => void submit(event)}>
        <h3>Manual override</h3>
        <p>
          Current override: {current.role ? current.role.replaceAll('_', ' ') : 'None'}. A manual
          choice persists when source observations change.
        </p>
        {stale ? (
          <p role="alert">The override changed. Reload before editing or resetting it.</p>
        ) : null}
        <Button
          onClick={() => {
            setBaseline(current)
            setRole(current.role || 'other')
            save.reset()
            reset.reset()
          }}
        >
          Reload current role override
        </Button>
        {canWrite ? (
          <>
            <Select
              label="Manual interface role"
              value={role}
              options={roleOptions}
              onChange={(event) => setRole(event.target.value as InterfaceRole)}
            />
            <Button type="submit" disabled={save.isPending || stale}>
              Save manual role override
            </Button>
            <Button
              disabled={!baseline.id || reset.isPending || stale}
              onClick={() => setConfirm({ ...baseline })}
            >
              Reset manual role override
            </Button>
          </>
        ) : null}
        {save.isError ? <p role="alert">{save.error.message}</p> : null}
        {save.isSuccess ? <p role="status">Manual role override saved.</p> : null}
      </form>
      <Modal
        open={Boolean(confirm)}
        onClose={() => setConfirm(null)}
        title="Reset manual interface role?"
        footer={
          <>
            <Button onClick={() => setConfirm(null)}>Cancel</Button>
            <Button variant="danger" disabled={reset.isPending} onClick={() => void remove()}>
              Confirm role reset
            </Button>
          </>
        }
      >
        <p>
          The confirmed manual choice is removed. The next classification must use current
          authorized evidence.
        </p>
        {reset.isError ? <p role="alert">{reset.error.message}</p> : null}
      </Modal>
    </div>
  )
}
