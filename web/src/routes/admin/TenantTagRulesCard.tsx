// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/useAuth'
import { useEntityContexts } from '../../api/entities'
import {
  MAX_TAG_VALUE_INPUT_UNITS,
  tagValueTooLong,
  useCreateTagRule,
  useDeleteTagRule,
  useTagDefinitions,
  useTagRules,
  useUpdateTagRule,
  type TagRule,
  type TagRuleInput,
} from '../../api/tags'
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
} from '../../components'
import { TagValue } from './TagValue'
import styles from './EntityRegistryCard.module.css'

const targetKinds = ['device', 'interface', 'prefix', 'exporter', 'agent', 'test'] as const
const addressSides = ['src', 'dst', 'exporter', 'interface', 'device'] as const
const snmpFields = ['sys_name', 'sys_descr', 'if_name', 'if_descr'] as const

type TargetKind = (typeof targetKinds)[number]
type AddressSide = (typeof addressSides)[number]
type SNMPField = (typeof snmpFields)[number]
type MatchKind = TagRule['match_kind']

export function TenantTagRulesCard() {
  const { permissions, tenant } = useAuth()
  if (!permissions.includes('tags.read')) return null
  return (
    <TenantTagRulesContents
      key={tenant.id}
      tenantID={tenant.id}
      canWrite={permissions.includes('tags.write')}
    />
  )
}

function TenantTagRulesContents({ tenantID, canWrite }: { tenantID: string; canWrite: boolean }) {
  const contexts = useEntityContexts(tenantID)
  const allContexts = useMemo(
    () => contexts.data?.pages.flatMap((page) => page.items) ?? [],
    [contexts.data],
  )
  const definitions = useTagDefinitions(tenantID)
  const [contextID, setContextID] = useState('')
  const [pageIndex, setPageIndex] = useState(0)
  const rules = useTagRules(tenantID, contextID)
  const create = useCreateTagRule(tenantID, contextID)
  const update = useUpdateTagRule(tenantID, contextID)
  const remove = useDeleteTagRule(tenantID, contextID)
  const [editing, setEditing] = useState<TagRule | null>(null)
  const [deleting, setDeleting] = useState<TagRule | null>(null)
  const [tagID, setTagID] = useState('')
  const [targetKind, setTargetKind] = useState<TargetKind>('exporter')
  const [matchKind, setMatchKind] = useState<MatchKind>('cidr')
  const [addressSide, setAddressSide] = useState<AddressSide>('exporter')
  const [cidr, setCIDR] = useState('')
  const [namePattern, setNamePattern] = useState('')
  const [snmpField, setSNMPField] = useState<SNMPField>('sys_name')
  const [snmpValue, setSNMPValue] = useState('')
  const [value, setValue] = useState('')
  const [priority, setPriority] = useState('0')

  useEffect(() => {
    if (!contextID && allContexts.length > 0) setContextID(allContexts[0].context_id)
  }, [allContexts, contextID])
  useEffect(() => {
    if (!definitions.data) return
    if (!definitions.data.items.some((item) => item.id === tagID)) {
      setTagID(definitions.data.items[0]?.id ?? '')
    }
  }, [definitions.data, tagID])

  function chooseContext(id: string) {
    setContextID(id)
    setPageIndex(0)
    setEditing(null)
  }

  function editRule(rule: TagRule) {
    setEditing(rule)
    setTagID(rule.tag_id)
    setTargetKind(rule.target_kind)
    setMatchKind(rule.match_kind)
    setAddressSide(rule.address_side ?? 'exporter')
    setCIDR(rule.cidr ?? '')
    setNamePattern(rule.name_pattern ?? '')
    setSNMPField(rule.snmp_field ?? 'sys_name')
    setSNMPValue(
      rule.snmp_field === 'sys_descr'
        ? JSON.stringify(rule.snmp_value ?? '')
        : (rule.snmp_value ?? ''),
    )
    setValue(rule.value)
    setPriority(String(rule.priority ?? 0))
  }

  function ruleInput(): TagRuleInput {
    const base: TagRuleInput = {
      tag_id: tagID,
      target_kind: targetKind,
      match_kind: matchKind,
      value: value.trim(),
      priority: Number(priority),
    }
    if (matchKind === 'cidr') return { ...base, address_side: addressSide, cidr: cidr.trim() }
    if (matchKind === 'name_pattern') return { ...base, name_pattern: namePattern.trim() }
    return { ...base, snmp_field: snmpField, snmp_value: exactSNMPValue ?? '' }
  }

  let exactSNMPValue: string | undefined = snmpValue
  if (snmpField === 'sys_descr') {
    try {
      const parsed: unknown = JSON.parse(snmpValue)
      exactSNMPValue = typeof parsed === 'string' ? parsed : undefined
    } catch {
      exactSNMPValue = undefined
    }
  }
  const snmpError =
    matchKind !== 'snmp_field'
      ? undefined
      : exactSNMPValue === undefined
        ? 'Enter a JSON string, including double quotes.'
        : !exactSNMPValue || new TextEncoder().encode(exactSNMPValue).length > 1024
          ? 'Use 1–1,024 UTF-8 bytes of exact field text.'
          : /\p{Cc}/u.test(
                snmpField === 'sys_descr'
                  ? exactSNMPValue.replace(/[\t\r\n]/g, '')
                  : exactSNMPValue,
              )
            ? 'Only sys_descr permits tab, carriage return and line feed.'
            : undefined

  async function onSave(event: FormEvent) {
    event.preventDefault()
    if (definitions.isPending || definitions.isError) return
    if (!contextID || !tagID || !value.trim() || tagValueTooLong(value) || snmpError) return
    try {
      const input = ruleInput()
      if (editing) await update.mutateAsync({ id: editing.id, input })
      else await create.mutateAsync(input)
      setEditing(null)
      setPageIndex(0)
      setValue('')
      setCIDR('')
      setNamePattern('')
      setSNMPValue('')
    } catch {
      // Keep the form and show the exact server error.
    }
  }

  async function onDelete() {
    if (!deleting) return
    try {
      await remove.mutateAsync(deleting.id)
      setDeleting(null)
      setPageIndex(0)
    } catch {
      // Keep confirmation visible with the error.
    }
  }

  const rows = rules.data?.pages[pageIndex]?.items ?? []
  const keyByID = new Map<string, string>(
    definitions.data?.items.map((definition): [string, string] => [
      definition.id,
      definition.key,
    ]) ?? [],
  )
  const columns: Column<TagRule>[] = [
    {
      key: 'tag',
      header: 'Tag',
      render: (row) => <code>{keyByID.get(row.tag_id) ?? row.tag_id}</code>,
    },
    { key: 'target', header: 'Target', render: (row) => row.target_kind },
    {
      key: 'match',
      header: 'Match',
      render: (row) => `${row.match_kind}: ${row.cidr ?? row.name_pattern ?? row.snmp_field ?? ''}`,
    },
    {
      key: 'value',
      header: 'Value',
      render: (row) => <TagValue value={row.value} />,
    },
    { key: 'priority', header: 'Priority', render: (row) => row.priority ?? 0, numeric: true },
    {
      key: 'actions',
      header: 'Actions',
      render: (row) =>
        canWrite ? (
          <div className={styles.row}>
            <Button size="sm" onClick={() => editRule(row)} aria-label={`Edit rule ${row.id}`}>
              Edit
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setDeleting(row)}
              aria-label={`Delete rule ${row.id}`}
            >
              Delete
            </Button>
          </div>
        ) : (
          'Read only'
        ),
    },
  ]

  return (
    <Card data-tenant-tag-rules>
      <CardHeader
        title="Tenant tag rules"
        description="Rules assign current tag values to retained history. Manual assignments take precedence; the longest matching CIDR wins among rules."
      />
      <CardBody>
        <div className={styles.stack}>
          {definitions.isPending ? <LoadingState label="Loading rule tag keys…" /> : null}
          {definitions.isError ? (
            <ErrorState description="Rule tag keys could not be loaded." />
          ) : null}
          {contexts.isPending ? <LoadingState label="Loading routing contexts…" /> : null}
          {contexts.isError ? (
            <ErrorState description="Routing contexts could not be loaded." />
          ) : null}
          {contexts.data ? (
            <div className={styles.row}>
              <Select
                label="Tag routing context"
                value={contextID}
                onChange={(event) => chooseContext(event.target.value)}
                options={[
                  { value: '', label: 'Choose a site and VRF' },
                  ...allContexts.map((item) => ({
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
                  Load more contexts
                </Button>
              ) : null}
            </div>
          ) : null}
          {contextID ? (
            <>
              {rules.isPending ? <LoadingState label="Loading tag rules…" /> : null}
              {rules.isError ? <ErrorState description="Tag rules could not be loaded." /> : null}
              {rules.data ? (
                <>
                  <Table
                    caption="Tag rules in selected routing context"
                    columns={columns}
                    rows={rows}
                    rowKey={(row) => row.id}
                    empty="No tag rules in this context."
                  />
                  <div className={styles.row}>
                    <Button disabled={pageIndex === 0} onClick={() => setPageIndex(pageIndex - 1)}>
                      Previous page
                    </Button>
                    <span aria-live="polite">Page {pageIndex + 1}</span>
                    <Button
                      disabled={
                        rules.isFetchingNextPage ||
                        (pageIndex + 1 >= rules.data.pages.length && !rules.hasNextPage)
                      }
                      onClick={() => {
                        if (pageIndex + 1 < rules.data.pages.length) setPageIndex(pageIndex + 1)
                        else void rules.fetchNextPage().then(() => setPageIndex(pageIndex + 1))
                      }}
                    >
                      Next page
                    </Button>
                  </div>
                </>
              ) : null}
              {canWrite && !definitions.isError && definitions.data?.items.length ? (
                <form className={styles.form} onSubmit={(event) => void onSave(event)}>
                  <h3>{editing ? 'Edit tag rule' : 'Create tag rule'}</h3>
                  <div className={styles.row}>
                    <Select
                      label="Tag key"
                      value={tagID}
                      onChange={(event) => setTagID(event.target.value)}
                      options={definitions.data.items.map((item) => ({
                        value: item.id,
                        label: item.key,
                      }))}
                    />
                    <Select
                      label="Target kind"
                      value={targetKind}
                      onChange={(event) => setTargetKind(event.target.value as TargetKind)}
                      options={targetKinds.map((kind) => ({ value: kind, label: kind }))}
                    />
                    <Select
                      label="Match kind"
                      value={matchKind}
                      onChange={(event) => setMatchKind(event.target.value as MatchKind)}
                      options={[
                        { value: 'cidr', label: 'CIDR' },
                        { value: 'name_pattern', label: 'Name pattern' },
                        { value: 'snmp_field', label: 'SNMP field' },
                      ]}
                    />
                  </div>
                  <div className={styles.row}>
                    {matchKind === 'cidr' ? (
                      <>
                        <Select
                          label="Address side"
                          value={addressSide}
                          onChange={(event) => setAddressSide(event.target.value as AddressSide)}
                          options={addressSides.map((side) => ({ value: side, label: side }))}
                        />
                        <Field
                          label="Canonical CIDR"
                          required
                          value={cidr}
                          onChange={(event) => setCIDR(event.target.value)}
                        />
                      </>
                    ) : null}
                    {matchKind === 'name_pattern' ? (
                      <Field
                        label="RE2 name pattern"
                        required
                        maxLength={256}
                        value={namePattern}
                        onChange={(event) => setNamePattern(event.target.value)}
                      />
                    ) : null}
                    {matchKind === 'snmp_field' ? (
                      <>
                        <Select
                          label="SNMP field"
                          value={snmpField}
                          onChange={(event) => {
                            const next = event.target.value as SNMPField
                            setSNMPValue(
                              next === 'sys_descr'
                                ? JSON.stringify(exactSNMPValue ?? '')
                                : (exactSNMPValue ?? ''),
                            )
                            setSNMPField(next)
                          }}
                          options={snmpFields.map((field) => ({ value: field, label: field }))}
                        />
                        <Field
                          label="SNMP field value"
                          required
                          maxLength={snmpField === 'sys_descr' ? 6146 : 1024}
                          hint={
                            snmpField === 'sys_descr'
                              ? 'Quoted JSON string; use \\r, \\n and \\t for exact formatting. Up to 1,024 UTF-8 bytes after decoding.'
                              : 'Exact text, including spaces; up to 1,024 UTF-8 bytes.'
                          }
                          error={snmpError}
                          value={snmpValue}
                          onChange={(event) => setSNMPValue(event.target.value)}
                        />
                      </>
                    ) : null}
                  </div>
                  <div className={styles.row}>
                    <Field
                      label="Tag value"
                      required
                      maxLength={MAX_TAG_VALUE_INPUT_UNITS}
                      hint="Up to 24,000 Unicode characters."
                      error={tagValueTooLong(value) ? 'Use at most 24,000 characters.' : undefined}
                      value={value}
                      onChange={(event) => setValue(event.target.value)}
                    />
                    <Field
                      label="Rule priority"
                      type="number"
                      min={-1000}
                      max={1000}
                      value={priority}
                      onChange={(event) => setPriority(event.target.value)}
                    />
                    <Button
                      type="submit"
                      disabled={
                        create.isPending ||
                        update.isPending ||
                        !tagID ||
                        !value.trim() ||
                        tagValueTooLong(value) ||
                        !!snmpError
                      }
                    >
                      {editing ? 'Save rule' : 'Create rule'}
                    </Button>
                    {editing ? <Button onClick={() => setEditing(null)}>Cancel edit</Button> : null}
                  </div>
                  {create.isError ? <p role="alert">{create.error.message}</p> : null}
                  {update.isError ? <p role="alert">{update.error.message}</p> : null}
                </form>
              ) : null}
            </>
          ) : (
            <p>Choose a routing context to inspect tag rules.</p>
          )}
        </div>
      </CardBody>
      <Modal
        open={Boolean(deleting)}
        onClose={() => setDeleting(null)}
        title="Delete tag rule?"
        footer={
          <>
            <Button onClick={() => setDeleting(null)}>Cancel</Button>
            <Button variant="danger" disabled={remove.isPending} onClick={() => void onDelete()}>
              Delete rule
            </Button>
          </>
        }
      >
        <p>
          The current tag value for matching retained history will change after this rule is
          removed.
        </p>
        {remove.isError ? <p role="alert">{remove.error.message}</p> : null}
      </Modal>
    </Card>
  )
}
