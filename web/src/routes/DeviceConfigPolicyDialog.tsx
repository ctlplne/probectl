// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useContext, useRef, useState } from 'react'
import { apiDownload, apiFetch, isApiStatus } from '../api/client'
import type { DeviceConfigVersion } from '../api/planes'
import type {
  DeviceConfigPolicyArchiveEvaluation,
  DeviceConfigPolicyBindingInput,
  DeviceConfigPolicyRevision,
  DeviceConfigPolicyRuleInput,
  DeviceConfigPolicyVerdict,
} from '../api/sdk.gen'
import { AuthContext } from '../auth/AuthProvider'
import { Badge, Button, ErrorState, Field, LoadingState, Modal, Select } from '../components'
import { DateTime } from '../time/DateTime'
import styles from './planes.module.css'

const modes = [
  { value: 'must_contain', label: 'Must contain' },
  { value: 'must_not_contain', label: 'Must not contain' },
  { value: 'template', label: 'Configuration template' },
]

const templates = [
  { value: 'ios_ntp_server', label: 'Cisco IOS NTP server' },
  { value: 'ios_snmpv3_only', label: 'Cisco IOS SNMPv3 only' },
  { value: 'ios_vty_ssh_only', label: 'Cisco IOS SSH-only VTY' },
  { value: 'ios_aaa_login', label: 'Cisco IOS AAA login' },
  { value: 'ios_remote_logging', label: 'Cisco IOS remote logging' },
  { value: 'frr_configured_logging', label: 'FRRouting logging' },
  { value: 'chrony_ntp_source', label: 'Chrony NTP source' },
]

const states = {
  pass: { label: 'Pass', tone: 'success' },
  violation: { label: 'Violation', tone: 'danger' },
  evidence_unavailable: { label: 'Evidence unavailable', tone: 'neutral' },
} as const

export function DeviceConfigPolicyAction({ config }: { config: DeviceConfigVersion }) {
  const auth = useContext(AuthContext)
  const [open, setOpen] = useState(false)
  const trigger = useRef<HTMLButtonElement | null>(null)
  if (!config.binding) return null
  const { context_id, device_entity_id, agent_id, source_ref } = config.binding
  return (
    <>
      <Button
        variant="secondary"
        size="sm"
        onClick={(event) => {
          trigger.current = event.currentTarget
          setOpen(true)
        }}
      >
        Configuration policy
      </Button>
      {open ? (
        <Modal
          open
          onClose={() => setOpen(false)}
          returnFocusRef={trigger}
          title={`Configuration policy · ${config.device}`}
          footer={<Button onClick={() => setOpen(false)}>Close</Button>}
        >
          <DeviceConfigPolicy
            key={JSON.stringify([auth?.tenant.id, auth?.user.id, config.id])}
            id={config.id}
            binding={{ context_id, device_entity_id, agent_id, source_ref }}
          />
        </Modal>
      ) : null}
    </>
  )
}

function DeviceConfigPolicy({
  id,
  binding,
}: {
  id: string
  binding: DeviceConfigPolicyBindingInput
}) {
  const auth = useContext(AuthContext)
  const key = ['device-config-policy', auth?.tenant.id, auth?.user.id, auth?.permissions]
  const path = `/device/configs/${encodeURIComponent(id)}/policy-evaluation`
  const result = useQuery({
    queryKey: [...key, id],
    queryFn: ({ signal }) => apiFetch<DeviceConfigPolicyArchiveEvaluation>(path, { signal }),
  })
  const [downloadError, setDownloadError] = useState(false)
  const download = () => {
    try {
      apiDownload(`${path}?format=csv`)
    } catch {
      setDownloadError(true)
    }
  }

  return (
    <div className={styles.configDiff}>
      <section aria-label="Archived evaluation" className={styles.configDiff}>
        {result.isPending ? (
          <LoadingState label="Loading configuration policy evaluation" />
        ) : result.isError ? (
          <ErrorState description="The original policy evaluation is unavailable." />
        ) : result.data.evaluation ? (
          <>
            <div className={styles.configDiffSummary}>
              <span>Rule revision {result.data.evaluation.policy_version}</span>
              <DateTime value={result.data.evaluation.evaluated_at} />
              <Button variant="secondary" size="sm" onClick={download}>
                Download CSV
              </Button>
            </div>
            {downloadError ? <p role="alert">The CSV download is unavailable.</p> : null}
            <ul className={styles.configDiff}>
              {result.data.evaluation.verdicts.map((verdict) => (
                <PolicyVerdict key={verdict.rule_id} verdict={verdict} />
              ))}
            </ul>
          </>
        ) : (
          <p className={styles.muted}>This archive has no retained policy evaluation.</p>
        )}
      </section>
      {auth?.permissions.includes('metrics.write') ? (
        <ConfigPolicyEditor binding={binding} queryKey={[...key, binding]} />
      ) : null}
    </div>
  )
}

function PolicyVerdict({ verdict }: { verdict: DeviceConfigPolicyVerdict }) {
  const state = states[verdict.state]
  return (
    <li className={styles.configDiff}>
      <div className={styles.configDiffSummary}>
        <strong>{verdict.rule_id}</strong>
        <Badge tone={state.tone}>{state.label}</Badge>
      </div>
      {verdict.offending_lines?.map((line) => (
        <div key={line.line_number}>
          <span>Line {line.line_number} </span>
          <code dir="ltr">{line.redacted_line}</code>
        </div>
      ))}
    </li>
  )
}

function ConfigPolicyEditor({
  binding,
  queryKey,
}: {
  binding: DeviceConfigPolicyBindingInput
  queryKey: readonly unknown[]
}) {
  const client = useQueryClient()
  const search = new URLSearchParams({ ...binding })
  const policy = useQuery({
    queryKey,
    queryFn: ({ signal }) =>
      apiFetch<DeviceConfigPolicyRevision>(`/device/config-policy?${search}`, { signal }),
  })
  const [draft, setDraft] = useState<{
    version: string
    rules: DeviceConfigPolicyRuleInput[]
  } | null>(null)
  const publish = useMutation({
    mutationFn: ({ version, rules }: { version: string; rules: DeviceConfigPolicyRuleInput[] }) =>
      apiFetch<DeviceConfigPolicyRevision>('/device/config-policy', {
        method: 'PUT',
        body: JSON.stringify({ binding, expected_revision: version, rules }),
      }),
    onSuccess: (value) => {
      client.setQueryData(queryKey, value)
      setDraft(null)
    },
  })

  if (policy.isPending) return <LoadingState label="Loading current configuration rules" />
  if (policy.isError)
    return <ErrorState description="Current configuration rules are unavailable." />

  const { version } = policy.data
  const rules =
    draft?.rules ??
    policy.data.rules.map(({ id, mode, text, template }) => ({ id, mode, text, template }))
  const changeRules = (next: DeviceConfigPolicyRuleInput[]) =>
    setDraft({ version: draft?.version ?? version, rules: next })
  const replaceRule = (index: number, rule: DeviceConfigPolicyRuleInput) =>
    changeRules(rules.map((item, i) => (i === index ? rule : item)))

  return (
    <form
      aria-label="Current configuration rules"
      className={styles.configDiff}
      onSubmit={(event) => {
        event.preventDefault()
        if (draft) publish.mutate(draft)
      }}
    >
      <strong>Current rules</strong>
      {rules.map((rule, index) => (
        <PolicyRuleEditor
          key={index}
          rule={rule}
          index={index}
          onChange={(value) => replaceRule(index, value)}
          onRemove={() => changeRules(rules.filter((_, i) => i !== index))}
        />
      ))}
      <div className={styles.configDiffSummary}>
        <Button
          type="button"
          variant="secondary"
          disabled={rules.length >= 128}
          onClick={() =>
            changeRules([...rules, { id: '', mode: 'template', template: 'ios_ntp_server' }])
          }
        >
          Add rule
        </Button>
        <Button type="submit" disabled={draft === null || publish.isPending}>
          Publish for new archives
        </Button>
      </div>
      {isApiStatus(publish.error, 409) ? (
        <div className={styles.configDiffSummary}>
          <p role="alert">The saved policy changed while you were editing.</p>
          <Button
            type="button"
            variant="secondary"
            onClick={() => {
              setDraft(null)
              publish.reset()
              void policy.refetch()
            }}
          >
            Discard draft and reload
          </Button>
        </div>
      ) : publish.isError ? (
        <p role="alert">Could not publish the configuration rules.</p>
      ) : null}
    </form>
  )
}

function PolicyRuleEditor({
  rule,
  index,
  onChange,
  onRemove,
}: {
  rule: DeviceConfigPolicyRuleInput
  index: number
  onChange: (rule: DeviceConfigPolicyRuleInput) => void
  onRemove: () => void
}) {
  return (
    <fieldset className={styles.configDiff}>
      <legend>Rule {index + 1}</legend>
      <Field
        label="Rule ID"
        value={rule.id}
        pattern="[a-z0-9_\-]+"
        maxLength={64}
        required
        onChange={(event) => onChange({ ...rule, id: event.target.value })}
      />
      <Select
        label="Rule type"
        options={modes}
        value={rule.mode}
        onChange={(event) => {
          const mode = event.target.value as DeviceConfigPolicyRuleInput['mode']
          onChange(
            mode === 'template'
              ? { id: rule.id, mode, template: 'ios_ntp_server' }
              : { id: rule.id, mode, text: '' },
          )
        }}
      />
      {rule.mode === 'template' ? (
        <Select
          label="Template"
          options={templates}
          value={rule.template ?? 'ios_ntp_server'}
          onChange={(event) =>
            onChange({
              ...rule,
              template: event.target.value as DeviceConfigPolicyRuleInput['template'],
            })
          }
        />
      ) : (
        <Field
          label="Match text"
          value={rule.text ?? ''}
          maxLength={256}
          required
          onChange={(event) => onChange({ ...rule, text: event.target.value })}
        />
      )}
      <Button type="button" variant="secondary" size="sm" onClick={onRemove}>
        Remove rule
      </Button>
    </fieldset>
  )
}
