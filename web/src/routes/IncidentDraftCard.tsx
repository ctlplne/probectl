// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { generateIncidentDraft, type Incident } from '../api/incidents'
import type {
  IncidentDraftCitation,
  IncidentDraftKind,
  IncidentDraftResponse,
} from '../api/sdk.gen'
import { useAuth } from '../auth/useAuth'
import { Badge, Button, Card, CardBody, CardHeader, ErrorState, Field, Select } from '../components'
import type { MessageKey } from '../i18n/messages'
import { useI18n } from '../i18n/useI18n'
import styles from './flowExplorer.module.css'

const kindLabels: Record<IncidentDraftKind, MessageKey> = {
  carrier_ticket: 'incidents.draft.carrier',
  postmortem: 'incidents.draft.postmortem',
  executive_summary: 'incidents.draft.executive',
}

const sectionLabels: Record<string, MessageKey> = {
  overview: 'incidents.draft.overview',
  impact: 'incidents.draft.impact',
  timeline: 'incidents.draft.timeline',
  technical_findings: 'incidents.draft.findings',
  follow_up: 'incidents.draft.followUp',
  measurements: 'incidents.draft.measurements',
  routing: 'incidents.draft.routing',
  handoffs: 'incidents.draft.handoffs',
  coverage: 'incidents.draft.coverage',
}

const stateLabels: Record<string, MessageKey> = {
  observed: 'incidents.draft.observed',
  inferred: 'incidents.draft.inferred',
  unknown: 'incidents.draft.unknown',
  stale: 'incidents.draft.stale',
  unsupported: 'incidents.draft.unsupported',
}

type DisplayedDraft = {
  response: IncidentDraftResponse
  bytes: Uint8Array<ArrayBuffer>
  excerpts: unknown[][][]
}

export function IncidentDraftCard({ incident }: { incident: Incident }) {
  const { tenant, user, permissions, hasScopedGrants } = useAuth()
  const { t } = useI18n()
  if (!permissions.includes('incident.read') || !permissions.includes('ai.query')) return null
  const has = (...needed: string[]) =>
    needed.every((permission) => permissions.includes(permission))
  const identity = JSON.stringify([
    tenant.id,
    user.id,
    [...permissions].sort(),
    Boolean(hasScopedGrants),
    incident.id,
  ])
  return (
    <Card>
      <CardHeader title={t('incidents.draft.title')} />
      <CardBody>
        <DraftForm
          key={identity}
          incident={incident}
          canCarrier={has(
            'entities.read',
            'metrics.read',
            'events.read',
            'test.read',
            'change.read',
          )}
          canImpact={has('entities.read', 'metrics.read', 'events.read', 'flow.read')}
          canVerdict={has('entities.read', 'metrics.read', 'events.read', 'test.read')}
        />
      </CardBody>
    </Card>
  )
}

function DraftForm({
  incident,
  canCarrier,
  canImpact,
  canVerdict,
}: {
  incident: Incident
  canCarrier: boolean
  canImpact: boolean
  canVerdict: boolean
}) {
  const { t } = useI18n()
  const [kind, setKind] = useState<IncidentDraftKind>('postmortem')
  const [from, setFrom] = useState(incident.started_at)
  const [to, setTo] = useState(incident.last_seen_at)
  const [impact, setImpact] = useState(false)
  const [verdict, setVerdict] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<DisplayedDraft>()
  const active = useRef<AbortController | null>(null)
  const carrier = kind === 'carrier_ticket'
  const useWindow = carrier || impact || verdict

  const clearDraft = useCallback(() => {
    active.current?.abort()
    active.current = null
    setResult(undefined)
    setError('')
    setBusy(false)
  }, [])

  useEffect(() => {
    const clearHidden = () => {
      if (document.visibilityState === 'hidden') clearDraft()
    }
    window.addEventListener('focus', clearDraft)
    document.addEventListener('visibilitychange', clearHidden)
    return () => {
      active.current?.abort()
      active.current = null
      window.removeEventListener('focus', clearDraft)
      document.removeEventListener('visibilitychange', clearHidden)
    }
  }, [clearDraft])

  async function generate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    clearDraft()
    const request = new AbortController()
    active.current = request
    setBusy(true)
    const window = { from: from.trim(), to: to.trim() }
    try {
      const response = await generateIncidentDraft(
        incident.id,
        {
          kind,
          carrier: carrier ? window : undefined,
          impact: !carrier && impact ? window : undefined,
          verdict: !carrier && verdict ? window : undefined,
        },
        request.signal,
      )
      if (active.current === request && !request.signal.aborted) {
        setResult(readDraftEvidence(response))
      }
    } catch (reason) {
      if (active.current === request && !request.signal.aborted) {
        setError(reason instanceof Error ? reason.message : t('incidents.draft.unavailable'))
      }
    } finally {
      if (active.current === request) {
        active.current = null
        setBusy(false)
      }
    }
  }

  const kinds: IncidentDraftKind[] = canCarrier
    ? ['postmortem', 'executive_summary', 'carrier_ticket']
    : ['postmortem', 'executive_summary']

  return (
    <div className={styles.stack}>
      <form className={styles.stack} onSubmit={(event) => void generate(event)} aria-busy={busy}>
        <Select
          label={t('incidents.draft.kind')}
          options={kinds.map((value) => ({ value, label: t(kindLabels[value]) }))}
          value={kind}
          onChange={(event) => {
            const next = kinds.find((item) => item === event.target.value)
            if (!next) return
            clearDraft()
            setKind(next)
          }}
        />
        {!carrier && canImpact ? (
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={impact}
              onChange={(event) => {
                clearDraft()
                setImpact(event.target.checked)
              }}
            />
            {t('incidents.draft.includeImpact')}
          </label>
        ) : null}
        {!carrier && canVerdict ? (
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={verdict}
              onChange={(event) => {
                clearDraft()
                setVerdict(event.target.checked)
              }}
            />
            {t('incidents.draft.includeVerdict')}
          </label>
        ) : null}
        {useWindow ? (
          <div className={styles.grid}>
            <Field
              label={t('incidents.draft.from')}
              required
              value={from}
              onChange={(event) => {
                clearDraft()
                setFrom(event.target.value)
              }}
            />
            <Field
              label={t('incidents.draft.to')}
              required
              value={to}
              onChange={(event) => {
                clearDraft()
                setTo(event.target.value)
              }}
            />
          </div>
        ) : null}
        <Button type="submit" disabled={busy}>
          {t('incidents.draft.generate')}
        </Button>
      </form>
      {busy ? <p role="status">{t('incidents.draft.generating')}</p> : null}
      {error ? <ErrorState title={t('incidents.draft.unavailable')} description={error} /> : null}
      {result ? <DraftResult incidentID={incident.id} result={result} /> : null}
    </div>
  )
}

function DraftResult({ incidentID, result }: { incidentID: string; result: DisplayedDraft }) {
  const { t } = useI18n()
  const { response, bytes, excerpts } = result
  const filename = `probectl-incident-${incidentID}-${response.kind}`
  return (
    <div className={styles.stack}>
      <p role="status">
        {t('incidents.draft.ready', { model: response.model })}
        {response.degraded ? ` ${t('incidents.draft.fallback')}` : ''}
      </p>
      {response.sections.map((section, i) => (
        <section key={section.name} className={styles.roleSources}>
          <h3>
            {Object.prototype.hasOwnProperty.call(sectionLabels, section.name)
              ? t(sectionLabels[section.name])
              : section.name}
          </h3>
          {section.sentences.length === 0 ? (
            <p>{t('incidents.draft.empty')}</p>
          ) : (
            <ol>
              {section.sentences.map((sentence, j) => (
                <li key={`${section.name}-${j}`}>
                  <Badge tone={sentence.state === 'observed' ? 'success' : 'neutral'}>
                    {t(stateLabels[sentence.state] ?? 'incidents.draft.unknown')}
                  </Badge>
                  <p>{sentence.text}</p>
                  <details>
                    <summary>{t('incidents.draft.evidence')}</summary>
                    <ul>
                      {sentence.citations.map((citation, k) => (
                        <li key={`${citation.evidence_id ?? ''}${citation.pointer}`}>
                          <code>{citation.pointer}</code>
                          <pre className="overflow-x-auto">
                            {JSON.stringify(excerpts[i][j][k], null, 2)}
                          </pre>
                        </li>
                      ))}
                    </ul>
                  </details>
                </li>
              ))}
            </ol>
          )}
        </section>
      ))}
      <div className="flex flex-wrap gap-2">
        <Button
          variant="secondary"
          onClick={() =>
            download(
              new Blob([JSON.stringify(response, null, 2)], { type: 'application/json' }),
              `${filename}.json`,
            )
          }
        >
          {t('incidents.draft.download')}
        </Button>
        <Button
          variant="secondary"
          onClick={() =>
            download(
              new Blob([bytes], { type: 'application/vnd.probectl.evidence+json' }),
              `${filename}-evidence.json`,
            )
          }
        >
          {t('incidents.draft.downloadSource')}
        </Button>
      </div>
    </div>
  )
}

function readDraftEvidence(response: IncidentDraftResponse): DisplayedDraft {
  const bytes = Uint8Array.from(atob(response.evidence_package), (character) =>
    character.charCodeAt(0),
  )
  const signed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as {
    manifest: {
      package_id: string
      evidence: { id: string; attachment_digest: string }[]
    }
    attachments: { digest: string; content: unknown }[]
  }
  if (signed.manifest.package_id !== response.package_id)
    throw new Error('Draft evidence did not match')
  const records = new Map(
    signed.manifest.evidence.map((record) => [record.id, record.attachment_digest]),
  )
  const attachments = new Map(
    signed.attachments.map((attachment) => [attachment.digest, attachment.content]),
  )
  function excerpt(citation: IncidentDraftCitation): unknown {
    const digest = citation.evidence_id ? records.get(citation.evidence_id) : undefined
    let value: unknown = !citation.evidence_id ? signed.manifest : digest && attachments.get(digest)
    if (!citation.pointer.startsWith('/')) return undefined
    for (const segment of citation.pointer.slice(1).split('/')) {
      const key = segment.replace(/~1/g, '/').replace(/~0/g, '~')
      if (
        value === null ||
        typeof value !== 'object' ||
        !Object.prototype.hasOwnProperty.call(value, key)
      ) {
        return undefined
      }
      value = (value as Record<string, unknown>)[key]
    }
    return value
  }
  const excerpts = response.sections.map((section) =>
    section.sentences.map((sentence) => {
      if (sentence.citations.length === 0) throw new Error('Draft sentence has no evidence')
      return sentence.citations.map((citation) => {
        const value = excerpt(citation)
        if (value === undefined) throw new Error('Draft evidence reference could not be opened')
        return value
      })
    }),
  )
  return { response, bytes, excerpts }
}

function download(blob: Blob, filename: string) {
  const href = URL.createObjectURL(blob)
  try {
    const anchor = document.createElement('a')
    anchor.href = href
    anchor.download = filename
    anchor.click()
  } finally {
    URL.revokeObjectURL(href)
  }
}
