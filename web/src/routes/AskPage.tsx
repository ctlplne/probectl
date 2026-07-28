// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import styles from './ask.module.css'
import { Page } from './RoutePage'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingState,
  useToast,
} from '../components'
import {
  confidenceTone,
  useAsk,
  useSubmitFeedback,
  type Answer,
  type Evidence,
  type InvestigationStep,
} from '../api/ai'
import { useCreateRemediationProposal, useRemediations } from '../api/remediation'
import { proposalFromAnswer, type ProposalContext } from '../remediation/proposalContext'
import { DateTime } from '../time/DateTime'
import { useI18n } from '../i18n/useI18n'
import { formatCount } from '../i18n/number'
import type { MessageKey } from '../i18n/messages'
import { parsePivotContext, replacePivotContext, type PivotContext } from './pivotContext'
import { useIncident } from '../api/incidents'
import { isApiStatus } from '../api/client'
import { ReasoningBadge } from './ExplainView'
import { resolveClaims } from './explanationGrounding'
import { downloadHandoff } from '../ai/handoff'

function fmtVal(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (typeof v === 'object') return JSON.stringify(v) ?? ''
  if (typeof v === 'function') return '[function]'
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean' || typeof v === 'bigint') {
    return String(v)
  }
  if (typeof v === 'symbol') return v.description ?? ''
  return ''
}

function planTone(status: InvestigationStep['status']): 'success' | 'warning' | 'neutral' {
  if (status === 'queried') return 'success'
  if (status === 'blocked' || status === 'skipped') return 'warning'
  return 'neutral'
}

const EXAMPLES: MessageKey[] = [
  'ask.example.slow',
  'ask.example.routingChange',
  'ask.example.latestIncident',
]

function planStatusLabel(status: InvestigationStep['status'], t: (key: MessageKey) => string) {
  if (status === 'queried') return t('ask.plan.status.queried')
  if (status === 'blocked') return t('ask.plan.status.blocked')
  if (status === 'skipped') return t('ask.plan.status.skipped')
  return t('ask.plan.status.pending')
}

/** The AI assistant surface (S24, design-led). PR1 established correctness +
 *  citations + trust cues; PR2 iterates the experience: citations jump to and
 *  highlight the exact cited signal, evidence is grouped by plane with a "cited
 *  by" backlink and expandable raw detail, the trust summary is sharper, and
 *  feedback takes an optional note. Built on the S8a design system. */
export function AskPage() {
  const [params, setParams] = useSearchParams()
  const { t } = useI18n()
  const parsedPivot = useMemo(() => parsePivotContext(params), [params])
  const pivot = parsedPivot.context
  const prefillQuestion = params.get('question') ?? ''
  const contextIncident = useIncident(pivot.incidentId)
  const contextIncidentID = contextIncident.data?.id
  const authorizedContextIncident =
    contextIncidentID === pivot.incidentId ? contextIncidentID : undefined
  const incidentID =
    authorizedContextIncident ??
    (!pivot.incidentId
      ? (params.get('incident_id') ?? params.get('incident') ?? undefined)
      : undefined)
  const target = params.get('target') ?? undefined
  const [question, setQuestion] = useState(prefillQuestion)
  const ask = useAsk()
  const proposalContext = useMemo<ProposalContext>(
    () => ({ ...(incidentID ? { incidentID } : {}), ...(target ? { target } : {}) }),
    [incidentID, target],
  )

  useEffect(() => {
    if (prefillQuestion) setQuestion(prefillQuestion)
  }, [prefillQuestion])

  useEffect(() => {
    if (
      pivot.incidentId &&
      (contextIncident.isError ||
        (contextIncident.isSuccess && contextIncident.data.id !== pivot.incidentId))
    ) {
      setParams(
        replacePivotContext(params, {
          ...pivot,
          incidentId: undefined,
          selection: undefined,
        }),
        { replace: true },
      )
    }
  }, [
    contextIncident.data,
    contextIncident.isError,
    contextIncident.isSuccess,
    params,
    pivot,
    setParams,
  ])

  function onSubmit(e: FormEvent) {
    e.preventDefault()
    const q = question.trim()
    const subject: Record<string, string> = {}
    if (incidentID) subject.incident_id = incidentID
    if (target) subject.target = target
    if (q) {
      const range = pivot.from && pivot.to ? { start: pivot.from, end: pivot.to } : undefined
      ask.mutate({
        question: q,
        ...(Object.keys(subject).length > 0 ? { subject } : {}),
        ...(range ? { range } : {}),
      })
    }
  }

  return (
    <Page title={t('ask.page.title')} subtitle={t('ask.page.subtitle')}>
      <Card>
        <CardHeader title={t('ask.card.title')} />
        <CardBody>
          <form className={styles.askForm} onSubmit={onSubmit}>
            <label className={styles.label} htmlFor="ai-question">
              {t('ask.question.label')}
            </label>
            <textarea
              id="ai-question"
              className={styles.textarea}
              rows={3}
              placeholder={t('ask.question.placeholder')}
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
            />
            <div className={styles.formRow}>
              <div className={styles.examples}>
                {EXAMPLES.map((ex) => {
                  const label = t(ex)
                  return (
                    <button
                      key={ex}
                      type="button"
                      className={styles.example}
                      onClick={() => setQuestion(label)}
                    >
                      {label}
                    </button>
                  )
                })}
              </div>
              <Button
                type="submit"
                disabled={
                  ask.isPending ||
                  (Boolean(pivot.incidentId) &&
                    (contextIncident.isPending || !authorizedContextIncident)) ||
                  question.trim() === ''
                }
              >
                {ask.isPending ? t('ask.submit.pending') : t('ask.submit')}
              </Button>
            </div>
          </form>
        </CardBody>
      </Card>

      {ask.isPending ? (
        <LoadingState label={t('ask.loading')} />
      ) : ask.isError ? (
        <ErrorState description={t('ask.error')} />
      ) : ask.data ? (
        <AnswerView
          answer={ask.data}
          proposalContext={proposalContext}
          pivotContext={pivot}
          params={params}
          setParams={setParams}
        />
      ) : (
        <EmptyState title={t('ask.empty.title')} description={t('ask.empty.description')} />
      )}
    </Page>
  )
}

interface PlaneGroup {
  plane: string
  items: Evidence[]
}

function evidenceMatchesSelection(evidence: Evidence, selectionID: string): boolean {
  return evidence.id === selectionID || evidence.fields?.id === selectionID
}

export function AnswerView({
  answer,
  proposalContext,
  pivotContext,
  params,
  setParams,
}: {
  answer: Answer
  proposalContext?: ProposalContext
  pivotContext: PivotContext
  params: URLSearchParams
  setParams: ReturnType<typeof useSearchParams>[1]
}) {
  const { locale, t } = useI18n()
  const feedback = useSubmitFeedback()
  const remediations = useRemediations()
  const createProposal = useCreateRemediationProposal()
  const { push } = useToast()
  const [comment, setComment] = useState('')
  const remediationError = remediations.isError && !isApiStatus(remediations.error, 404)
  const selectedEvidence =
    pivotContext.selection?.kind === 'evidence'
      ? answer.evidence.find((evidence) =>
          evidenceMatchesSelection(evidence, pivotContext.selection?.id ?? ''),
        )
      : undefined
  const selectedEvidenceID = selectedEvidence?.id ?? null
  const canPropose = Boolean(remediations.data)
  const resolvedClaims = resolveClaims(answer)
  const proposalDisabled =
    createProposal.isPending ||
    answer.insufficient_evidence ||
    !resolvedClaims.rootResolved ||
    answer.evidence.length === 0
  const rootCauseGrounded = resolvedClaims.rootResolved
  const rootCauseCitations = resolvedClaims.rootResolved ? resolvedClaims.rootCitations : []
  const groundedFindings = resolvedClaims.findings
  const investigationPlan = answer.investigation_plan ?? []

  // Bidirectional grounding: which findings cite each piece of evidence.
  const citedBy = new Map<string, number[]>()
  groundedFindings.forEach((f, i) => {
    f.citations.forEach((c) => {
      const arr = citedBy.get(c.evidence_id) ?? []
      arr.push(i + 1)
      citedBy.set(c.evidence_id, arr)
    })
  })

  // Group evidence by plane (recency-ordered within a plane) for readability.
  const groups: PlaneGroup[] = []
  const index = new Map<string, number>()
  answer.evidence.forEach((e) => {
    const plane = e.plane || e.domain || 'other'
    let gi = index.get(plane)
    if (gi === undefined) {
      gi = groups.length
      index.set(plane, gi)
      groups.push({ plane, items: [] })
    }
    groups[gi].items.push(e)
  })
  groups.forEach((g) =>
    g.items.sort((a, b) => (b.occurred_at ?? '').localeCompare(a.occurred_at ?? '')),
  )
  const planes = groups.map((g) => g.plane)

  useEffect(() => {
    if (
      pivotContext.selection?.kind === 'evidence' &&
      !answer.evidence.some((evidence) =>
        evidenceMatchesSelection(evidence, pivotContext.selection?.id ?? ''),
      )
    ) {
      setParams(replacePivotContext(params, { ...pivotContext, selection: undefined }), {
        replace: true,
      })
    }
  }, [answer.evidence, params, pivotContext, setParams])

  function focusEvidence(id: string) {
    document.getElementById(`ev-${id}`)?.focus()
    setParams(
      replacePivotContext(params, {
        ...pivotContext,
        selection: { kind: 'evidence', id },
      }),
    )
  }

  function proposeFromAnswer() {
    createProposal.mutate(proposalFromAnswer(answer, proposalContext), {
      onSuccess: (p) =>
        push({
          tone: 'success',
          title: t('ask.toast.proposalCreated'),
          message: t('ask.toast.proposalCreatedMessage', { id: p.id }),
        }),
      onError: (err) =>
        push({
          tone: 'danger',
          title: t('ask.toast.proposalFailed'),
          message: err instanceof Error ? err.message : t('ask.toast.proposalFailedMessage'),
        }),
    })
  }

  function submitFeedback(rating: 'up' | 'down') {
    feedback.mutate(
      {
        answer_id: answer.id,
        rating,
        comment: comment || undefined,
        question: answer.question,
      },
      {
        onError: (error) =>
          push({
            tone: 'danger',
            title: 'Feedback not saved',
            message: error instanceof Error ? error.message : 'Could not save answer feedback.',
          }),
      },
    )
  }

  return (
    <div className={styles.answer}>
      {remediationError ? (
        <ErrorState
          title="Remediation availability unknown"
          description="Could not determine whether guarded, human-approved proposals are available."
        />
      ) : null}
      <Card>
        <CardHeader
          title={t('ask.root.title')}
          actions={
            <div className={styles.actionsRow}>
              <Badge tone={confidenceTone(answer.confidence)}>
                {t('ask.confidence', { value: answer.confidence })}
              </Badge>
              <Badge tone={rootCauseGrounded ? 'success' : 'warning'}>
                {rootCauseGrounded ? t('ask.grounding.grounded') : t('ask.grounding.ungrounded')}
              </Badge>
              {answer.degraded ? <Badge tone="warning">{t('ask.grounding.degraded')}</Badge> : null}
              <ReasoningBadge answer={answer} />
              <Button variant="secondary" onClick={() => downloadHandoff(answer, locale)}>
                {t('ask.handoff.download')}
              </Button>
              {canPropose ? (
                <Button
                  variant="secondary"
                  onClick={proposeFromAnswer}
                  disabled={proposalDisabled}
                  title={
                    answer.insufficient_evidence || answer.evidence.length === 0
                      ? t('ask.propose.disabledTitle')
                      : undefined
                  }
                >
                  {createProposal.isPending ? t('ask.propose.pending') : t('ask.propose.action')}
                </Button>
              ) : null}
            </div>
          }
        />
        <CardBody>
          {rootCauseGrounded ? <p className={styles.rootCause}>{answer.root_cause}</p> : null}
          {answer.insufficient_evidence ? (
            <p className={styles.note}>{t('ask.note.insufficient')}</p>
          ) : null}
          {!rootCauseGrounded ? (
            <p className={styles.note} role="status">
              {t('ask.note.ungrounded')}
            </p>
          ) : null}
          {resolvedClaims.suppressedClaims > 0 ? (
            <p className={styles.note}>
              {resolvedClaims.suppressedClaims} unresolved causal claim
              {resolvedClaims.suppressedClaims === 1 ? '' : 's'} suppressed because the exact
              evidence citation did not resolve.
            </p>
          ) : null}
          {answer.degraded ? <p className={styles.note}>{t('ask.note.degraded')}</p> : null}
          {rootCauseCitations.length > 0 ? (
            <p className={[styles.cites, styles.rootCites].join(' ')}>
              <span className={styles.citeLabel}>{t('ask.rootCauseCited')}</span>
              {rootCauseCitations.map((c) => (
                <a
                  key={c.evidence_id}
                  href={`#ev-${c.evidence_id}`}
                  className={styles.cite}
                  onClick={(ev) => {
                    ev.preventDefault()
                    focusEvidence(c.evidence_id)
                  }}
                >
                  {c.evidence_id}
                </a>
              ))}
            </p>
          ) : null}
          <p className={styles.provenance}>
            {t('ask.provenance', {
              model: answer.model,
              degraded: answer.degraded ? t('ask.provenance.degraded') : '',
              grounding: rootCauseGrounded
                ? t('ask.grounding.grounded')
                : t('ask.grounding.ungrounded'),
              signals: formatCount(
                answer.evidence.length,
                t('ask.signal.singular'),
                t('ask.signal.plural'),
                locale,
              ),
              planes: formatCount(
                planes.length,
                t('ask.plane.singular'),
                t('ask.plane.plural'),
                locale,
              ),
              planeList: planes.length ? `: ${planes.join(', ')}` : '',
            })}
          </p>
        </CardBody>
      </Card>

      {investigationPlan.length > 0 ? (
        <Card>
          <CardHeader title={t('ask.investigation.title')} />
          <CardBody>
            <ol className={styles.plan} aria-label={t('ask.investigation.aria')}>
              {investigationPlan.map((step) => (
                <li key={`${step.step}-${step.domain}`} className={styles.planStep}>
                  <div className={styles.planTopline}>
                    <span className={styles.planIndex}>{step.step}</span>
                    <span className={styles.planDomain}>{step.domain}</span>
                    <Badge tone={planTone(step.status)}>{planStatusLabel(step.status, t)}</Badge>
                    {step.read_only ? <Badge tone="neutral">{t('ask.plan.readOnly')}</Badge> : null}
                  </div>
                  <p className={styles.planGoal}>{step.goal}</p>
                  <p className={styles.planMeta}>
                    {[
                      formatCount(
                        step.evidence_count ?? 0,
                        t('ask.signal.singular'),
                        t('ask.signal.plural'),
                        locale,
                      ),
                      step.node_id ? t('ask.plan.node', { id: step.node_id }) : '',
                      step.reason ?? '',
                      step.truncated ? t('ask.plan.truncated') : '',
                    ]
                      .filter(Boolean)
                      .join(' · ')}
                  </p>
                </li>
              ))}
            </ol>
          </CardBody>
        </Card>
      ) : null}

      {groundedFindings.length > 0 ? (
        <Card>
          <CardHeader title={t('ask.findings.title')} />
          <CardBody>
            <ol className={styles.findings} aria-label={t('ask.findings.aria')}>
              {groundedFindings.map((f, i) => (
                <li key={i} className={styles.finding}>
                  <p className={styles.statement}>{f.statement}</p>
                  <p className={styles.cites}>
                    <span className={styles.citeLabel}>{t('ask.cited')}</span>
                    {f.citations.map((c) => (
                      <a
                        key={c.evidence_id}
                        href={`#ev-${c.evidence_id}`}
                        className={styles.cite}
                        onClick={(ev) => {
                          ev.preventDefault()
                          focusEvidence(c.evidence_id)
                        }}
                      >
                        {c.evidence_id}
                      </a>
                    ))}
                  </p>
                </li>
              ))}
            </ol>
          </CardBody>
        </Card>
      ) : null}

      {answer.evidence.length > 0 ? (
        <Card>
          <CardHeader title={t('ask.evidence.title')} />
          <CardBody>
            {groups.map((g) => (
              <section
                key={g.plane}
                className={styles.planeGroup}
                aria-label={t('ask.evidence.aria', { plane: g.plane })}
              >
                <h3 className={styles.planeHeader}>{g.plane}</h3>
                <ul className={styles.evidence}>
                  {g.items.map((e) => {
                    const cites = citedBy.get(e.id)
                    return (
                      <li
                        key={e.id}
                        id={`ev-${e.id}`}
                        tabIndex={-1}
                        className={[
                          styles.evItem,
                          selectedEvidenceID === e.id ? styles.evHighlight : '',
                        ]
                          .filter(Boolean)
                          .join(' ')}
                      >
                        <span className={styles.evId}>{e.id}</span>
                        <div className={styles.evBody}>
                          <div className={styles.evRow}>
                            {e.severity ? <Badge tone="neutral">{e.severity}</Badge> : null}
                            {e.occurred_at ? (
                              <DateTime value={e.occurred_at} className={styles.evTime} />
                            ) : null}
                            {cites ? (
                              <span className={styles.citedBy}>
                                {t('ask.citedBy', { indexes: cites.join(', ') })}
                              </span>
                            ) : null}
                          </div>
                          <p className={styles.evTitle}>{e.title || e.ref || e.id}</p>
                          {e.summary ? <p className={styles.evSummary}>{e.summary}</p> : null}
                          {e.fields && Object.keys(e.fields).length > 0 ? (
                            <details className={styles.raw}>
                              <summary className={styles.rawSummary}>{t('ask.rawSignal')}</summary>
                              <dl className={styles.rawFields}>
                                {Object.entries(e.fields).map(([k, v]) => (
                                  <div key={k} className={styles.rawRow}>
                                    <dt>{k}</dt>
                                    <dd>{fmtVal(v)}</dd>
                                  </div>
                                ))}
                              </dl>
                            </details>
                          ) : null}
                        </div>
                      </li>
                    )
                  })}
                </ul>
              </section>
            ))}
          </CardBody>
        </Card>
      ) : null}

      <Card>
        <CardHeader title={t('ask.feedback.title')} />
        <CardBody>
          {feedback.isSuccess ? (
            <p className={styles.thanks} role="status">
              {t('ask.feedback.thanks')}
            </p>
          ) : (
            <div className={styles.feedback}>
              <label className={styles.fbCommentLabel} htmlFor="fb-comment">
                {t('ask.feedback.label')}
              </label>
              <textarea
                id="fb-comment"
                className={styles.fbComment}
                rows={2}
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder={t('ask.feedback.placeholder')}
              />
              <div className={styles.fbButtons} role="group" aria-label={t('ask.feedback.aria')}>
                <Button
                  variant="secondary"
                  onClick={() => submitFeedback('up')}
                  disabled={feedback.isPending}
                >
                  {t('ask.feedback.yes')}
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => submitFeedback('down')}
                  disabled={feedback.isPending}
                >
                  {t('ask.feedback.no')}
                </Button>
              </div>
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  )
}
