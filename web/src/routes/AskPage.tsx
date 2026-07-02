import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import styles from './ask.module.css'
import { Page } from './pages'
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
  const [params] = useSearchParams()
  const { t } = useI18n()
  const prefillQuestion = params.get('question') ?? ''
  const incidentID = params.get('incident_id') ?? params.get('incident') ?? undefined
  const target = params.get('target') ?? undefined
  const [question, setQuestion] = useState(prefillQuestion)
  const ask = useAsk()
  const context = useMemo<ProposalContext>(
    () => ({ ...(incidentID ? { incidentID } : {}), ...(target ? { target } : {}) }),
    [incidentID, target],
  )

  useEffect(() => {
    if (prefillQuestion) setQuestion(prefillQuestion)
  }, [prefillQuestion])

  function onSubmit(e: FormEvent) {
    e.preventDefault()
    const q = question.trim()
    const subject: Record<string, string> = {}
    if (incidentID) subject.incident_id = incidentID
    if (target) subject.target = target
    if (q) ask.mutate(Object.keys(subject).length > 0 ? { question: q, subject } : { question: q })
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
              <Button type="submit" disabled={ask.isPending || question.trim() === ''}>
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
        <AnswerView answer={ask.data} context={context} />
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

function AnswerView({ answer, context }: { answer: Answer; context?: ProposalContext }) {
  const { locale, t } = useI18n()
  const feedback = useSubmitFeedback()
  const remediations = useRemediations()
  const createProposal = useCreateRemediationProposal()
  const { push } = useToast()
  const [comment, setComment] = useState('')
  const [highlighted, setHighlighted] = useState<string | null>(null)
  const canPropose = Boolean(remediations.data)
  const proposalDisabled =
    createProposal.isPending || answer.insufficient_evidence || answer.evidence.length === 0
  const rootCauseGrounded = answer.root_cause_grounded === true
  const rootCauseCitations = answer.root_cause_citations ?? []
  const investigationPlan = answer.investigation_plan ?? []

  // Bidirectional grounding: which findings cite each piece of evidence.
  const citedBy = new Map<string, number[]>()
  answer.findings.forEach((f, i) => {
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

  function focusEvidence(id: string) {
    setHighlighted(id)
    document.getElementById(`ev-${id}`)?.focus()
  }

  function proposeFromAnswer() {
    createProposal.mutate(proposalFromAnswer(answer, context), {
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

  return (
    <div className={styles.answer}>
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
          <p className={styles.rootCause}>{answer.root_cause}</p>
          {answer.insufficient_evidence ? (
            <p className={styles.note}>{t('ask.note.insufficient')}</p>
          ) : null}
          {!rootCauseGrounded && !answer.insufficient_evidence ? (
            <p className={styles.note}>{t('ask.note.ungrounded')}</p>
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

      {answer.findings.length > 0 ? (
        <Card>
          <CardHeader title={t('ask.findings.title')} />
          <CardBody>
            <ol className={styles.findings} aria-label={t('ask.findings.aria')}>
              {answer.findings.map((f, i) => (
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
                        className={[styles.evItem, highlighted === e.id ? styles.evHighlight : '']
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
                  onClick={() =>
                    feedback.mutate({
                      answer_id: answer.id,
                      rating: 'up',
                      comment: comment || undefined,
                      question: answer.question,
                    })
                  }
                  disabled={feedback.isPending}
                >
                  {t('ask.feedback.yes')}
                </Button>
                <Button
                  variant="secondary"
                  onClick={() =>
                    feedback.mutate({
                      answer_id: answer.id,
                      rating: 'down',
                      comment: comment || undefined,
                      question: answer.question,
                    })
                  }
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
