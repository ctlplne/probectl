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
import { confidenceTone, useAsk, useSubmitFeedback, type Answer, type Evidence } from '../api/ai'
import { useCreateRemediationProposal, useRemediations } from '../api/remediation'
import { proposalFromAnswer, type ProposalContext } from '../remediation/proposalContext'
import { DateTime } from '../time/DateTime'

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

const EXAMPLES = [
  'Why is api.example.com slow?',
  'Did a routing change affect 192.0.2.0/24?',
  'What caused the latest incident?',
]

/** The AI assistant surface (S24, design-led). PR1 established correctness +
 *  citations + trust cues; PR2 iterates the experience: citations jump to and
 *  highlight the exact cited signal, evidence is grouped by plane with a "cited
 *  by" backlink and expandable raw detail, the trust summary is sharper, and
 *  feedback takes an optional note. Built on the S8a design system. */
export function AskPage() {
  const [params] = useSearchParams()
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
    <Page
      title="Ask (AI)"
      subtitle="Cross-plane root-cause analysis grounded in your network's signals. Every claim is cited, and answers stay within your tenant and permissions."
    >
      <Card>
        <CardHeader title="Ask probectl" />
        <CardBody>
          <form className={styles.askForm} onSubmit={onSubmit}>
            <label className={styles.label} htmlFor="ai-question">
              Your question
            </label>
            <textarea
              id="ai-question"
              className={styles.textarea}
              rows={3}
              placeholder="Why is api.example.com slow?"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
            />
            <div className={styles.formRow}>
              <div className={styles.examples}>
                {EXAMPLES.map((ex) => (
                  <button
                    key={ex}
                    type="button"
                    className={styles.example}
                    onClick={() => setQuestion(ex)}
                  >
                    {ex}
                  </button>
                ))}
              </div>
              <Button type="submit" disabled={ask.isPending || question.trim() === ''}>
                {ask.isPending ? 'Analyzing…' : 'Ask'}
              </Button>
            </div>
          </form>
        </CardBody>
      </Card>

      {ask.isPending ? (
        <LoadingState label="Analyzing signals across planes…" />
      ) : ask.isError ? (
        <ErrorState description="The assistant is temporarily unavailable. Please try again." />
      ) : ask.data ? (
        <AnswerView answer={ask.data} context={context} />
      ) : (
        <EmptyState
          title="Ask a question to begin"
          description="probectl correlates synthetic, path, routing, flow, and change signals into a cited root cause — and says so when the evidence is insufficient."
        />
      )}
    </Page>
  )
}

interface PlaneGroup {
  plane: string
  items: Evidence[]
}

function AnswerView({ answer, context }: { answer: Answer; context?: ProposalContext }) {
  const feedback = useSubmitFeedback()
  const remediations = useRemediations()
  const createProposal = useCreateRemediationProposal()
  const { push } = useToast()
  const [comment, setComment] = useState('')
  const [highlighted, setHighlighted] = useState<string | null>(null)
  const canPropose = Boolean(remediations.data)
  const proposalDisabled =
    createProposal.isPending || answer.insufficient_evidence || answer.evidence.length === 0

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
        push({ tone: 'success', title: 'Proposal created', message: `${p.id} is proposed` }),
      onError: (err) =>
        push({
          tone: 'danger',
          title: 'Proposal failed',
          message: err instanceof Error ? err.message : 'Could not create proposal',
        }),
    })
  }

  return (
    <div className={styles.answer}>
      <Card>
        <CardHeader
          title="Root cause"
          actions={
            <div className={styles.actionsRow}>
              <Badge
                tone={confidenceTone(answer.confidence)}
              >{`${answer.confidence} confidence`}</Badge>
              {canPropose ? (
                <Button
                  variant="secondary"
                  onClick={proposeFromAnswer}
                  disabled={proposalDisabled}
                  title={
                    answer.insufficient_evidence || answer.evidence.length === 0
                      ? 'RCA evidence is insufficient for a remediation proposal.'
                      : undefined
                  }
                >
                  {createProposal.isPending ? 'Proposing...' : 'Propose remediation'}
                </Button>
              ) : null}
            </div>
          }
        />
        <CardBody>
          <p className={styles.rootCause}>{answer.root_cause}</p>
          {answer.insufficient_evidence ? (
            <p className={styles.note}>
              probectl did not find enough evidence to name a confident root cause — it will not
              guess.
            </p>
          ) : null}
          <p className={styles.provenance}>
            {`Synthesized by ${answer.model} · grounded in ${answer.evidence.length} signal(s) across ${planes.length} plane(s)${
              planes.length ? ': ' + planes.join(', ') : ''
            }.`}
          </p>
        </CardBody>
      </Card>

      {answer.findings.length > 0 ? (
        <Card>
          <CardHeader title="Findings" />
          <CardBody>
            <ol className={styles.findings} aria-label="Findings">
              {answer.findings.map((f, i) => (
                <li key={i} className={styles.finding}>
                  <p className={styles.statement}>{f.statement}</p>
                  <p className={styles.cites}>
                    <span className={styles.citeLabel}>Cited:</span>
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
          <CardHeader title="Evidence" />
          <CardBody>
            {groups.map((g) => (
              <section
                key={g.plane}
                className={styles.planeGroup}
                aria-label={`${g.plane} signals`}
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
                              <span
                                className={styles.citedBy}
                              >{`Cited in finding ${cites.join(', ')}`}</span>
                            ) : null}
                          </div>
                          <p className={styles.evTitle}>{e.title || e.ref || e.id}</p>
                          {e.summary ? <p className={styles.evSummary}>{e.summary}</p> : null}
                          {e.fields && Object.keys(e.fields).length > 0 ? (
                            <details className={styles.raw}>
                              <summary className={styles.rawSummary}>Raw signal</summary>
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
        <CardHeader title="Feedback" />
        <CardBody>
          {feedback.isSuccess ? (
            <p className={styles.thanks} role="status">
              Thanks — your feedback improves future answers.
            </p>
          ) : (
            <div className={styles.feedback}>
              <label className={styles.fbCommentLabel} htmlFor="fb-comment">
                Was this answer helpful? Add a note (optional).
              </label>
              <textarea
                id="fb-comment"
                className={styles.fbComment}
                rows={2}
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder="e.g. the real cause was the upstream peer"
              />
              <div className={styles.fbButtons} role="group" aria-label="Rate this answer">
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
                  Yes, helpful
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
                  No, not helpful
                </Button>
              </div>
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  )
}
