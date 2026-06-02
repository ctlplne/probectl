import { useState, type FormEvent } from 'react'
import styles from './ask.module.css'
import { Page } from './pages'
import { Badge, Button, Card, CardBody, CardHeader, EmptyState, ErrorState, LoadingState } from '../components'
import { confidenceTone, useAsk, useSubmitFeedback, type Answer, type Evidence } from '../api/ai'

function when(iso?: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

const EXAMPLES = [
  'Why is api.example.com slow?',
  'Did a routing change affect 192.0.2.0/24?',
  'What caused the latest incident?',
]

/** The AI assistant surface (S24, design-led): an ask box and a cited,
 *  trust-cued root-cause answer, built on the S8a design system. PR1 establishes
 *  correctness + citations + the trust cues (confidence, provenance, citation
 *  chips); later PRs iterate the experience (streaming, evidence reading). */
export function AskPage() {
  const [question, setQuestion] = useState('')
  const ask = useAsk()

  function onSubmit(e: FormEvent) {
    e.preventDefault()
    const q = question.trim()
    if (q) ask.mutate({ question: q })
  }

  return (
    <Page
      title="Ask (AI)"
      subtitle="Cross-plane root-cause analysis grounded in your network's signals. Every claim is cited, and answers stay within your tenant and permissions."
    >
      <Card>
        <CardHeader title="Ask netctl" />
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
                  <button key={ex} type="button" className={styles.example} onClick={() => setQuestion(ex)}>
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
        <AnswerView answer={ask.data} />
      ) : (
        <EmptyState
          title="Ask a question to begin"
          description="netctl correlates synthetic, path, routing, flow, and change signals into a cited root cause — and says so when the evidence is insufficient."
        />
      )}
    </Page>
  )
}

function AnswerView({ answer }: { answer: Answer }) {
  const feedback = useSubmitFeedback()
  return (
    <div className={styles.answer}>
      <Card>
        <CardHeader
          title="Root cause"
          actions={<Badge tone={confidenceTone(answer.confidence)}>{`${answer.confidence} confidence`}</Badge>}
        />
        <CardBody>
          <p className={styles.rootCause}>{answer.root_cause}</p>
          {answer.insufficient_evidence ? (
            <p className={styles.note}>netctl did not find enough evidence to name a confident root cause — it will not guess.</p>
          ) : null}
          <p className={styles.provenance}>
            {`Synthesized by ${answer.model}, grounded in ${answer.evidence.length} signal(s) within your scope.`}
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
                    {f.citations.map((c) => (
                      <a key={c.evidence_id} href={`#ev-${c.evidence_id}`} className={styles.cite}>
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
            <ul className={styles.evidence} aria-label="Evidence">
              {answer.evidence.map((e: Evidence) => (
                <li key={e.id} id={`ev-${e.id}`} className={styles.evItem}>
                  <span className={styles.evId}>{e.id}</span>
                  <div className={styles.evBody}>
                    <div className={styles.evRow}>
                      <Badge tone="accent">{e.plane || e.domain}</Badge>
                      {e.severity ? <Badge tone="neutral">{e.severity}</Badge> : null}
                      {e.occurred_at ? <span className={styles.evTime}>{when(e.occurred_at)}</span> : null}
                    </div>
                    <p className={styles.evTitle}>{e.title || e.ref || e.id}</p>
                    {e.summary ? <p className={styles.evSummary}>{e.summary}</p> : null}
                  </div>
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>
      ) : null}

      <Card>
        <CardBody>
          <div className={styles.feedback}>
            <span id="fb-label">Was this answer helpful?</span>
            {feedback.isSuccess ? (
              <span className={styles.thanks} role="status">
                Thanks — your feedback improves future answers.
              </span>
            ) : (
              <div className={styles.fbButtons} role="group" aria-labelledby="fb-label">
                <Button
                  variant="secondary"
                  onClick={() => feedback.mutate({ answer_id: answer.id, rating: 'up', question: answer.question })}
                  disabled={feedback.isPending}
                >
                  Yes, helpful
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => feedback.mutate({ answer_id: answer.id, rating: 'down', question: answer.question })}
                  disabled={feedback.isPending}
                >
                  No, not helpful
                </Button>
              </div>
            )}
          </div>
        </CardBody>
      </Card>
    </div>
  )
}
