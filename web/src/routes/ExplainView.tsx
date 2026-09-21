// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { forwardRef, useRef } from 'react'
import { Badge, Button, Card, CardBody, CardHeader, ErrorState } from '../components'
import {
  confidenceTone,
  normalizeAnswer,
  useAsk,
  type Answer,
  type Citation,
  type Evidence,
} from '../api/ai'
import { DateTime } from '../time/DateTime'
import type { PivotContext } from './pivotContext'
import { resolveClaims } from './explanationGrounding'
import styles from './explainView.module.css'

export interface ExplainViewProps {
  surface: string
  question: string
  subject?: Record<string, string | undefined>
  pivotContext: PivotContext
  onEvidenceSelect?: (evidence: Evidence) => void
  onAnswer?: (answer: Answer) => void
  initialAnswer?: Answer
}

function requestSubject(
  surface: string,
  subject: Record<string, string | undefined> | undefined,
  pivotContext: PivotContext,
): Record<string, string> {
  const clean: Record<string, string> = { surface }
  for (const [key, value] of Object.entries(subject ?? {})) {
    if (value && key !== 'tenant' && key !== 'tenant_id' && key !== 'evidence_id')
      clean[key] = value
  }
  for (const [key, value] of Object.entries(pivotContext.filters)) {
    if (value) clean[`filter_${key}`] = value
  }
  if (pivotContext.selection?.kind === 'entity') clean.node = pivotContext.selection.id
  return clean
}

export function ReasoningBadge({ answer }: { answer: Answer }) {
  const receipt = answer.reasoning
  if (!receipt) return <Badge tone="warning">Sovereignty state unavailable</Badge>

  switch (receipt.execution) {
    case 'builtin_local':
      return <Badge tone="success">Built-in · local/air-gapped</Badge>
    case 'local_adapter':
      return <Badge tone="success">{receipt.adapter} · local adapter</Badge>
    case 'external_adapter':
      return <Badge tone="warning">{receipt.adapter} · external · tenant consent granted</Badge>
    case 'builtin_fallback':
      return (
        <Badge tone="warning">
          Built-in fallback · local/air-gapped
          {receipt.attempted_adapter ? ` · ${receipt.attempted_adapter} unavailable` : ''}
        </Badge>
      )
    default:
      return <Badge tone="warning">Sovereignty state unavailable</Badge>
  }
}

export function ExplainView({
  surface,
  question,
  subject,
  pivotContext,
  onEvidenceSelect,
  onAnswer,
  initialAnswer,
}: ExplainViewProps) {
  const ask = useAsk()
  const inspector = useRef<HTMLElement>(null)
  const rawDisplayedAnswer = ask.data ?? initialAnswer
  const displayedAnswer = rawDisplayedAnswer ? normalizeAnswer(rawDisplayedAnswer) : undefined

  function explain() {
    const range =
      pivotContext.from && pivotContext.to
        ? { start: pivotContext.from, end: pivotContext.to }
        : undefined
    ask.mutate(
      {
        question,
        subject: requestSubject(surface, subject, pivotContext),
        ...(range ? { range } : {}),
      },
      {
        onSuccess: (answer) => {
          onAnswer?.(answer)
          requestAnimationFrame(() => inspector.current?.focus())
        },
      },
    )
  }

  return (
    <div className={styles.explain}>
      {!initialAnswer ? (
        <Button variant="secondary" onClick={explain} disabled={ask.isPending}>
          {ask.isPending ? 'Explaining…' : 'Explain this view'}
        </Button>
      ) : null}
      {ask.isError ? (
        <ErrorState description="This view could not be explained within your authorized scope." />
      ) : null}
      {displayedAnswer ? (
        <ExplanationInspector
          ref={inspector}
          answer={displayedAnswer}
          onEvidenceSelect={onEvidenceSelect}
        />
      ) : null}
    </div>
  )
}

function CitationLinks({
  citations,
  onSelect,
}: {
  citations: Citation[]
  onSelect?: (evidenceID: string) => void
}) {
  return (
    <span className={styles.citations} aria-label="Exact evidence citations">
      {citations.map((citation) => (
        <a
          key={citation.evidence_id}
          href={`#ev-${citation.evidence_id}`}
          onClick={(event) => {
            event.preventDefault()
            document.getElementById(`ev-${citation.evidence_id}`)?.focus()
            onSelect?.(citation.evidence_id)
          }}
        >
          {citation.evidence_id}
        </a>
      ))}
    </span>
  )
}

const ExplanationInspector = forwardRef<
  HTMLElement,
  { answer: Answer; onEvidenceSelect?: (evidence: Evidence) => void }
>(function ExplanationInspector({ answer, onEvidenceSelect }, ref) {
  const claims = resolveClaims(answer)
  const insufficient = answer.insufficient_evidence || !claims.rootResolved
  const selectEvidence = (id: string) => {
    const evidence = answer.evidence.find((item) => item.id === id)
    if (evidence) onEvidenceSelect?.(evidence)
  }

  return (
    <section
      ref={ref}
      tabIndex={-1}
      className={styles.inspector}
      aria-label="Explanation inspector"
    >
      <Card>
        <CardHeader
          title="Explanation"
          actions={
            <div className={styles.badges}>
              <Badge tone={confidenceTone(answer.confidence)}>{answer.confidence} confidence</Badge>
              <ReasoningBadge answer={answer} />
            </div>
          }
        />
        <CardBody>
          {claims.rootResolved ? (
            <div className={styles.claim}>
              <p>{answer.root_cause}</p>
              <CitationLinks citations={claims.rootCitations} onSelect={selectEvidence} />
            </div>
          ) : (
            <p className={styles.insufficient} role="status">
              Insufficient evidence: no causal headline with exact, authorized citations can be
              shown for this view.
            </p>
          )}

          {claims.findings.length > 0 ? (
            <ol className={styles.findings} aria-label="Grounded findings">
              {claims.findings.map((finding, index) => (
                <li key={`${index}-${finding.statement}`} className={styles.claim}>
                  <p>{finding.statement}</p>
                  <CitationLinks citations={finding.citations} onSelect={selectEvidence} />
                </li>
              ))}
            </ol>
          ) : null}
          {claims.suppressedClaims > 0 ? (
            <p className={styles.suppressed}>
              {claims.suppressedClaims} unresolved causal claim
              {claims.suppressedClaims === 1 ? '' : 's'} suppressed because its citations did not
              resolve.
            </p>
          ) : null}

          {answer.evidence.length > 0 ? (
            <EvidenceList evidence={answer.evidence} />
          ) : insufficient ? null : (
            <p className={styles.insufficient}>No authorized evidence was returned.</p>
          )}
        </CardBody>
      </Card>
    </section>
  )
})

function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  return (
    <div className={styles.evidenceBlock}>
      <h3>Authorized evidence</h3>
      <ul className={styles.evidence}>
        {evidence.map((item) => (
          <li key={item.id} id={`ev-${item.id}`} tabIndex={-1}>
            <code>{item.id}</code>
            <span>{item.title || item.summary || item.ref || item.domain}</span>
            <Badge tone="neutral">{item.plane || item.domain}</Badge>
            {item.occurred_at ? <DateTime value={item.occurred_at} /> : null}
          </li>
        ))}
      </ul>
    </div>
  )
}
