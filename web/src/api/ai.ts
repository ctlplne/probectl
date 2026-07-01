import { useMutation } from '@tanstack/react-query'
import { apiFetch } from './client'

/** The AI assistant API (S24). Answers are cited and scoped to the caller's
 *  tenant + permissions server-side (the S23 boundary) — the browser never
 *  selects a tenant. */
export type Confidence = 'low' | 'medium' | 'high'

export interface Citation {
  evidence_id: string
}

export interface Finding {
  statement: string
  citations: Citation[]
}

export interface Evidence {
  id: string
  domain: string
  plane?: string
  severity?: string
  title?: string
  summary?: string
  ref?: string
  occurred_at?: string
  fields?: Record<string, unknown>
}

export interface Answer {
  id: string
  tenant: string
  question: string
  root_cause: string
  root_cause_citations?: Citation[]
  root_cause_grounded?: boolean
  degraded?: boolean
  confidence: Confidence
  findings: Finding[]
  evidence: Evidence[]
  model: string
  insufficient_evidence: boolean
}

export interface AskRequest {
  question: string
  subject?: Record<string, string>
}

/** useAsk runs an RCA: a natural-language question → a cited, RBAC-scoped answer. */
export function useAsk() {
  return useMutation({
    mutationFn: (req: AskRequest) =>
      apiFetch<Answer>('/ai/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      }),
  })
}

export type Rating = 'up' | 'down'

export interface FeedbackRequest {
  answer_id: string
  rating: Rating
  comment?: string
  question?: string
}

/** useSubmitFeedback records a thumbs up/down on an answer (the quality loop). */
export function useSubmitFeedback() {
  return useMutation({
    mutationFn: (req: FeedbackRequest) =>
      apiFetch<void>('/ai/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      }),
  })
}

/** confidenceTone maps a confidence level to a design-system Badge tone. */
export function confidenceTone(c: Confidence): 'success' | 'warning' | 'neutral' {
  if (c === 'high') return 'success'
  if (c === 'medium') return 'warning'
  return 'neutral'
}
