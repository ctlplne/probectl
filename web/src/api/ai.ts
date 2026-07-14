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

export type InvestigationStatus = 'planned' | 'queried' | 'skipped' | 'blocked'

export interface InvestigationStep {
  step: number
  domain: string
  goal: string
  selector?: Record<string, string>
  node_id?: string
  window_start?: string
  window_end?: string
  limit: number
  read_only: boolean
  status: InvestigationStatus
  reason?: string
  evidence_count?: number
  truncated?: boolean
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
  investigation_plan?: InvestigationStep[]
  findings: Finding[]
  evidence: Evidence[]
  model: string
  reasoning: ReasoningProvenance
  insufficient_evidence: boolean
}

export type ReasoningExecution =
  | 'builtin_local'
  | 'local_adapter'
  | 'external_adapter'
  | 'builtin_fallback'

export interface ReasoningProvenance {
  adapter: string
  execution: ReasoningExecution
  egress_consent: 'not_required' | 'granted'
  attempted_adapter?: string
}

export interface AskRequest {
  question: string
  subject?: Record<string, string>
  range?: {
    start: string
    end: string
  }
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
