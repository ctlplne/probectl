// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

type AnswerPayload = Omit<
  Answer,
  'findings' | 'evidence' | 'investigation_plan' | 'root_cause_citations'
> & {
  findings: Finding[] | null
  evidence: Evidence[] | null
  investigation_plan?: InvestigationStep[] | null
  root_cause_citations?: Citation[] | null
}

/**
 * Treat response collections as untrusted at the HTTP boundary. Older servers
 * and persisted artifacts may encode a nil Go slice as null; the UI must still
 * render the honest insufficient-evidence state instead of going blank.
 */
export function normalizeAnswer(answer: Answer | AnswerPayload): Answer {
  return {
    ...answer,
    findings: answer.findings ?? [],
    evidence: answer.evidence ?? [],
    investigation_plan: answer.investigation_plan ?? [],
    root_cause_citations: answer.root_cause_citations ?? [],
  }
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
    mutationFn: async (req: AskRequest) =>
      normalizeAnswer(
        await apiFetch<Answer>('/ai/ask', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(req),
        }),
      ),
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
