// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, apiFetch } from './client'

/** Guarded agentic remediation (S-EE5, F44 — ee-backed). The AI PROPOSES; a
 *  human APPROVES; probectl NEVER executes — there is no executor. Approve is a
 *  recorded, audited human sign-off; operators carry the action out elsewhere.
 *  A 404 means the feature is not licensed (hidden-unlicensed): the card simply
 *  does not render. */

export interface DryRun {
  blast_radius: number
  impacted_services?: string[]
  impacted_prefixes?: string[]
  disconnected?: string[]
  note?: string
}

export interface Proposal {
  id: string
  kind: string
  title: string
  rationale?: string
  target?: string
  incident_id?: string
  dry_run: DryRun
  state: 'proposed' | 'approved' | 'rejected' | 'applied'
  proposed_by: string
  decided_by?: string
  decision_note?: string
  created_at: string
  decided_at?: string
}

export interface RemediationList {
  items: Proposal[]
  approvals_enabled: boolean
}

export interface CreateProposalInput {
  kind: 'reroute_suggestion' | 'traffic_shift_suggestion' | 'open_ticket' | 'trustctl_renewal'
  title: string
  rationale?: string
  target?: string
  incident_id?: string
}

export function useRemediations(enabled = true) {
  return useQuery({
    queryKey: ['remediation-proposals'],
    enabled,
    queryFn: () => apiFetch<RemediationList>('/remediation/proposals'),
    retry: (count, err) => !(err instanceof ApiError && err.status === 404) && count < 2,
  })
}

export function useCreateRemediationProposal() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: CreateProposalInput) =>
      apiFetch<Proposal>('/remediation/proposals', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['remediation-proposals'] }),
  })
}

export function useDecideRemediation() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({
      id,
      decision,
      note,
    }: {
      id: string
      decision: 'approve' | 'reject'
      note?: string
    }) =>
      apiFetch<Proposal>(`/remediation/proposals/${id}/${decision}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: note ?? '' }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['remediation-proposals'] }),
  })
}
