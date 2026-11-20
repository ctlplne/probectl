// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, apiFetch } from './client'
import type {
  RemediationDiversionApprovalInput,
  RemediationDiversionPreview,
  RemediationDiversionPreviewInput,
  RemediationDiversionProposalInput,
  RemediationDiversionReceipt,
  RemediationDiversionReview,
  RemediationFlowSpecApprovalInput,
  RemediationFlowSpecHandoffStatus,
  RemediationFlowSpecPreview,
  RemediationFlowSpecPreviewInput,
  RemediationFlowSpecProposalInput,
  RemediationFlowSpecReview,
  RemediationFlowSpecRouterQualification,
  RemediationFlowSpecRouterQualificationInput,
  RemediationRTBHPreview,
  RemediationRTBHPreviewInput,
  RemediationRTBHProposalInput,
  RemediationRTBHReview,
  RemediationRTBHUpstreamTemplates,
} from './sdk.gen'

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

export function useRemediations(enabled = true, identity?: string) {
  return useQuery({
    queryKey: ['remediation-proposals', ...(identity ? [identity] : [])],
    enabled,
    queryFn: () => apiFetch<RemediationList>('/remediation/proposals'),
    retry: (count, err) => !(err instanceof ApiError && err.status === 404) && count < 2,
  })
}

export function useRTBHReview(id: string | undefined, identity: string) {
  return useQuery({
    queryKey: ['remediation-proposals', identity, 'routing-review', id],
    enabled: Boolean(id),
    retry: false,
    staleTime: 0,
    queryFn: () =>
      apiFetch<RemediationRTBHReview>(
        `/remediation/proposals/${encodeURIComponent(id ?? '')}/routing-review`,
      ),
  })
}

export function useRTBHUpstreamTemplates(identity: string, enabled: boolean) {
  return useQuery({
    queryKey: ['remediation-proposals', identity, 'rtbh-templates'],
    enabled,
    retry: false,
    queryFn: () => apiFetch<RemediationRTBHUpstreamTemplates>('/remediation/rtbh-templates'),
  })
}

export function usePreviewRTBH() {
  return useMutation({
    mutationFn: async (input: RemediationRTBHPreviewInput) => ({
      input,
      assessment: await apiFetch<RemediationRTBHPreview>('/remediation/rtbh-preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    }),
  })
}

export function useProposeRTBH() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: RemediationRTBHProposalInput) =>
      apiFetch<Proposal>('/remediation/rtbh-proposals', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['remediation-proposals'] }),
  })
}

export function useFlowSpecReview(id: string | undefined, identity: string) {
  return useQuery({
    queryKey: ['remediation-proposals', identity, 'flowspec-review', id],
    enabled: Boolean(id),
    retry: false,
    staleTime: 0,
    queryFn: () =>
      apiFetch<RemediationFlowSpecReview>(
        `/remediation/proposals/${encodeURIComponent(id ?? '')}/flowspec-review`,
      ),
  })
}

export function usePreviewFlowSpec() {
  return useMutation({
    mutationFn: async (input: RemediationFlowSpecPreviewInput) => ({
      input,
      assessment: await apiFetch<RemediationFlowSpecPreview>('/remediation/flowspec-preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    }),
  })
}

export function useProposeFlowSpec() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: RemediationFlowSpecProposalInput) =>
      apiFetch<Proposal>('/remediation/flowspec-proposals', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['remediation-proposals'] }),
  })
}

export function useQualifyFlowSpec(id: string) {
  return useMutation({
    mutationFn: (input: RemediationFlowSpecRouterQualificationInput) =>
      apiFetch<RemediationFlowSpecRouterQualification>(
        `/remediation/proposals/${encodeURIComponent(id)}/flowspec-qualification`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
        },
      ),
  })
}

export function useApproveFlowSpec() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, input }: { id: string; input: RemediationFlowSpecApprovalInput }) =>
      apiFetch<Proposal>(`/remediation/proposals/${encodeURIComponent(id)}/flowspec-approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['remediation-proposals'] }),
  })
}

export function useFlowSpecHandoff(id: string, identity: string) {
  return useQuery({
    queryKey: ['remediation-proposals', identity, 'flowspec-handoff', id],
    queryFn: () =>
      apiFetch<RemediationFlowSpecHandoffStatus>(
        `/remediation/proposals/${encodeURIComponent(id)}/flowspec-handoff`,
      ),
    retry: false,
    refetchInterval: ({ state }) => {
      if (state.data?.state !== 'authorized') return false
      return Math.max(250, Math.min(5000, Date.parse(state.data.expires_at) - Date.now() + 100))
    },
  })
}

export function useWithdrawFlowSpec(id: string, identity: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<RemediationFlowSpecHandoffStatus>(
        `/remediation/proposals/${encodeURIComponent(id)}/flowspec-withdraw`,
        { method: 'POST' },
      ),
    onSuccess: (handoff) =>
      qc.setQueryData(['remediation-proposals', identity, 'flowspec-handoff', id], handoff),
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
      fingerprint,
    }: {
      id: string
      decision: 'approve' | 'reject'
      note?: string
      fingerprint?: string
    }) =>
      apiFetch<Proposal>(`/remediation/proposals/${id}/${decision}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: note ?? '', review_fingerprint: fingerprint }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['remediation-proposals'] }),
  })
}

export function usePreviewDiversion() {
  return useMutation({
    mutationFn: async (input: RemediationDiversionPreviewInput) => ({
      input,
      assessment: await apiFetch<RemediationDiversionPreview>('/remediation/diversion-preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    }),
  })
}

export function useProposeDiversion() {
  const query = useQueryClient()
  return useMutation({
    mutationFn: (input: RemediationDiversionProposalInput) =>
      apiFetch<Proposal>('/remediation/diversion-proposals', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () => query.invalidateQueries({ queryKey: ['remediation-proposals'] }),
  })
}

export function useDiversionReview(id: string, identity: string) {
  return useQuery({
    queryKey: ['remediation-proposals', identity, 'diversion-review', id],
    retry: false,
    queryFn: () =>
      apiFetch<RemediationDiversionReview>(
        `/remediation/proposals/${encodeURIComponent(id)}/diversion-review`,
      ),
  })
}

export function useApproveDiversion() {
  const query = useQueryClient()
  return useMutation({
    mutationFn: ({ id, input }: { id: string; input: RemediationDiversionApprovalInput }) =>
      apiFetch<RemediationDiversionReceipt>(
        `/remediation/proposals/${encodeURIComponent(id)}/diversion-approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
        },
      ),
    onSuccess: () => query.invalidateQueries({ queryKey: ['remediation-proposals'] }),
  })
}
