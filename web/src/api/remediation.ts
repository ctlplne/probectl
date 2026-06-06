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

export function useRemediations() {
  return useQuery({
    queryKey: ['remediation-proposals'],
    queryFn: () => apiFetch<RemediationList>('/remediation/proposals'),
    retry: (count, err) => !(err instanceof ApiError && err.status === 404) && count < 2,
  })
}

export function useDecideRemediation() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, decision, note }: { id: string; decision: 'approve' | 'reject'; note?: string }) =>
      apiFetch<Proposal>(`/remediation/proposals/${id}/${decision}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: note ?? '' }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['remediation-proposals'] }),
  })
}
