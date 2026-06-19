import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

/** The tenant lifecycle view (S-T5, core): retention control + residency/
 *  isolation visibility. Export streams from /v1/lifecycle/export. */

export interface LifecycleStatus {
  tenant_id?: string
  flow_retention_days: number | null
  isolation_model: string
  residency?: string
}

export interface LifecycleRetentionInput {
  flow_retention_days: number | null
}

export function useLifecycle() {
  return useQuery({
    queryKey: ['lifecycle'],
    queryFn: () => apiFetch<LifecycleStatus>('/lifecycle/retention'),
  })
}

export function useSaveLifecycleRetention() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: LifecycleRetentionInput) =>
      apiFetch<LifecycleStatus>('/lifecycle/retention', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['lifecycle'] }),
  })
}
