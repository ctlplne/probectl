// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuth } from '../auth/useAuth'
import { apiFetch } from './client'

export type RolloutWaveStatus = 'pending' | 'applying' | 'complete' | 'halted'

export interface RolloutWave {
  cohort: 'canary' | 'early' | 'main'
  agents: number
  status: RolloutWaveStatus
}

export interface Rollout {
  id: string
  target: string
  digest: string
  endpoint?: { platform: string; executable_identity: string }
  halted: boolean
  halt_reason?: string
  done: boolean
  progress: string
  waves: RolloutWave[]
  /** DPR-099: agents in the applying wave not yet on the target with a fresh heartbeat. */
  stragglers?: string[]
  /** DPR-099: agents left out at planning time because they were offline or never connected. */
  skipped_offline?: string[]
}

export interface RolloutList {
  items: Rollout[]
}

export type RolloutAction = 'advance' | 'verify' | 'halt' | 'resume'

export interface RolloutActionInput {
  id: string
  action: RolloutAction
  reason?: string
}

/**
 * Rollouts are tenant-scoped by the authenticated server session. `enabled`
 * stays false until /v1/agents confirms this deployment has rollout storage,
 * so the browser never guesses that a missing commercial seam is available.
 */
export function useRollouts(enabled: boolean) {
  const { tenant } = useAuth()
  return useQuery({
    queryKey: ['rollouts', tenant.id],
    queryFn: ({ signal }) =>
      apiFetch<RolloutList>('/rollouts', {
        signal,
        headers: { 'X-Probectl-Tenant': tenant.id },
      }),
    enabled,
  })
}

/**
 * These mutations record human decisions in the rollout state machine.
 * The initiating tenant owns the acknowledgement and any follow-up refresh.
 */
export function useRolloutAction() {
  const { tenant } = useAuth()
  const qc = useQueryClient()
  return useMutation({
    mutationKey: ['rollouts', tenant.id],
    mutationFn: ({ id, action, reason }: RolloutActionInput) =>
      apiFetch<Rollout>(`/rollouts/${encodeURIComponent(id)}/${action}`, {
        method: 'POST',
        headers: {
          'X-Probectl-Tenant': tenant.id,
          ...(action === 'halt' || action === 'resume'
            ? { 'Content-Type': 'application/json' }
            : {}),
        },
        ...(action === 'halt' || action === 'resume'
          ? { body: JSON.stringify({ reason: reason?.trim() }) }
          : {}),
      }),
    onMutate: () => tenant.id,
    onSuccess: (updated, _input, tenantID) => {
      if (!tenantID) return
      qc.setQueryData<RolloutList>(['rollouts', tenantID], (current) => ({
        items: current?.items.map((rollout) => (rollout.id === updated.id ? updated : rollout)) ?? [
          updated,
        ],
      }))
    },
    onSettled: (_updated, _error, _input, tenantID) => {
      if (!tenantID) return
      void qc.invalidateQueries({ queryKey: ['rollouts', tenantID] })
      void qc.invalidateQueries({ queryKey: ['agents', tenantID] })
    },
  })
}
