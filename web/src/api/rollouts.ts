// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
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
  return useQuery({
    queryKey: ['rollouts'],
    queryFn: () => apiFetch<RolloutList>('/rollouts'),
    enabled,
  })
}

/**
 * These mutations move only the persisted rollout state machine. Agents never
 * receive code or an update command from this API; an external orchestrator
 * applies the operator-verified digest after a human advances a wave.
 */
export function useRolloutAction() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, action, reason }: RolloutActionInput) =>
      apiFetch<Rollout>(`/rollouts/${encodeURIComponent(id)}/${action}`, {
        method: 'POST',
        ...(action === 'halt' || action === 'resume'
          ? {
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ reason: reason?.trim() }),
            }
          : {}),
      }),
    onSuccess: (updated) => {
      qc.setQueryData<RolloutList>(['rollouts'], (current) => ({
        items: current?.items.map((rollout) => (rollout.id === updated.id ? updated : rollout)) ?? [
          updated,
        ],
      }))
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['rollouts'] })
      void qc.invalidateQueries({ queryKey: ['agents'] })
    },
  })
}
