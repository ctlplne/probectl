// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useInfiniteQuery, useMutation, useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

export interface Agent {
  id: string
  name: string
  hostname: string
  agent_version: string
  status: 'registered' | 'online' | 'offline'
  capabilities: string[]
  labels?: Record<string, string>
  last_seen_at?: string
  heartbeat_age_seconds?: number
  heartbeat_state?: 'ready' | 'stale' | 'never_seen'
  heartbeat_reason?: string
  version_state?: 'current' | 'supported_skew' | 'unsupported' | 'unknown'
  version_reason?: string
  readiness_state?:
    | 'ready'
    | 'stale'
    | 'never_connected'
    | 'unsupported_capability'
    | 'version_skew'
  readiness_reason?: string
  rollout_id?: string
  rollout_target?: string
  rollout_cohort?: 'canary' | 'early' | 'main'
  rollout_state?: 'pending' | 'applying' | 'complete' | 'halted'
  rollout_halted?: boolean
  rollout_halt_reason?: string
  last_failure?: string
  next_safe_action?: {
    kind:
      | 'inspect_heartbeat'
      | 'review_capabilities'
      | 'review_staged_rollout'
      | 'verify_rollout_wave'
      | 'review_halted_rollout'
      | 'inspect_evidence'
    label: string
    reason: string
    href: string
  }
}

export interface AgentsPage {
  items: Agent[]
  next_cursor?: string
  control_version?: string
  rollouts_available?: boolean
}

export interface MintAgentEnrollTokenInput {
  agent_id?: string
  name?: string
  ttl_seconds?: number
}

export interface AgentEnrollToken {
  token: string
  id: string
  tenant_id: string
  expires_at: string
  server_cert_pin?: string
}

export type CollectorPlane = 'bgp' | 'flow' | 'device' | 'ebpf' | 'endpoint'

export interface RegisterCollectorInput {
  token: string
  plane: CollectorPlane
  hostname?: string
}

export interface CollectorRegistration {
  tenant_id: string
  agent_id: string
  plane: CollectorPlane
  hostname?: string
  capabilities: string[]
  config: {
    env: Record<string, string>
    yaml: Record<string, string>
    startup_command?: string
  }
}

export interface OnboardingProgress {
  agent_enroll_token_created: boolean
  agent_registered: boolean
  agent_connected: boolean
  producer_healthy: boolean
  first_test_created: boolean
  first_result_received: boolean
  first_finding_visible: boolean
  scim_token_created: boolean
  readiness_steps_complete: number
  readiness_steps_total: number
  first_finding?: {
    title: string
    type: string
    target: string
    success: boolean
    observed_at: string
    href: string
  }
  producers: OnboardingReadiness[]
  engines: OnboardingReadiness[]
}

export interface OnboardingReadiness {
  id: string
  state: 'ready' | 'quiet' | 'blocked'
  detail: string
  next_action: string
}

// UX-004: the agent fleet can be large, so the list MUST ride the backend's
// cursor pagination (handleListAgents: ?after=<id>&limit=<n>, next_cursor when a
// full page is returned). Previously useAgents() fetched bare `/agents` and
// rendered every row — unbounded at fleet scale. Now it pages with
// useInfiniteQuery; the page wires a load-more control and the Table bounds the
// rows it actually renders.
export const AGENTS_PAGE_SIZE = 100

export function useAgents() {
  return useInfiniteQuery({
    queryKey: ['agents'],
    initialPageParam: '',
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ limit: String(AGENTS_PAGE_SIZE) })
      if (pageParam) params.set('after', pageParam)
      return apiFetch<AgentsPage>(`/agents?${params.toString()}`)
    },
    // next_cursor is present only when the page was full; absent = end of set.
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  })
}

export function useMintAgentEnrollToken() {
  return useMutation({
    mutationFn: (input: MintAgentEnrollTokenInput) =>
      apiFetch<AgentEnrollToken>('/agents/enroll-tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
  })
}

export function useRegisterCollector() {
  return useMutation({
    mutationFn: (input: RegisterCollectorInput) =>
      apiFetch<CollectorRegistration>('/collectors/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
  })
}

export function useOnboardingProgress() {
  return useQuery({
    queryKey: ['onboarding', 'progress'],
    queryFn: () => apiFetch<OnboardingProgress>('/onboarding/progress'),
    refetchInterval: 5_000,
  })
}

/** Flatten the paged result into the agent rows fetched so far. */
export function flattenAgents(pages: AgentsPage[] | undefined): Agent[] {
  return (pages ?? []).flatMap((p) => p.items)
}

/** Fleet metadata is repeated per cursor page; the first page is authoritative. */
export function fleetMetadata(pages: AgentsPage[] | undefined) {
  const first = pages?.[0]
  return {
    controlVersion: first?.control_version ?? '',
    rolloutsAvailable: first?.rollouts_available === true,
  }
}
