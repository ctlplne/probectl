// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, apiFetch, holdLoginRedirect } from './client'
import type {
  LifecycleRetentionInput,
  LifecycleStatus,
  ProspectEngagement,
  ProspectEngagementInput,
  ProspectProviderAccess,
  ProspectProviderAccessInput,
} from './sdk.gen'

export type { LifecycleRetentionInput, LifecycleStatus } from './sdk.gen'

/** The tenant lifecycle view (S-T5, core): retention control + residency/
 *  isolation visibility. Export streams from /v1/lifecycle/export. */

export interface LifecycleStoreResult {
  store: string
  deleted: number
  verified_zero: boolean
  notes?: string
}

export interface LifecycleEraseAttestation {
  format_version: number
  tenant_id: string
  tenant_slug?: string
  actor: string
  started_at: string
  finished_at: string
  stores: LifecycleStoreResult[]
  backup_policy: string
  backup_retention_days?: number
  backup_erasure_deadline?: string
  complete: boolean
  report_sha256: string
}

export interface LifecycleEraseInput {
  confirm: string
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

export function useEraseTenantLifecycle() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: LifecycleEraseInput) =>
      apiFetch<LifecycleEraseAttestation>('/lifecycle/erase', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    // The erasure took this tenant's users and sessions with its data: every
    // later call answers 401. Hold the login redirect and stop refetching, or
    // the login page replaces the receipt before the admin can read or keep it.
    onSuccess: () => {
      holdLoginRedirect()
      void qc.cancelQueries()
    },
  })
}

export function useProspectEngagement(identity: string) {
  return useQuery({
    queryKey: ['lifecycle', 'prospect', identity],
    queryFn: async () => {
      try {
        return await apiFetch<ProspectEngagement>('/lifecycle/prospect')
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) return null
        throw error
      }
    },
    refetchInterval: 30_000,
  })
}

type ProspectAction =
  | { action: 'start'; input: ProspectEngagementInput }
  | { action: 'convert' | 'revoke-consent'; revision: number }

function jsonInit(method: string, body: unknown): RequestInit {
  return {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }
}

export function useProspectEngagementAction(identity: string) {
  const queryClient = useQueryClient()
  const queryKey = ['lifecycle', 'prospect', identity]
  return useMutation({
    mutationFn: (request: ProspectAction) => {
      if (request.action === 'start') {
        return apiFetch<ProspectEngagement>('/lifecycle/prospect', jsonInit('POST', request.input))
      }
      const input = { revision: request.revision }
      if (request.action === 'convert') {
        return apiFetch<ProspectEngagement>('/lifecycle/prospect/convert', jsonInit('POST', input))
      }
      return apiFetch<ProspectEngagement>(
        '/lifecycle/prospect/revoke-consent',
        jsonInit('POST', input),
      )
    },
    onSuccess: (data) => {
      queryClient.setQueryData(queryKey, data)
      void queryClient.invalidateQueries({
        queryKey: ['lifecycle', 'prospect-provider-access', identity],
      })
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 409) {
        void queryClient.invalidateQueries({ queryKey })
      }
    },
  })
}

export function useProspectProviderAccess(identity: string, enabled: boolean) {
  return useQuery({
    queryKey: ['lifecycle', 'prospect-provider-access', identity],
    queryFn: async () => {
      try {
        return await apiFetch<ProspectProviderAccess>('/lifecycle/prospect/provider-access')
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) return null
        throw error
      }
    },
    enabled,
  })
}

export function useSetProspectProviderAccess(identity: string) {
  const queryClient = useQueryClient()
  const queryKey = ['lifecycle', 'prospect-provider-access', identity]
  return useMutation({
    mutationFn: (input: ProspectProviderAccessInput) =>
      apiFetch<ProspectProviderAccess>(
        '/lifecycle/prospect/provider-access',
        jsonInit('POST', input),
      ),
    onSuccess: (data) => queryClient.setQueryData(queryKey, data),
    onError: (error) => {
      if (error instanceof ApiError && error.status === 409) {
        void queryClient.invalidateQueries({ queryKey })
      }
    },
  })
}
