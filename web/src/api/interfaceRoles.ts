// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type {
  InterfaceRolePolicy,
  InterfaceRolePolicyInput,
  InterfaceRoleOverride,
  InterfaceRoleOverrideInput,
  InterfaceRoleOverrideResetInput,
  InterfaceRoleExplanation,
} from './sdk.gen'
export type {
  InterfaceRole,
  InterfaceRoleDescriptionRule,
  InterfaceRolePolicy,
  InterfaceRolePolicyDefinition,
  InterfaceRoleOverride,
  InterfaceRoleExplanation,
} from './sdk.gen'

const key = (tenant: string, context: string, subject = '') =>
  ['interface-role-config', tenant, context, subject] as const
const explanationKey = (tenant: string, context: string, subject = '') =>
  ['interface-role-explanation', tenant, context, subject] as const

export function useInterfaceRoleExplanation(
  tenant: string,
  context: string,
  subject: string,
  enabled: boolean,
) {
  return useQuery({
    queryKey: explanationKey(tenant, context, subject),
    staleTime: 0,
    refetchOnWindowFocus: true,
    enabled: enabled && Boolean(tenant && context && subject),
    gcTime: 0,
    queryFn: ({ signal }) =>
      apiFetch<InterfaceRoleExplanation>(
        `/entity-contexts/${encodeURIComponent(context)}/interfaces/${encodeURIComponent(subject)}/role`,
        { signal },
      ),
  })
}
const jsonInit = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export function useInterfaceRolePolicy(tenant: string, context: string) {
  return useQuery({
    queryKey: key(tenant, context),
    enabled: Boolean(context),
    queryFn: ({ signal }) =>
      apiFetch<InterfaceRolePolicy>(
        `/entity-contexts/${encodeURIComponent(context)}/interface-role-policy`,
        { signal },
      ),
  })
}
export function useSaveInterfaceRolePolicy(tenant: string, context: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: InterfaceRolePolicyInput) =>
      apiFetch<InterfaceRolePolicy>(
        `/entity-contexts/${encodeURIComponent(context)}/interface-role-policy`,
        jsonInit('PUT', input),
      ),
    onSuccess: async (data) => {
      client.setQueryData(key(tenant, context), data)
      await client.invalidateQueries({ queryKey: ['interface-role-explanation', tenant, context] })
    },
  })
}
export function useInterfaceRoleOverride(tenant: string, context: string, subject: string) {
  return useQuery({
    queryKey: key(tenant, context, subject),
    enabled: Boolean(context && subject),
    queryFn: ({ signal }) =>
      apiFetch<InterfaceRoleOverride>(
        `/entity-contexts/${encodeURIComponent(context)}/interfaces/${encodeURIComponent(subject)}/role-override`,
        { signal },
      ),
  })
}
export function useSaveInterfaceRoleOverride(tenant: string, context: string, subject: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: InterfaceRoleOverrideInput) =>
      apiFetch<InterfaceRoleOverride>(
        `/entity-contexts/${encodeURIComponent(context)}/interfaces/${encodeURIComponent(subject)}/role-override`,
        jsonInit('PUT', input),
      ),
    onSuccess: async (data) => {
      client.setQueryData(key(tenant, context, subject), data)
      await client.invalidateQueries({ queryKey: explanationKey(tenant, context, subject) })
    },
  })
}
export function useResetInterfaceRoleOverride(tenant: string, context: string, subject: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: InterfaceRoleOverrideResetInput) =>
      apiFetch<void>(
        `/entity-contexts/${encodeURIComponent(context)}/interfaces/${encodeURIComponent(subject)}/role-override`,
        jsonInit('DELETE', input),
      ),
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: key(tenant, context, subject) }),
        client.invalidateQueries({ queryKey: explanationKey(tenant, context, subject) }),
      ])
    },
  })
}
