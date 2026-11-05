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
} from './sdk.gen'
export type {
  InterfaceRole,
  InterfaceRoleDescriptionRule,
  InterfaceRolePolicy,
  InterfaceRolePolicyDefinition,
  InterfaceRoleOverride,
} from './sdk.gen'

const key = (tenant: string, context: string, subject = '') =>
  ['interface-role-config', tenant, context, subject] as const
const root = (context: string) => `/entity-contexts/${encodeURIComponent(context)}`
const overridePath = (context: string, subject: string) =>
  `${root(context)}/interfaces/${encodeURIComponent(subject)}/role-override`
const json = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export function useInterfaceRolePolicy(tenant: string, context: string) {
  return useQuery({
    queryKey: key(tenant, context),
    enabled: Boolean(context),
    queryFn: ({ signal }) =>
      apiFetch<InterfaceRolePolicy>(`${root(context)}/interface-role-policy`, { signal }),
  })
}
export function useSaveInterfaceRolePolicy(tenant: string, context: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: InterfaceRolePolicyInput) =>
      apiFetch<InterfaceRolePolicy>(`${root(context)}/interface-role-policy`, json('PUT', input)),
    onSuccess: (data) => client.setQueryData(key(tenant, context), data),
  })
}
export function useInterfaceRoleOverride(tenant: string, context: string, subject: string) {
  return useQuery({
    queryKey: key(tenant, context, subject),
    enabled: Boolean(context && subject),
    queryFn: ({ signal }) =>
      apiFetch<InterfaceRoleOverride>(overridePath(context, subject), { signal }),
  })
}
export function useSaveInterfaceRoleOverride(tenant: string, context: string, subject: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: InterfaceRoleOverrideInput) =>
      apiFetch<InterfaceRoleOverride>(overridePath(context, subject), json('PUT', input)),
    onSuccess: (data) => client.setQueryData(key(tenant, context, subject), data),
  })
}
export function useResetInterfaceRoleOverride(tenant: string, context: string, subject: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: InterfaceRoleOverrideResetInput) =>
      apiFetch<void>(overridePath(context, subject), json('DELETE', input)),
    onSuccess: () => client.invalidateQueries({ queryKey: key(tenant, context, subject) }),
  })
}
