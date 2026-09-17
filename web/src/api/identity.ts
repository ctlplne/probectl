// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { DeviceIdentityConflict, DeviceIdentityConflictResponse } from './sdk.gen'

export type {
  DeviceIdentityAffectedCorrelation,
  DeviceIdentityClaim,
  DeviceIdentityConflict,
  DeviceIdentityConflictResponse,
} from './sdk.gen'

export type IdentityConflictKind = DeviceIdentityConflict['kind']
export type IdentityConflictStatus = DeviceIdentityConflict['status']

export interface IdentityConflictFilters {
  q?: string
  kind?: IdentityConflictKind | 'all'
  source?: string
  status?: IdentityConflictStatus | 'all'
  limit?: number
}

export interface ScimToken {
  id: string
  tenant_id: string
  name: string
  created_at: string
  last_used_at?: string
  revoked_at?: string
}

export interface CreatedScimToken {
  id: string
  name: string
  token: string
}

/** DPR-027: a tenant user with the role slugs bound at tenant scope. */
export interface DirectoryUser {
  id: string
  tenant_id: string
  email: string
  display_name: string
  status: string
  external_id?: string
  user_name?: string
  roles: string[]
  created_at: string
  updated_at: string
}

export interface DirectoryRole {
  id: string
  tenant_id: string
  slug: string
  name: string
  description?: string
  is_system: boolean
  permissions: string[]
  members: number
}

export interface ABACPolicy {
  id?: string
  name?: string
  effect: 'allow' | 'deny'
  permission: string
  subject?: Record<string, string>
  resource?: Record<string, string>
  priority?: number
  enabled?: boolean
}

export interface TenantIdPSettings {
  source: 'tenant' | 'environment' | 'none'
  configured: boolean
  valid: boolean
  issuer: string
  client_id: string
  client_secret_configured: boolean
  redirect_url: string
  scopes: string[]
  enabled: boolean
  flags: Record<string, boolean>
}

export interface TenantIdPSettingsInput {
  issuer: string
  client_id: string
  client_secret?: string
  redirect_url: string
  scopes: string[]
  enabled: boolean
  flags: Record<string, boolean>
}

function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
}

export function useTenantIdPSettings() {
  return useQuery({
    queryKey: ['identity', 'idp-settings'],
    queryFn: () => apiFetch<TenantIdPSettings>('/identity/settings'),
  })
}

export function useUpdateTenantIdPSettings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: TenantIdPSettingsInput) =>
      apiFetch<TenantIdPSettings>('/identity/settings', jsonInit('PUT', input)),
    onSuccess: (settings) => qc.setQueryData(['identity', 'idp-settings'], settings),
  })
}

export function useScimTokens() {
  return useQuery({
    queryKey: ['identity', 'scim-tokens'],
    queryFn: () => apiFetch<{ items: ScimToken[] }>('/directory/scim-tokens').then((r) => r.items),
  })
}

export function useCreateScimToken() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: { name: string }) =>
      apiFetch<CreatedScimToken>('/directory/scim-tokens', jsonInit('POST', input)),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['identity', 'scim-tokens'] }),
  })
}

export function useRevokeScimToken() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(`/directory/scim-tokens/${id}`, { method: 'DELETE' }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['identity', 'scim-tokens'] }),
  })
}

export function useDirectoryUsers() {
  return useQuery({
    queryKey: ['identity', 'directory-users'],
    queryFn: () =>
      apiFetch<{ items: DirectoryUser[]; total: number }>('/directory/users').then((r) => r.items),
  })
}

export function useDirectoryRoles() {
  return useQuery({
    queryKey: ['identity', 'directory-roles'],
    queryFn: () => apiFetch<{ items: DirectoryRole[] }>('/directory/roles').then((r) => r.items),
  })
}

function invalidateDirectory(qc: ReturnType<typeof useQueryClient>) {
  void qc.invalidateQueries({ queryKey: ['identity', 'directory-users'] })
  void qc.invalidateQueries({ queryKey: ['identity', 'directory-roles'] })
}

export function useCreateDirectoryUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: { email: string; display_name?: string; role?: string }) =>
      apiFetch<DirectoryUser>('/directory/users', jsonInit('POST', input)),
    onSuccess: () => invalidateDirectory(qc),
  })
}

export function useBindDirectoryRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, role }: { id: string; role: string }) =>
      apiFetch<DirectoryUser>(`/directory/users/${id}/roles`, jsonInit('POST', { role })),
    onSuccess: () => invalidateDirectory(qc),
  })
}

export function useUnbindDirectoryRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, role }: { id: string; role: string }) =>
      apiFetch<void>(`/directory/users/${id}/roles/${role}`, { method: 'DELETE' }),
    onSuccess: () => invalidateDirectory(qc),
  })
}

export function useABACPolicies() {
  return useQuery({
    queryKey: ['identity', 'abac-policies'],
    queryFn: () => apiFetch<{ items: ABACPolicy[] }>('/abac/policies').then((r) => r.items),
  })
}

export function useCreateABACPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: ABACPolicy) =>
      apiFetch<ABACPolicy>('/abac/policies', jsonInit('POST', input)),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['identity', 'abac-policies'] }),
  })
}

export function useDeleteABACPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiFetch<void>(`/abac/policies/${id}`, { method: 'DELETE' }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['identity', 'abac-policies'] }),
  })
}

export function useIdentityConflicts(filters: IdentityConflictFilters = {}) {
  const query = new URLSearchParams()
  if (filters.q?.trim()) query.set('q', filters.q.trim())
  if (filters.kind && filters.kind !== 'all') query.set('kind', filters.kind)
  if (filters.source?.trim()) query.set('source', filters.source.trim())
  if (filters.status && filters.status !== 'all') query.set('status', filters.status)
  query.set('limit', String(filters.limit ?? 100))
  const qs = query.toString()
  return useQuery({
    queryKey: [
      'device',
      'identity-conflicts',
      filters.q ?? '',
      filters.kind ?? 'all',
      filters.source ?? '',
      filters.status ?? 'all',
      filters.limit ?? 100,
    ],
    queryFn: () => apiFetch<DeviceIdentityConflictResponse>(`/device/identity-conflicts?${qs}`),
  })
}
