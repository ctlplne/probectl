import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

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

function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
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
    mutationFn: (id: string) => apiFetch<void>(`/directory/scim-tokens/${id}`, { method: 'DELETE' }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['identity', 'scim-tokens'] }),
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
    mutationFn: (input: ABACPolicy) => apiFetch<ABACPolicy>('/abac/policies', jsonInit('POST', input)),
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
