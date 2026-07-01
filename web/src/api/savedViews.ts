import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

export type SavedViewSurface = 'endpoints' | 'targets' | 'agents' | 'incidents' | 'alerts'

export interface SavedInventoryView {
  id: string
  tenant_id: string
  owner_id?: string
  surface: SavedViewSurface
  name: string
  filters: Record<string, string>
  created_at: string
  updated_at: string
}

export interface SavedInventoryViewInput {
  surface: SavedViewSurface
  name: string
  filters: Record<string, string>
}

export interface SavedInventoryViewsResponse {
  items: SavedInventoryView[]
}

function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
}

export function useSavedViews(surface: SavedViewSurface) {
  return useQuery({
    queryKey: ['inventory', 'views', surface],
    queryFn: () =>
      apiFetch<SavedInventoryViewsResponse>(`/inventory/views?surface=${surface}`),
  })
}

export function useCreateSavedView(surface: SavedViewSurface) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: Omit<SavedInventoryViewInput, 'surface'>) =>
      apiFetch<SavedInventoryView>('/inventory/views', jsonInit('POST', { ...input, surface })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['inventory', 'views', surface] }),
  })
}
