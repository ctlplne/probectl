import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

export interface Test {
  id: string
  name: string
  type: string
  target: string
  interval_seconds: number
  timeout_seconds: number
  params: Record<string, string>
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface TestInput {
  name: string
  type: string
  target: string
  interval_seconds: number
  timeout_seconds: number
  enabled: boolean
}

const key = ['tests'] as const

export function useTests() {
  return useQuery({
    queryKey: key,
    queryFn: () => apiFetch<{ items: Test[] }>('/tests').then((r) => r.items),
  })
}

export function useCreateTest() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: TestInput) =>
      apiFetch<Test>('/tests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: key }),
  })
}

export function useDeleteTest() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiFetch<void>(`/tests/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: key }),
  })
}
