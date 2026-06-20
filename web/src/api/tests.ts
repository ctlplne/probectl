import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
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
  params?: Record<string, string>
  enabled: boolean
}

const key = ['tests'] as const
const pageSize = 50

interface TestList {
  items: Test[]
  next_cursor?: string
}

export function useTests() {
  const query = useInfiniteQuery({
    queryKey: key,
    initialPageParam: '',
    queryFn: ({ pageParam }) => {
      const cursor = typeof pageParam === 'string' ? pageParam : ''
      const params = new URLSearchParams({ limit: String(pageSize) })
      if (cursor) params.set('after', cursor)
      return apiFetch<TestList>(`/tests?${params}`)
    },
    getNextPageParam: (lastPage) => lastPage.next_cursor || undefined,
  })
  return {
    ...query,
    data: query.data?.pages.flatMap((page) => page.items),
  }
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
