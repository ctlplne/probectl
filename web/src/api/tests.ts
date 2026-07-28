// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { Test, TestList, TestRequest } from './sdk.gen'

export type { Test } from './sdk.gen'
export type TestInput = Omit<TestRequest, 'type'> & { type: string }

const key = ['tests'] as const
const pageSize = 50

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

export function useTest(id: string) {
  return useQuery({
    queryKey: [...key, id],
    queryFn: () => apiFetch<Test>(`/tests/${encodeURIComponent(id)}`),
    enabled: id.length > 0,
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
