// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMutation, useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { TestInput } from './tests'

/** AI test authoring + auto-discovery (S26). Everything PROPOSES — nothing is
 *  created until the user confirms via the test API. */
export interface TestSpec {
  name: string
  type: string
  target: string
  interval_seconds: number
  timeout_seconds: number
  params?: Record<string, string>
  enabled: boolean
}

export interface TestProposal {
  spec: TestSpec
  rationale?: string
  source: string
}

export interface DiscoverProposal {
  spec: TestSpec
  rationale: string
  score: number
  source: string
}

/** useAuthorTest turns a natural-language prompt into a schema-valid proposal. */
export function useAuthorTest() {
  return useMutation({
    mutationFn: (prompt: string) =>
      apiFetch<TestProposal>('/ai/author', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt }),
      }),
  })
}

/** useDiscover proposes monitorable targets mined from observed telemetry. */
export function useDiscover(enabled = true) {
  return useQuery({
    queryKey: ['ai', 'discover'],
    queryFn: () =>
      apiFetch<{ proposals: DiscoverProposal[] }>('/ai/discover', { method: 'POST' }).then(
        (r) => r.proposals,
      ),
    enabled,
  })
}

/** specToInput maps a proposed spec onto the test-create input. */
export function specToInput(s: TestSpec): TestInput {
  return {
    name: s.name,
    type: s.type,
    target: s.target,
    interval_seconds: s.interval_seconds,
    timeout_seconds: s.timeout_seconds,
    enabled: true,
  }
}
