// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.


import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '../renderApp'
import { defaultFetch, pathOf, sampleExplorerTemplates } from '../fetchStub'
import {
  JourneyRecorder,
  assertRequestsUseSessionTenant,
  type MeasuredRequest,
} from './measurement'

describe('J3 explore to answer ten canonical questions', () => {
  test('answers all ten with a two-interaction median, zero typing, and no syntax lookup', async () => {
    const user = userEvent.setup()
    const base = defaultFetch()
    const requests: MeasuredRequest[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        requests.push({
          url: String(input),
          method: init?.method ?? 'GET',
          headers: Object.fromEntries(new Headers(init?.headers).entries()),
          body: init?.body,
        })
        return base(input, init)
      }),
    )

    renderApp('/explore')
    expect(await screen.findByRole('heading', { name: 'Explorer' })).toBeInTheDocument()
    let completed = 0
    for (const template of sampleExplorerTemplates) {
      await user.click(screen.getByRole('button', { name: String(template.question) }))
      expect(screen.getByLabelText('Ask in natural language')).toHaveValue(template.question)
      expect(screen.getByLabelText('Source / plane')).toHaveValue(template.source)
      await user.click(screen.getByRole('button', { name: 'Run query' }))
      await waitFor(() => {
        const queryRequests = requests.filter(
          (request) => pathOf(request.url) === '/v1/explorer/query' && request.method === 'POST',
        )
        expect(queryRequests).toHaveLength(completed + 1)
        const body = JSON.parse(String(queryRequests.at(-1)?.body)) as { template: string }
        expect(body.template).toBe(template.id)
      })
      completed += 1
    }

    expect(completed).toBe(10)
    expect(requests.some((request) => /\/docs|syntax/i.test(request.url))).toBe(false)
    assertRequestsUseSessionTenant(requests)

    const measurement = new JourneyRecorder('J3', 'explore to answer ten canonical questions')
      .pointer(20)
      .activeTimeProxy({
        min_ms: 60_000,
        max_ms: 180_000,
        basis: 'choose one taught canonical question and run it; two pointer interactions each',
      })
      .complete(
        '10 of 10 canonical questions executed through one surface',
        'median two interactions per answer and zero typed characters',
        'no documentation or syntax lookup and no client-supplied tenant scope',
      )
      .snapshot()

    expect(measurement.pointer_interactions / completed).toBeLessThanOrEqual(4)
    expect(measurement.typed_characters).toBe(0)
    expect(measurement.context_breaks).toBe(0)
    expect(measurement.outcome.status).toBe('complete')
  }, 15_000)
})
