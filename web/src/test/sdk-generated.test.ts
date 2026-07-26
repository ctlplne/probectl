// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { ProbectlSDKClient, type ListTestsResponse } from '../api/sdk.gen'

describe('generated OpenAPI SDK', () => {
  test('listTests builds a typed tenant-scoped request', async () => {
    const fetcher = vi.fn(async () => {
      const body: ListTestsResponse = {
        items: [
          {
            id: '018f7a3a-5f38-7cc1-bf69-8e8f62a6d2b0',
            tenant_id: 'tenant-a',
            name: 'checkout',
            type: 'http',
            created_at: '2026-06-21T00:00:00Z',
            updated_at: '2026-06-21T00:00:00Z',
          },
        ],
      }
      return new Response(JSON.stringify(body), { status: 200 })
    })
    const client = new ProbectlSDKClient({
      baseUrl: '',
      tenant: 'tenant-a',
      fetch: fetcher as unknown as typeof fetch,
    })

    const tests = await client.listTests({ limit: 50 })

    expect(tests.items[0].name).toBe('checkout')
    expect(fetcher).toHaveBeenCalledWith(
      '/v1/tests?limit=50',
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({ 'X-Probectl-Tenant': 'tenant-a' }),
      }),
    )
  })

  test('flowTopTalkers preserves repeated exact-match filters', async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ items: [] }), { status: 200 }))
    const client = new ProbectlSDKClient({
      baseUrl: '',
      tenant: 'tenant-a',
      fetch: fetcher as unknown as typeof fetch,
    })

    await client.flowTopTalkers({
      by: 'dst_country',
      filter: ['src:10.0.0.1', 'protocol:ipfix'],
    })

    expect(fetcher).toHaveBeenCalledWith(
      '/v1/flows/top?by=dst_country&filter=src%3A10.0.0.1&filter=protocol%3Aipfix',
      expect.objectContaining({ method: 'GET' }),
    )
  })
})
