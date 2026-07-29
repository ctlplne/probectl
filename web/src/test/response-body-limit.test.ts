// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test } from 'vitest'
import { readResponseJSON, readResponseText, ResponseBodyTooLargeError } from '../api/response'

const encoder = new TextEncoder()

function chunkedResponse(
  chunks: string[],
  options: { close?: boolean; contentLength?: string; status?: number } = {},
) {
  let cancelled = false
  let index = 0
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index < chunks.length) {
        controller.enqueue(encoder.encode(chunks[index++]))
      } else if (options.close !== false) {
        controller.close()
      }
    },
    cancel() {
      cancelled = true
    },
  })
  const headers = options.contentLength ? { 'Content-Length': options.contentLength } : undefined
  return {
    response: new Response(stream, { status: options.status ?? 200, headers }),
    wasCancelled: () => cancelled,
  }
}

describe('bounded browser response reader', () => {
  test('accepts an exact-limit chunked JSON body', async () => {
    const fixture = chunkedResponse(['{"ok"', ':true}'])
    const expected = { ok: true }
    const bytes = encoder.encode(JSON.stringify(expected)).byteLength

    await expect(readResponseJSON(fixture.response, bytes)).resolves.toEqual(expected)
    expect(fixture.wasCancelled()).toBe(false)
  })

  test('cancels and rejects the first streamed byte over the limit', async () => {
    const fixture = chunkedResponse(['abc', 'd'], { close: false })

    await expect(readResponseText(fixture.response, 3)).rejects.toEqual(
      new ResponseBodyTooLargeError(3),
    )
    expect(fixture.wasCancelled()).toBe(true)
  })

  test('does not trust a smaller Content-Length header', async () => {
    const fixture = chunkedResponse(['abc', 'd'], {
      close: false,
      contentLength: '3',
    })

    await expect(readResponseText(fixture.response, 3)).rejects.toBeInstanceOf(
      ResponseBodyTooLargeError,
    )
    expect(fixture.wasCancelled()).toBe(true)
  })

  test('rejects an oversized declared length before reading', async () => {
    const fixture = chunkedResponse(['not-read'], {
      close: false,
      contentLength: '4',
      status: 502,
    })

    await expect(readResponseText(fixture.response, 3)).rejects.toBeInstanceOf(
      ResponseBodyTooLargeError,
    )
    expect(fixture.wasCancelled()).toBe(true)
  })
})
