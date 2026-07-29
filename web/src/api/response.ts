// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/** Largest successful JSON/text response a browser client may buffer. */
export const MAX_RESPONSE_BODY_BYTES = 32 * 1024 * 1024

/** Tighter ceiling for diagnostic error envelopes. */
export const MAX_ERROR_RESPONSE_BODY_BYTES = 1024 * 1024

/** Raised before parsing when a response crosses its application byte budget. */
export class ResponseBodyTooLargeError extends Error {
  constructor(readonly limitBytes: number) {
    super(`Response body exceeds the ${limitBytes}-byte limit.`)
    this.name = 'ResponseBodyTooLargeError'
  }
}

/** Selects the success/error budget before any response bytes are buffered. */
export function responseBodyLimit(response: Response): number {
  return response.ok ? MAX_RESPONSE_BODY_BYTES : MAX_ERROR_RESPONSE_BODY_BYTES
}

/**
 * Reads a response incrementally and cancels at the first byte past maxBytes.
 * Content-Length is only an early rejection hint: streamed bytes are always
 * counted because the header may be absent, compressed, or dishonest.
 */
export async function readResponseBytes(
  response: Response,
  maxBytes = responseBodyLimit(response),
): Promise<Uint8Array> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new RangeError(`Response body limit must be a non-negative safe integer: ${maxBytes}`)
  }

  const declared = response.headers.get('Content-Length')?.trim()
  if (declared && /^\d+$/.test(declared)) {
    const length = Number(declared)
    if (!Number.isSafeInteger(length) || length > maxBytes) {
      await cancelUnlocked(response.body)
      throw new ResponseBodyTooLargeError(maxBytes)
    }
  }

  if (!response.body) return new Uint8Array()

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (!value || value.byteLength === 0) continue
      if (value.byteLength > maxBytes - total) {
        try {
          await reader.cancel()
        } catch {
          // The body is still rejected; cancellation is a best-effort release.
        }
        throw new ResponseBodyTooLargeError(maxBytes)
      }
      chunks.push(value)
      total += value.byteLength
    }
  } finally {
    reader.releaseLock()
  }

  const body = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.byteLength
  }
  return body
}

/** Reads one bounded response as UTF-8 text. */
export async function readResponseText(
  response: Response,
  maxBytes = responseBodyLimit(response),
): Promise<string> {
  return new TextDecoder().decode(await readResponseBytes(response, maxBytes))
}

/** Reads and parses one bounded JSON response. */
export async function readResponseJSON<T>(
  response: Response,
  maxBytes = responseBodyLimit(response),
): Promise<T> {
  return JSON.parse(await readResponseText(response, maxBytes)) as T
}

async function cancelUnlocked(body: ReadableStream<Uint8Array> | null): Promise<void> {
  if (!body) return
  try {
    await body.cancel()
  } catch {
    // The response is rejected regardless; cancellation is a best-effort release.
  }
}
