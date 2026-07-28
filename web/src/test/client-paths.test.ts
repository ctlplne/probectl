// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { afterEach, describe, expect, test, vi } from 'vitest'
import { ApiError, apiFetch, apiURL } from '../api/client'
import { assertNoDoublePrefix, pathOf } from './fetchStub'

afterEach(() => vi.unstubAllGlobals())

/**
 * UX-006 / RED-006: the API path conventions are enforced, not just hoped for.
 *  - apiFetch rejects a /v1-prefixed path (it already prepends the base), so a
 *    `/v1/v1/...` double-prefix can't slip through at runtime.
 *  - the test fetch stub's assertNoDoublePrefix fails on a doubled segment, so a
 *    UX-001-style regression reddens the suite instead of matching leniently.
 */
describe('API path conventions', () => {
  test('apiFetch rejects a /v1-prefixed path (UX-006)', async () => {
    // The /v1 literals here are the deliberate negative cases the runtime guard
    // catches; the lint rule that bans them in product code is asserted by the
    // gate elsewhere, so it is disabled on these two intentional lines.
    /* eslint-disable no-restricted-syntax */
    await expect(apiFetch('/v1/topology')).rejects.toThrow(/drop the \/v1 prefix/)
    await expect(apiFetch('/v1')).rejects.toThrow(/drop the \/v1 prefix/)
    /* eslint-enable no-restricted-syntax */
  })

  test('a relative path passes the guard and reaches fetch', async () => {
    // Stub fetch so a relative (correct) path resolves — proving the /v1 guard
    // only fires on a /v1 prefix, never on a well-formed relative path.
    const stub = vi.fn(() => Promise.resolve(new Response('{}', { status: 200 })))
    vi.stubGlobal('fetch', stub)
    await apiFetch('/topology')
    expect(stub).toHaveBeenCalledWith('/v1/topology', expect.anything())
  })

  test('preserves JSON defaults and same-origin credentials beside caller headers', async () => {
    const stub = vi.fn(() => Promise.resolve(new Response('{}', { status: 200 })))
    vi.stubGlobal('fetch', stub)

    await apiFetch('/alerts', {
      method: 'POST',
      credentials: 'omit',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })

    const call = stub.mock.calls[0] as unknown as Parameters<typeof fetch>
    const init = call[1] as RequestInit
    const headers = new Headers(init.headers)
    expect(init.credentials).toBe('same-origin')
    expect(headers.get('Accept')).toBe('application/json')
    expect(headers.get('Content-Type')).toBe('application/json')
  })

  test('merges Headers instances and preserves an explicit caller Accept value', async () => {
    const stub = vi.fn(() => Promise.resolve(new Response('{}', { status: 200 })))
    vi.stubGlobal('fetch', stub)

    await apiFetch('/alerts', {
      headers: new Headers({
        Accept: 'application/problem+json',
        'X-Request-Mode': 'operator',
      }),
    })

    const call = stub.mock.calls[0] as unknown as Parameters<typeof fetch>
    const init = call[1] as RequestInit
    const headers = new Headers(init.headers)
    expect(headers.get('Accept')).toBe('application/problem+json')
    expect(headers.get('X-Request-Mode')).toBe('operator')
  })

  test('returns undefined for a successful no-content response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(new Response(null, { status: 204 }))),
    )

    await expect(apiFetch('/alerts', { method: 'DELETE' })).resolves.toBeUndefined()
  })

  test('uses a structured API error message when the server provides one', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response(JSON.stringify({ error: { message: 'tenant scope unavailable' } }), {
            status: 403,
            statusText: 'Forbidden',
            headers: { 'Content-Type': 'application/json' },
          }),
        ),
      ),
    )

    const error = await apiFetch('/topology').catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({
      status: 403,
      message: 'tenant scope unavailable',
    })
  })

  test('falls back to status text for a non-JSON error body', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response('upstream failed', { status: 502, statusText: 'Bad Gateway' }),
        ),
      ),
    )

    const error = await apiFetch('/topology').catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({
      status: 502,
      message: '502 Bad Gateway',
    })
  })

  test('preserves network failures instead of disguising them as API responses', async () => {
    const networkError = new TypeError('network unavailable')
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(networkError)),
    )

    await expect(apiFetch('/topology')).rejects.toBe(networkError)
  })

  test('apiURL builds download paths without a double version prefix', () => {
    expect(apiURL('/compliance/evidence')).toBe('/v1/compliance/evidence')
    expect(() => apiURL('/v1/compliance/evidence')).toThrow(/drop the \/v1 prefix/)
  })

  test('pathOf strips query + origin to a bare pathname', () => {
    expect(pathOf('/v1/agents?after=x&limit=50')).toBe('/v1/agents')
    expect(pathOf('https://host.example/v1/me')).toBe('/v1/me')
  })

  test('assertNoDoublePrefix fails on a doubled /v1 segment (RED-006)', () => {
    expect(() => assertNoDoublePrefix('/v1/v1/topology')).toThrow(/double \/v1 prefix/)
    // A single-prefix path is fine.
    expect(() => assertNoDoublePrefix('/v1/topology')).not.toThrow()
  })
})
