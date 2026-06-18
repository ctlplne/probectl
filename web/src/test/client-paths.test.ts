import { describe, expect, test, vi } from 'vitest'
import { apiFetch, apiURL } from '../api/client'
import { assertNoDoublePrefix, pathOf } from './fetchStub'

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
    vi.unstubAllGlobals()
  })

  test('apiURL builds download paths without a double version prefix', () => {
    expect(apiURL('/compliance/evidence')).toBe('/v1/compliance/evidence')
    /* eslint-disable no-restricted-syntax */
    expect(() => apiURL('/v1/compliance/evidence')).toThrow(/drop the \/v1 prefix/)
    /* eslint-enable no-restricted-syntax */
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
