// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { vi } from 'vitest'
import openapiSpec from '../../../internal/control/openapi.json'
import { fixtureFetch, jsonResponse, pathOf } from './fixtureApi'

// The fixture catalog itself is pure and lives in fixtureApi.ts so the
// dev-only Vite fixture middleware (web/dev) can serve the same data without
// importing vitest. This module adds the test-only mock wrapper.
export * from './fixtureApi'

function fixtureWithOpenAPI(
  profile?: 'populated' | 'cold',
  options?: Parameters<typeof fixtureFetch>[1],
): typeof fetch {
  const fixture = fixtureFetch(profile, options)
  return async (input, init) =>
    pathOf(input) === '/openapi.json' ? jsonResponse(openapiSpec) : fixture(input, init)
}

/** A read-only default fetch covering the list endpoints, so any screen renders
 *  with data in tests. CRUD tests install their own stateful stub. */
export function defaultFetch(): typeof fetch {
  return vi.fn(fixtureWithOpenAPI())
}

/** The populated stub with the commercial provider plane licensed, so the
 * tenant-side surfaces that talk to /provider/v1 (break-glass consent) render. */
export function providerFetch(): typeof fetch {
  return vi.fn(fixtureWithOpenAPI('populated', { providerPlane: true }))
}

/** The install-day stub: a freshly deployed control plane before any agent
 * enrolls. See fixtureApi coldFixture. */
export function coldFetch() {
  return vi.fn(fixtureWithOpenAPI('cold'))
}
