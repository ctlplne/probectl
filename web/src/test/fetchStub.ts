// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { vi } from 'vitest'
import { fixtureFetch } from './fixtureApi'

// The fixture catalog itself is pure and lives in fixtureApi.ts so the
// dev-only Vite fixture middleware (web/dev) can serve the same data without
// importing vitest. This module adds the test-only mock wrapper.
export * from './fixtureApi'

/** A read-only default fetch covering the list endpoints, so any screen renders
 *  with data in tests. CRUD tests install their own stateful stub. */
export function defaultFetch(): typeof fetch {
  return vi.fn(fixtureFetch())
}

/** The install-day stub: a freshly deployed control plane before any agent
 * enrolls. See fixtureApi coldFixture. */
export function coldFetch() {
  return vi.fn(fixtureFetch('cold'))
}
