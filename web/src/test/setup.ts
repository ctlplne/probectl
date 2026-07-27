// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import '@testing-library/jest-dom'
import { expect, afterEach, beforeEach, vi } from 'vitest'
import { cleanup, configure } from '@testing-library/react'
import { toHaveNoViolations } from 'jest-axe'
import { defaultFetch } from './fetchStub'

expect.extend(toHaveNoViolations)

// Testing Library otherwise gives every findBy*/waitFor query only one second,
// even though Vitest's finite hang detector below the suite is 15 seconds. A
// fully instrumented coverage run can spend more than one second scheduling a
// healthy render on a loaded runner. Keep async UI queries bounded, but give
// them enough headroom to observe that render without turning retries into the
// test oracle.
configure({ asyncUtilTimeout: 5_000 })

// Every test gets a working fetch (the read-only default); CRUD tests override
// it with their own stateful stub via vi.stubGlobal.
beforeEach(() => {
  vi.stubGlobal('fetch', defaultFetch())
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})
