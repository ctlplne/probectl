// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import '@testing-library/jest-dom'
import { expect, afterEach, beforeEach, vi } from 'vitest'
import { cleanup } from '@testing-library/react'
import { toHaveNoViolations } from 'jest-axe'
import { defaultFetch } from './fetchStub'

expect.extend(toHaveNoViolations)

// Every test gets a working fetch (the read-only default); CRUD tests override
// it with their own stateful stub via vi.stubGlobal.
beforeEach(() => {
  vi.stubGlobal('fetch', defaultFetch())
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})
