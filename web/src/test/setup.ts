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
