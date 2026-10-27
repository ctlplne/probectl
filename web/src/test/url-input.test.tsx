// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { test, expect, vi } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import { flushSync } from 'react-dom'
import { App } from '../App'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

test('URL-backed input retains every character before deferred navigation work runs', async () => {
  const base = defaultFetch()
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (pathOf(input) === '/v1/me')
        return Promise.resolve(
          jsonResponse({
            tenant_id: 'tenant-red',
            user_id: 'operator',
            email: 'qa@example.test',
            display_name: 'QA',
            mfa_satisfied: false,
            permissions: ['incident.read'],
          }),
        )
      return base(input, init)
    }),
  )
  window.history.replaceState(
    null,
    '',
    '/ui/incidents?incident_status=open&incident_severity=critical',
  )
  render(<App />)
  const input = await screen.findByRole('textbox', { name: 'Find' })
  if (!(input instanceof HTMLInputElement)) throw new Error('Find must be an input')
  const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.bind(
    input,
  )
  if (!setValue) throw new Error('Native input setter is unavailable')
  // Separate native input events must preserve the controlled value even when
  // there is no idle turn between keys for a router transition to commit.
  act(() => {
    for (const char of 'link-down firing') {
      flushSync(() => {
        setValue(input.value + char)
        input.dispatchEvent(new Event('input', { bubbles: true }))
      })
    }
    expect(input).toHaveValue('link-down firing')
  })
  expect(new URLSearchParams(window.location.search).get('incident_q')).toBe('link-down firing')
  expect(screen.getByRole('combobox', { name: 'Status' })).toHaveValue('open')
  expect(screen.getByRole('combobox', { name: 'Severity' })).toHaveValue('critical')
})
