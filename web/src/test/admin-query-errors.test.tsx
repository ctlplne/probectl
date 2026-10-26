// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { expect, test, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

const restrictedPaths = [
  '/v1/lifecycle/retention',
  '/v1/security/keys',
  '/v1/secrets/health',
  '/v1/editions',
  '/v1/diagnostics',
  '/v1/remediation/proposals',
]

test.each(restrictedPaths)('Admin identifies permission denial for %s', async (path) => {
  const base = defaultFetch()
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
      pathOf(input) === path ? jsonResponse({ message: 'Forbidden' }, 403) : base(input, init),
    ),
  )
  renderApp('/admin')
  expect(await screen.findByRole('heading', { name: 'Permission denied' })).toBeInTheDocument()
  expect(
    screen.getByText(
      'Your current access does not allow viewing this information. Ask your tenant administrator if you need access.',
    ),
  ).toBeInTheDocument()
  expect(
    screen.queryByText('Tenant lifecycle is not wired on this deployment.'),
  ).not.toBeInTheDocument()
})

test('lifecycle service failure does not imply missing configuration or permission denial', async () => {
  const base = defaultFetch()
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
      pathOf(input) === '/v1/lifecycle/retention'
        ? jsonResponse({ message: 'Unavailable' }, 503)
        : base(input, init),
    ),
  )
  renderApp('/admin')
  expect(
    await screen.findByText(
      'Could not load tenant lifecycle. Configuration and health are unknown.',
    ),
  ).toBeInTheDocument()
  expect(screen.queryByRole('heading', { name: 'Permission denied' })).not.toBeInTheDocument()
})
