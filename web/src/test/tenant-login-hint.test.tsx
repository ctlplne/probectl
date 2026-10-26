// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { afterEach, expect, test, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Link, MemoryRouter, useLocation } from 'react-router-dom'
import { AuthContext, type AuthContextValue } from '../auth/AuthProvider'
import { TenantLoginHint } from '../auth/TenantLoginHint'
import { redirectToLogin } from '../api/client'

const tenant = '00000000-0000-0000-0000-0000000000a1'
const foreign = '00000000-0000-0000-0000-0000000000b1'
afterEach(() => vi.unstubAllGlobals())
function Location() {
  const location = useLocation()
  return <output>{location.pathname + location.search + location.hash}</output>
}
test('server tenant replaces an untrusted hint and survives navigation without losing filters', async () => {
  const identity = { tenant: { id: tenant } } as AuthContextValue
  render(
    <MemoryRouter initialEntries={['/targets?q=http&login_tenant=' + foreign + '#tests']}>
      <AuthContext.Provider value={identity}>
        <TenantLoginHint />
        <Location />
        <Link to="/audit?action=test.create">Audit</Link>
      </AuthContext.Provider>
    </MemoryRouter>,
  )
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent(
      '/targets?q=http&login_tenant=' + tenant + '#tests',
    ),
  )
  await userEvent.click(screen.getByRole('link', { name: 'Audit' }))
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent(
      '/audit?action=test.create&login_tenant=' + tenant,
    ),
  )
})
test.each([
  ['?login_tenant=' + tenant, '/auth/login?tenant=' + tenant],
  ['?login_tenant=https://other.example', '/auth/login'],
  ['?login_tenant=invalid', '/auth/login'],
  ['', '/auth/login'],
])('login redirect validates routing hint %s', (search, expected) => {
  const assign = vi.fn()
  const replace = vi.fn()
  vi.stubGlobal('location', { search, assign, replace })
  redirectToLogin()
  expect(assign).toHaveBeenCalledWith(expected)
  redirectToLogin({ replace: true })
  expect(replace).toHaveBeenCalledWith(expected)
})
