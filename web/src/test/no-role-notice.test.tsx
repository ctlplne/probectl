// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { screen, waitFor } from '@testing-library/react'
import { describe, expect, test, vi } from 'vitest'
import { defaultFetch } from './fetchStub'
import { renderApp } from './renderApp'

/** DPR-016: a signed-in user with no role sees one clear notice naming the
 * way out; anyone holding a permission never sees it. renderApp serves the
 * signed-in identity (/v1/me), so the fixture is passed through its `me`
 * option rather than by stubbing the identity route. */
describe('no-role notice', () => {
  test('a user with no permissions is told so and shown the bootstrap grant', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/targets', { me: { email: 'new.person@example.test', permissions: [] } })
    const notice = await screen.findByLabelText('Access status')
    expect(notice).toHaveAttribute('role', 'status')
    expect(notice).toHaveTextContent('No role yet')
    expect(notice).toHaveTextContent(/signed in as new\.person@example\.test/)
    expect(notice).toHaveTextContent(/ask a tenant administrator/i)
    expect(notice).toHaveTextContent('probectl-control bootstrap-admin -email new.person@example.test')
  })

  test('a user holding any permission never sees it', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/targets', { me: { permissions: ['test.read'] } })
    await screen.findByRole('main')
    await waitFor(() => expect(screen.queryByLabelText('Access status')).toBeNull())
  })
})
