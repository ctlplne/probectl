// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
import { defaultFetch } from './fetchStub'
import { renderApp } from './renderApp'

describe('first-touch surfaces', () => {
  test('an unknown route lands on 404 with a working way back', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/definitely-not-a-route')

    expect(
      await screen.findByRole('heading', { name: /404 - page not found/i }),
    ).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /go to dashboards/i }))
    expect(await screen.findByRole('heading', { name: /^dashboards$/i })).toBeInTheDocument()
  })
})
