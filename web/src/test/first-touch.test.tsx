// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
