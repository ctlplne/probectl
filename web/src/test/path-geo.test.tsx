// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
import { defaultFetch } from './fetchStub'
import { renderApp } from './renderApp'

describe('path geography view', () => {
  test('located hops render on the vendored map; private hops are counted, never invented', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/path')

    await screen.findByRole('group', { name: /network path to 1\.1\.1\.1/i })
    await userEvent.click(screen.getByRole('button', { name: /^geography$/i }))

    const geo = await screen.findByRole('group', { name: /geographic path to 1\.1\.1\.1/i })
    // The two public, geo-enriched fixture hops appear with their places.
    expect(within(geo).getByRole('button', { name: /192\.0\.2\.9.*ashburn/i })).toBeInTheDocument()
    const dest = within(geo).getByRole('button', { name: /1\.1\.1\.1.*san francisco/i })
    // Private-range responders are counted honestly, not placed.
    expect(within(geo).getByText(/responders without location/i)).toBeInTheDocument()

    // Selection is the same contract as the other views.
    await userEvent.click(dest)
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
  })
})
