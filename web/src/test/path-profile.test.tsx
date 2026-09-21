// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
import { defaultFetch } from './fetchStub'
import { renderApp } from './renderApp'

describe('path latency profile view', () => {
  test('topology stays default; the profile is a secondary toggle of the same nodes', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/path')

    // Default view: the TTL topology graph, no profile mounted.
    await screen.findByRole('group', { name: /network path to 1\.1\.1\.1/i })
    expect(screen.queryByRole('group', { name: /latency by hop/i })).toBeNull()

    await userEvent.click(screen.getByRole('button', { name: /latency profile/i }))
    const profile = await screen.findByRole('group', { name: /latency by hop to 1\.1\.1\.1/i })
    expect(screen.queryByRole('group', { name: /network path to 1\.1\.1\.1/i })).toBeNull()

    // Same node identity: the lossy responder is selectable here too, with
    // RTT and loss in its accessible name.
    const lossy = within(profile).getByRole('button', { name: /172\.16\.3\.2.*loss/i })
    await userEvent.click(lossy)
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
    await userEvent.keyboard('{Escape}')

    // Toggling back re-mounts the primary view.
    await userEvent.click(screen.getByRole('button', { name: /^topology$/i }))
    expect(
      await screen.findByRole('group', { name: /network path to 1\.1\.1\.1/i }),
    ).toBeInTheDocument()
  })
})
