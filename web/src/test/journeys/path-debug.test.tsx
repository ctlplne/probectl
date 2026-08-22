// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '../renderApp'
import { pathIncident, stubPathHistoryFetch } from '../pathHistoryFixture'
import { parsePivotContext } from '../../routes/pivotContext'
import {
  JourneyRecorder,
  assertRequestsUseSessionTenant,
  type MeasuredRequest,
} from './measurement'

describe('J4 lossy ECMP path debugging', () => {
  test('opens incident-scoped path evidence with the matching test and clock', async () => {
    const requests: MeasuredRequest[] = []
    stubPathHistoryFetch(requests)
    renderApp('/incidents?incident=inc-path')

    const signalButtons = await screen.findAllByRole('button', {
      name: 'branch 10.0.0.2 is lossy',
    })
    await userEvent.click(signalButtons.at(-1) as HTMLElement)
    const pathLink = await screen.findByRole('link', { name: 'Open path evidence for 9.9.9.9' })
    const pathURL = new URL(pathLink.getAttribute('href') ?? '/', 'https://probectl.invalid')
    expect(parsePivotContext(pathURL.searchParams).context).toMatchObject({
      incidentId: 'inc-path',
      from: new Date(pathIncident.started_at).toISOString(),
      to: new Date(pathIncident.last_seen_at).toISOString(),
      filters: {
        path_target: '9.9.9.9',
        path_source_evidence: 'inc-path:0',
      },
      returnTo: '/incidents?incident=inc-path',
    })
    expect(pathURL.search.toLowerCase()).not.toContain('tenant')

    await userEvent.click(pathLink)
    expect(await screen.findByText('edge → 9.9.9.9')).toBeInTheDocument()
    expect(screen.getByText('Incident context:')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: pathIncident.title })).toHaveAttribute(
      'href',
      '/incidents?incident=inc-path',
    )
    assertRequestsUseSessionTenant(requests)
  })

  test('isolates, compares, pivots to incident evidence, and shares in five interactions', async () => {
    const user = userEvent.setup()
    const requests: MeasuredRequest[] = []
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(window.navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    })
    stubPathHistoryFetch(requests)
    renderApp('/path')

    // 1: isolate the branch identified by the above-fold triage.
    await user.click(await screen.findByRole('button', { name: /inspect worst hop/i }))
    expect(
      await screen.findByRole('dialog', { name: /hop 2 .*branch 1.*10\.0\.0\.2/i }),
    ).toBeInTheDocument()

    // 2: close the detail inspector; selection remains in the X3 context.
    await user.click(screen.getByRole('button', { name: /close/i }))

    // 3: compare against the previous immutable path round.
    const history = screen.getByRole('region', { name: /path history and comparison/i })
    await user.selectOptions(within(history).getByLabelText(/compare with/i), 'round-previous')
    expect(
      within(history).getByRole('status', { name: /path comparison summary/i }),
    ).toHaveTextContent(/1 changed/i)

    // 4: copy the stable, tenant-free replay URL.
    await user.click(screen.getByRole('button', { name: /copy stable path link/i }))
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce())
    const stableLink = String(writeText.mock.calls[0][0])
    expect(stableLink).toContain('path_round%3Around-current')
    expect(stableLink).toContain('compare_round%3Around-previous')
    expect(stableLink).toContain('ctx_selected_id=2%3A10.0.0.2')
    expect(stableLink).not.toMatch(/tenant/i)

    // 5: open the exact incident while retaining test, round, branch, and clock.
    await user.click(
      screen.getByRole('link', {
        name: /open incident evidence: loss on one ecmp branch/i,
      }),
    )
    const room = await screen.findByRole('region', {
      name: /unified five-plane incident room/i,
    })
    expect(within(room).getByText(pathIncident.title)).toBeInTheDocument()

    assertRequestsUseSessionTenant(requests)
    const measurement = new JourneyRecorder('J4', 'debug a lossy ECMP path')
      .pointer(5)
      .activeTimeProxy({
        min_ms: 30_000,
        max_ms: 90_000,
        basis: 'above-fold branch triage, inline round diff, stable copy, and incident pivot',
      })
      .complete(
        'lossy ECMP branch remains selected across round comparison',
        'stable link contains opaque rounds and no tenant selector',
        'incident pivot retains the X3 clock and branch evidence',
      )
      .snapshot()

    expect(measurement.pointer_interactions).toBeLessThanOrEqual(5)
    expect(measurement.typed_characters).toBeLessThanOrEqual(8)
    expect(measurement.context_breaks).toBe(0)
    expect(measurement.outcome.status).toBe('complete')
  })
})
