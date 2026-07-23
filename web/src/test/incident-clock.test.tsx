// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { IncidentClock, type IncidentClockItem } from '../viz/IncidentClock'
import { TimeContext, type TimeContextValue } from '../time/context'
import { formatDateTime } from '../time/format'

const timeStub: TimeContextValue = {
  mode: 'utc',
  setMode: () => undefined,
  preferredTimeZone: 'UTC',
  timeZone: 'UTC',
  timeZoneLabel: 'UTC',
  format: (value) => formatDateTime(value, { locale: 'en-US', timeZone: 'UTC' }),
}

const lanes = [
  { id: 'synthetic', label: 'Synthetic & path' },
  { id: 'routing', label: 'BGP & routing' },
  { id: 'device', label: 'Device telemetry' },
  { id: 'change', label: 'Candidate changes' },
]

const items: IncidentClockItem[] = [
  {
    id: 'inc:0',
    laneID: 'synthetic',
    meta: 'network',
    title: 'HTTP latency above SLO',
    occurredAt: '2026-06-04T11:55:00Z',
    severity: 'warning',
    kind: 'signal',
  },
  {
    id: 'inc:1',
    laneID: 'routing',
    meta: 'bgp',
    title: 'Unexpected more-specific route',
    occurredAt: '2026-06-04T11:57:00Z',
    severity: 'critical',
    kind: 'signal',
  },
  {
    id: 'chg-1',
    laneID: 'change',
    meta: 'change',
    title: 'Export policy edit',
    occurredAt: '2026-06-04T11:50:00Z',
    kind: 'change',
  },
]

function renderClock(selectedID?: string, onSelect = vi.fn()) {
  const view = render(
    <TimeContext.Provider value={timeStub}>
      <IncidentClock
        lanes={lanes}
        items={items}
        selectedID={selectedID}
        onSelect={onSelect}
        label="Incident evidence on one time axis"
        windowStart="2026-06-04T11:45:00Z"
        windowEnd="2026-06-04T12:00:00Z"
      />
    </TimeContext.Provider>,
  )
  return { view, onSelect }
}

describe('IncidentClock timeline', () => {
  test('renders one lane per plane with evidence and omits empty lanes', () => {
    renderClock()
    const list = screen.getByRole('list', { name: /one time axis/i })
    expect(within(list).getByText('Synthetic & path')).toBeInTheDocument()
    expect(within(list).getByText('BGP & routing')).toBeInTheDocument()
    expect(within(list).getByText('Candidate changes')).toBeInTheDocument()
    // Device telemetry produced no evidence: no whispering empty lane.
    expect(within(list).queryByText('Device telemetry')).not.toBeInTheDocument()
    expect(within(list).getAllByRole('button')).toHaveLength(3)
    // Raw plane identifiers stay exposed for coordination and AT.
    expect(within(list).getByText('bgp')).toBeInTheDocument()
    expect(within(list).getByText('network')).toBeInTheDocument()
  })

  test('selection follows aria-pressed and activating a marker selects evidence', async () => {
    const user = userEvent.setup()
    const { onSelect } = renderClock('inc:1')
    const selected = screen.getByRole('button', { name: /unexpected more-specific route/i })
    expect(selected).toHaveAttribute('aria-pressed', 'true')
    const other = screen.getByRole('button', { name: /http latency above slo/i })
    expect(other).toHaveAttribute('aria-pressed', 'false')
    await user.click(other)
    expect(onSelect).toHaveBeenCalledWith('inc:0')
  })

  test('markers are positioned inside the axis span', () => {
    renderClock()
    for (const button of screen.getAllByRole('button')) {
      const inset = Number.parseFloat(button.style.insetInlineStart)
      expect(inset).toBeGreaterThanOrEqual(0)
      expect(inset).toBeLessThanOrEqual(100)
    }
  })

  test('renders nothing without items', () => {
    const { container } = render(
      <TimeContext.Provider value={timeStub}>
        <IncidentClock
          lanes={lanes}
          items={[]}
          onSelect={() => undefined}
          label="Incident evidence on one time axis"
        />
      </TimeContext.Provider>,
    )
    expect(container).toBeEmptyDOMElement()
  })

  test('has no axe violations', async () => {
    const { view } = renderClock('inc:0')
    expect(await axe(view.container)).toHaveNoViolations()
  })
})
