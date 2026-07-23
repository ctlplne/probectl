// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { axe } from 'jest-axe'
import { TimeSeries } from '../components/TimeSeries'
import { TimeContext, type TimeContextValue } from '../time/context'
import { formatDateTime } from '../time/format'

// jsdom has no 2d canvas, so these tests exercise the honest fallback path:
// the sampled data-table twin that also serves assistive tech in browsers.

const timeStub: TimeContextValue = {
  mode: 'utc',
  setMode: () => undefined,
  preferredTimeZone: 'UTC',
  timeZone: 'UTC',
  timeZoneLabel: 'UTC',
  format: (value) => formatDateTime(value, { locale: 'en-US', timeZone: 'UTC' }),
}

function renderSeries(count: number) {
  const timestamps = Array.from({ length: count }, (_, index) =>
    new Date(Date.UTC(2026, 5, 4, 0, index)).toISOString(),
  )
  const values = Array.from({ length: count }, (_, index) => index * 0.1)
  return render(
    <TimeContext.Provider value={timeStub}>
      <TimeSeries
        label="Cost trend"
        timestamps={timestamps}
        series={[{ label: 'USD', values }]}
        formatValue={(value) => `$${value.toFixed(2)}`}
      />
    </TimeContext.Provider>,
  )
}

describe('TimeSeries', () => {
  test('exposes an accessible sampled table twin when canvas is unavailable', () => {
    renderSeries(3)
    const table = screen.getByRole('table', { name: 'Cost trend' })
    expect(within(table).getByRole('columnheader', { name: 'USD' })).toBeInTheDocument()
    expect(within(table).getAllByRole('row')).toHaveLength(4) // header + 3 samples
    expect(within(table).getByText('$0.20')).toBeInTheDocument()
  })

  test('caps the table at the 24 most recent samples and says so in the caption', () => {
    renderSeries(30)
    const table = screen.getByRole('table', { name: /most recent 24 of 30 samples/i })
    expect(within(table).getAllByRole('row')).toHaveLength(25)
    expect(within(table).getByText('$2.90')).toBeInTheDocument() // newest kept
    expect(within(table).queryByText('$0.00')).not.toBeInTheDocument() // oldest sampled out
  })

  test('renders honest gaps as an em dash, never interpolated values', () => {
    render(
      <TimeContext.Provider value={timeStub}>
        <TimeSeries
          label="Gappy series"
          timestamps={['2026-06-04T10:00:00Z', '2026-06-04T11:00:00Z', '2026-06-04T12:00:00Z']}
          series={[{ label: 'bps', values: [10, null, 30] }]}
        />
      </TimeContext.Provider>,
    )
    const table = screen.getByRole('table', { name: 'Gappy series' })
    expect(within(table).getByText('—')).toBeInTheDocument()
  })

  test('has no axe violations', async () => {
    const { container } = renderSeries(3)
    expect(await axe(container)).toHaveNoViolations()
  })
})
