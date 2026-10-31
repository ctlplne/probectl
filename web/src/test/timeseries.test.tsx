// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
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
  test('percentage display preserves original exact samples and explains an undefined zero denominator', () => {
    render(
      <TimeContext.Provider value={timeStub}>
        <TimeSeries
          label="Percentage source"
          timestamps={[2, 1, 3]}
          timeStyle="percent_area"
          logarithmic
          series={[{ label: 'source', values: [0, 0, null], exactValues: ['0', '0', null] }]}
        />
      </TimeContext.Provider>,
    )
    expect(screen.getByText(/No percentage is defined/)).toBeInTheDocument()
    expect(screen.queryByText(/No positive values/)).not.toBeInTheDocument()
    expect(within(screen.getByRole('table')).getAllByText('0')).toHaveLength(2)
  })

  test('does not invoke jsdom canvas placeholders on the fallback path', () => {
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext')

    try {
      renderSeries(1)

      expect(screen.getByRole('table', { name: 'Cost trend' })).toBeInTheDocument()
      expect(getContext).not.toHaveBeenCalled()
    } finally {
      getContext.mockRestore()
    }
  })

  test('exposes an accessible sampled table twin when canvas is unavailable', () => {
    renderSeries(3)
    const table = screen.getByRole('table', { name: 'Cost trend' })
    expect(within(table).getByRole('columnheader', { name: 'USD' })).toBeInTheDocument()
    expect(within(table).getAllByRole('row')).toHaveLength(4) // header + 3 samples
    expect(within(table).getByText('$0.20')).toBeInTheDocument()
  })

  test('bounds the DOM at24 rows while earlier/latest pages reach every sample', () => {
    renderSeries(30)
    const table = screen.getByRole('table', { name: /samples 7–30 of 30/i })
    expect(within(table).getAllByRole('row')).toHaveLength(25)
    expect(within(table).getByText('$2.90')).toBeInTheDocument() // newest kept
    expect(within(table).queryByText('$0.00')).not.toBeInTheDocument() // oldest sampled out
    fireEvent.click(screen.getByRole('button', { name: 'Earlier samples' }))
    expect(screen.getByRole('table', { name: /samples 1–24 of 30/i })).toBeInTheDocument()
    expect(within(table).getByText('$0.00')).toBeInTheDocument()
    expect(within(table).getAllByRole('row')).toHaveLength(25)
    expect(screen.getByRole('button', { name: 'First samples' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Later samples' }))
    expect(screen.getByRole('table', { name: /samples 25–30 of 30/i })).toBeInTheDocument()
    expect(within(table).getAllByRole('row')).toHaveLength(7)
    expect(screen.getByRole('button', { name: 'Latest samples' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'First samples' }))
    fireEvent.click(screen.getByRole('button', { name: 'Latest samples' }))
    expect(screen.getByRole('table', { name: /samples 7–30 of 30/i })).toBeInTheDocument()
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

  test('preserves authoritative decimal readouts while sorting approximate plot coordinates', () => {
    render(
      <TimeContext.Provider value={timeStub}>
        <TimeSeries
          label="Exact flow buckets"
          timestamps={['2026-06-04T12:00:00Z', '2026-06-04T11:00:00Z']}
          series={[
            {
              label: 'bytes',
              values: [9007199254740992, 9007199254740992],
              exactValues: ['9007199254740993', '9007199254740994'],
            },
          ]}
        />
      </TimeContext.Provider>,
    )
    const rows = within(screen.getByRole('table', { name: 'Exact flow buckets' })).getAllByRole(
      'row',
    )
    expect(within(rows[1]).getByText('9007199254740994')).toBeInTheDocument()
    expect(within(rows[2]).getByText('9007199254740993')).toBeInTheDocument()
  })

  test('has no axe violations', async () => {
    const { container } = renderSeries(30)
    expect(await axe(container)).toHaveNoViolations()
  })
  test('logarithmic fallback preserves nonpositive exact values without fabricating a floor', () => {
    render(
      <TimeContext.Provider value={timeStub}>
        <TimeSeries
          label="Log samples"
          timestamps={['2026-06-04T00:00:00Z', '2026-06-04T00:01:00Z']}
          series={[{ label: 'exact', values: [0, -1], exactValues: ['0', '-1'] }]}
          logarithmic
        />
      </TimeContext.Provider>,
    )
    expect(screen.getByText(/No positive values can be plotted/)).toBeInTheDocument()
    const table = screen.getByRole('table', { name: 'Log samples' })
    expect(within(table).getByText('0')).toBeInTheDocument()
    expect(within(table).getByText('-1')).toBeInTheDocument()
  })
})
