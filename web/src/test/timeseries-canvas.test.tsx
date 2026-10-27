// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { afterEach, expect, test, vi } from 'vitest'
import { render, waitFor } from '@testing-library/react'
import type uPlot from 'uplot'
import { TimeSeries } from '../components/TimeSeries'
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

const mounts = vi.hoisted(() => vi.fn())
vi.mock('uplot', () => ({
  default: class {
    constructor(options: uPlot.Options, data: uPlot.AlignedData) {
      mounts(options, data)
    }
    destroy() {}
  },
}))

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  mounts.mockClear()
})

test.each(['2026-10-27T00:45:00Z', 1793061900, 1793061900000])(
  'one timestamp %s stays visible near its real time without synthetic samples',
  async (timestamp) => {
    vi.stubGlobal('CanvasRenderingContext2D', class {})
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(
      {} as CanvasRenderingContext2D,
    )
    render(
      <TimeContext.Provider value={timeStub}>
        <TimeSeries
          timestamps={[timestamp]}
          series={[{ label: 'bytes', values: [29000] }]}
          label="Flow"
        />
      </TimeContext.Provider>,
    )
    await waitFor(() => expect(mounts).toHaveBeenCalled())
    const [options, data] = mounts.mock.calls[0] as [uPlot.Options, uPlot.AlignedData]
    const timestampSeconds = 1793061900
    const range = options.scales?.x?.range as [number, number] | undefined
    expect(range).toBeDefined()
    expect(range![0]).toBeLessThan(timestampSeconds)
    expect(range![1]).toBeGreaterThan(timestampSeconds)
    expect(range![1] - range![0]).toBeLessThanOrEqual(60)
    expect(options.series[1].points?.show).toBe(true)
    expect(data).toEqual([[timestampSeconds], [29000]])
  },
)

test('multiple timestamps keep the ordinary automatic range and gaps', async () => {
  vi.stubGlobal('CanvasRenderingContext2D', class {})
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(
    {} as CanvasRenderingContext2D,
  )
  render(
    <TimeContext.Provider value={timeStub}>
      <TimeSeries
        timestamps={[1793061900, 1793061960, 1793062020]}
        series={[{ label: 'bytes', values: [12, null, 34] }]}
        label="Flow"
      />
    </TimeContext.Provider>,
  )
  await waitFor(() => expect(mounts).toHaveBeenCalled())
  const [options, data] = mounts.mock.calls[0] as [uPlot.Options, uPlot.AlignedData]
  expect(options.scales?.x?.range).toBeUndefined()
  expect(options.series[1].points?.show).toBe(false)
  expect(data).toEqual([
    [1793061900, 1793061960, 1793062020],
    [12, null, 34],
  ])
})
