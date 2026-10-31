// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { axe } from 'jest-axe'
import type { FlowExplorerResult, FlowResultRow } from '../api/flowExplorer'
import { FlowVisuals } from '../routes/FlowVisuals'
import { flowAxisRange, flowChartGroups, flowPlot, mergeFlowTuples } from '../routes/flowPlot'
import { flowGroupLabel } from '../routes/flowResults'
import { TimeContext, type TimeContextValue } from '../time/context'
import { formatDateTime } from '../time/format'

const metric = 'bytes:total'
const from = '2026-10-28T00:00:00Z'
function row(value: string, bytes = '9007199254740993'): FlowResultRow {
  return { group: { src_addr: value }, other: false, metrics: { [metric]: bytes } }
}
function flow(view: 'line' | 'matrix' | 'bar' = 'line'): FlowExplorerResult {
  return {
    query: {
      view,
      from,
      to: '2026-10-28T01:00:00Z',
      bucket_seconds: 60,
      group_by: ['src_addr'],
      metrics: [{ measure: 'bytes', calculation: 'total', role: 'primary' }],
    },
    source: 'raw',
    resolution_seconds: 60,
    total_groups: 1,
    detail_limited: false,
    rows: [row('DETAIL_ONLY')],
    chart_rows: [row('192.0.2.1')],
    totals: { [metric]: '9007199254740993' },
    series: [{ ...row('192.0.2.1'), ts: from, duration_seconds: '60' }],
    other_series: [],
    matrix: [],
  }
}
const time: TimeContextValue = {
  mode: 'utc',
  setMode: () => {},
  preferredTimeZone: 'UTC',
  timeZone: 'UTC',
  timeZoneLabel: 'UTC',
  format: (value) => formatDateTime(value, { locale: 'en-US', timeZone: 'UTC' }),
}

describe('global native flow visualizations', () => {
  test.each(['percent_area', 'horizon'] as const)(
    '%s figures keep source cardinality totals on a separate absolute scale and retain them when groups hide',
    (timeStyle) => {
      const current = flow()
      current.chart_rows = [row('a', '1'), row('b', '1')]
      current.total_groups = 2
      current.series = current.chart_rows.map((item) => ({
        ...item,
        ts: from,
        duration_seconds: '60',
      }))
      current.total_series = [
        { group: {}, other: false, ts: from, duration_seconds: '60', metrics: { [metric]: '1' } },
      ]
      const before = JSON.stringify(current)
      render(
        <TimeContext.Provider value={time}>
          <FlowVisuals
            current={current}
            display={{
              time_style: timeStyle,
              percent_basis: 'returned',
              total_overlay: true,
              one_chart_per_series: true,
            }}
            onDrill={vi.fn()}
          />
        </TimeContext.Provider>,
      )
      expect(screen.getAllByRole('figure')).toHaveLength(3)
      const total = screen
        .getAllByRole('figure')
        .find((figure) => figure.textContent?.includes('absolute scale'))!
      expect(
        within(total).getByRole('columnheader', {
          name: `Current · Total (all matching inputs) · ${metric}`,
        }),
      ).toBeInTheDocument()
      expect(within(total).getAllByRole('columnheader')).toHaveLength(2)
      fireEvent.click(screen.getByText('Chart groups (2 of 2 shown)'))
      fireEvent.click(screen.getByRole('button', { name: 'Hide chart group src_addr: a' }))
      fireEvent.click(screen.getByRole('button', { name: 'Hide chart group src_addr: b' }))
      expect(screen.getAllByRole('figure')).toHaveLength(1)
      expect(
        screen.getByText('All chart groups are hidden. Show a group to plot this visualization.'),
      ).toBeInTheDocument()
      expect(JSON.stringify(current)).toBe(before)
    },
  )

  test('columns retain source partial intervals and reject old or inconsistent duration metadata', () => {
    const current = flow()
    current.query.to = '2026-10-28T00:01:15Z'
    current.series = [
      { ...row('192.0.2.1', '2'), ts: from, duration_seconds: '60' },
      { ...row('192.0.2.1', '3'), ts: '2026-10-28T00:01:00Z', duration_seconds: '15' },
    ]
    const plot = flowPlot(current, undefined, metric, undefined, { intervals: true })
    expect(
      plot.series[0].intervals
        ?.slice(0, 2)
        .map((interval) => interval && interval[1] - interval[0]),
    ).toEqual([60, 15])
    expect(plot.series[0].exactValues?.slice(0, 2)).toEqual(['2', '3'])
    current.series[1].duration_seconds = '60'
    expect(() => flowPlot(current, undefined, metric, undefined, { intervals: true })).toThrow(
      'intervals',
    )
    current.series[1].duration_seconds = ''
    expect(() => flowPlot(current, undefined, metric, undefined, { intervals: true })).toThrow(
      'Run a fresh query',
    )
    expect(flowPlot(current, undefined, metric).series[0].exactValues).toContain('3')
  })

  test('total overlay uses source cardinalities and survives hiding every group', () => {
    const current = flow()
    const key = 'unique_src:total'
    current.query.metrics = [{ measure: 'unique_src', calculation: 'total', role: 'primary' }]
    current.query.group_by = ['src_port']
    current.chart_rows = ['80', '443'].map((port) => ({
      group: { src_port: port },
      other: false,
      metrics: { [key]: '1' },
    }))
    current.series = current.chart_rows.map((item) => ({
      ...item,
      ts: from,
      duration_seconds: '60',
    }))
    current.total_groups = 2
    current.totals = { [key]: '1' }
    current.total_series = [
      { group: {}, other: false, ts: from, duration_seconds: '60', metrics: { [key]: '1' } },
    ]
    const plot = flowPlot(current, undefined, key, undefined, { total: true })
    const total = plot.series.find((item) => item.total)!
    expect(total.values[0]).toBe(1)
    expect(total.exactValues?.[0]).toBe('1')
    expect(total.emphasis).toBe('total')
    const before = JSON.stringify(current)
    render(
      <TimeContext.Provider value={time}>
        <FlowVisuals current={current} display={{ total_overlay: true }} onDrill={vi.fn()} />
      </TimeContext.Provider>,
    )
    fireEvent.click(screen.getByText('Chart groups (2 of 2 shown)'))
    const controls = within(screen.getByRole('region', { name: 'All global chart group controls' }))
    fireEvent.click(controls.getByRole('button', { name: 'Hide chart group src_port: 80' }))
    fireEvent.click(controls.getByRole('button', { name: 'Hide chart group src_port: 443' }))
    expect(
      screen.getByRole('columnheader', { name: `Current · Total (all matching inputs) · ${key}` }),
    ).toBeInTheDocument()
    expect(screen.getAllByRole('columnheader')).toHaveLength(2)
    expect(JSON.stringify(current)).toBe(before)
  })

  test('total overlays retain exact previous timestamps, cost accounting and explicit old-metadata refusal', () => {
    const current = flow(),
      previous = flow()
    current.total_series = [
      {
        group: {},
        other: false,
        ts: from,
        duration_seconds: '60',
        metrics: { [metric]: '18446744073709551617' },
      },
    ]
    previous.query.from = '2020-01-01T00:00:00.123456789Z'
    previous.query.to = '2020-01-01T01:00:00.123456789Z'
    previous.series[0].ts = previous.query.from
    previous.total_series = [{ ...current.total_series[0], ts: previous.query.from }]
    const plot = flowPlot(current, previous, metric, undefined, { total: true })
    expect(plot.series.filter((item) => item.total)[1].exactValues).toContain(
      '18446744073709551617 (previous 2020-01-01T00:00:00.123456789Z)',
    )
    expect(() => flowPlot(current, previous, metric, 10, { total: true })).toThrow(
      'rendering budget exceeded',
    )
    previous.total_series = undefined
    expect(() => flowPlot(current, previous, metric, undefined, { total: true })).toThrow(
      'Run a fresh query',
    )
    current.total_series = []
    expect(() => flowPlot(current, undefined, metric, undefined, { total: true })).toThrow(
      'unavailable',
    )
  })

  test('shared axes consider visible values with positive bounds for mixed logarithmic metrics', () => {
    const values = [
      { label: 'a', values: [0, 1, 10, null] },
      { label: 'b', values: [1000, null] },
    ]
    expect(flowAxisRange(values, false)).toEqual([0, 1000])
    expect(flowAxisRange(values, true)).toEqual([1, 1000])
    expect(flowAxisRange([{ label: 'zero', values: [0] }], false)).toEqual([0, 1])
    expect(flowAxisRange([{ label: 'zero', values: [0] }], true)).toBeUndefined()
  })

  test('generated charts retain40global groups plus Other and every exact sample', () => {
    const current = flow()
    current.chart_rows = Array.from({ length: 40 }, (_, i) => row(`g${i}`))
    current.chart_other = { group: {}, other: true, metrics: { [metric]: '7' } }
    current.series = current.chart_rows.map((item) => ({
      ...item,
      ts: from,
      duration_seconds: '60',
    }))
    current.other_series = [{ ...current.chart_other, ts: from, duration_seconds: '60' }]
    render(
      <TimeContext.Provider value={time}>
        <FlowVisuals
          current={current}
          display={{ one_chart_per_series: true, charts_per_row: 4, chart_height: 'short' }}
          onDrill={vi.fn()}
        />
      </TimeContext.Provider>,
    )
    expect(screen.getAllByRole('figure')).toHaveLength(41)
    expect(screen.getAllByRole('table')).toHaveLength(41)
    expect(
      screen.getByRole('columnheader', { name: `Current · src_addr: g39 · ${metric}` }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('columnheader', { name: `Current · Other (unselected groups) · ${metric}` }),
    ).toBeInTheDocument()
  })

  test('bar reference uses exact whole-period statistics rather than the last bucket', () => {
    const current = flow('bar')
    current.totals[metric] = '10'
    current.chart_rows![0].metrics[metric] = '5'
    current.total_series = [
      { group: {}, other: false, ts: from, duration_seconds: '60', metrics: { [metric]: '10000' } },
    ]
    const { container } = render(
      <FlowVisuals current={current} display={{ total_overlay: true }} onDrill={vi.fn()} />,
    )
    const total = screen.getByText('Total current: 10')
    expect((total.nextElementSibling?.firstElementChild as HTMLElement).style.left).toBe('100%')
    expect(container.querySelector('ol li [style*="width"]')).toHaveStyle({ width: '50%' })
  })
  test('long sparse ranges retain exact values and zero sentinels without allocating every empty minute', () => {
    const current = flow()
    current.query.from = '1926-10-28T00:00:00Z'
    current.query.to = '2026-10-28T01:00:00Z'
    current.series[0].ts = current.query.to.replace('01:00:00', '00:00:00')
    const plot = flowPlot(current, undefined, metric)
    expect(plot.timestamps.length).toBeLessThan(10)
    const selected = plot.series[0]
    expect(selected.exactValues).toContain('9007199254740993')
    expect(selected.exactValues).toContain('0')
    expect(selected.values[selected.values.length - 1]).toBeNull()
  })

  test('any previous range aligns by elapsed offset and never fabricates current data outside its window', () => {
    const current = flow()
    const previous = flow()
    previous.query.from = '2020-01-01T00:00:00Z'
    previous.query.to = '2020-01-01T02:00:00Z'
    previous.series[0].ts = '2020-01-01T01:30:00Z'
    previous.series[0].metrics[metric] = '18446744073709551617'
    const plot = flowPlot(current, previous, metric)
    const at = plot.timestamps.indexOf(Date.parse('2026-10-28T01:30:00Z') / 1000)
    expect(at).toBeGreaterThan(-1)
    expect(plot.series[0].values[at]).toBeNull()
    expect(plot.series[1].exactValues?.[at]).toContain('18446744073709551617')
    expect(plot.series[1].exactValues?.[at]).toContain('2020-01-01T01:30:00')
    expect(plot.series[0].colorIndex).toBe(plot.series[1].colorIndex)
    expect(plot.series[0].lineStyle).toBe('solid')
    expect(plot.series[1].lineStyle).toBe('previous')
    previous.chart_rows = [row('PREVIOUS_ONLY')]
    previous.series = []
    const absent = flowPlot(current, previous, metric).series.find(
      (item) => item.label.startsWith('Current') && item.label.includes('PREVIOUS_ONLY'),
    )
    expect(absent?.values.every((value) => value === null)).toBe(true)
  })

  test('cost and invalid geometry refuse explicitly without dropping series or replacing an overflow with zero', () => {
    const current = flow()
    current.chart_rows = Array.from({ length: 40 }, (_, i) => row(`group-${i}`))
    current.series = current.chart_rows.map((item) => ({
      ...item,
      ts: from,
      duration_seconds: '60',
    }))
    expect(flowChartGroups(current)).toHaveLength(40)
    expect(() => flowPlot(current, undefined, metric, 10)).toThrow('rendering budget exceeded')
    current.series[0].metrics = { [metric]: '1' + '0'.repeat(400) }
    expect(() => flowPlot(current, undefined, metric)).toThrow('cannot be represented numerically')
  })

  test('previous readouts preserve the actual nanosecond timestamp supplied by the source', () => {
    const current = flow(),
      previous = flow()
    previous.query.from = '2020-01-01T00:00:00.123456789Z'
    previous.query.to = '2020-01-01T01:00:00.123456789Z'
    previous.series[0].ts = previous.query.from
    expect(flowPlot(current, previous, metric).series[1].exactValues).toContain(
      '9007199254740993 (previous 2020-01-01T00:00:00.123456789Z)',
    )
  })

  test('bars use all40 global chart groups and structural Other, independently of the visible details', () => {
    const current = flow('bar')
    current.chart_rows = Array.from({ length: 40 }, (_, i) => row(`global-${i}`, String(i + 1)))
    current.chart_rows[0] = row('Other', '9007199254740993')
    current.chart_other = { group: {}, other: true, metrics: { [metric]: '18446744073709551617' } }
    const drill = vi.fn()
    const { container } = render(<FlowVisuals current={current} onDrill={drill} />)
    const visual = within(container.querySelector('figure')!)
    expect(visual.getByText('src_addr: global-39')).toBeInTheDocument()
    expect(screen.getByText('Current: 9007199254740993')).toBeInTheDocument()
    expect(screen.getByText('Current: 18446744073709551617')).toBeInTheDocument()
    expect(visual.getByText('Other (unselected groups)')).toBeInTheDocument()
    expect(screen.queryByText(/DETAIL_ONLY/)).not.toBeInTheDocument()
    fireEvent.click(visual.getByText('src_addr: Other'))
    expect(drill).toHaveBeenCalledWith({ src_addr: 'Other' })
  })

  test('hide/solo/restore affects both period bars without changing exact results or structural Other', async () => {
    const current = flow('bar'),
      previous = flow('bar')
    current.chart_rows = [row('Other'), row('current-only')]
    previous.chart_rows = [row('Other', '18446744073709551617'), row('previous-only')]
    current.chart_other = { group: {}, other: true, metrics: { [metric]: '7' } }
    const original = JSON.stringify([current, previous])
    const drill = vi.fn()
    const { container } = render(
      <FlowVisuals current={current} previous={previous} onDrill={drill} />,
    )
    fireEvent.click(screen.getByText('Chart groups (4 of 4 shown)'))
    const controls = within(screen.getByRole('region', { name: 'All global chart group controls' }))
    const bars = () => container.querySelectorAll('figure ol > li')
    expect(bars()).toHaveLength(4)
    const previousColor = (bars()[3] as HTMLElement).style.getPropertyValue('--flow-series-color')
    fireEvent.click(controls.getByRole('button', { name: 'Hide chart group src_addr: Other' }))
    expect(bars()).toHaveLength(3)
    expect(
      screen.queryByText('Current: 9007199254740993', { selector: 'figure span' }),
    ).not.toBeNull()
    expect(container.querySelector('figure')?.textContent).not.toContain('18446744073709551617')
    fireEvent.click(
      controls.getByRole('button', { name: 'Show all except chart group src_addr: current-only' }),
    )
    expect(bars()).toHaveLength(3)
    expect(container.querySelector('figure')?.textContent).toContain('18446744073709551617')
    expect(container.querySelector('figure')?.textContent).not.toContain('src_addr: current-only')
    fireEvent.click(
      controls.getByRole('button', { name: 'Only show chart group src_addr: previous-only' }),
    )
    expect(bars()).toHaveLength(1)
    expect((bars()[0] as HTMLElement).style.getPropertyValue('--flow-series-color')).toBe(
      previousColor,
    )
    expect(container.querySelector('figure')?.textContent).toContain('Current: Missing')
    fireEvent.click(screen.getByRole('button', { name: 'Show all chart groups' }))
    expect(bars()).toHaveLength(4)
    fireEvent.click(
      controls.getByRole('button', { name: 'Only show chart group Other (unselected groups)' }),
    )
    expect(bars()).toHaveLength(1)
    expect(container.querySelector('figure')?.textContent).toContain('Current: 7')
    expect(container.querySelector('figure')?.textContent).not.toContain('src_addr: Other')
    fireEvent.click(
      controls.getByRole('button', { name: 'Hide chart group Other (unselected groups)' }),
    )
    expect(screen.getByRole('status')).toHaveTextContent('No chart groups are visible')
    fireEvent.click(controls.getByRole('button', { name: 'Show chart group src_addr: Other' }))
    expect(bars()).toHaveLength(1)
    expect(container.querySelector('figure')?.textContent).toContain('18446744073709551617')
    expect(JSON.stringify([current, previous])).toBe(original)
    fireEvent.click(controls.getByRole('button', { name: 'Exclude chart group src_addr: Other' }))
    expect(drill).toHaveBeenLastCalledWith({ src_addr: 'Other' }, 'exclude')
    expect(
      controls.queryByRole('button', { name: 'Exclude chart group Other (unselected groups)' }),
    ).not.toBeInTheDocument()
    expect(await axe(container)).toHaveNoViolations()
  })

  test('matrix renders15 full8-field tuples per axis plus Other and drills all16 fields', () => {
    const current = flow('matrix')
    const rowFields = [
      'src_addr',
      'src_port',
      'protocol',
      'exporter',
      'in_if',
      'vlan',
      'dscp',
      'src_asn',
    ]
    const colFields = [
      'dst_addr',
      'dst_port',
      'transport',
      'next_hop',
      'out_if',
      'tos',
      'net_type',
      'dst_country',
    ]
    current.query.group_by = rowFields
    current.query.matrix_with = colFields
    current.matrix_rows = Array.from({ length: 15 }, (_, i) => ({
      group: Object.fromEntries(rowFields.map((field) => [field, `${i}`])),
      other: false,
      metrics: {},
    }))
    current.matrix_columns = Array.from({ length: 15 }, (_, i) => ({
      group: Object.fromEntries(colFields.map((field) => [field, `${i}`])),
      other: false,
      metrics: {},
    }))
    current.matrix = current.matrix_rows.flatMap((r, i) =>
      current.matrix_columns!.map((c, j) => ({
        row: r.group,
        column: c.group,
        row_other: false,
        column_other: false,
        metrics: { [metric]: String(1000 + i * 100 + j) },
      })),
    )
    current.matrix.push({
      row: {},
      column: {},
      row_other: true,
      column_other: true,
      metrics: { [metric]: '9007199254740993' },
    })
    const drill = vi.fn()
    render(<FlowVisuals current={current} onDrill={drill} />)
    const table = screen.getByRole('table')
    expect(table.querySelectorAll('tbody td')).toHaveLength(256)
    expect(within(table).getByText('Current: 2414')).toBeInTheDocument()
    const r = current.matrix_rows[14].group,
      c = current.matrix_columns[14].group
    fireEvent.click(
      screen.getByLabelText(`Filter to Row ${flowGroupLabel(r)}; column ${flowGroupLabel(c)}`),
    )
    expect(drill).toHaveBeenCalledWith({ ...r, ...c })
    fireEvent.click(screen.getByLabelText(`Filter to matrix row ${flowGroupLabel(r)}`))
    expect(drill).toHaveBeenLastCalledWith(r)
    fireEvent.click(screen.getByLabelText(`Filter to matrix column ${flowGroupLabel(c)}`))
    expect(drill).toHaveBeenLastCalledWith(c)
    fireEvent.click(screen.getByLabelText(`Exclude matrix column ${flowGroupLabel(c)}`))
    expect(drill).toHaveBeenLastCalledWith(c, 'exclude')
    fireEvent.click(screen.getByLabelText(`Exclude matrix row ${flowGroupLabel(r)}`))
    expect(drill).toHaveBeenLastCalledWith(r, 'exclude')
    fireEvent.click(
      screen.getByLabelText(`Exclude Row ${flowGroupLabel(r)}; column ${flowGroupLabel(c)}`),
    )
    expect(drill).toHaveBeenLastCalledWith({ ...r, ...c }, 'exclude')
    const summary = screen.getByLabelText(`Show matrix row tuple ${flowGroupLabel(r)}`)
    const details = summary.closest('details')
    expect(details?.querySelectorAll('dt')).toHaveLength(8)
    expect(details).not.toHaveAttribute('open')
    fireEvent.click(summary)
    expect(details).toHaveAttribute('open')
    expect(within(summary).getByText('src_addr')).toBeInTheDocument()
    expect(() => mergeFlowTuples({ src_addr: 'a' }, { src_addr: 'b' })).toThrow(
      'conflicting values',
    )
  })

  test('time rendering exposes exact current and actual previous-time values through the accessible table', async () => {
    const current = flow(),
      previous = flow()
    previous.query.from = '2020-01-01T00:00:00Z'
    previous.query.to = '2020-01-01T01:00:00Z'
    previous.series[0].ts = previous.query.from
    const { container } = render(
      <TimeContext.Provider value={time}>
        <FlowVisuals current={current} previous={previous} onDrill={vi.fn()} />
      </TimeContext.Provider>,
    )
    expect(screen.getByText('9007199254740993')).toBeInTheDocument()
    expect(screen.getByText(/9007199254740993 \(previous 2020-01-01/)).toBeInTheDocument()
    expect(await axe(container)).toHaveNoViolations()
  })
})
