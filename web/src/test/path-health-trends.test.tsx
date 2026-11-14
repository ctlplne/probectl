// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { cleanup, render, screen, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { PathInterfaceHealthView } from '../routes/PathInterfaceHealthView'

test('paired path baseline views show original wrapped words and minimum-rate qualifications', () => {
  for (const lane of [1, 2]) {
    render(
      <PathInterfaceHealthView
        health={{
          status: 'observed_originals',
          from: '2026-11-14T00:00:00Z',
          to: '2026-11-14T00:00:04Z',
          method: 'original_counter_poll_start_mean',
          config_coverage: 'unavailable_no_context_bound_archive',
          interface_id: `owned-interface-${lane}`,
          counters: [],
          error_trends: [
            {
              metric: 'probectl.device.if.in.fcs.errors',
              state: 'rising_minimum_rate',
              model: 'local-zscore-v1',
              sensitivity: 3,
              rate_kind: 'minimum_under_counter_continuity',
              baseline_samples: 3,
              baseline_mean: 1,
              baseline_stddev: 0,
              score: 22,
              observations: [
                {
                  metric: 'probectl.device.if.in.fcs.errors',
                  previous_value: '4294967291',
                  value: '15',
                  rate_numerator: '20',
                  rate_denominator: '1',
                  rate_unit: 'packets/s',
                  rate_kind: 'minimum_under_counter_continuity',
                  previous_capture_key: `previous-owned-${lane}`,
                  capture_key: `current-owned-${lane}`,
                },
              ],
            },
          ],
        }}
      />,
    )
    expect(screen.getByText('in fcs errors · rising minimum rate')).toBeInTheDocument()
    expect(screen.getByText(/3 baseline rate samples/)).toBeInTheDocument()
    const table = screen.getByRole('table', {
      name: 'Original contiguous error-rate observations',
      hidden: true,
    })
    expect(table).toHaveTextContent('20 packets/s · Minimum if counter continuity holds')
    expect(within(table).getByText('4294967291 → 15')).toBeInTheDocument()
    expect(table).toHaveTextContent(`current-owned-${lane}`)
    expect(table).not.toHaveTextContent(`current-owned-${3 - lane}`)
    cleanup()
  }
})
