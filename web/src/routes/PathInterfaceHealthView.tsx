// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { PathHealthCounter, PathInterfaceHealth } from '../api/sdk.gen'
import { Table } from '../components'

function ratio(numerator?: string, denominator?: string) {
  if (numerator === undefined || denominator === undefined) return 'Unavailable'
  return denominator === '1' ? numerator : `${numerator}/${denominator}`
}

function rateLabel(counter: PathHealthCounter) {
  if (counter.rate_kind === 'unavailable')
    return counter.reason?.replace(/_/g, ' ') ?? 'Unavailable'
  const assumption =
    counter.rate_kind === 'minimum_under_counter_continuity'
      ? 'Minimum if counter continuity holds'
      : 'Exact under the explicit physical bound'
  return `${ratio(counter.rate_numerator, counter.rate_denominator)} ${counter.rate_unit} · ${assumption}`
}

/** Source words and assumptions stay visible; JavaScript never rounds counters. */
export function PathInterfaceHealthView({ health }: { health: PathInterfaceHealth }) {
  return (
    <details>
      <summary>Polled interface health preview · {health.status.replace(/_/g, ' ')}</summary>
      <p>
        Window {health.from} to {health.to}. Means use original poll start times.
      </p>
      {health.interface_id ? (
        <p>
          Interface <code>{health.interface_id}</code> · device <code>{health.device_id}</code> ·
          source{' '}
          <code>
            {health.agent_id}/{health.source_ref}
          </code>
        </p>
      ) : null}
      <p>Recent configuration: {health.config_coverage.replace(/_/g, ' ')}.</p>
      <Table<PathHealthCounter>
        caption="Original directional interface counters"
        rows={health.counters}
        rowKey={(counter) => counter.metric}
        columns={[
          {
            key: 'metric',
            header: 'Direction and metric',
            render: (counter) =>
              counter.metric.replace('probectl.device.if.', '').replace(/\./g, ' '),
          },
          { key: 'rate', header: 'Observed mean rate', render: rateLabel },
          {
            key: 'utilisation',
            header: 'Utilisation',
            render: (counter) =>
              counter.utilization_numerator === undefined
                ? 'Unavailable'
                : `${ratio(counter.utilization_numerator, counter.utilization_denominator)}% · ${counter.utilization_kind?.startsWith('minimum_') ? 'minimum if counter continuity holds' : 'under explicit physical bound'} and constant polled speed`,
          },
          {
            key: 'originals',
            header: 'Original observations',
            render: (counter) => (
              <details>
                <summary>Counter words and receipts</summary>
                <p>
                  Previous <code>{counter.previous_value ?? 'Unavailable'}</code> · latest{' '}
                  <code>{counter.value ?? 'Unavailable'}</code> · width{' '}
                  {counter.counter_width ?? 'Unavailable'}
                </p>
                <p>
                  Polls {counter.previous_poll_started_at ?? 'Unavailable'} to{' '}
                  {counter.previous_poll_completed_at ?? 'Unavailable'};{' '}
                  {counter.poll_started_at ?? 'Unavailable'} to{' '}
                  {counter.poll_completed_at ?? 'Unavailable'}.
                </p>
                <p>
                  Polled speed <code>{counter.previous_interface_speed_bps ?? 'Unavailable'}</code>{' '}
                  → <code>{counter.interface_speed_bps ?? 'Unavailable'}</code> bits/s.
                </p>
                <p>
                  Previous capture <code>{counter.previous_capture_key ?? 'Unavailable'}</code> ·
                  digest <code>{counter.previous_raw_digest ?? 'Unavailable'}</code>
                </p>
                <p>
                  Latest capture <code>{counter.capture_key ?? 'Unavailable'}</code> · digest{' '}
                  <code>{counter.raw_digest ?? 'Unavailable'}</code>
                </p>
              </details>
            ),
          },
        ]}
        empty="No original counters are available for this responder."
      />
    </details>
  )
}
