// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useState } from 'react'
import { Card, CardBody, CardHeader, DemoDataBadge } from '../components'
import { TimeSeries } from '../components/TimeSeries'
import { IncidentClock, type IncidentClockItem, type IncidentClockLane } from '../viz/IncidentClock'
import { PathGraph } from '../viz/PathGraph'
import type { Path } from '../api/paths'
import type { DemoVizSpec } from './demoPages'
import styles from './DemoWorkspace.module.css'

/**
 * Sample hero visualizations for the isolated product tour. Every component
 * here is the real presentational one the live routes use — mounted on static
 * props so the tour stays inside the demo transport boundary (no data hook or
 * live query exists below this file). Loaded lazily so the tour's viz never
 * weighs on the entry chunk.
 */

// One shared fiction across the tour: the 09:30–09:45 UTC checkout incident.
const CLOCK_LANES: IncidentClockLane[] = [
  { id: 'change', label: 'Changes' },
  { id: 'bgp', label: 'BGP' },
  { id: 'flow', label: 'Flow' },
  { id: 'synthetic', label: 'Synthetic' },
]

const CLOCK_ITEMS: IncidentClockItem[] = [
  {
    id: 'demo-change-policy',
    laneID: 'change',
    meta: 'change',
    title: 'edge-r1 routing policy update',
    occurredAt: '2026-07-24T09:32:00Z',
    kind: 'change',
  },
  {
    id: 'demo-bgp-path',
    laneID: 'bgp',
    meta: 'bgp',
    title: 'AS path changed for the checkout prefix',
    occurredAt: '2026-07-24T09:37:00Z',
    severity: 'warning',
    kind: 'signal',
  },
  {
    id: 'demo-flow-shift',
    laneID: 'flow',
    meta: 'flow',
    title: '41% of transit traffic shifted',
    occurredAt: '2026-07-24T09:38:00Z',
    severity: 'warning',
    kind: 'signal',
  },
  {
    id: 'demo-synthetic-p95',
    laneID: 'synthetic',
    meta: 'synthetic',
    title: 'Checkout p95 rose to 91 ms',
    occurredAt: '2026-07-24T09:39:00Z',
    severity: 'critical',
    kind: 'signal',
  },
]

function pathNode(ip: string, rtt: number, loss = 0) {
  return {
    ip,
    sent: 12,
    received: Math.round(12 * (1 - loss)),
    loss_ratio: loss,
    rtt_min_ms: Math.max(0, rtt - 1),
    rtt_avg_ms: rtt,
    rtt_max_ms: rtt + 2,
  }
}

// Mirrors the page tables exactly: edge-r1 at hop 3 (8 ms), the lossy transit
// hop at TTL 6 (67 ms, 3.8%), checkout reached at TTL 9 (91 ms). The silent
// TTLs in between are how a real traceroute looks.
const DEMO_PATH: Path = {
  target: 'checkout.example',
  target_ip: '203.0.113.20',
  mode: 'icmp',
  max_hops: 30,
  trace_count: 12,
  destination_reached: true,
  hops: [
    { ttl: 1, nodes: [pathNode('10.0.0.1', 1)] },
    {
      ttl: 2,
      nodes: [pathNode('10.0.2.1', 3), pathNode('10.0.2.2', 4), pathNode('10.0.2.3', 5)],
    },
    {
      ttl: 3,
      nodes: [
        {
          ...pathNode('172.16.3.1', 8),
          mpls: [{ label: 16259, tc: 0, s: true, ttl: 1 }],
        },
      ],
    },
    { ttl: 6, nodes: [pathNode('192.0.2.9', 67, 0.038)] },
    { ttl: 9, nodes: [pathNode('203.0.113.20', 91)] },
  ],
  links: [
    { ttl: 1, from: '10.0.0.1', to: '10.0.2.1' },
    { ttl: 1, from: '10.0.0.1', to: '10.0.2.2' },
    { ttl: 1, from: '10.0.0.1', to: '10.0.2.3' },
    { ttl: 2, from: '10.0.2.1', to: '172.16.3.1' },
    { ttl: 2, from: '10.0.2.2', to: '172.16.3.1' },
    { ttl: 2, from: '10.0.2.3', to: '172.16.3.1' },
    { ttl: 3, from: '172.16.3.1', to: '192.0.2.9' },
    { ttl: 6, from: '192.0.2.9', to: '203.0.113.20' },
  ],
}

// 09:30–09:45 UTC, one point per minute; checkout steps at 09:37.
const SERIES_START_UNIX = Date.parse('2026-07-24T09:30:00Z') / 1000
const SERIES_TIMESTAMPS = Array.from({ length: 16 }, (_, i) => SERIES_START_UNIX + i * 60)
const SERIES_CHECKOUT = [42, 43, 42, 44, 43, 42, 43, 58, 74, 88, 91, 90, 91, 89, 90, 91]
const SERIES_PAYMENTS = [44, 43, 45, 44, 43, 44, 45, 44, 43, 44, 45, 44, 44, 43, 44, 44]

export default function DemoViz({ spec }: { spec: DemoVizSpec }) {
  return (
    <Card>
      <CardHeader title={spec.title} description={spec.description} actions={<DemoDataBadge />} />
      <CardBody>
        <DemoVizBody kind={spec.kind} />
      </CardBody>
    </Card>
  )
}

function DemoVizBody({ kind }: { kind: DemoVizSpec['kind'] }) {
  if (kind === 'incident-clock') return <DemoClock />
  if (kind === 'path-graph') return <DemoPath />
  return (
    <TimeSeries
      timestamps={SERIES_TIMESTAMPS}
      series={[
        { label: 'checkout p95', values: SERIES_CHECKOUT },
        { label: 'payments p95', values: SERIES_PAYMENTS },
      ]}
      label="Checkout vs payments p95 latency, sample window"
      formatValue={(value) => `${Math.round(value)} ms`}
    />
  )
}

function DemoClock() {
  const [selectedID, setSelectedID] = useState<string>()
  const selected = CLOCK_ITEMS.find((item) => item.id === selectedID)
  return (
    <div className={styles.vizStack}>
      <IncidentClock
        lanes={CLOCK_LANES}
        items={CLOCK_ITEMS}
        selectedID={selectedID}
        onSelect={setSelectedID}
        label="Sample checkout incident timeline"
        windowStart="2026-07-24T09:30:00Z"
        windowEnd="2026-07-24T09:45:00Z"
      />
      <p className={styles.vizCaption} aria-live="polite">
        {selected
          ? `Selected evidence: ${selected.title}`
          : 'Select any marker to inspect the correlated sample evidence.'}
      </p>
    </div>
  )
}

function DemoPath() {
  const [selectedHop, setSelectedHop] = useState<{ id: string; ttl: number; ip: string }>()
  return (
    <div className={styles.vizStack}>
      <PathGraph
        path={DEMO_PATH}
        selectedId={selectedHop?.id}
        onSelect={(node) => setSelectedHop({ id: node.id, ttl: node.ttl, ip: node.ip })}
      />
      <p className={styles.vizCaption} aria-live="polite">
        {selectedHop
          ? `Selected hop: TTL ${selectedHop.ttl} · ${selectedHop.ip}`
          : 'Select any hop to focus it; the tables below cite the same sample evidence.'}
      </p>
    </div>
  )
}
