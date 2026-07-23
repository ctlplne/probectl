// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useState } from 'react'
import styles from './Gallery.module.css'
import { Page } from './RoutePage'
import { useTheme } from '../theme/useTheme'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  ChartShell,
  EmptyState,
  Field,
  HonestDataState,
  Icon,
  ICON_NAMES,
  LoadingState,
  Modal,
  Sparkline,
  StatusDot,
  useToast,
  type HonestDataStateKind,
} from '../components'
import { IncidentClock } from '../viz/IncidentClock'
// Direct import (not the components barrel): uplot must ride only in lazy
// route chunks so the app-shell entry stays inside its bundle budget.
import { TimeSeries } from '../components/TimeSeries'

// Deterministic showcase samples (hourly): the gallery must render identically
// on every visit — no randomness, no clock reads.
const DEMO_HOURS = Array.from(
  { length: 8 },
  (_, index) => `2026-06-04T${String(9 + index).padStart(2, '0')}:00:00Z`,
)

const HONEST_STATES: HonestDataStateKind[] = [
  'ready-no-data',
  'blocked',
  'permission-denied',
  'degraded',
  'quiet',
  'demo',
]

const DEMO_CLOCK_LANES = [
  { id: 'synthetic', label: 'Synthetic & path' },
  { id: 'flow', label: 'Flow analytics' },
  { id: 'change', label: 'Candidate changes' },
]

const DEMO_CLOCK_ITEMS = [
  {
    id: 'g1',
    laneID: 'synthetic',
    meta: 'synthetic',
    title: 'HTTP latency above SLO',
    occurredAt: '2026-06-04T11:55:00Z',
    severity: 'warning' as const,
    kind: 'signal' as const,
  },
  {
    id: 'g2',
    laneID: 'flow',
    meta: 'flow',
    title: 'edge-r1 throughput spike',
    occurredAt: '2026-06-04T11:58:00Z',
    severity: 'critical' as const,
    kind: 'signal' as const,
  },
  {
    id: 'g3',
    laneID: 'change',
    meta: 'change',
    title: 'Export policy edit',
    occurredAt: '2026-06-04T11:50:00Z',
    kind: 'change' as const,
  },
]

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader title={title} />
      <CardBody>
        <div className={styles.row}>{children}</div>
      </CardBody>
    </Card>
  )
}

export function Gallery() {
  const { theme, toggleTheme } = useTheme()
  const { push } = useToast()
  const [modalOpen, setModalOpen] = useState(false)

  return (
    <Page
      title="Design system"
      subtitle="The probectl component library — every value comes from design tokens, so the whole set re-themes when the token set is swapped."
      actions={
        <Button variant="primary" onClick={toggleTheme}>
          Theme: {theme} — swap
        </Button>
      }
    >
      <Section title="Buttons">
        <Button variant="primary">Primary</Button>
        <Button variant="secondary">Secondary</Button>
        <Button variant="ghost">Ghost</Button>
        <Button variant="danger">Danger</Button>
        <Button variant="secondary" size="sm">
          Small
        </Button>
        <Button variant="primary" disabled>
          Disabled
        </Button>
      </Section>

      <Section title="Badges & status">
        <Badge tone="neutral">neutral</Badge>
        <Badge tone="accent">accent</Badge>
        <Badge tone="success">success</Badge>
        <Badge tone="warning">warning</Badge>
        <Badge tone="danger">danger</Badge>
        <Badge tone="info">info</Badge>
        <StatusDot tone="success" label="Online" />
        <StatusDot tone="danger" label="Down" />
      </Section>

      <Section title="Form fields">
        <Field label="Test name" placeholder="edge-dns" hint="A short, unique name." />
        <Field label="Target" placeholder="1.1.1.1" error="Target is required." />
      </Section>

      <Section title="Overlays & feedback">
        <Button onClick={() => setModalOpen(true)}>Open modal</Button>
        <Button
          onClick={() =>
            push({ tone: 'success', title: 'Saved', message: 'Your test was created.' })
          }
        >
          Show toast
        </Button>
        <Modal
          open={modalOpen}
          onClose={() => setModalOpen(false)}
          title="Create test"
          footer={
            <>
              <Button variant="ghost" onClick={() => setModalOpen(false)}>
                Cancel
              </Button>
              <Button variant="primary" onClick={() => setModalOpen(false)}>
                Create
              </Button>
            </>
          }
        >
          <Field label="Test name" placeholder="edge-dns" />
        </Modal>
      </Section>

      <Section title="Charts & states">
        <ChartShell title="Latency" height={120}>
          <Sparkline label="Sample latency series" data={[12, 14, 9, 18, 22, 16, 13, 19]} />
        </ChartShell>
        <ChartShell
          title="Time series (uPlot)"
          height={200}
          legend={
            <span>
              Aligned multi-series on a real time axis; dash patterns carry the non-color series
              encoding. Drag to zoom x, double-click to reset.
            </span>
          }
        >
          <TimeSeries
            label="Demo latency percentiles over eight hours"
            timestamps={DEMO_HOURS}
            series={[
              { label: 'p50 (ms)', values: [12, 14, 9, 18, 22, 16, 13, 19] },
              { label: 'p95 (ms)', values: [28, 31, 24, 44, 61, 39, 33, 47] },
            ]}
            formatValue={(value) => `${value} ms`}
          />
        </ChartShell>
        <LoadingState label="Loading…" />
        <EmptyState title="Nothing here yet" description="Empty states guide the next action." />
      </Section>

      <Section title="Incident clock timeline">
        <div className={styles.wide}>
          <IncidentClock
            lanes={DEMO_CLOCK_LANES}
            items={DEMO_CLOCK_ITEMS}
            selectedID="g2"
            onSelect={() => undefined}
            label="Demo incident evidence on one time axis"
            windowStart="2026-06-04T11:45:00Z"
            windowEnd="2026-06-04T12:00:00Z"
          />
        </div>
      </Section>

      <Section title="Honest data states">
        <div className={styles.stack}>
          {HONEST_STATES.map((state) => (
            <HonestDataState
              key={state}
              state={state}
              producer="Flow collector"
              producerReadiness={
                state === 'blocked'
                  ? 'Server reports flow_running=false'
                  : 'The tenant query succeeded'
              }
              lastSuccessfulIngest={state === 'quiet' ? '2026-06-04T12:00:00Z' : null}
              coverageLimitation="Only registered exporters contribute samples."
              action={<Button variant="secondary">Open flow readiness</Button>}
            />
          ))}
        </div>
      </Section>

      <Section title="Icons">
        <ul className={styles.iconGrid} aria-label="Every probectl icon">
          {ICON_NAMES.map((name) => (
            <li key={name} className={styles.iconCell}>
              <Icon name={name} size={20} />
              <span>{name}</span>
            </li>
          ))}
        </ul>
      </Section>
    </Page>
  )
}
