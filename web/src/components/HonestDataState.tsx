// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactElement } from 'react'
import type { HonestDataStateKind } from '../data/classifySurfaceTruth'
import { Badge, type BadgeTone } from './Badge'
import { Icon, type IconName } from './Icon'
import { SampleTourLink } from '../demo/SampleTourLink'

/** Cold states where offering the isolated sample tour helps a fresh install;
 * denied/degraded surfaces must not suggest fiction as a next step, and the
 * demo state IS the fiction. */
const SAMPLE_TOUR_STATES: ReadonlySet<HonestDataStateKind> = new Set([
  'ready-no-data',
  'blocked',
  'quiet',
])

const PRESENTATION: Record<
  HonestDataStateKind,
  { title: string; badge: string; tone: BadgeTone; icon: IconName }
> = {
  'ready-no-data': {
    title: 'Ready, waiting for first data',
    badge: 'Ready · no data yet',
    tone: 'info',
    icon: 'dashboards',
  },
  blocked: {
    title: 'Producer setup is required',
    badge: 'Blocked · configuration required',
    tone: 'warning',
    icon: 'admin',
  },
  'permission-denied': {
    title: 'This data is outside your authority',
    badge: 'Permission denied',
    tone: 'danger',
    icon: 'alert',
  },
  degraded: {
    title: 'Data coverage is degraded',
    badge: 'Degraded · incomplete coverage',
    tone: 'warning',
    icon: 'alert',
  },
  quiet: {
    title: 'No events in this observed window',
    badge: 'Quiet · producer is ready',
    tone: 'success',
    icon: 'dashboards',
  },
  demo: {
    title: 'Illustrative data only',
    badge: 'Demo · not tenant telemetry',
    tone: 'warning',
    icon: 'dashboards',
  },
}

/**
 * HonestDataState is the only empty-state primitive for tenant data. Callers
 * must provide readiness, ingest recency, a coverage limitation, and exactly
 * one safe next action. Filter/search empties may continue using EmptyState.
 */
export function HonestDataState({
  state,
  producer,
  producerReadiness,
  lastSuccessfulIngest,
  coverageLimitation,
  action,
  title,
  icon,
  headingLevel = 3,
}: {
  state: HonestDataStateKind
  producer: string
  producerReadiness: string
  /** An ISO timestamp when the server reports one; null means it did not. */
  lastSuccessfulIngest: string | null
  coverageLimitation: string
  /** One authorization-safe button or link. Never pass an action the caller cannot use. */
  action: ReactElement
  title?: string
  icon?: IconName
  headingLevel?: 2 | 3
}) {
  const presentation = PRESENTATION[state]
  const Heading = headingLevel === 2 ? 'h2' : 'h3'

  return (
    <section
      className="flex flex-col items-center gap-3 rounded-panel border border-dashed border-border bg-muted/40 px-6 py-8 text-center"
      data-data-state={state}
      aria-live={state === 'degraded' || state === 'permission-denied' ? 'assertive' : 'polite'}
    >
      <span
        className="grid size-10 place-items-center rounded-pill bg-card text-muted-foreground shadow-elevation1"
        aria-hidden="true"
      >
        <Icon name={icon ?? presentation.icon} size={24} />
      </span>
      <Heading className="text-title font-semibold text-foreground">
        {title ?? presentation.title}
      </Heading>
      <Badge tone={presentation.tone}>{presentation.badge}</Badge>
      <dl className="grid w-full max-w-2xl gap-2 text-left text-caption [&_dd]:text-muted-foreground [&_dt]:font-semibold [&_dt]:uppercase [&_dt]:tracking-wide [&_dt]:text-muted-foreground [&>div]:grid [&>div]:gap-0.5">
        <div>
          <dt>Producer readiness</dt>
          <dd>
            <strong>{producer}</strong> · {producerReadiness}
          </dd>
        </div>
        <div>
          <dt>Last successful ingest</dt>
          <dd>
            {lastSuccessfulIngest ? (
              <time dateTime={lastSuccessfulIngest}>{lastSuccessfulIngest}</time>
            ) : (
              'Not reported by the producer'
            )}
          </dd>
        </div>
        <div>
          <dt>Coverage limitation</dt>
          <dd>{coverageLimitation}</dd>
        </div>
      </dl>
      <div className="pt-1" data-authorized-next-action>
        {action}
      </div>
      {SAMPLE_TOUR_STATES.has(state) ? <SampleTourLink /> : null}
    </section>
  )
}
