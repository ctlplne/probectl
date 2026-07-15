// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import type { ReactElement } from 'react'
import type { HonestDataStateKind } from '../data/classifySurfaceTruth'
import { Badge, type BadgeTone } from './Badge'
import { Icon, type IconName } from './Icon'
import styles from './HonestDataState.module.css'

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
      className={styles.state}
      data-data-state={state}
      aria-live={state === 'degraded' || state === 'permission-denied' ? 'assertive' : 'polite'}
    >
      <span className={styles.glyph} aria-hidden="true">
        <Icon name={icon ?? presentation.icon} size={24} />
      </span>
      <Heading className={styles.title}>{title ?? presentation.title}</Heading>
      <Badge tone={presentation.tone}>{presentation.badge}</Badge>
      <dl className={styles.facts}>
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
      <div className={styles.action} data-authorized-next-action>
        {action}
      </div>
    </section>
  )
}
