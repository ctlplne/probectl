// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import type { ReactNode } from 'react'
import styles from './Badge.module.css'

export type BadgeTone = 'neutral' | 'accent' | 'success' | 'warning' | 'danger' | 'info'

export function Badge({ tone = 'neutral', children }: { tone?: BadgeTone; children: ReactNode }) {
  return <span className={[styles.badge, styles[tone]].join(' ')}>{children}</span>
}

/** Marks illustrative values that are not tenant telemetry. */
export function DemoDataBadge() {
  return <Badge tone="warning">Demo data</Badge>
}

/** StatusDot pairs a tone dot with a label (used for health/up-down states). */
export function StatusDot({ tone = 'neutral', label }: { tone?: BadgeTone; label: string }) {
  return (
    <span className={styles.status}>
      <span className={[styles.dot, styles[tone]].join(' ')} aria-hidden="true" />
      {label}
    </span>
  )
}
