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
