// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactNode } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '../lib/cn'

/**
 * A chip reads as text on a 10%-tint wash, never as a saturated block. Each
 * tone's foreground is chosen to clear 4.5:1 on a white card AND on its own
 * tint, because these nest inside muted summary panels.
 */
const badge = cva(
  'inline-flex items-center gap-1.5 rounded-pill px-2 py-0.5 text-caption font-medium',
  {
    variants: {
      tone: {
        neutral: 'bg-status-neutral/10 text-status-neutral',
        accent: 'bg-brand-accent/10 text-brand-accent',
        success: 'bg-status-success/10 text-status-success',
        warning: 'bg-status-warning/10 text-status-warning',
        danger: 'bg-destructive/10 text-destructive',
        info: 'bg-status-info/10 text-status-info',
      },
    },
    defaultVariants: { tone: 'neutral' },
  },
)

const dot = cva('size-2 shrink-0 rounded-pill', {
  variants: {
    tone: {
      neutral: 'bg-status-neutral',
      accent: 'bg-brand-accent',
      success: 'bg-status-success',
      warning: 'bg-status-warning',
      danger: 'bg-destructive',
      info: 'bg-status-info',
    },
  },
  defaultVariants: { tone: 'neutral' },
})

export type BadgeTone = NonNullable<VariantProps<typeof badge>['tone']>

export function Badge({
  tone = 'neutral',
  className,
  children,
}: {
  tone?: BadgeTone
  className?: string
  children: ReactNode
}) {
  return <span className={cn(badge({ tone }), className)}>{children}</span>
}

/** Marks illustrative values that are not tenant telemetry. */
export function DemoDataBadge() {
  return <Badge tone="warning">Demo data</Badge>
}

/** StatusDot pairs a tone dot with a label (used for health/up-down states).
 *  The label carries the meaning; the dot is decorative, so colour alone never
 *  communicates state. */
export function StatusDot({ tone = 'neutral', label }: { tone?: BadgeTone; label: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-data text-foreground">
      <span className={dot({ tone })} aria-hidden="true" />
      {label}
    </span>
  )
}
