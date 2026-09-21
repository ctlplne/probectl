// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactNode } from 'react'
import { cn } from '../lib/cn'
import { Icon, type IconName } from './Icon'

export function EmptyState({
  icon = 'dashboards',
  title,
  description,
  action,
  preview,
  headingLevel = 3,
}: {
  icon?: IconName
  title: string
  description?: ReactNode
  action?: ReactNode
  preview?: ReactNode
  headingLevel?: 2 | 3
}) {
  const Heading = headingLevel === 2 ? 'h2' : 'h3'

  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-panel border border-dashed border-border px-6 py-10 text-center">
      <span className="grid size-10 place-items-center rounded-pill bg-muted text-muted-foreground">
        <Icon name={icon} size={24} />
      </span>
      <Heading className="text-title font-semibold text-foreground">{title}</Heading>
      {description ? (
        <p className="max-w-prose text-data text-muted-foreground">{description}</p>
      ) : null}
      {action ? <div className="pt-1">{action}</div> : null}
      {preview ? <div className="w-full pt-2">{preview}</div> : null}
    </div>
  )
}

export function ErrorState({
  title = 'Something went wrong',
  description,
  action,
  headingLevel = 3,
}: {
  title?: string
  description?: ReactNode
  action?: ReactNode
  headingLevel?: 2 | 3
}) {
  const Heading = headingLevel === 2 ? 'h2' : 'h3'

  return (
    <div
      className="flex flex-col items-center justify-center gap-3 rounded-panel border border-dashed border-border px-6 py-10 text-center"
      role="alert"
    >
      <span
        className={cn(
          'grid size-10 place-items-center rounded-pill bg-muted text-muted-foreground',
          'bg-destructive/10 text-destructive',
        )}
      >
        <Icon name="alert" size={24} />
      </span>
      <Heading className="text-title font-semibold text-foreground">{title}</Heading>
      {description ? (
        <p className="max-w-prose text-data text-muted-foreground">{description}</p>
      ) : null}
      {action ? <div className="pt-1">{action}</div> : null}
    </div>
  )
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div
      className="flex flex-col items-center justify-center gap-3 rounded-panel border border-dashed border-border px-6 py-10 text-center"
      aria-busy="true"
    >
      <span
        className="size-6 animate-spin rounded-pill border-2 border-border border-t-brand-accent [animation-duration:var(--motion-spinner)]"
        aria-hidden="true"
      />
      <p className="max-w-prose text-data text-muted-foreground">{label}</p>
    </div>
  )
}

export function Skeleton({
  width = '100%',
  height = 14,
}: {
  width?: string | number
  height?: string | number
}) {
  return (
    <span
      className="block animate-pulse rounded-control bg-muted [animation-duration:var(--motion-shimmer)]"
      style={{ width, height }}
      aria-hidden="true"
    />
  )
}
