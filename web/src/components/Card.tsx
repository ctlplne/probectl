// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { HTMLAttributes, ReactNode } from 'react'
import { cn } from '../lib/cn'

/**
 * A card is a panel on the paper, lifted by one elevation step rather than by a
 * heavier border. Padding comes from the density tokens so compact mode reshapes
 * every panel at once.
 *
 * The data-card-* attributes are load-bearing: layout tests and the rendered
 * a11y pass select on them rather than on class names, which are generated.
 */
export function Card({ className, children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <section
      className={cn(
        'rounded-panel border border-border bg-card text-card-foreground shadow-elevation1',
        className,
      )}
      {...rest}
    >
      {children}
    </section>
  )
}

export function CardHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
}) {
  return (
    <header
      // Stacked at phone width, side by side from sm up. Relying on flex-wrap
      // alone did not stack: a card whose body is a wide table gives the header
      // hundreds of pixels to work with, so heading plus actions kept "fitting"
      // on one line at a 390px viewport and the actions were clipped by the card.
      className="flex flex-col items-start gap-4 border-b border-border px-panel-padding py-4 sm:flex-row sm:flex-wrap sm:items-start sm:justify-between"
      data-card-header
    >
      {/* grow + an explicit basis, not min-w-0 alone: with a shrink-0 action
          group beside it, a heading that may shrink to nothing never forces a
          wrap, so flex squeezed the title instead of moving the actions. */}
      <div className="w-full min-w-0 grow basis-56 space-y-1 sm:w-auto" data-card-heading>
        <h2 className="text-title font-semibold tracking-snug text-card-foreground">{title}</h2>
        {description ? <p className="text-data text-muted-foreground">{description}</p> : null}
      </div>
      {actions ? (
        <div className="flex shrink-0 items-center gap-2" data-card-actions>
          {actions}
        </div>
      ) : null}
    </header>
  )
}

export function CardBody({ className, children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn('px-panel-padding py-panel-padding', className)} {...rest}>
      {children}
    </div>
  )
}
