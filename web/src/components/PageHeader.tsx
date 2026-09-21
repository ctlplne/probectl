// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactNode } from 'react'
import { cn } from '../lib/cn'

/**
 * The standard page title block, so every screen shares one hierarchy instead of
 * each route inventing its own heading. Three layers, in the order an operator
 * needs them:
 *
 *   answer  — the title and a plain-language description of what this screen says
 *   operate — the actions, grouped and labelled, never mixed into the prose
 *   prove   — exact identifiers, commands and evidence, disclosed on request
 *
 * The third layer is a <details>, not a hidden div: it is reachable by keyboard
 * and by a screen reader without JavaScript, and it keeps precise facts on the
 * page without making the page read like a log file.
 */
export function PageHeader({
  title,
  titleId,
  description,
  technicalDetails,
  detailsLabel = 'Show technical details',
  detailsLabelOpen = 'Hide technical details',
  eyebrow,
  actions,
  actionsLabel = 'Page actions',
  className,
}: {
  title: ReactNode
  titleId?: string
  description?: ReactNode
  /** Exact identifiers, policy facts, commands and recovery evidence. Kept
   *  reachable, but disclosed after the operator-facing answer. */
  technicalDetails?: ReactNode
  detailsLabel?: string
  detailsLabelOpen?: string
  eyebrow?: ReactNode
  actions?: ReactNode
  actionsLabel?: string
  className?: string
}) {
  return (
    <div className={cn('mb-6 border-b border-border pb-5', className)}>
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0 max-w-4xl">
          {eyebrow ? (
            <p className="mb-1.5 text-caption font-semibold uppercase tracking-wider text-brand-accent">
              {eyebrow}
            </p>
          ) : null}
          <h1 id={titleId} className="text-display font-bold tracking-tight text-foreground">
            {title}
          </h1>
          {description ? (
            <p className="mt-2 max-w-4xl text-body text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {actions ? (
          <div
            aria-label={actionsLabel}
            role="group"
            className="flex w-full min-w-0 flex-wrap items-center gap-2 sm:w-auto sm:shrink-0"
          >
            {actions}
          </div>
        ) : null}
      </div>
      {technicalDetails ? (
        <details className="group mt-4 min-w-0">
          <summary className="inline-flex cursor-pointer list-none items-center text-caption font-medium text-muted-foreground marker:hidden hover:text-foreground">
            <span className="group-open:hidden">{detailsLabel}</span>
            <span className="hidden group-open:inline">{detailsLabelOpen}</span>
          </summary>
          <div className="mt-2 max-w-4xl border-s-2 border-border ps-3 text-caption leading-relaxed text-muted-foreground">
            {technicalDetails}
          </div>
        </details>
      ) : null}
    </div>
  )
}
