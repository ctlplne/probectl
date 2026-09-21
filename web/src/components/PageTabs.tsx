// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { NavLink } from 'react-router-dom'
import { cn } from '../lib/cn'

export interface PageTab {
  to: string
  label: string
  /** A count or short status shown after the label. */
  badge?: string | number
}

/**
 * Sub-navigation within one module. These are real links, not buttons that swap
 * state, so a tab is bookmarkable, opens in a new tab, and survives a reload —
 * which matters when an operator is sharing what they are looking at.
 *
 * The active tab is marked with aria-current, and the underline is paired with a
 * weight change so the selection is not signalled by colour alone.
 */
export function PageTabs({ tabs, className }: { tabs: PageTab[]; className?: string }) {
  return (
    <nav className={cn('-mb-px flex gap-1 overflow-x-auto border-b border-border', className)}>
      {tabs.map((tab) => (
        <NavLink
          key={tab.to}
          to={tab.to}
          end
          className={({ isActive }) =>
            cn(
              'inline-flex min-h-touch items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2',
              'text-data transition-colors duration-fast ease-standard',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus',
              isActive
                ? 'border-brand-accent font-semibold text-foreground'
                : 'border-transparent font-medium text-muted-foreground hover:border-border hover:text-foreground',
            )
          }
          aria-current={undefined}
        >
          {({ isActive }) => (
            <>
              <span aria-current={isActive ? 'page' : undefined}>{tab.label}</span>
              {tab.badge !== undefined ? (
                <span className="rounded-pill bg-muted px-1.5 py-0.5 text-caption font-medium text-muted-foreground">
                  {tab.badge}
                </span>
              ) : null}
            </>
          )}
        </NavLink>
      ))}
    </nav>
  )
}
