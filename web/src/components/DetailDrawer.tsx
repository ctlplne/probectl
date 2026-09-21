// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useId, type ReactNode, type RefObject } from 'react'
import { createPortal } from 'react-dom'
import { Button } from './Button'
import { Icon } from './Icon'
import { useDialogFocus } from './useDialogFocus'

export interface DetailDrawerProps {
  open: boolean
  onClose: () => void
  title: string
  /** Optional second line: the record's id, tenant, or status summary. */
  subtitle?: ReactNode
  children: ReactNode
  footer?: ReactNode
  returnFocusRef?: RefObject<HTMLElement | null>
}

/**
 * A side drawer for inspecting one record WITHOUT losing the list behind it —
 * which is the whole reason it exists rather than a modal: on the incident and
 * agent screens the row you came from is context you still need.
 *
 * It is a modal dialog in the accessibility sense (focus is trapped, the
 * background is inert) and shares Modal's focus contract through
 * useDialogFocus, so Escape, Tab-cycling and focus restoration behave
 * identically on both surfaces.
 */
export function DetailDrawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  returnFocusRef,
}: DetailDrawerProps) {
  const drawerRef = useDialogFocus(open, onClose, returnFocusRef)
  const titleId = useId()

  if (!open) return null

  return createPortal(
    <div
      className="fixed inset-0 z-modal flex justify-end bg-foreground/40 animate-overlay-in"
      onMouseDown={onClose}
    >
      <div
        ref={drawerRef}
        className="flex h-full w-full max-w-lg flex-col border-l border-border bg-card text-card-foreground shadow-elevation3 animate-drawer-in"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4 border-b border-border px-panel-padding py-4">
          <div className="min-w-0 space-y-1">
            <h2 id={titleId} className="truncate text-title font-semibold tracking-snug">
              {title}
            </h2>
            {subtitle ? (
              <p className="truncate text-caption text-muted-foreground">{subtitle}</p>
            ) : null}
          </div>
          <Button variant="ghost" size="sm" iconOnly onClick={onClose} aria-label="Close details">
            <Icon name="close" />
          </Button>
        </div>
        <div className="flex-1 overflow-auto px-panel-padding py-panel-padding">{children}</div>
        {footer ? (
          <footer className="flex items-center justify-end gap-2 border-t border-border px-panel-padding py-3">
            {footer}
          </footer>
        ) : null}
      </div>
    </div>,
    document.body,
  )
}
