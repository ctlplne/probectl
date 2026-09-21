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

export interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  footer?: ReactNode
  returnFocusRef?: RefObject<HTMLElement | null>
}

/** An accessible modal dialog: focus trap, Escape to close, focus restoration.
 *  Use it for a decision the operator must finish. For inspecting a record while
 *  keeping the list visible, use DetailDrawer instead. */
export function Modal({ open, onClose, title, children, footer, returnFocusRef }: ModalProps) {
  const dialogRef = useDialogFocus(open, onClose, returnFocusRef)
  const titleId = useId()

  if (!open) return null

  return createPortal(
    <div
      className="fixed inset-0 z-modal flex items-start justify-center bg-foreground/40 p-4 pt-[var(--layout-dialog-inset-block)] animate-overlay-in"
      onMouseDown={onClose}
    >
      <div
        ref={dialogRef}
        className="flex w-full max-w-xl flex-col overflow-hidden rounded-panel border border-border bg-card text-card-foreground shadow-elevation3 animate-panel-in"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onMouseDown={(e) => e.stopPropagation()}
      >
        {/* A div, not <header>: inside a dialog a header maps to a second
            banner landmark (axe landmark-no-duplicate-banner); the dialog is
            labeled via aria-labelledby. */}
        <div className="flex items-start justify-between gap-4 border-b border-border px-panel-padding py-4">
          <h2 id={titleId} className="text-title font-semibold tracking-snug">
            {title}
          </h2>
          <Button variant="ghost" size="sm" iconOnly onClick={onClose} aria-label="Close dialog">
            <Icon name="close" />
          </Button>
        </div>
        <div className="max-h-[var(--layout-dialog-scroll-max-block)] overflow-auto px-panel-padding py-panel-padding">
          {children}
        </div>
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
