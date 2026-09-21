// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useId, useRef, type ReactNode, type RefObject } from 'react'
import { createPortal } from 'react-dom'
import styles from './Modal.module.css'
import { Button } from './Button'
import { Icon } from './Icon'

export interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  footer?: ReactNode
  returnFocusRef?: RefObject<HTMLElement | null>
}

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])'

// isVisible answers "would a browser paint this?" — checkVisibility where the
// engine has it (it is correct for position: fixed, which offsetParent reports
// as hidden), otherwise the offsetParent test, which display: none nulls out.
function isVisible(el: HTMLElement): boolean {
  if (typeof el.checkVisibility === 'function') return el.checkVisibility()
  return el.offsetParent !== null
}

// DPR-167: restore focus to the TRIGGER, not to the node it used to be. A list
// that re-renders while a dialog is open (a poll landing, a refetch, a
// responsive re-layout) replaces the captured element, and focusing a detached
// node silently does nothing — focus falls to <body>, where the next Tab
// restarts at the top of the page. That is a WCAG 2.4.3 focus-order failure that
// reads like working code, so this walks the alternatives in order of how much
// it actually knows, and never gives up silently.
function restoreFocus(trigger: HTMLElement | null) {
  const captured = trigger?.isConnected && trigger !== document.body ? trigger : null
  if (captured && isVisible(captured)) {
    captured.focus?.()
    return
  }
  // The trigger is gone, or still mounted but no longer painted (the responsive
  // copy that display: none took away). A stable key re-finds the live one.
  const key = trigger?.dataset?.focusKey
  const candidates = key
    ? Array.from(document.querySelectorAll<HTMLElement>(`[data-focus-key="${CSS.escape(key)}"]`))
    : []
  const visible = candidates.find(isVisible)
  if (visible) {
    visible.focus()
    return
  }
  // Nothing confirmed visible — which is also every environment without layout,
  // so do not throw away a node we do have: the caller's own still-mounted
  // trigger beats a guess, and a re-rendered copy beats the page body.
  const fallback = captured ?? candidates[0]
  if (fallback) {
    fallback.focus?.()
    return
  }
  // No identifiable trigger left: park focus on the main landmark, the same
  // place a route change puts it, rather than dropping it on <body>.
  const main = document.getElementById('main-content') ?? document.querySelector('main')
  main?.focus?.()
}

/** An accessible modal dialog: focus trap, Escape to close, focus restoration. */
export function Modal({ open, onClose, title, children, footer, returnFocusRef }: ModalProps) {
  const dialogRef = useRef<HTMLDivElement>(null)
  const titleId = useId()

  useEffect(() => {
    if (!open) return
    const previouslyFocused =
      returnFocusRef?.current ?? (document.activeElement as HTMLElement | null)
    const dialog = dialogRef.current
    dialog?.focus()

    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
        return
      }
      if (e.key === 'Tab' && dialog) {
        const items = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE))
        if (items.length === 0) return
        const first = items[0]
        const last = items[items.length - 1]
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      restoreFocus(previouslyFocused)
    }
  }, [open, onClose, returnFocusRef])

  if (!open) return null

  return createPortal(
    <div className={styles.overlay} onMouseDown={onClose}>
      <div
        ref={dialogRef}
        className={styles.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onMouseDown={(e) => e.stopPropagation()}
      >
        {/* A div, not <header>: inside a dialog a header maps to a second
            banner landmark (axe landmark-no-duplicate-banner); the dialog is
            labeled via aria-labelledby. */}
        <div className={styles.header}>
          <h2 id={titleId} className={styles.title}>
            {title}
          </h2>
          <Button variant="ghost" size="sm" iconOnly onClick={onClose} aria-label="Close dialog">
            <Icon name="close" />
          </Button>
        </div>
        <div className={styles.body}>{children}</div>
        {footer ? <footer className={styles.footer}>{footer}</footer> : null}
      </div>
    </div>,
    document.body,
  )
}
