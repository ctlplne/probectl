// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, type RefObject } from 'react'

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), summary, [tabindex]:not([tabindex="-1"])'

// Portals are siblings under body. Only the last painted dialog may receive
// input; preserve pre-existing inert attributes when dialogs open or close.
const dialogs = new Set<HTMLElement>()
const inertOriginals = new Map<HTMLElement, string | null>()
let topDialog: HTMLElement | undefined
let bodyObserver: MutationObserver | undefined

function lockOutside(surface: HTMLElement) {
  function refresh() {
    const painted = [...dialogs]
      .filter((node) => node.isConnected)
      .sort((a, b) => (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1))
    topDialog = painted[painted.length - 1]
    const outside = new Set(
      Array.from(document.body.children).filter(
        (node): node is HTMLElement =>
          node instanceof HTMLElement && !!topDialog && !node.contains(topDialog),
      ),
    )
    for (const [node, original] of inertOriginals) {
      if (outside.has(node)) continue
      if (original === null) node.removeAttribute('inert')
      else node.setAttribute('inert', original)
      inertOriginals.delete(node)
    }
    for (const node of outside) {
      if (!inertOriginals.has(node)) inertOriginals.set(node, node.getAttribute('inert'))
      node.setAttribute('inert', '')
    }
  }
  dialogs.add(surface)
  refresh()
  if (!bodyObserver) {
    bodyObserver = new MutationObserver(refresh)
    bodyObserver.observe(document.body, { childList: true })
  }
  return () => {
    dialogs.delete(surface)
    refresh()
    if (!dialogs.size) {
      bodyObserver?.disconnect()
      bodyObserver = undefined
    }
  }
}

// isVisible answers "would a browser paint this?" — checkVisibility where the
// engine has it, otherwise inspect ancestor styles (fixed controls can have a
// null offsetParent while still being visible).
function isVisible(el: HTMLElement): boolean {
  if (el.closest('[hidden], [inert], [aria-hidden="true"]')) return false
  const closed = el.closest('details:not([open])')
  if (closed && !closed.querySelector(':scope > summary')?.contains(el)) return false
  if (typeof el.checkVisibility === 'function' && !el.checkVisibility()) return false
  for (let node: HTMLElement | null = el; node; node = node.parentElement) {
    const style = getComputedStyle(node)
    if (style.display === 'none' || style.visibility === 'hidden') return false
  }
  return true
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

/**
 * useDialogFocus is the ONE implementation of the dialog focus contract: trap
 * Tab inside the surface, make the background inert, close on Escape, and
 * restore focus to the trigger on unmount. Modal and DetailDrawer both use it,
 * because a second copy is how one
 * of them silently loses WCAG 2.4.3 (DPR-167).
 */
export function useDialogFocus(
  open: boolean,
  onClose: () => void,
  returnFocusRef?: RefObject<HTMLElement | null>,
) {
  const surfaceRef = useRef<HTMLDivElement>(null)
  const onCloseRef = useRef(onClose)

  useEffect(() => {
    onCloseRef.current = onClose
  }, [onClose])

  useEffect(() => {
    if (!open) return
    const previouslyFocused =
      returnFocusRef?.current ?? (document.activeElement as HTMLElement | null)
    const surface = surfaceRef.current
    if (!surface) return
    const releaseOutside = lockOutside(surface)
    const active = () => topDialog === surface && surface.isConnected && !surface.closest('[inert]')
    const items = () =>
      Array.from(surface.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (item) => item.tabIndex >= 0 && isVisible(item),
      )

    const onFocusIn = (event: FocusEvent) => {
      if (!active() || surface.contains(event.target as Node)) return
      const destination = items()[0] ?? surface
      destination.focus()
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (!active()) return
      if (e.key === 'Escape') {
        e.preventDefault()
        onCloseRef.current()
        return
      }
      if (e.key === 'Tab') {
        const focusable = items()
        if (focusable.length === 0) {
          e.preventDefault()
          surface.focus()
          return
        }
        const first = focusable[0]
        const last = focusable[focusable.length - 1]
        if (document.activeElement === surface || !surface.contains(document.activeElement)) {
          e.preventDefault()
          const destination = e.shiftKey ? last : first
          destination.focus()
        } else if (e.shiftKey && document.activeElement === first) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }
    document.addEventListener('focusin', onFocusIn)
    document.addEventListener('keydown', onKeyDown)
    surface.focus()
    return () => {
      document.removeEventListener('focusin', onFocusIn)
      document.removeEventListener('keydown', onKeyDown)
      releaseOutside()
      restoreFocus(previouslyFocused)
    }
  }, [open, returnFocusRef])

  return surfaceRef
}
