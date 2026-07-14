// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useCallback, useEffect, useRef, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import styles from './AppShell.module.css'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { CommandPalette } from './CommandPalette'
import { SkipLink } from './SkipLink'
import { MobileNavDrawer } from './MobileNavDrawer'

export function AppShell() {
  const location = useLocation()
  const mainRef = useRef<HTMLElement>(null)
  const firstRouteRender = useRef(true)
  const previousPathname = useRef(location.pathname)
  const skipNextRouteFocus = useRef(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const openPalette = useCallback(() => setPaletteOpen(true), [])
  const closePalette = useCallback(() => setPaletteOpen(false), [])
  const skipRouteFocusOnce = useCallback(() => {
    skipNextRouteFocus.current = true
  }, [])
  const openMobileNav = useCallback(() => setMobileNavOpen(true), [])
  const closeMobileNav = useCallback(() => setMobileNavOpen(false), [])

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen((o) => !o)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    const pathnameChanged = previousPathname.current !== location.pathname
    previousPathname.current = location.pathname
    if (firstRouteRender.current) {
      firstRouteRender.current = false
      return
    }
    // Query-string changes are in-page context/filter/history updates. Moving
    // focus to <main> here would steal it from the selected evidence or entity.
    if (!pathnameChanged) return
    if (skipNextRouteFocus.current) {
      skipNextRouteFocus.current = false
      return
    }
    mainRef.current?.focus()
  }, [location.key, location.pathname])

  return (
    <div className={styles.shell}>
      <SkipLink />
      <Sidebar />
      <TopBar
        onOpenPalette={openPalette}
        onOpenNavigation={openMobileNav}
        navigationOpen={mobileNavOpen}
      />
      <main id="main-content" ref={mainRef} className={styles.main} tabIndex={0}>
        <div className={styles.content}>
          <Outlet />
        </div>
      </main>
      <MobileNavDrawer open={mobileNavOpen} onClose={closeMobileNav} />
      <CommandPalette
        open={paletteOpen}
        onClose={closePalette}
        onRouteCommand={skipRouteFocusOnce}
      />
    </div>
  )
}
