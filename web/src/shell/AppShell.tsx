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
    if (firstRouteRender.current) {
      firstRouteRender.current = false
      return
    }
    if (skipNextRouteFocus.current) {
      skipNextRouteFocus.current = false
      return
    }
    mainRef.current?.focus()
  }, [location.key])

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
