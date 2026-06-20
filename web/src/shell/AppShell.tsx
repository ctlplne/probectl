import { useCallback, useEffect, useState } from 'react'
import { Outlet } from 'react-router-dom'
import styles from './AppShell.module.css'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { CommandPalette } from './CommandPalette'
import { SkipLink } from './SkipLink'

export function AppShell() {
  const [paletteOpen, setPaletteOpen] = useState(false)
  const openPalette = useCallback(() => setPaletteOpen(true), [])
  const closePalette = useCallback(() => setPaletteOpen(false), [])

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

  return (
    <div className={styles.shell}>
      <SkipLink />
      <Sidebar />
      <TopBar onOpenPalette={openPalette} />
      <main id="main-content" className={styles.main} tabIndex={0}>
        <div className={styles.content}>
          <Outlet />
        </div>
      </main>
      <CommandPalette open={paletteOpen} onClose={closePalette} />
    </div>
  )
}
