import { useEffect, useId, useRef } from 'react'
import { createPortal } from 'react-dom'
import { NavLink } from 'react-router-dom'
import styles from './MobileNavDrawer.module.css'
import { Button } from '../components/Button'
import { Icon } from '../components/Icon'
import { NAV, NAV_GROUPS } from '../nav/ia'
import { useI18n } from '../i18n/useI18n'

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])'

export function MobileNavDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const drawerRef = useRef<HTMLDivElement>(null)
  const titleId = useId()
  const { t } = useI18n()

  useEffect(() => {
    if (!open) return
    const previouslyFocused = document.activeElement as HTMLElement | null
    const drawer = drawerRef.current
    const firstLink = drawer?.querySelector<HTMLElement>('a[href]')
    firstLink?.focus()

    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
        return
      }
      if (e.key !== 'Tab' || !drawer) return
      const items = Array.from(drawer.querySelectorAll<HTMLElement>(FOCUSABLE))
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

    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      previouslyFocused?.focus?.()
    }
  }, [open, onClose])

  if (!open) return null

  return createPortal(
    <div className={styles.overlay} onMouseDown={onClose}>
      <div
        ref={drawerRef}
        id="mobile-primary-navigation"
        className={styles.drawer}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className={styles.header}>
          <h2 id={titleId} className={styles.title}>
            Navigation
          </h2>
          <Button variant="ghost" size="sm" iconOnly onClick={onClose} aria-label="Close navigation">
            <Icon name="close" />
          </Button>
        </div>
        <nav className={styles.nav} aria-label="Mobile primary">
          {NAV_GROUPS.map((group) => {
            const items = NAV.filter((item) => item.group === group.id)
            if (items.length === 0) return null
            return (
              <div key={group.id} className={styles.group}>
                <p className={styles.groupLabel}>{t(group.labelKey)}</p>
                <ul className={styles.list} role="list">
                  {items.map((item) => (
                    <li key={item.to}>
                      <NavLink
                        to={item.to}
                        className={({ isActive }) =>
                          [styles.link, isActive ? styles.active : ''].join(' ')
                        }
                        onClick={onClose}
                      >
                        {({ isActive }) => (
                          <>
                            <span className={styles.icon} aria-hidden="true">
                              <Icon name={item.icon} />
                            </span>
                            <span>{t(item.labelKey)}</span>
                            {isActive ? <span className="sr-only">{t('nav.current')}</span> : null}
                          </>
                        )}
                      </NavLink>
                    </li>
                  ))}
                </ul>
              </div>
            )
          })}
        </nav>
      </div>
    </div>,
    document.body,
  )
}
