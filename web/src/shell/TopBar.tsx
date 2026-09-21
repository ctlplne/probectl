// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState } from 'react'
import styles from './TopBar.module.css'
import { TenantIndicator } from './TenantIndicator'
import { AuthorityBadge } from './AuthorityBadge'
import { useTheme } from '../theme/useTheme'
import { useAuth } from '../auth/useAuth'
import { Button } from '../components/Button'
import { Icon } from '../components/Icon'
import { TimeZoneToggle } from '../time/TimeZoneToggle'

function initials(name: string) {
  return name
    .split(' ')
    .map((p) => p[0])
    .slice(0, 2)
    .join('')
    .toUpperCase()
}

export function TopBar({
  onOpenPalette,
  onOpenNavigation,
  navigationOpen,
}: {
  onOpenPalette: () => void
  onOpenNavigation: () => void
  navigationOpen: boolean
}) {
  const { theme, toggleTheme } = useTheme()
  const { user, tenant, signOut } = useAuth()
  const [accountOpen, setAccountOpen] = useState(false)
  const accountRef = useRef<HTMLDivElement>(null)
  const accountButtonRef = useRef<HTMLButtonElement>(null)
  const signOutRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!accountOpen) return

    signOutRef.current?.focus()
    function onDocumentPointerDown(event: PointerEvent) {
      if (accountRef.current && !accountRef.current.contains(event.target as Node)) {
        setAccountOpen(false)
      }
    }
    function onDocumentKeyDown(event: KeyboardEvent) {
      if (event.key !== 'Escape') return
      setAccountOpen(false)
      accountButtonRef.current?.focus()
    }

    document.addEventListener('pointerdown', onDocumentPointerDown)
    document.addEventListener('keydown', onDocumentKeyDown)
    return () => {
      document.removeEventListener('pointerdown', onDocumentPointerDown)
      document.removeEventListener('keydown', onDocumentKeyDown)
    }
  }, [accountOpen])

  return (
    <header className={styles.topbar}>
      <div className={styles.left}>
        <button
          type="button"
          className={styles.menuButton}
          aria-label="Open navigation"
          aria-expanded={navigationOpen}
          aria-controls="mobile-primary-navigation"
          onClick={onOpenNavigation}
        >
          <Icon name="menu" size={18} />
        </button>
        <TenantIndicator />
        <AuthorityBadge />
      </div>

      <button
        type="button"
        className={styles.command}
        onClick={onOpenPalette}
        aria-label="Search or run a command"
        aria-keyshortcuts="Meta+K Control+K"
      >
        <Icon name="search" size={16} />
        <span className={styles.commandLabel}>Search or run a command</span>
        <kbd className={styles.kbd}>⌘K</kbd>
      </button>

      <div className={styles.right}>
        <TimeZoneToggle />
        <Button
          variant="ghost"
          size="sm"
          iconOnly
          aria-label={`Switch theme (current: ${theme})`}
          onClick={toggleTheme}
        >
          <Icon name={theme === 'light' ? 'moon' : 'sun'} />
        </Button>
        <div className={styles.account} ref={accountRef}>
          <button
            ref={accountButtonRef}
            type="button"
            className={styles.userButton}
            aria-label={`Open account menu for ${user.name}`}
            aria-haspopup="menu"
            aria-expanded={accountOpen}
            aria-controls="account-menu"
            onClick={() => setAccountOpen((open) => !open)}
          >
            <span aria-hidden="true">{initials(user.name)}</span>
          </button>
          {accountOpen ? (
            <div id="account-menu" className={styles.accountMenu} role="menu" aria-label="Account">
              <div className={styles.accountIdentity} role="presentation">
                <strong>{user.name}</strong>
                <span>{user.email}</span>
                <span className={styles.accountTenant}>Tenant · {tenant.name}</span>
              </div>
              <button
                ref={signOutRef}
                type="button"
                role="menuitem"
                className={styles.signOut}
                onClick={() => {
                  setAccountOpen(false)
                  signOut()
                }}
              >
                Sign out
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  )
}
