import styles from './TopBar.module.css'
import { TenantIndicator } from './TenantIndicator'
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
  const { user } = useAuth()

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
      </div>

      <button
        type="button"
        className={styles.command}
        onClick={onOpenPalette}
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
          <Icon name={theme === 'aurora' ? 'moon' : 'sun'} />
        </Button>
        <span className={styles.user} title={`${user.name} · ${user.email}`} aria-hidden="true">
          {initials(user.name)}
        </span>
      </div>
    </header>
  )
}
