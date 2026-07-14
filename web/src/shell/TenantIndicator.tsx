import { useEffect, useRef, useState } from 'react'
import styles from './TenantIndicator.module.css'
import { useAuth } from '../auth/useAuth'
import { Icon } from '../components/Icon'

/**
 * The always-visible tenant indicator (PRD §6.2) — the operator can never lose
 * track of which tenant's data they are looking at. It doubles as a switcher.
 */
export function TenantIndicator() {
  const { tenant, tenants, switchTenant } = useAuth()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const canSwitch = tenants.length > 1

  useEffect(() => {
    if (!open) return
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div className={styles.wrap} ref={ref}>
      {canSwitch ? (
        <button
          type="button"
          className={styles.button}
          aria-label={`Switch tenant; current tenant ${tenant.name}`}
          aria-haspopup="menu"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
        >
          <TenantName name={tenant.name} />
          <Icon name="chevron" size={14} />
        </button>
      ) : (
        <div className={styles.indicator} aria-label={`Current tenant: ${tenant.name}`}>
          <TenantName name={tenant.name} />
        </div>
      )}
      {canSwitch && open ? (
        <div className={styles.menu} role="menu" aria-label="Switch tenant">
          {tenants.map((t) => (
            <button
              key={t.id}
              type="button"
              role="menuitemradio"
              aria-checked={t.id === tenant.id}
              className={styles.item}
              onClick={() => {
                switchTenant(t.id)
                setOpen(false)
              }}
            >
              <span>{t.name}</span>
              {t.id === tenant.id ? <Icon name="check" size={16} /> : null}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  )
}

function TenantName({ name }: { name: string }) {
  return (
    <>
      <span className={styles.dot} aria-hidden="true" />
      <span className={styles.meta}>
        <span className={styles.kicker}>Tenant</span>
        <span className={styles.name}>{name}</span>
      </span>
    </>
  )
}
