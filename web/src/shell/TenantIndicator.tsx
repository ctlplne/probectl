// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import styles from './TenantIndicator.module.css'
import { useAuth } from '../auth/useAuth'
import { Icon } from '../components/Icon'

/**
 * The always-visible tenant indicator (PRD §6.2) — the operator can never lose
 * track of which tenant's data they are looking at. It doubles as a switcher.
 */
export function TenantIndicator() {
  const navigate = useNavigate()
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
                if (t.id === tenant.id) {
                  setOpen(false)
                  return
                }
                // Neutralize all tenant-owned object references and pending
                // task parameters before provider code switches credentials.
                // The new tenant therefore cannot replay an old-tenant action.
                void navigate('/onboarding', { replace: true })
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
