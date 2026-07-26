// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useEffect, useMemo, useRef, useState, useId, type KeyboardEvent } from 'react'
import { createPortal } from 'react-dom'
import { useLocation, useNavigate } from 'react-router-dom'
import styles from './CommandPalette.module.css'
import { NAV } from '../nav/ia'
import { useTheme } from '../theme/useTheme'
import { useAuth } from '../auth/useAuth'
import { Icon, type IconName } from '../components/Icon'
import { useI18n } from '../i18n/useI18n'
import { parsePivotContext, pivotHref } from '../routes/pivotContext'
import {
  JOURNEY_PALETTE_COMMANDS,
  journeyCommandHref,
  type JourneyAvailability,
} from './journeyCommands'
import { useDemoMode } from '../demo/useDemoMode'

interface Command {
  id: string
  label: string
  hint: string
  icon: IconName
  changesRoute?: boolean
  disabledReason?: string
  tag?: string
  run: () => void
}

const PIVOT_ROUTES = new Set([
  '/alerts',
  '/ask',
  '/explore',
  '/incidents',
  '/path',
  '/planes',
  '/security',
  '/topology',
])

function isExplicitlyReadOnly(permissions: string[]) {
  return (
    permissions.length > 0 &&
    permissions.every(
      (permission) =>
        permission.endsWith('.read') ||
        permission === 'audit.read' ||
        permission === 'diagnostics.read' ||
        permission === 'lifecycle.export',
    )
  )
}

/**
 * The command palette (⌘K) — the keyboard-first spine of the app. It is a
 * combobox: focus stays in the input, options are tracked with
 * aria-activedescendant, arrows move, Enter runs, Escape closes.
 */
export function CommandPalette({
  open,
  onClose,
  onRouteCommand,
}: {
  open: boolean
  onClose: () => void
  onRouteCommand?: () => void
}) {
  const navigate = useNavigate()
  const location = useLocation()
  const { setTheme, themes } = useTheme()
  const { permissions, tenant: activeTenant, tenants, switchTenant } = useAuth()
  const { t } = useI18n()
  const { active: demoMode, exit: exitDemoMode } = useDemoMode()
  const inputRef = useRef<HTMLInputElement>(null)
  const dialogRef = useRef<HTMLDivElement>(null)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const listId = useId()

  const commands = useMemo<Command[]>(() => {
    const currentParams = new URLSearchParams(location.search)
    const parsedPivot = parsePivotContext(currentParams)
    const currentContext = {
      ...parsedPivot.context,
      returnTo: `${location.pathname}${location.search}${location.hash}`,
    }
    const readOnly = isExplicitlyReadOnly(permissions)
    const disabledFor = (availability: JourneyAvailability) => {
      if (availability === 'incident-open' && location.pathname !== '/incidents')
        return t('command.unavailable.incident')
      if (availability === 'path-open' && location.pathname !== '/path')
        return t('command.unavailable.path')
      if (
        availability === 'topology-selected' &&
        (location.pathname !== '/topology' || parsedPivot.context.selection?.kind !== 'entity')
      )
        return t('command.unavailable.topologySelection')
      return undefined
    }
    const journey = JOURNEY_PALETTE_COMMANDS.map<Command>((spec) => {
      const disabledReason =
        spec.requiresWrite && readOnly
          ? t('command.unavailable.readOnly')
          : disabledFor(spec.availability)
      return {
        id: spec.id,
        label: t(spec.labelKey),
        hint: t(spec.hintKey),
        icon: spec.icon,
        changesRoute: true,
        disabledReason,
        tag: spec.journey,
        run: () =>
          void navigate(
            journeyCommandHref(spec, `${location.pathname}${location.search}${location.hash}`),
          ),
      }
    })
    const task: Command[] = [
      {
        id: 'task:create-test',
        label: t('command.task.createTest'),
        hint: t('command.task.createTestHint'),
        icon: 'targets',
        changesRoute: true,
        disabledReason: readOnly ? t('command.unavailable.readOnly') : undefined,
        run: () => void navigate('/targets?create=test'),
      },
      {
        id: 'task:discover-path',
        label: t('command.task.discoverPath'),
        hint: t('command.task.discoverPathHint'),
        icon: 'path',
        changesRoute: true,
        disabledReason: readOnly ? t('command.unavailable.readOnly') : undefined,
        run: () => void navigate(pivotHref('/path', currentContext, { task: 'discover-path' })),
      },
      {
        id: 'task:silence-alert',
        label: t('command.task.silenceAlert'),
        hint: t('command.task.silenceAlertHint'),
        icon: 'alert',
        changesRoute: true,
        disabledReason: readOnly ? t('command.unavailable.readOnly') : undefined,
        run: () => void navigate('/alerts?alert_state=firing&task=silence-alert'),
      },
      {
        id: 'task:schedule-maintenance',
        label: t('command.task.scheduleMaintenance'),
        hint: t('command.task.scheduleMaintenanceHint'),
        icon: 'alert',
        changesRoute: true,
        disabledReason: readOnly ? t('command.unavailable.readOnly') : undefined,
        run: () => void navigate('/alerts?task=schedule-maintenance'),
      },
      {
        id: 'task:export-audit',
        label: t('command.task.exportAudit'),
        hint: t('command.task.exportAuditHint'),
        icon: 'compliance',
        changesRoute: true,
        disabledReason:
          permissions.length > 0 && !permissions.includes('audit.read')
            ? t('command.unavailable.audit')
            : undefined,
        run: () => void navigate('/audit?task=export-audit'),
      },
      {
        id: 'task:open-support-bundle',
        label: t('command.task.openSupportBundle'),
        hint: t('command.task.openSupportBundleHint'),
        icon: 'admin',
        changesRoute: true,
        disabledReason: readOnly ? t('command.unavailable.readOnly') : undefined,
        run: () => void navigate('/admin#support-bundle'),
      },
      {
        id: 'task:register-collector',
        label: t('command.task.registerCollector'),
        hint: t('command.task.registerCollectorHint'),
        icon: 'admin',
        changesRoute: true,
        run: () => void navigate('/admin?register_collector=flow'),
      },
    ]
    const go = NAV.map<Command>((n) => ({
      id: `go:${n.to}`,
      label: t('command.goTo', { label: t(n.labelKey) }),
      hint: t('command.navigate'),
      icon: n.icon,
      changesRoute: true,
      run: () =>
        void navigate(
          parsedPivot.hasContract && PIVOT_ROUTES.has(n.to)
            ? pivotHref(n.to, currentContext)
            : n.to,
        ),
    }))
    const theme = themes.map<Command>((themeName) => ({
      id: `theme:${themeName}`,
      label: t('command.theme', { theme: themeName }),
      hint: t('command.appearance'),
      icon: themeName === 'aurora' ? 'sun' : 'moon',
      run: () => setTheme(themeName),
    }))
    const tenant =
      tenants.length > 1
        ? tenants.map<Command>((tenant) => ({
            id: `tenant:${tenant.id}`,
            label: t('command.switchTenant', { tenant: tenant.name }),
            hint: t('command.tenant'),
            icon: 'targets',
            changesRoute: true,
            run: () => {
              // Clear every object/action-bearing URL before the provider-owned
              // tenant switch can update credentials. This prevents a render in
              // the new tenant from replaying the old tenant's selected object.
              void navigate('/onboarding', { replace: true })
              switchTenant(tenant.id)
            },
          }))
        : []
    const demo: Command[] = demoMode
      ? [
          {
            id: 'demo:exit',
            label: 'Exit demo mode',
            hint: 'Return to live tenant data · Shift+D',
            icon: 'dashboards',
            run: exitDemoMode,
          },
        ]
      : []
    return [...demo, ...journey, ...task, ...go, ...theme, ...tenant]
  }, [
    demoMode,
    exitDemoMode,
    location,
    navigate,
    permissions,
    setTheme,
    t,
    themes,
    tenants,
    switchTenant,
  ])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return q ? commands.filter((c) => c.label.toLowerCase().includes(q)) : commands
  }, [commands, query])

  useEffect(() => {
    setActive(0)
  }, [query, open])

  useEffect(() => {
    if (!open) return
    const prev = document.activeElement as HTMLElement | null
    inputRef.current?.focus()
    return () => prev?.focus?.()
  }, [open])

  useEffect(() => {
    // Defense in depth for tenant switches initiated outside this palette. The
    // explicit switch commands navigate first; this catches future switchers
    // and clears palette state when the authenticated tenant identity changes.
    setQuery('')
    setActive(0)
  }, [activeTenant.id])

  if (!open) return null

  function run(cmd?: Command) {
    if (!cmd || cmd.disabledReason) return
    if (cmd.changesRoute) onRouteCommand?.()
    cmd.run()
    setQuery('')
    onClose()
  }

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((i) => (filtered.length ? Math.min(i + 1, filtered.length - 1) : 0))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((i) => Math.max(i - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      run(filtered[active])
    }
  }

  function onDialogKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Escape') {
      e.preventDefault()
      e.stopPropagation()
      onClose()
    } else if (e.key === 'Tab') {
      // The combobox owns option focus through aria-activedescendant, so the
      // input is intentionally the dialog's only tab stop.
      e.preventDefault()
      inputRef.current?.focus()
    }
  }

  const activeOptionId = filtered[active] ? `${listId}-${filtered[active].id}` : undefined

  return createPortal(
    <div className={styles.overlay} onMouseDown={onClose}>
      <div
        ref={dialogRef}
        className={styles.palette}
        role="dialog"
        aria-modal="true"
        aria-label={t('command.palette')}
        onKeyDown={onDialogKeyDown}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className={styles.search}>
          <Icon name="search" />
          <input
            ref={inputRef}
            className={styles.input}
            type="text"
            placeholder={t('command.searchPlaceholder')}
            aria-label={t('command.search')}
            role="combobox"
            aria-expanded={true}
            aria-controls={listId}
            aria-activedescendant={activeOptionId}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
          />
          <kbd className={styles.kbd}>Esc</kbd>
        </div>
        <ul className={styles.list} role="listbox" id={listId} aria-label={t('command.commands')}>
          {filtered.length === 0 ? (
            <li className={styles.none}>{t('command.empty')}</li>
          ) : (
            filtered.map((c, i) => (
              <li
                key={c.id}
                id={`${listId}-${c.id}`}
                role="option"
                aria-selected={i === active}
                aria-disabled={c.disabledReason ? 'true' : undefined}
                className={[
                  styles.item,
                  i === active ? styles.active : '',
                  c.disabledReason ? styles.disabled : '',
                ].join(' ')}
                onMouseEnter={() => setActive(i)}
                onMouseDown={(e) => {
                  e.preventDefault()
                  run(c)
                }}
              >
                <Icon name={c.icon} />
                <span className={styles.label}>{c.label}</span>
                {c.tag ? <kbd className={styles.kbd}>{c.tag}</kbd> : null}
                <span className={styles.hint}>
                  {c.hint}
                  {c.disabledReason ? ` · ${c.disabledReason}` : ''}
                </span>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>,
    document.body,
  )
}
