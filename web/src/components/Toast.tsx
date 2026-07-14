// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react'
import styles from './Toast.module.css'
import { Icon, type IconName } from './Icon'

export type ToastTone = 'info' | 'success' | 'warning' | 'danger'

interface Toast {
  id: number
  tone: ToastTone
  title: string
  message?: string
}

interface ToastContextValue {
  push: (toast: Omit<Toast, 'id'>) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

const toneIcon: Record<ToastTone, IconName> = {
  info: 'info',
  success: 'check',
  warning: 'alert',
  danger: 'alert',
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const idRef = useRef(0)

  const push = useCallback((toast: Omit<Toast, 'id'>) => {
    const id = ++idRef.current
    setToasts((cur) => [...cur, { ...toast, id }])
    window.setTimeout(() => setToasts((cur) => cur.filter((t) => t.id !== id)), 4500)
  }, [])

  return (
    <ToastContext.Provider value={{ push }}>
      {children}
      <div className={styles.viewport} role="region" aria-label="Notifications">
        {toasts.map((t) => (
          <div key={t.id} className={[styles.toast, styles[t.tone]].join(' ')} role="status">
            <Icon name={toneIcon[t.tone]} />
            <div>
              <strong className={styles.title}>{t.title}</strong>
              {t.message ? <p className={styles.message}>{t.message}</p> : null}
            </div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return ctx
}
