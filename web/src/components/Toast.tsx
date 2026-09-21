// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react'
import { cn } from '../lib/cn'
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
      <div
        className="pointer-events-none fixed inset-x-0 bottom-0 z-toast flex flex-col items-center gap-2 p-4"
        role="region"
        aria-label="Notifications"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            className={cn(
              'pointer-events-auto flex w-full max-w-md items-start gap-3 rounded-panel border bg-card',
              'px-4 py-3 shadow-elevation2 animate-panel-in',
              t.tone === 'success' && 'border-status-success/40 text-status-success',
              t.tone === 'warning' && 'border-status-warning/40 text-status-warning',
              t.tone === 'danger' && 'border-destructive/40 text-destructive',
              t.tone === 'info' && 'border-status-info/40 text-status-info',
            )}
            role="status"
          >
            <Icon name={toneIcon[t.tone]} />
            <div>
              <strong className="block text-data font-semibold text-card-foreground">
                {t.title}
              </strong>
              {t.message ? <p className="text-caption text-muted-foreground">{t.message}</p> : null}
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
