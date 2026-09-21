// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useId, type InputHTMLAttributes, type ReactNode } from 'react'
import { cn } from '../lib/cn'
import { controlInput, controlShell, fieldLabel } from './controlStyles'

export interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string
  hint?: ReactNode
  error?: string
  leading?: ReactNode
}

/** Field is a labeled text input with hint/error wiring (WCAG-correct). */
export function Field({ label, hint, error, leading, id, className, ...rest }: FieldProps) {
  const reactId = useId()
  const inputId = id ?? reactId
  const hintId = `${inputId}-hint`
  const errId = `${inputId}-err`
  const describedBy =
    [hint ? hintId : null, error ? errId : null].filter(Boolean).join(' ') || undefined

  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      <label className={fieldLabel} htmlFor={inputId}>
        {label}
      </label>
      <div className={cn(controlShell, error ? 'border-destructive' : 'border-border')}>
        {leading ? <span className="shrink-0 text-muted-foreground">{leading}</span> : null}
        <input
          id={inputId}
          className={controlInput}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          {...rest}
        />
      </div>
      {hint && !error ? (
        <p id={hintId} className="text-caption text-muted-foreground">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={errId} className="text-caption text-destructive" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  )
}
