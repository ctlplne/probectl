// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useId, type TextareaHTMLAttributes, type ReactNode } from 'react'
import { cn } from '../lib/cn'
import { controlInput, controlShell, fieldLabel } from './controlStyles'

export interface TextAreaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label: string
  hint?: ReactNode
  error?: string
}

export function TextArea({ label, hint, error, id, className, ...rest }: TextAreaProps) {
  const generated = useId()
  const inputID = id ?? generated
  const describedBy =
    [hint && !error ? `${inputID}-hint` : '', error ? `${inputID}-error` : '']
      .filter(Boolean)
      .join(' ') || undefined
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      <label htmlFor={inputID} className={fieldLabel}>
        {label}
      </label>
      <div
        className={cn(
          controlShell,
          'h-auto items-start',
          error ? 'border-destructive' : 'border-border',
        )}
      >
        <textarea
          id={inputID}
          className={cn(controlInput, 'resize-y')}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          {...rest}
        />
      </div>
      {hint && !error ? (
        <p id={`${inputID}-hint`} className="text-caption text-muted-foreground">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={`${inputID}-error`} className="text-caption text-destructive" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  )
}
