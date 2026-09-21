// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useId, type InputHTMLAttributes, type ReactNode } from 'react'
import styles from './Input.module.css'

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
    <div className={[styles.field, className].filter(Boolean).join(' ')}>
      <label className={styles.label} htmlFor={inputId}>
        {label}
      </label>
      <div className={[styles.control, error ? styles.invalid : ''].join(' ')}>
        {leading ? <span className={styles.leading}>{leading}</span> : null}
        <input
          id={inputId}
          className={styles.input}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          {...rest}
        />
      </div>
      {hint && !error ? (
        <p id={hintId} className={styles.hint}>
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={errId} className={styles.error} role="alert">
          {error}
        </p>
      ) : null}
    </div>
  )
}
