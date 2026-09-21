// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useId, type SelectHTMLAttributes } from 'react'
import { cn } from '../lib/cn'
import { controlInput, controlShell, fieldLabel } from './controlStyles'

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label: string
  options: { value: string; label: string }[]
}

/** Select is a labeled native select, sharing Field's control shell so the two
 *  line up in a row. Native keeps the platform's keyboard and screen-reader
 *  behaviour, which no custom listbox has matched. */
export function Select({ label, options, id, className, ...rest }: SelectProps) {
  const reactId = useId()
  const selectId = id ?? reactId
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      <label className={fieldLabel} htmlFor={selectId}>
        {label}
      </label>
      <div className={cn(controlShell, 'border-border')}>
        <select id={selectId} className={cn(controlInput, 'cursor-pointer')} {...rest}>
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>
    </div>
  )
}
