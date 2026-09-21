// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactNode } from 'react'
import { useTime } from './useTime'
import styles from './DateTime.module.css'

export type DateTimeValue = string | number | Date | undefined | null

export function DateTime({
  value,
  empty = '—',
  className,
}: {
  value: DateTimeValue
  empty?: ReactNode
  className?: string
}) {
  const { format } = useTime()
  const formatted = format(value)
  if (!formatted.text) return <>{empty}</>
  const classes = [styles.time, className].filter(Boolean).join(' ')
  if (!formatted.valid) return <span className={classes}>{formatted.text}</span>
  return (
    <time
      className={classes}
      dateTime={formatted.dateTime}
      title={`${formatted.dateTime} (${formatted.timeZone})`}
    >
      {formatted.text}
    </time>
  )
}
