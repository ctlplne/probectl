// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
