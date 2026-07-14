// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { useAuth } from '../auth/useAuth'
import { useI18n } from '../i18n/useI18n'
import {
  UTC_TIME_ZONE,
  formatDateTime,
  resolveTimeZone,
  shortTimeZoneLabel,
  type TimeMode,
} from './format'
import { TimeContext, type TimeContextValue } from './context'

export function TimeProvider({ children }: { children: ReactNode }) {
  const { locale } = useI18n()
  const { tenant, user } = useAuth()
  const preferredTimeZone = resolveTimeZone(user.time_zone ?? tenant.time_zone)
  const defaultMode: TimeMode = preferredTimeZone === UTC_TIME_ZONE ? 'utc' : 'preferred'
  const [mode, setMode] = useState<TimeMode>(defaultMode)
  const timeZone = mode === 'utc' ? UTC_TIME_ZONE : preferredTimeZone

  const format = useCallback(
    (value: string | number | Date | undefined | null) =>
      formatDateTime(value, { locale, timeZone }),
    [locale, timeZone],
  )

  const value = useMemo<TimeContextValue>(
    () => ({
      mode,
      setMode,
      preferredTimeZone,
      timeZone,
      timeZoneLabel: shortTimeZoneLabel(timeZone),
      format,
    }),
    [format, mode, preferredTimeZone, timeZone],
  )

  return <TimeContext.Provider value={value}>{children}</TimeContext.Provider>
}
