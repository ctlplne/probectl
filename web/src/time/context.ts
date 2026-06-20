import { createContext } from 'react'
import type { FormattedDateTime, TimeMode } from './format'

export interface TimeContextValue {
  mode: TimeMode
  setMode: (mode: TimeMode) => void
  preferredTimeZone: string
  timeZone: string
  timeZoneLabel: string
  format: (value: string | number | Date | undefined | null) => FormattedDateTime
}

export const TimeContext = createContext<TimeContextValue | null>(null)
