// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
