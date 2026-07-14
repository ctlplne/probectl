// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
