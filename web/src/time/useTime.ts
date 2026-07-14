// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useContext } from 'react'
import { TimeContext } from './context'

export function useTime() {
  const ctx = useContext(TimeContext)
  if (!ctx) throw new Error('useTime must be used inside TimeProvider')
  return ctx
}
