// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useContext } from 'react'
import { TimeContext } from './context'

export function useTime() {
  const ctx = useContext(TimeContext)
  if (!ctx) throw new Error('useTime must be used inside TimeProvider')
  return ctx
}
