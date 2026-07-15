// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { ApiError } from '../api/client'

export type HonestDataStateKind =
  | 'ready-no-data'
  | 'blocked'
  | 'permission-denied'
  | 'degraded'
  | 'quiet'
  | 'demo'

export interface SurfaceTruth {
  /** True only when the whole product is in the isolated demo workspace. */
  demo?: boolean
  /** The actual query error. A server 403 is permission-denied; other failures are degraded. */
  error?: unknown
  /** Server-reported producer/engine readiness. False is blocked, never a healthy zero. */
  producerRunning?: boolean
  /** Server-reported partial service or coverage. */
  degraded?: boolean
  /** Server-reported absence of events in the selected observation window. */
  quiet?: boolean
}

/**
 * Converts server truth to presentation truth. Priority matters: demo data must
 * never masquerade as live, a 403 must never masquerade as no data, and an
 * unavailable producer must never become a zero-valued chart.
 */
export function classifySurfaceTruth(truth: SurfaceTruth): HonestDataStateKind {
  if (truth.demo) return 'demo'
  if (truth.error instanceof ApiError && truth.error.status === 403) return 'permission-denied'
  if (truth.error || truth.degraded) return 'degraded'
  if (truth.producerRunning === false) return 'blocked'
  if (truth.quiet) return 'quiet'
  return 'ready-no-data'
}
