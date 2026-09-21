// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { DeepHealth } from './sdk.gen'

export type {
  DeepHealth,
  HealthCheck,
  HealthStatus,
  ReadinessAction,
  ReadinessFinding,
  SelfMetricsSnapshot,
  Version,
} from './sdk.gen'

/**
 * The supportability API (S-EE4). Deep health reports per-component status
 * aggregated to the worst; the support bundle (downloaded directly) is
 * secret-stripped — it never contains credentials or PII.
 */

export function useDiagnostics() {
  return useQuery({
    queryKey: ['diagnostics'],
    queryFn: () => apiFetch<DeepHealth>('/diagnostics'),
  })
}
