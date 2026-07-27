// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { DeepHealth } from './sdk.gen'

export type {
  DeepHealth,
  HealthCheck,
  HealthStatus,
  ReadinessAction,
  ReadinessFinding,
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
