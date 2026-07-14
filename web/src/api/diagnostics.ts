// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * The supportability API (S-EE4). Deep health reports per-component status
 * aggregated to the worst; the support bundle (downloaded directly) is
 * secret-stripped — it never contains credentials or PII.
 */

export type HealthStatus = 'ok' | 'degraded' | 'down'

export interface HealthCheck {
  name: string
  status: HealthStatus
  detail?: string
}

export interface DeepHealth {
  status: HealthStatus
  checks: HealthCheck[]
  checked_at: string
}

export function useDiagnostics() {
  return useQuery({
    queryKey: ['diagnostics'],
    queryFn: () => apiFetch<DeepHealth>('/diagnostics'),
  })
}
