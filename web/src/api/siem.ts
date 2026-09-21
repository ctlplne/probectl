// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * SIEM export posture (F26, surface S38). Read-only and deliberately
 * secret-free: the server returns booleans for "is an endpoint configured" and
 * "is a token configured" plus scheme-free `host:port` metadata, never the
 * endpoint path, query string, or the ingest token itself (§7 guardrail 6). The
 * card must therefore render CONFIGURED/NOT CONFIGURED, never a value.
 * Requires `threat.read`.
 */

export type SIEMReason =
  | 'disabled'
  | 'missing_endpoint'
  | 'insecure_endpoint'
  | 'invalid_format'
  | 'configured'

export type SIEMPreset = 'generic' | 'splunk' | 'sentinel' | 'elastic' | 'chronicle'

export type SIEMStream = 'audit' | 'threat'

export interface SIEMStatus {
  id: string
  name: string
  summary: string
  siem_running: boolean
  enabled: boolean
  configured: boolean
  reason?: SIEMReason
  preset: SIEMPreset
  /** Resolved format when valid; the raw configured value when reason=invalid_format. */
  format: string
  endpoint_configured: boolean
  endpoint_tls_configured: boolean
  /** Scheme-free host:port only. Absent when no endpoint is configured. */
  endpoint_host?: string
  token_configured: boolean
  audit_poll_interval: string
  buffer_size: number
  redact_key_count: number
  tls_required: boolean
  no_drop_delivery: boolean
  streams: SIEMStream[]
}

interface SIEMStatusWire extends Omit<SIEMStatus, 'streams'> {
  streams?: SIEMStream[] | null
}

/**
 * A missing `streams` is "no stream is forwarded", which is a posture the card
 * has to state out loud — not an empty render.
 */
export function normalizeSIEMStatus(wire: SIEMStatusWire): SIEMStatus {
  return { ...wire, streams: wire.streams ?? [] }
}

export function useSIEMStatus() {
  return useQuery({
    queryKey: ['siem', 'status'],
    queryFn: async () => normalizeSIEMStatus(await apiFetch<SIEMStatusWire>('/siem/status')),
  })
}
