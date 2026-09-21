// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { Severity } from './incidents'
import { formatPercentValue } from '../i18n/number'

/**
 * The threat-detection triage API (surface: S-FE3, fed by S28 IOC matches and
 * later S42 NDR detections). A Detection is a confidence-scored SIGNAL with
 * verbatim source attribution — probectl never blocks, and feeds can list
 * benign infrastructure, so the surface renders provenance honestly.
 */

export interface Detection {
  id: string
  kind: string
  plane: string
  severity: Severity
  /** Threat confidence in percentage points from 0 through 100. */
  confidence?: number
  source?: string
  category?: string
  type?: string
  license?: string
  indicator?: string
  entity: string
  title: string
  summary?: string
  incident_id?: string
  observed_at: string
}

/** Render the threat contract's percentage-point value without accidentally
 * treating it as a 0..1 ratio. Older servers may omit confidence, so keep that
 * state explicit instead of turning it into zero. */
export function formatThreatConfidence(confidence: number | undefined, locale: string): string {
  return confidence === undefined
    ? 'n/a'
    : formatPercentValue(confidence, locale, { maximumFractionDigits: 0 })
}

interface DetectionsResponse {
  items: Detection[]
  detections_running: boolean
}

export interface SourceAUP {
  license: string
  url: string
  attribution: string
  commercial_use: string
  redistribution: string
}

export interface OpenDataSourceStatus {
  name: string
  kind: string
  cadence_seconds: number
  aup: SourceAUP
  enabled: boolean
  status: string
  last_success: string
  last_error: string
}

export interface ThreatIntelFeedStatus extends OpenDataSourceStatus {
  ioc_count: number
}

export interface ThreatIntelStatusResponse {
  open_data_enabled: boolean
  threat_intel_enabled: boolean
  ioc_count: number
  open_data_sources: OpenDataSourceStatus[]
  threat_intel_feeds: ThreatIntelFeedStatus[]
}

/** useDetections polls the tenant's recent detections (15s cadence). */
export function useDetections() {
  return useQuery({
    queryKey: ['threat', 'detections'],
    queryFn: () => apiFetch<DetectionsResponse>('/threat/detections'),
    refetchInterval: 15_000,
  })
}

/** ThreatRule is one live NDR detection rule: the embedded default merged with
 *  the operator's detection-as-code overlay (DPR-075). */
export interface ThreatRule {
  id: string
  version: number
  kind: string
  name: string
  description?: string
  severity: string
  base_confidence: number
  suppress: string
  enabled: boolean
  thresholds?: Record<string, number>
  lists?: Record<string, string[]>
}

export interface ThreatRulesResponse {
  rules_running: boolean
  overlay_dir: string
  rules: ThreatRule[]
}

/** useThreatRules reads the live rule set — the answer to "which detections
 *  are in force, at which thresholds" without reading a startup log. */
export function useThreatRules() {
  return useQuery({
    queryKey: ['threat', 'rules'],
    queryFn: () => apiFetch<ThreatRulesResponse>('/threat/rules'),
    staleTime: 60_000,
  })
}

/** useThreatIntelStatus polls the shared feed AUP + last-good health matrix. */
export function useThreatIntelStatus() {
  return useQuery({
    queryKey: ['threat', 'intel-status'],
    queryFn: () => apiFetch<ThreatIntelStatusResponse>('/threat/intel/status'),
    refetchInterval: 60_000,
  })
}
