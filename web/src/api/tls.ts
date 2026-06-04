import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * The S27 TLS/cert posture API (surface: S-FE2). The inventory is the latest
 * analyzed posture per target — leaf certificate, protocol/cipher, weakness/
 * CT/threat-intel findings, and the VERBATIM certctl handoff payload (the UI
 * forwards it as-is, never re-derives it).
 */

export interface TLSCertificate {
  subject: string
  issuer: string
  sans?: string[]
  serial_number: string
  not_before: string
  not_after: string
  key_type: string
  key_bits: number
  signature_algorithm: string
  self_signed: boolean
  is_ca: boolean
}

export interface TLSFinding {
  kind: string
  severity: 'info' | 'warning' | 'critical'
  message: string
  source?: string
  confidence?: number
  indicator?: string
}

export interface CertctlHandoff {
  target: string
  subject: string
  issuer: string
  sans?: string[]
  serial: string
  not_after: string
  reason: string
  url?: string
}

export interface TLSPosture {
  target: string
  source: string
  tls_version: string
  cipher: string
  leaf?: TLSCertificate
  findings: TLSFinding[] | null
  severity: 'info' | 'warning' | 'critical'
  handoff?: CertctlHandoff
  observed_at: string
}

interface PostureResponse {
  items: TLSPosture[]
  collector_running: boolean
}

/** useTLSPosture polls the tenant's certificate inventory (30s cadence). */
export function useTLSPosture() {
  return useQuery({
    queryKey: ['tls', 'posture'],
    queryFn: () => apiFetch<PostureResponse>('/tls/posture'),
    refetchInterval: 30_000,
  })
}

/** daysUntil returns whole days from now until iso (negative = past). */
export function daysUntil(iso: string): number {
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return NaN
  return Math.floor((t - Date.now()) / 86_400_000)
}

/** findingLabel renders a finding kind as a short human label. */
export function findingLabel(kind: string): string {
  const labels: Record<string, string> = {
    cert_expired: 'expired',
    cert_expiring_soon: 'expiring soon',
    cert_not_yet_valid: 'not yet valid',
    cert_self_signed: 'self-signed',
    weak_key: 'weak key',
    untrusted_chain: 'untrusted chain',
    deprecated_protocol: 'deprecated TLS',
    weak_cipher: 'weak cipher',
    ct_not_logged: 'CT anomaly',
    malicious_cert: 'intel: cert',
    malicious_ja3: 'intel: JA3',
  }
  return labels[kind] ?? kind
}
