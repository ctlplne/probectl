import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * The secret-backend health API (surface: S41). Operational state of the
 * credential-resolution backends (Vault / CyberArk / AWS / Azure / GCP / env):
 * counters, live lease counts, and the last REDACTED error. The payload never
 * contains secret material — the backend guarantees it and the test asserts it.
 * resolver_running=false means the control plane has no resolver wired (the
 * honesty flag), distinct from "configured but idle".
 */

export interface SecretBackendHealth {
  scheme: string
  configured: boolean
  resolves: number
  failures: number
  last_ok?: string
  last_error?: string
  last_error_at?: string
  cached_leases: number
}

export interface SecretsHealthResponse {
  resolver_running: boolean
  backends: SecretBackendHealth[]
}

export function useSecretsHealth() {
  return useQuery({
    queryKey: ['secrets-health'],
    queryFn: () => apiFetch<SecretsHealthResponse>('/v1/secrets/health'),
  })
}
