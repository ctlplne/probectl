/**
 * The probectl web API client (S8a contract). Every call targets the versioned
 * control-plane API (`/v1/...`) and relies on the session for identity — the
 * tenant is resolved server-side from the caller's auth (never spoofed by the
 * browser), matching the backend's tenant-first boundary. Requests are
 * same-origin; the API is HTTPS-by-default at the ingress.
 */
export const API_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? '/v1'

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: 'same-origin',
    headers: { Accept: 'application/json', ...(init?.headers ?? {}) },
    ...init,
  })
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`
    try {
      const body = (await res.json()) as { error?: { message?: string } }
      if (body?.error?.message) message = body.error.message
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}
