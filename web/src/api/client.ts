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

export function apiURL(path: string): string {
  if (path.startsWith('/v1/') || path === '/v1') {
    throw new Error(
      `API path must be relative to API_BASE (got ${path}); drop the /v1 prefix — API_BASE already provides it (UX-001/UX-006)`,
    )
  }
  return `${API_BASE}${path}`
}

/**
 * apiFetch targets the versioned API. The `path` is RELATIVE to API_BASE and
 * must NOT itself carry the `/v1` prefix — passing `/v1/...` here produces a
 * `/v1/v1/...` double-prefix (UX-001/UX-006). The check below fails loudly in
 * dev/test; the ban-/v1-literal lint rule (eslint no-restricted-syntax) and the
 * client unit test enforce it at build time too.
 */
export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(apiURL(path), {
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

/**
 * publicFetch targets a same-origin endpoint that is deliberately OUTSIDE the
 * versioned `/v1` API base — the pre-auth surfaces (`/branding`, `/auth/...`).
 * Centralising them here keeps "off-/v1" a single, documented convention
 * instead of scattered raw `fetch()` calls (UX-006). It does NOT auto-prepend
 * a base, so callers pass an absolute same-origin path (e.g. `/branding`).
 */
export async function publicFetch(path: string, init?: RequestInit): Promise<Response> {
  return fetch(path, { credentials: 'same-origin', ...init })
}

/** The pre-auth SSO login entry point (outside the /v1 base). */
export const LOGIN_PATH = '/auth/login'

/**
 * redirectToLogin sends the browser to the SSO login. Used both by the initial
 * auth bootstrap and by the global TanStack Query onError handler so that a
 * session that expires MID-SESSION (a later 401, not just the first /me call)
 * also re-authenticates instead of surfacing a dead per-query error (UX-005).
 */
export function redirectToLogin() {
  if (typeof window !== 'undefined') window.location.assign(LOGIN_PATH)
}

/** True when an error is an ApiError carrying the given HTTP status. */
export function isApiStatus(err: unknown, status: number): boolean {
  return err instanceof ApiError && err.status === status
}
