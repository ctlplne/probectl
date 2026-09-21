// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

/**
 * The probectl web API client (S8a contract). Every call targets the versioned
 * control-plane API (`/v1/...`) and relies on the session for identity — the
 * tenant is resolved server-side from the caller's auth (never spoofed by the
 * browser), matching the backend's tenant-first boundary. Requests are
 * same-origin; the API is HTTPS-by-default at the ingress.
 */
import {
  readResponseBytes,
  readResponseJSON,
  ResponseBodyTooLargeError,
  responseBodyLimit,
} from './response'

export const API_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? '/v1'

let demoTransportIsolated = false

/**
 * Demo mode is a product-wide transport boundary, not a per-chart badge. The
 * tenant shell sets this before mounting demo content. Keeping the final check
 * here means a future demo component cannot accidentally reach a live tenant
 * endpoint even if it bypasses the normal route boundary.
 */
export function setDemoTransportIsolation(active: boolean) {
  demoTransportIsolated = active
}

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
  if (demoTransportIsolated && path !== '/me') {
    throw new ApiError(403, 'Live tenant APIs are disabled while demo mode is active.')
  }
  const headers = new Headers(init?.headers)
  if (!headers.has('Accept')) headers.set('Accept', 'application/json')
  const res = await fetch(apiURL(path), {
    ...init,
    credentials: 'same-origin',
    headers,
  })
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`
    try {
      const body = await readResponseJSON<{ error?: { message?: string } }>(
        res,
        responseBodyLimit(res),
      )
      if (body?.error?.message) message = body.error.message
    } catch (err) {
      if (err instanceof ResponseBodyTooLargeError) message = err.message
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message)
  }
  if (res.status === 204) return undefined as T
  return readResponseJSON<T>(res, responseBodyLimit(res))
}

/** apiFetchBytes preserves a signed/content-addressed response byte-for-byte.
 * It uses the same same-origin, demo-isolation, error, and body-limit policy as
 * apiFetch; callers must not parse and reserialize an evidence package before
 * download because doing so would change the signed canonical bytes. */
export async function apiFetchBytes(path: string, init?: RequestInit): Promise<Uint8Array> {
  if (demoTransportIsolated && path !== '/me') {
    throw new ApiError(403, 'Live tenant APIs are disabled while demo mode is active.')
  }
  const headers = new Headers(init?.headers)
  if (!headers.has('Accept')) headers.set('Accept', 'application/octet-stream')
  const res = await fetch(apiURL(path), { ...init, credentials: 'same-origin', headers })
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`
    try {
      const body = await readResponseJSON<{ error?: { message?: string } }>(
        res,
        responseBodyLimit(res),
      )
      if (body?.error?.message) message = body.error.message
    } catch (err) {
      if (err instanceof ResponseBodyTooLargeError) message = err.message
    }
    throw new ApiError(res.status, message)
  }
  return readResponseBytes(res, responseBodyLimit(res))
}

/**
 * publicFetch targets a same-origin endpoint that is deliberately OUTSIDE the
 * versioned `/v1` API base — the pre-auth surfaces (`/branding`, `/auth/...`).
 * Centralizing them here keeps "off-/v1" a single, documented convention
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
export function redirectToLogin({ replace = false }: { replace?: boolean } = {}) {
  if (typeof window === 'undefined') return
  if (replace) {
    window.location.replace(LOGIN_PATH)
    return
  }
  window.location.assign(LOGIN_PATH)
}

/** True when an error is an ApiError carrying the given HTTP status. */
export function isApiStatus(err: unknown, status: number): boolean {
  return err instanceof ApiError && err.status === status
}
