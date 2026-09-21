// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.
//
// Provider-plane data layer: the same react-query discipline the tenant app
// uses (caching, dedupe, deliberate retry policy) over the console's typed
// fetch helper. Hidden-unlicensed stays honest: a 404 surfaces as
// NotEnabledError and is never retried.

import { useQuery } from "@tanstack/react-query";

export class NotEnabledError extends Error {
  constructor() {
    super("provider plane not enabled");
  }
}

export class APIError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export async function api<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 404) throw new NotEnabledError();
  if (res.status === 429) {
    // UX-005: rate-limited — surface a clear retry hint rather than a bare
    // "HTTP 429". Honor Retry-After when the server sends it.
    const after = res.headers.get("Retry-After");
    const hint = after
      ? ` Retry after ${after}s.`
      : " Please wait a moment and try again.";
    throw new APIError("rate_limited", `Too many requests.${hint}`);
  }
  if (!res.ok) {
    const payload = (await res.json().catch(() => null)) as {
      error?: { message?: string; code?: string };
    } | null;
    throw new APIError(
      payload?.error?.code ?? "error",
      payload?.error?.message ?? `HTTP ${res.status}`,
    );
  }
  return (await res.json()) as T;
}

/** Cached provider-plane read. Not-enabled (404) and other failures are never
 * retried into a licensed-looking state; mutations keep calling `refetch()`. */
export function useProviderData<T>(key: string[], path: string) {
  return useQuery<T>({
    queryKey: ["provider", ...key],
    queryFn: () => api<T>("GET", path),
    retry: false,
    staleTime: 15_000,
  });
}
