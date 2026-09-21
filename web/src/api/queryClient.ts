// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { QueryCache, QueryClient, MutationCache } from '@tanstack/react-query'
import { isApiStatus, redirectToLogin } from './client'

/**
 * Server state lives in TanStack Query; component/UI state stays in React. This
 * is the data-fetching pattern every later screen follows: a typed apiFetch
 * wrapped in useQuery/useMutation. A factory keeps each app mount (and each test)
 * on an isolated cache.
 *
 * UX-005: a GLOBAL onError on both caches redirects to SSO on any 401 — so a
 * session that expires mid-session re-authenticates instead of leaving a dead
 * per-query error on screen. 429 (rate-limited) is surfaced, not redirected.
 */
export function onApiError(err: unknown) {
  if (isApiStatus(err, 401)) redirectToLogin()
}

export function makeQueryClient() {
  return new QueryClient({
    queryCache: new QueryCache({ onError: onApiError }),
    mutationCache: new MutationCache({ onError: onApiError }),
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        // Don't retry auth failures — a 401/403 won't fix itself on retry.
        retry: (failureCount, err) =>
          isApiStatus(err, 401) || isApiStatus(err, 403) ? false : failureCount < 1,
        refetchOnWindowFocus: false,
      },
    },
  })
}
