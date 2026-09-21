// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, apiFetch } from './client'
import type { TenantKeyInfo, TenantKeyList } from './sdk.gen'

/** Per-tenant key isolation / BYOK (S-T6, ee-backed). The API serves key
 *  chain STATE only — material never crosses. A 404 means the byok feature
 *  is not licensed (hidden-unlicensed): the card simply does not render. */

export type KeyInfo = TenantKeyInfo

export function useKeys() {
  return useQuery({
    queryKey: ['security-keys'],
    queryFn: () => apiFetch<TenantKeyList>('/security/keys').then((r) => r.items),
    retry: (count, err) => !(err instanceof ApiError && err.status === 404) && count < 2,
  })
}

export function useRotateKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: { mode: string; byok_ref?: string }) =>
      apiFetch<KeyInfo>('/security/keys/rotate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['security-keys'] }),
  })
}
