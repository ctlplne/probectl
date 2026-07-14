// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, apiFetch } from './client'

/** Per-tenant key isolation / BYOK (S-T6, ee-backed). The API serves key
 *  chain STATE only — material never crosses. A 404 means the byok feature
 *  is not licensed (hidden-unlicensed): the card simply does not render. */

export interface KeyInfo {
  version: number
  mode: string // managed | byok
  state: string // active | retired | destroyed
  created_at: string
  retired_at?: string
  destroyed_at?: string
}

export function useKeys() {
  return useQuery({
    queryKey: ['security-keys'],
    queryFn: () => apiFetch<{ items: KeyInfo[] }>('/security/keys').then((r) => r.items),
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
