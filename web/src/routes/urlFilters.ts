// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import type { SetURLSearchParams } from 'react-router-dom'

export type FilterDefaults = Record<string, string>

export function filterValue(params: URLSearchParams, key: string, fallback = ''): string {
  return params.get(key) ?? fallback
}

export function setURLFilters(
  params: URLSearchParams,
  setParams: SetURLSearchParams,
  defaults: FilterDefaults,
  patch: Record<string, string>,
) {
  const next = new URLSearchParams(params)
  for (const [key, value] of Object.entries({ ...defaults, ...patch })) {
    const v = value.trim()
    if (!v || v === defaults[key]) next.delete(key)
    else next.set(key, v)
  }
  setParams(next, { replace: true })
}

export function filtersForSave(
  params: URLSearchParams,
  defaults: FilterDefaults,
): Record<string, string> {
  const out: Record<string, string> = {}
  for (const key of Object.keys(defaults)) {
    const value = params.get(key) ?? defaults[key]
    if (value && value !== defaults[key]) out[key] = value
  }
  return out
}
