// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
  // A patch updates only its own controls; an empty patch explicitly clears
  // this surface's filters. Preserve whitespace while a controlled input is
  // being edited so typing the separator between two words is not discarded.
  for (const [key, value] of Object.entries(Object.keys(patch).length ? patch : defaults)) {
    if (!value || value === defaults[key]) next.delete(key)
    else next.set(key, value)
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
