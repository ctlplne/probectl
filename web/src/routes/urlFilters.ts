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
