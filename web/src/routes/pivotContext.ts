// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

export const PIVOT_CONTEXT_VERSION = '1'
export const PIVOT_CONTEXT_TTL_MS = 30 * 60 * 1000

export type PivotSelection = { kind: 'evidence'; id: string } | { kind: 'entity'; id: string }

/**
 * Context that may cross observability surfaces.
 *
 * tenant_id is intentionally absent. The server session derives the tenant and
 * every destination re-authorizes incident/evidence/entity IDs against its
 * tenant-scoped response before using them.
 */
export interface PivotContext {
  incidentId?: string
  from?: string
  to?: string
  filters: Record<string, string>
  selection?: PivotSelection
  returnTo?: string
  expiresAt?: string
}

export interface ParsedPivotContext {
  context: PivotContext
  hasContract: boolean
  referencesValid: boolean
}

export type PivotReference =
  | { kind: 'incident'; id: string }
  | { kind: PivotSelection['kind']; id: string }

export interface ParsePivotContextOptions {
  now?: Date
  authorize?: (reference: PivotReference) => boolean
}

export type PlaneID = 'bgp' | 'flow' | 'device' | 'ebpf'

export const REGISTERED_PLANE_PATHS: Readonly<Record<PlaneID, string>> = {
  bgp: '/planes/bgp',
  flow: '/planes/flow',
  device: '/planes/device',
  ebpf: '/planes/ebpf',
}

const CONTRACT_KEYS = new Set([
  'ctx_v',
  'ctx_expires',
  'ctx_incident',
  'ctx_from',
  'ctx_to',
  'ctx_filter',
  'ctx_selected_kind',
  'ctx_selected_id',
  'ctx_return',
])
const FILTER_KEY = /^[a-z][a-z0-9_.-]{0,63}$/i
const MAX_FILTERS = 24
const MAX_VALUE_LENGTH = 512
const MAX_REFERENCE_LENGTH = 256
const SAFE_RETURN_PREFIXES = [
  '/ask',
  '/explore',
  '/incidents',
  '/path',
  '/planes',
  '/results',
  '/security',
  '/topology',
]

function normalizedAbsoluteTime(value: string | null | undefined): string | undefined {
  if (!value || value.length > 64 || !/^\d{4}-\d{2}-\d{2}T/.test(value)) return undefined
  const timestamp = Date.parse(value)
  if (!Number.isFinite(timestamp)) return undefined
  return new Date(timestamp).toISOString()
}

function safeReference(value: string | null | undefined): string | undefined {
  const candidate = value?.trim()
  if (!candidate || candidate.length > MAX_REFERENCE_LENGTH) return undefined
  if (
    Array.from(candidate).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0
      return codePoint < 32 || codePoint === 127
    })
  )
    return undefined
  return candidate
}

function isTenantKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '')
  return normalized === 'tenant' || normalized === 'tenantid'
}

function safeReturnLocation(value: string | null | undefined): string | undefined {
  if (!value || value.length > 2048 || !value.startsWith('/') || value.startsWith('//')) {
    return undefined
  }
  try {
    const url = new URL(value, 'https://probectl.invalid')
    if (url.origin !== 'https://probectl.invalid') return undefined
    if (
      !SAFE_RETURN_PREFIXES.some(
        (prefix) => url.pathname === prefix || url.pathname.startsWith(`${prefix}/`),
      )
    ) {
      return undefined
    }
    if (
      Array.from(url.searchParams.keys()).some((key) => isTenantKey(key) || key.startsWith('ctx_'))
    ) {
      return undefined
    }
    return `${url.pathname}${url.search}${url.hash}`
  } catch {
    return undefined
  }
}

function safeFilters(values: string[]): { filters: Record<string, string>; malformed: boolean } {
  const filters: Record<string, string> = {}
  let malformed = values.length > MAX_FILTERS
  for (const encoded of values.slice(0, MAX_FILTERS)) {
    const separator = encoded.indexOf(':')
    if (separator < 1) {
      malformed = true
      continue
    }
    const key = encoded.slice(0, separator)
    const value = encoded.slice(separator + 1)
    if (!FILTER_KEY.test(key) || isTenantKey(key) || value.length > MAX_VALUE_LENGTH) {
      malformed = true
      continue
    }
    filters[key] = value
  }
  return { filters, malformed }
}

/** Parse untrusted URL state. Safe time/filter context survives a bad reference. */
export function parsePivotContext(
  params: URLSearchParams,
  options: ParsePivotContextOptions = {},
): ParsedPivotContext {
  const contractEntries = Array.from(params.keys()).filter((key) => key.startsWith('ctx_'))
  const hasContract = contractEntries.length > 0
  const parsedFilters = safeFilters(params.getAll('ctx_filter'))
  const from = normalizedAbsoluteTime(params.get('ctx_from'))
  const to = normalizedAbsoluteTime(params.get('ctx_to'))
  const expiresAt = normalizedAbsoluteTime(params.get('ctx_expires'))
  const returnTo = safeReturnLocation(params.get('ctx_return'))

  let malformed = parsedFilters.malformed
  if (hasContract && params.get('ctx_v') !== PIVOT_CONTEXT_VERSION) malformed = true
  if (hasContract && !params.has('ctx_expires')) malformed = true
  if (contractEntries.some((key) => !CONTRACT_KEYS.has(key))) malformed = true
  if (params.has('ctx_from') && !from) malformed = true
  if (params.has('ctx_to') && !to) malformed = true
  if (from && to && Date.parse(from) > Date.parse(to)) malformed = true
  if (params.has('ctx_expires') && !expiresAt) malformed = true
  if (params.has('ctx_return') && !returnTo) malformed = true

  const now = options.now ?? new Date()
  const expired = Boolean(expiresAt && Date.parse(expiresAt) <= now.getTime())
  let incidentId = safeReference(params.get('ctx_incident'))
  const selectionKind = params.get('ctx_selected_kind')
  const selectionID = safeReference(params.get('ctx_selected_id'))
  let selection: PivotSelection | undefined
  if (selectionKind === 'evidence' || selectionKind === 'entity') {
    if (selectionID) selection = { kind: selectionKind, id: selectionID }
    else if (params.has('ctx_selected_kind')) malformed = true
  } else if (selectionKind !== null || params.has('ctx_selected_id')) {
    malformed = true
  }
  if (params.has('ctx_incident') && !incidentId) malformed = true

  let referencesValid = !malformed && !expired
  if (
    referencesValid &&
    incidentId &&
    options.authorize?.({ kind: 'incident', id: incidentId }) === false
  ) {
    referencesValid = false
  }
  if (referencesValid && selection && options.authorize?.(selection) === false) {
    referencesValid = false
  }
  if (!referencesValid) {
    incidentId = undefined
    selection = undefined
  }

  const safeFrom = from && to && Date.parse(from) > Date.parse(to) ? undefined : from
  const safeTo = from && to && Date.parse(from) > Date.parse(to) ? undefined : to
  return {
    hasContract,
    referencesValid,
    context: {
      filters: parsedFilters.filters,
      ...(safeFrom ? { from: safeFrom } : {}),
      ...(safeTo ? { to: safeTo } : {}),
      ...(expiresAt ? { expiresAt } : {}),
      ...(returnTo ? { returnTo } : {}),
      ...(incidentId ? { incidentId } : {}),
      ...(selection ? { selection } : {}),
    },
  }
}

export function serializePivotContext(
  context: PivotContext,
  now: Date = new Date(),
): URLSearchParams {
  const params = new URLSearchParams()
  params.set('ctx_v', PIVOT_CONTEXT_VERSION)
  const expiresAt = normalizedAbsoluteTime(context.expiresAt)
  params.set(
    'ctx_expires',
    expiresAt && Date.parse(expiresAt) > now.getTime()
      ? expiresAt
      : new Date(now.getTime() + PIVOT_CONTEXT_TTL_MS).toISOString(),
  )

  const from = normalizedAbsoluteTime(context.from)
  const to = normalizedAbsoluteTime(context.to)
  if (from && (!to || Date.parse(from) <= Date.parse(to))) params.set('ctx_from', from)
  if (to && (!from || Date.parse(from) <= Date.parse(to))) params.set('ctx_to', to)

  const incidentId = safeReference(context.incidentId)
  if (incidentId) params.set('ctx_incident', incidentId)
  for (const [key, value] of Object.entries(context.filters).sort(([a], [b]) =>
    a.localeCompare(b),
  )) {
    if (!FILTER_KEY.test(key) || isTenantKey(key) || value.length > MAX_VALUE_LENGTH) continue
    params.append('ctx_filter', `${key}:${value}`)
  }
  const selectedID = safeReference(context.selection?.id)
  if (context.selection && selectedID) {
    params.set('ctx_selected_kind', context.selection.kind)
    params.set('ctx_selected_id', selectedID)
  }
  const returnTo = safeReturnLocation(context.returnTo)
  if (returnTo) params.set('ctx_return', returnTo)
  return params
}

/** Replace only contract keys; page-specific query parameters remain intact. */
export function replacePivotContext(
  current: URLSearchParams,
  context: PivotContext,
  now: Date = new Date(),
): URLSearchParams {
  const next = new URLSearchParams(current)
  for (const key of Array.from(next.keys())) {
    if (key.startsWith('ctx_')) next.delete(key)
  }
  serializePivotContext(context, now).forEach((value, key) => next.append(key, value))
  return next
}

export function pivotHref(
  path: string,
  context: PivotContext,
  extras: Record<string, string | undefined> = {},
  now: Date = new Date(),
): string {
  const [pathname, query = ''] = path.split('?', 2)
  const params = new URLSearchParams(query)
  for (const [key, value] of Object.entries(extras)) {
    if (value) params.set(key, value)
  }
  const next = replacePivotContext(params, context, now)
  const encoded = next.toString()
  return encoded ? `${pathname}?${encoded}` : pathname
}

export function planePivotHref(
  plane: PlaneID,
  context: PivotContext,
  now: Date = new Date(),
): string {
  return pivotHref(REGISTERED_PLANE_PATHS[plane], context, {}, now)
}
