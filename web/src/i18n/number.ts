// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { DEFAULT_LOCALE } from './messages'

interface DecimalOptions {
  minimumFractionDigits?: number
  maximumFractionDigits?: number
}

const numberFormatCache = new Map<string, Intl.NumberFormat>()
const pluralRulesCache = new Map<string, Intl.PluralRules>()

export function formatNumber(
  value: number,
  locale: string = DEFAULT_LOCALE,
  options: Intl.NumberFormatOptions = {},
): string {
  return numberFormatter(locale, options).format(value)
}

export function formatInteger(value: number, locale: string = DEFAULT_LOCALE): string {
  return formatNumber(value, locale, { maximumFractionDigits: 0 })
}

export function formatDecimal(
  value: number,
  locale: string = DEFAULT_LOCALE,
  options: DecimalOptions = {},
): string {
  return formatNumber(value, locale, {
    minimumFractionDigits: options.minimumFractionDigits,
    maximumFractionDigits: options.maximumFractionDigits ?? 1,
  })
}

export function formatCurrencyUSD(
  value: number,
  locale: string = DEFAULT_LOCALE,
  options: DecimalOptions = {},
): string {
  return formatNumber(value, locale, {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: options.minimumFractionDigits,
    maximumFractionDigits: options.maximumFractionDigits,
  })
}

export function formatRatioPercent(
  value: number,
  locale: string = DEFAULT_LOCALE,
  options: DecimalOptions = {},
): string {
  return formatNumber(value, locale, {
    style: 'percent',
    minimumFractionDigits: options.minimumFractionDigits,
    maximumFractionDigits: options.maximumFractionDigits ?? 1,
  })
}

export function formatPercentValue(
  value: number,
  locale: string = DEFAULT_LOCALE,
  options: DecimalOptions = {},
): string {
  return formatRatioPercent(value / 100, locale, options)
}

export function formatUnit(
  value: number,
  unit: string,
  locale: string = DEFAULT_LOCALE,
  options: DecimalOptions = {},
): string {
  return `${formatDecimal(value, locale, options)} ${unit}`
}

export function formatMultiplier(value: number, locale: string = DEFAULT_LOCALE): string {
  return `${formatDecimal(value, locale, { maximumFractionDigits: 1 })}x`
}

export function formatGibibytes(bytes: number, locale: string = DEFAULT_LOCALE): string {
  const value = bytes / 2 ** 30
  const digits = value >= 100 ? 0 : value >= 1 ? 1 : 2
  return formatDecimal(value, locale, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  })
}

export function formatGibibytesWithUnit(bytes: number, locale: string = DEFAULT_LOCALE): string {
  return `${formatGibibytes(bytes, locale)} GiB`
}

export function formatScaledBytes(
  bytes: number | undefined,
  locale: string = DEFAULT_LOCALE,
): string {
  if (!bytes) return `0 B`
  return formatScaled(bytes, 1024, ['B', 'KiB', 'MiB', 'GiB', 'TiB'], locale)
}

export function formatScaledBitRate(
  bps: number | undefined,
  locale: string = DEFAULT_LOCALE,
): string {
  if (!bps) return `0 bps`
  return formatScaled(bps, 1000, ['bps', 'Kbps', 'Mbps', 'Gbps'], locale)
}

export function formatCount(
  count: number,
  one: string,
  other: string,
  locale: string = DEFAULT_LOCALE,
): string {
  const label = pluralRules(locale).select(count) === 'one' ? one : other
  return `${formatInteger(count, locale)} ${label}`
}

function formatScaled(value: number, base: number, units: string[], locale: string): string {
  let scaled = value
  let unit = 0
  while (scaled >= base && unit < units.length - 1) {
    scaled /= base
    unit += 1
  }
  return formatUnit(scaled, units[unit], locale, {
    maximumFractionDigits: scaled >= 10 || unit === 0 ? 0 : 1,
  })
}

/**
 * formatDuration renders a number of seconds the way an operator reads a
 * duration: the two largest units that carry information.
 *
 * DPR-186: the fleet table printed "Heartbeat age: 104848s" and the support
 * card printed uptime the same way. Nobody converts 104,848 seconds in their
 * head, and the number that matters — a day and five hours — was sitting there
 * unread. Units come from Intl unit formatting, so the wording follows the
 * locale rather than a hard-coded "h".
 */
export function formatDuration(seconds: number, locale: string = DEFAULT_LOCALE): string {
  if (!Number.isFinite(seconds) || seconds < 0) return ''
  const whole = Math.floor(seconds)
  const units: Array<{ unit: Intl.NumberFormatOptions['unit']; size: number }> = [
    { unit: 'day', size: 86400 },
    { unit: 'hour', size: 3600 },
    { unit: 'minute', size: 60 },
    { unit: 'second', size: 1 },
  ]
  const parts: string[] = []
  let left = whole
  for (const { unit, size } of units) {
    const value = Math.floor(left / size)
    left -= value * size
    if (value === 0 && parts.length === 0) continue
    parts.push(
      numberFormatter(locale, { style: 'unit', unit, unitDisplay: 'narrow' }).format(value),
    )
    // Two units is the whole point: "1d 5h" answers the question, "1d 5h 7m 28s"
    // makes the reader do the reading.
    if (parts.length === 2) break
  }
  if (parts.length === 0) {
    return numberFormatter(locale, { style: 'unit', unit: 'second', unitDisplay: 'narrow' }).format(0)
  }
  return parts.join(' ')
}

function numberFormatter(locale: string, options: Intl.NumberFormatOptions): Intl.NumberFormat {
  const key = `${locale}:${JSON.stringify(options)}`
  let formatter = numberFormatCache.get(key)
  if (!formatter) {
    formatter = new Intl.NumberFormat(locale, options)
    numberFormatCache.set(key, formatter)
  }
  return formatter
}

function pluralRules(locale: string): Intl.PluralRules {
  let rules = pluralRulesCache.get(locale)
  if (!rules) {
    rules = new Intl.PluralRules(locale)
    pluralRulesCache.set(locale, rules)
  }
  return rules
}
