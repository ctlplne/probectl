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

export function formatCurrencyUSD(value: number, locale: string = DEFAULT_LOCALE): string {
  return formatNumber(value, locale, { style: 'currency', currency: 'USD' })
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
