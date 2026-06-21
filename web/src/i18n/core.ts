import { DEFAULT_LOCALE, LOCALES, messages, type Locale, type MessageKey } from './messages'

const RTL_LANGUAGES = new Set([
  'ar',
  'arc',
  'ckb',
  'dv',
  'fa',
  'he',
  'ks',
  'ku',
  'nqo',
  'ps',
  'sd',
  'ug',
  'ur',
  'yi',
])

export function translate(
  locale: Locale,
  key: MessageKey,
  vars: Record<string, string | number> = {},
) {
  const template = messages[locale][key] ?? messages[DEFAULT_LOCALE][key] ?? key
  return Object.entries(vars).reduce(
    (out, [name, value]) => out.split(`{${name}}`).join(String(value)),
    template,
  )
}

export function resolveLocale(raw: string | undefined | null): Locale {
  const normalized = primaryLanguage(raw)
  return LOCALES.includes(normalized as Locale) ? (normalized as Locale) : DEFAULT_LOCALE
}

export function documentLocale(raw: string | undefined | null): string {
  const normalized = normalizeLocaleTag(raw)
  return normalized || DEFAULT_LOCALE
}

export function directionForLocale(raw: string | undefined | null): 'ltr' | 'rtl' {
  return RTL_LANGUAGES.has(primaryLanguage(raw)) ? 'rtl' : 'ltr'
}

function normalizeLocaleTag(raw: string | undefined | null) {
  const normalized = raw?.trim().replace(/_/g, '-').split(/[.;\s]/)[0].toLowerCase()
  if (!normalized) return ''
  return /^[a-z]{2,3}(-[a-z0-9]{2,8})*$/.test(normalized) ? normalized : ''
}

function primaryLanguage(raw: string | undefined | null) {
  return normalizeLocaleTag(raw).split('-')[0] || DEFAULT_LOCALE
}
