import { DEFAULT_LOCALE, LOCALES, messages, type Locale, type MessageKey } from './messages'

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
  const normalized = raw?.toLowerCase().split(/[._-]/)[0]
  return LOCALES.includes(normalized as Locale) ? (normalized as Locale) : DEFAULT_LOCALE
}
