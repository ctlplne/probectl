import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { DEFAULT_LOCALE, type Locale } from './messages'
import { resolveLocale, translate } from './core'
import { I18nContext, type I18nContextValue } from './context'

export function I18nProvider({
  children,
  initialLocale,
}: {
  children: ReactNode
  initialLocale?: string
}) {
  const [locale, setLocale] = useState<Locale>(() =>
    resolveLocale(initialLocale ?? browserLocale()),
  )

  useEffect(() => {
    document.documentElement.lang = locale
    document.documentElement.dir = direction(locale)
  }, [locale])

  const value = useMemo<I18nContextValue>(
    () => ({
      locale,
      setLocale,
      t: (key, vars) => translate(locale, key, vars),
    }),
    [locale],
  )

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

function browserLocale() {
  return document.documentElement.dataset.locale || navigator.language || DEFAULT_LOCALE
}

function direction(locale: Locale) {
  return locale === 'en' || locale === 'es' ? 'ltr' : 'ltr'
}
