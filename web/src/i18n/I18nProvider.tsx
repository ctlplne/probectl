import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { DEFAULT_LOCALE, type Locale } from './messages'
import { directionForLocale, documentLocale, resolveLocale, translate } from './core'
import { I18nContext, type I18nContextValue } from './context'

export function I18nProvider({
  children,
  initialLocale,
}: {
  children: ReactNode
  initialLocale?: string
}) {
  const initialRawLocale = initialLocale ?? browserLocale()
  const [locale, setLocale] = useState<Locale>(() =>
    resolveLocale(initialRawLocale),
  )
  const [htmlLocale, setHTMLLocale] = useState(() => documentLocale(initialRawLocale))

  const setResolvedLocale = useCallback((next: Locale) => {
    setLocale(next)
    setHTMLLocale(documentLocale(next))
  }, [])

  useEffect(() => {
    document.documentElement.lang = htmlLocale
    document.documentElement.dir = directionForLocale(htmlLocale)
  }, [htmlLocale])

  const value = useMemo<I18nContextValue>(
    () => ({
      locale,
      setLocale: setResolvedLocale,
      t: (key, vars) => translate(locale, key, vars),
    }),
    [locale, setResolvedLocale],
  )

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

function browserLocale() {
  return document.documentElement.dataset.locale || navigator.language || DEFAULT_LOCALE
}
