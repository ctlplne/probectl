import { useEffect, useState, type ReactNode } from 'react'
import { BrowserRouter } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { ThemeProvider } from './theme/ThemeProvider'
import { BrandProvider } from './brand/BrandProvider'
import { AuthProvider } from './auth/AuthProvider'
import { useAuth } from './auth/useAuth'
import { ToastProvider } from './components'
import { makeQueryClient } from './api/queryClient'
import { AppRoutes } from './routes/AppRoutes'
import { I18nProvider } from './i18n/I18nProvider'
import { resolveLocale } from './i18n/core'
import { useI18n } from './i18n/useI18n'
import { TimeProvider } from './time/TimeProvider'

/** Providers wraps the app in theme, server-state, auth, and toast context. It is
 *  router-agnostic so tests can supply a MemoryRouter. */
export function Providers({
  children,
  initialLocale,
}: {
  children: ReactNode
  initialLocale?: string
}) {
  const [client] = useState(makeQueryClient)
  return (
    <I18nProvider initialLocale={initialLocale}>
      <ThemeProvider>
        <BrandProvider>
          <QueryClientProvider client={client}>
            <AuthProvider>
              <AuthPreferenceBridge>
                <TimeProvider>
                  <ToastProvider>{children}</ToastProvider>
                </TimeProvider>
              </AuthPreferenceBridge>
            </AuthProvider>
          </QueryClientProvider>
        </BrandProvider>
      </ThemeProvider>
    </I18nProvider>
  )
}

function AuthPreferenceBridge({ children }: { children: ReactNode }) {
  const { tenant, user } = useAuth()
  const { locale, setLocale } = useI18n()
  const preferredLocale = user.locale ?? tenant.locale

  useEffect(() => {
    if (!preferredLocale) return
    const next = resolveLocale(preferredLocale)
    if (next !== locale) setLocale(next)
  }, [locale, preferredLocale, setLocale])

  return <>{children}</>
}

export function App() {
  return (
    <Providers>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </Providers>
  )
}
