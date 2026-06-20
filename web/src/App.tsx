import { useState, type ReactNode } from 'react'
import { BrowserRouter } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { ThemeProvider } from './theme/ThemeProvider'
import { BrandProvider } from './brand/BrandProvider'
import { AuthProvider } from './auth/AuthProvider'
import { ToastProvider } from './components'
import { makeQueryClient } from './api/queryClient'
import { AppRoutes } from './routes/AppRoutes'
import { I18nProvider } from './i18n/I18nProvider'

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
              <ToastProvider>{children}</ToastProvider>
            </AuthProvider>
          </QueryClientProvider>
        </BrandProvider>
      </ThemeProvider>
    </I18nProvider>
  )
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
