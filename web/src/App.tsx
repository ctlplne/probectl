// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type ReactNode } from 'react'
import { BrowserRouter } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { ThemeProvider } from './theme/ThemeProvider'
import { BrandProvider } from './brand/BrandProvider'
import { ToastProvider } from './components'
import { makeQueryClient } from './api/queryClient'
import { AppRoutes } from './routes/AppRoutes'
import { I18nProvider } from './i18n/I18nProvider'

/** Providers wraps the app in the context EVERY surface shares — theme,
 *  server-state, brand and toast — and is router-agnostic so tests can supply a
 *  MemoryRouter. WEB-10: tenant authentication (AuthProvider) is deliberately
 *  NOT here. It gates the tenant app only, inside AppRoutes' TenantApp layout;
 *  the provider/operator console is a separate privilege domain that must be
 *  reachable WITHOUT a tenant session, so it renders outside that gate. */
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
            <ToastProvider>{children}</ToastProvider>
          </QueryClientProvider>
        </BrandProvider>
      </ThemeProvider>
    </I18nProvider>
  )
}

export function App() {
  return (
    <Providers>
      <BrowserRouter basename="/ui">
        <AppRoutes />
      </BrowserRouter>
    </Providers>
  )
}
