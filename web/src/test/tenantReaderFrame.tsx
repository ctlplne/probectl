// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactNode } from 'react'
import { AuthContext } from '../auth/AuthProvider'
import { I18nProvider } from '../i18n/I18nProvider'
import { TimeProvider } from '../time/TimeProvider'

export function TenantReaderFrame({
  tenant,
  permissions = [],
  children,
}: {
  tenant: string
  permissions?: string[]
  children: ReactNode
}) {
  return (
    <AuthContext.Provider
      value={{
        tenant: { id: tenant, name: tenant, slug: tenant },
        user: { id: `user-${tenant}`, name: tenant, email: `${tenant}@example.invalid` },
        tenants: [],
        permissions,
        switchTenant: () => undefined,
        signOut: () => undefined,
      }}
    >
      <I18nProvider initialLocale="en">
        <TimeProvider>{children}</TimeProvider>
      </I18nProvider>
    </AuthContext.Provider>
  )
}
