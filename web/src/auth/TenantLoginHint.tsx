// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { validLoginTenant } from '../api/client'
import { useAuth } from './useAuth'

/** Preserve the server-resolved sign-in destination across navigation/reload.
 * The URL is public routing context, never a tenant grant or API input. */
export function TenantLoginHint() {
  const { tenant } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  useEffect(() => {
    const id = validLoginTenant(tenant.id)
    if (!id) return
    const search = new URLSearchParams(location.search)
    // Default-tenant installs keep their existing short URLs. A forged or
    // stale hint is corrected from /me, not allowed to switch the session.
    if (id === '00000000-0000-0000-0000-000000000001') search.delete('login_tenant')
    else search.set('login_tenant', id)
    const next = search.toString()
    if (next !== location.search.replace(/^\?/, '')) {
      void navigate(
        { pathname: location.pathname, search: next ? `?${next}` : '', hash: location.hash },
        { replace: true },
      )
    }
  }, [tenant.id, location.pathname, location.search, location.hash, navigate])
  return null
}
