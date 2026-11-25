// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import {
  createContext,
  useContext,
  useEffect,
  useLayoutEffect,
  useState,
  type ReactNode,
} from 'react'
import { applyBrand, fetchBrand, DEFAULT_BRAND, type Brand } from '../api/brand'

type BrandState = {
  brand: Brand
  loaded: boolean
  customerDomain: boolean
  bindTenant?: (tenantID: string | null) => void
}

// The sign-in shell waits for the branding response before starting SSO.
// eslint-disable-next-line react-refresh/only-export-components
export const BrandContext = createContext<BrandState>({
  brand: DEFAULT_BRAND,
  loaded: true,
  customerDomain: false,
})

// eslint-disable-next-line react-refresh/only-export-components
export function useBrand(): Brand {
  return useContext(BrandContext).brand
}

// eslint-disable-next-line react-refresh/only-export-components
export function useBrandState() {
  return useContext(BrandContext)
}

export function BrandProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState({ brand: DEFAULT_BRAND, loaded: false })
  const [tenantID, bindTenant] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    void fetchBrand().then((brand) => {
      if (!cancelled) setState({ brand, loaded: true })
    })
    return () => {
      cancelled = true
    }
  }, [tenantID])

  const customerDomain = state.brand.customer_domain === true
  // A public, registered customer host can brand sign-in. For a protected
  // console, only use presentation confirmed for its authenticated tenant.
  const customerMatches = tenantID ? state.brand.sessionTenant === tenantID : customerDomain
  const brand = state.brand.customer && !customerMatches ? DEFAULT_BRAND : state.brand
  useLayoutEffect(() => applyBrand(brand), [brand])

  return (
    <BrandContext.Provider value={{ brand, loaded: state.loaded, customerDomain, bindTenant }}>
      {children}
    </BrandContext.Provider>
  )
}
