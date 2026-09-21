// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { applyBrand, fetchBrand, DEFAULT_BRAND, type Brand } from '../api/brand'

/**
 * BrandProvider fetches the deployment-wide probectl theme pre-auth and
 * applies its validated token overrides to <html>. Product identity stays
 * probectl and failures fall back to the shipped light/dark tokens.
 */
// eslint-disable-next-line react-refresh/only-export-components
export const BrandContext = createContext<Brand>(DEFAULT_BRAND)

// eslint-disable-next-line react-refresh/only-export-components
export function useBrand(): Brand {
  return useContext(BrandContext)
}

export function BrandProvider({ children }: { children: ReactNode }) {
  const [brand, setBrand] = useState<Brand>(DEFAULT_BRAND)

  useEffect(() => {
    let cancelled = false
    void fetchBrand().then(
      (b) => {
        if (cancelled) return
        applyBrand(b)
        setBrand(b)
      },
      () => {
        if (cancelled) return
        applyBrand(DEFAULT_BRAND)
        setBrand(DEFAULT_BRAND)
      },
    )
    return () => {
      cancelled = true
    }
  }, [])

  return <BrandContext.Provider value={brand}>{children}</BrandContext.Provider>
}
