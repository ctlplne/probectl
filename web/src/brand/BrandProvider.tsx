import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { applyBrand, fetchBrand, DEFAULT_BRAND, type Brand } from '../api/brand'

/**
 * BrandProvider (S-T4): fetches the deployment/tenant brand pre-auth and
 * applies it — token overrides land on <html> (the S8a token contract does
 * the rest: zero per-screen work), the product name reaches the shell and
 * document.title. Failures fall back to the probectl default: branding can
 * never take the app down.
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
    fetchBrand().then((b) => {
      if (cancelled) return
      applyBrand(b)
      setBrand(b)
    })
    return () => {
      cancelled = true
    }
  }, [])

  return <BrandContext.Provider value={brand}>{children}</BrandContext.Provider>
}
