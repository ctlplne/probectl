/**
 * The white-label brand (S-T4). Fetched PRE-AUTH from the public /branding
 * endpoint (Host-resolved: a custom domain answers its tenant's brand;
 * community/unlicensed deployments answer the probectl default). Branding is
 * a runtime override of the S8a design tokens — no screen knows about it.
 */

export interface Brand {
  product_name: string
  logo_data_uri?: string
  login_message?: string
  token_overrides?: Record<string, string>
  email_from_name?: string
  email_footer?: string
}

export const DEFAULT_BRAND: Brand = { product_name: 'probectl' }

/** Only S8a brandable tokens may be touched at runtime (mirror of the core
 *  allowlist — defense in depth on the client). */
const TOKEN_NAME = /^--(color-[a-z0-9-]+|radius-(sm|md|lg)|font-sans|font-mono)$/
const TOKEN_VALUE = /^(#[0-9a-fA-F]{3,8}|rgba?\([0-9.,/% ]+\)|hsla?\([0-9.,/% deg]+\)|[0-9]{1,3}(px|rem|em|%)|[A-Za-z0-9 ,'"-]{1,120})$/

export async function fetchBrand(): Promise<Brand> {
  try {
    const res = await fetch('/branding', { credentials: 'same-origin' })
    if (!res.ok) return DEFAULT_BRAND
    const b = (await res.json()) as Brand
    if (!b || typeof b.product_name !== 'string' || b.product_name === '') return DEFAULT_BRAND
    return b
  } catch {
    return DEFAULT_BRAND // branding must never take the app down
  }
}

/** Tracks which tokens we overrode so a brand change replaces CLEANLY —
 *  no residue from a previous brand (the client-side no-bleed property). */
let appliedTokens: string[] = []

export function applyBrand(b: Brand) {
  const root = document.documentElement
  for (const name of appliedTokens) root.style.removeProperty(name)
  appliedTokens = []
  for (const [name, value] of Object.entries(b.token_overrides ?? {})) {
    if (!TOKEN_NAME.test(name) || !TOKEN_VALUE.test(value)) continue
    root.style.setProperty(name, value)
    appliedTokens.push(name)
  }
  document.title = b.product_name
}
