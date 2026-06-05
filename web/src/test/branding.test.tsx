import { describe, expect, test, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderApp } from './renderApp'
import { jsonResponse, defaultFetch } from './fetchStub'
import { applyBrand, DEFAULT_BRAND } from '../api/brand'

/** S-T4: white-label branding applied purely through the S8a token contract —
 *  the brand arrives pre-auth from /branding and lands as token overrides on
 *  <html>, the wordmark, and document.title. Zero per-screen knowledge. */

function brandStub(brand: unknown) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/branding')) return jsonResponse(brand)
    return (defaultFetch() as unknown as (i: RequestInfo | URL, n?: RequestInit) => Promise<Response>)(input, init)
  }) as unknown as typeof fetch
}

afterEach(() => {
  applyBrand(DEFAULT_BRAND) // clear overrides between tests
  document.title = ''
})

describe('white-label branding (S-T4)', () => {
  test('tenant A sees A\'s brand: tokens override on <html>, wordmark + title swap, logo renders', async () => {
    vi.stubGlobal('fetch', brandStub({
      product_name: 'AcmeWatch',
      logo_data_uri: 'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=',
      token_overrides: { '--color-accent': '#ff3300' },
    }))
    renderApp('/targets')
    expect(await screen.findByText('AcmeWatch')).toBeInTheDocument()
    await waitFor(() => {
      expect(document.documentElement.style.getPropertyValue('--color-accent')).toBe('#ff3300')
    })
    expect(document.title).toBe('AcmeWatch')
    expect(screen.queryByText('probectl')).toBeNull() // the wordmark is replaced
  })

  test('community/unlicensed: the probectl default brand (a failed or default fetch never breaks the app)', async () => {
    vi.stubGlobal('fetch', brandStub({ product_name: 'probectl' }))
    renderApp('/targets')
    expect(await screen.findByText('probectl')).toBeInTheDocument()
    expect(document.documentElement.style.getPropertyValue('--color-accent')).toBe('')
  })

  test('no-bleed on the client: switching brands replaces overrides with NO residue', async () => {
    applyBrand({ product_name: 'AcmeWatch', token_overrides: { '--color-accent': '#ff3300', '--color-bg': '#101418' } })
    expect(document.documentElement.style.getPropertyValue('--color-bg')).toBe('#101418')

    // Brand B sets only the accent: A's bg override must VANISH.
    applyBrand({ product_name: 'GlobexNet', token_overrides: { '--color-accent': '#0055aa' } })
    expect(document.documentElement.style.getPropertyValue('--color-accent')).toBe('#0055aa')
    expect(document.documentElement.style.getPropertyValue('--color-bg')).toBe('')
    expect(document.title).toBe('GlobexNet')
  })

  test('client-side defense in depth: non-allowlisted or unsafe tokens are ignored', () => {
    applyBrand({
      product_name: 'X',
      token_overrides: {
        '--space-4': '999px',                       // layout token: not brandable
        '--color-accent': 'url(https://evil.example)', // unsafe value
        '--color-ok': '#00aa55',                    // fine
      },
    })
    expect(document.documentElement.style.getPropertyValue('--space-4')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--color-accent')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--color-ok')).toBe('#00aa55')
  })
})
