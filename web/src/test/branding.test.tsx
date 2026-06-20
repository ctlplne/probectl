import { describe, expect, test, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderApp } from './renderApp'
import { jsonResponse, defaultFetch } from './fetchStub'
import {
  applyBrand,
  DEFAULT_BRAND,
  sanitizeTokenOverrides,
  tokenOverridesPassContrast,
} from '../api/brand'

/** S-T4: white-label branding applied purely through the S8a token contract —
 *  the brand arrives pre-auth from /branding and lands as token overrides on
 *  <html>, the wordmark, and document.title. Zero per-screen knowledge. */

function brandStub(brand: unknown) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/branding')) return jsonResponse(brand)
    return defaultFetch()(input, init)
  }) as unknown as typeof fetch
}

afterEach(() => {
  applyBrand(DEFAULT_BRAND) // clear overrides between tests
  document.title = ''
})

describe('white-label branding (S-T4)', () => {
  test("tenant A sees A's brand: tokens override on <html>, wordmark + title swap, logo renders", async () => {
    vi.stubGlobal(
      'fetch',
      brandStub({
        product_name: 'AcmeWatch',
        logo_data_uri: 'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=',
        token_overrides: {
          '--color-accent': '#6a4cf0',
          '--color-accent-hover': '#7054f6',
          '--color-accent-strong': '#684af0',
          '--color-accent-contrast': '#ffffff',
        },
      }),
    )
    renderApp('/targets')
    expect(await screen.findByText('AcmeWatch')).toBeInTheDocument()
    await waitFor(() => {
      expect(document.documentElement.style.getPropertyValue('--color-accent')).toBe('#6a4cf0')
      expect(document.documentElement.style.getPropertyValue('--color-accent-contrast')).toBe(
        '#ffffff',
      )
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
    applyBrand({
      product_name: 'AcmeWatch',
      token_overrides: {
        '--color-accent': '#6a4cf0',
        '--color-accent-hover': '#7054f6',
        '--color-accent-strong': '#684af0',
        '--color-accent-contrast': '#ffffff',
        '--color-focus': '#6a4cf0',
      },
    })
    expect(document.documentElement.style.getPropertyValue('--color-focus')).toBe('#6a4cf0')

    // Brand B sets only the accent: A's focus override must VANISH.
    applyBrand({
      product_name: 'GlobexNet',
      token_overrides: {
        '--color-accent': '#684af0',
        '--color-accent-hover': '#6a4cf0',
        '--color-accent-strong': '#684af0',
        '--color-accent-contrast': '#ffffff',
      },
    })
    expect(document.documentElement.style.getPropertyValue('--color-accent')).toBe('#684af0')
    expect(document.documentElement.style.getPropertyValue('--color-focus')).toBe('')
    expect(document.title).toBe('GlobexNet')
  })

  test('client-side defense in depth: non-allowlisted or unsafe tokens are ignored', () => {
    applyBrand({
      product_name: 'X',
      token_overrides: {
        '--space-4': '999px', // layout token: not brandable
        '--color-accent': 'url(https://evil.example)', // unsafe value
        '--color-info': '24px', // color token must be a color, not any valid token shape
        '--color-ok': '#00aa55', // fine
      },
    })
    expect(document.documentElement.style.getPropertyValue('--space-4')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--color-accent')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--color-info')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--color-ok')).toBe('#00aa55')
  })

  test('contrast defense in depth: unreadable token sets are ignored atomically', () => {
    expect(
      tokenOverridesPassContrast({
        '--color-accent': '#6a4cf0',
        '--color-accent-hover': '#7054f6',
        '--color-accent-strong': '#684af0',
        '--color-accent-contrast': '#ffffff',
        '--color-focus': '#6a4cf0',
      }),
    ).toBe(true)
    expect(tokenOverridesPassContrast({ '--color-text': '#ffffff' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--color-accent': '#ff3300' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--color-chart-1': '#ffffff' })).toBe(false)
    expect(
      sanitizeTokenOverrides({
        '--color-accent': '#6a4cf0',
        '--color-accent-hover': '#7054f6',
        '--color-accent-strong': '#684af0',
        '--color-accent-contrast': '#ffffff',
        '--color-text': '#ffffff',
      }),
    ).toEqual({})

    applyBrand({
      product_name: 'BadBrand',
      token_overrides: {
        '--color-accent': '#6a4cf0',
        '--color-accent-hover': '#7054f6',
        '--color-accent-strong': '#684af0',
        '--color-accent-contrast': '#ffffff',
        '--color-text': '#ffffff',
      },
    })
    expect(document.documentElement.style.getPropertyValue('--color-accent')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--color-text')).toBe('')
  })
})
