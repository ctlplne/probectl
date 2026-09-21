// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { afterEach, describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse } from './fetchStub'
import {
  applyBrand,
  DEFAULT_BRAND,
  fetchBrand,
  sanitizeTokenOverrides,
  tokenOverridesPassContrast,
} from '../api/brand'
import { MAX_RESPONSE_BODY_BYTES } from '../api/response'

function brandingStub(response: unknown) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith('/branding')) return jsonResponse(response)
    return defaultFetch()(input, init)
  }) as unknown as typeof fetch
}

afterEach(() => {
  applyBrand(DEFAULT_BRAND)
  document.title = ''
})

describe('deployment-level probectl theming', () => {
  test('applies deployment tokens while keeping the probectl banner and title', async () => {
    vi.stubGlobal(
      'fetch',
      brandingStub({
        product_name: 'probectl',
        token_overrides: {
          '--primary': '28 85% 30%',
          '--primary-foreground': '0 0% 100%',
        },
      }),
    )
    renderApp('/targets')
    // Scoped to the shell's primary nav: the transient auth boot screen also
    // says "probectl", so an unscoped text query races the boot unmount.
    const nav = await screen.findByRole('navigation', { name: 'Primary' })
    expect(within(nav).getByText('probectl')).toBeInTheDocument()
    await waitFor(() => {
      expect(document.documentElement.style.getPropertyValue('--primary')).toBe('28 85% 30%')
    })
    expect(document.title).toBe('probectl')
  })

  test('rejects a response that attempts to replace the product identity', async () => {
    vi.stubGlobal(
      'fetch',
      brandingStub({
        product_name: 'OtherProduct',
        token_overrides: {
          '--primary': '28 85% 30%',
          '--primary-foreground': '0 0% 100%',
        },
      }),
    )
    renderApp('/targets')
    const nav = await screen.findByRole('navigation', { name: 'Primary' })
    expect(within(nav).getByText('probectl')).toBeInTheDocument()
    await waitFor(() =>
      expect(document.documentElement.style.getPropertyValue('--primary')).toBe(''),
    )
    expect(screen.queryByText('OtherProduct')).not.toBeInTheDocument()
    expect(document.title).toBe('probectl')
  })

  test('falls back without buffering an oversized branding response', async () => {
    let cancelled = false
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{}'))
      },
      cancel() {
        cancelled = true
      },
    })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        return new Response(stream, {
          status: 200,
          headers: { 'Content-Length': String(MAX_RESPONSE_BODY_BYTES + 1) },
        })
      }),
    )

    await expect(fetchBrand()).resolves.toEqual(DEFAULT_BRAND)
    expect(cancelled).toBe(true)
  })

  test.each([
    [[], 'Auditor read-only'],
    [['audit.read', 'test.read'], 'Read-only'],
    [['test.read', 'test.write'], 'Operator'],
    [['provider.tenant.provision'], 'Provider plane'],
    [['provider.breakglass.results'], 'Break-glass active'],
    [['license.read_only'], 'Degraded read-only'],
  ])('shell renders authority posture %s from /v1/me permissions', async (permissions, label) => {
    vi.stubGlobal('fetch', brandingStub(DEFAULT_BRAND))
    renderApp('/targets', { me: { permissions } })
    expect(
      await screen.findByRole('status', { name: `Authority posture: ${label}` }),
    ).toBeInTheDocument()
  })

  // One override map is validated against BOTH shipped themes, which is a real
  // constraint worth pinning: a single chip tone cannot clear 4.5:1 against a
  // near-white card AND a near-black one, so tones are overridable only as a
  // colour/foreground pair. Without this test the constraint reads like a bug the
  // next person "fixes" by validating one theme.
  test('an override is only valid if it holds in light AND dark', () => {
    // The shipped light value for a chip tone, which is unreadable on a dark card.
    expect(tokenOverridesPassContrast({ '--status-success': '166 55% 20%' })).toBe(false)
    // The shipped dark value for the same tone, unreadable on a light card.
    expect(tokenOverridesPassContrast({ '--status-success': '158 64% 52%' })).toBe(false)
    // A colour that carries its own foreground holds in both.
    expect(
      tokenOverridesPassContrast({
        '--primary': '28 85% 30%',
        '--primary-foreground': '0 0% 100%',
      }),
    ).toBe(true)
  })

  test('reapplying deployment config removes tokens omitted by the next config', () => {
    applyBrand({
      product_name: 'probectl',
      token_overrides: {
        '--primary': '28 85% 30%',
        '--primary-foreground': '0 0% 100%',
        '--radius-panel': '10px',
      },
    })
    applyBrand({
      product_name: 'probectl',
      token_overrides: {
        '--primary': '24 85% 28%',
        '--primary-foreground': '0 0% 100%',
      },
    })
    expect(document.documentElement.style.getPropertyValue('--primary')).toBe('24 85% 28%')
    expect(document.documentElement.style.getPropertyValue('--radius-panel')).toBe('')
    expect(document.title).toBe('probectl')
  })

  test('client defense ignores unsafe tokens and unreadable sets', () => {
    applyBrand({
      product_name: 'probectl',
      token_overrides: {
        '--space-4': '999px', // structural token, never overridable
        '--primary': 'url(https://evil.example)', // no browser fetch
        '--radius-control': '24', // unitless
        '--radius-panel': '10px', // the one legitimate entry
      },
    })
    expect(document.documentElement.style.getPropertyValue('--space-4')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--primary')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--radius-control')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--radius-panel')).toBe('10px')

    // A hex value is a valid CSS colour but NOT a valid token value: the
    // stylesheet reads the token as hsl(var(--primary) / <alpha>), so applying a
    // hex would break every rule that uses it rather than recolour it.
    expect(sanitizeTokenOverrides({ '--primary': '#6a4cf0' })).toEqual({})
    expect(sanitizeTokenOverrides({ '--primary': 'rgb(106 76 240)' })).toEqual({})
    // The retired vocabulary is refused outright rather than applied to nothing.
    expect(sanitizeTokenOverrides({ '--color-accent': '28 85% 30%' })).toEqual({})
    // A token name that ships nowhere, even under an overridable prefix.
    expect(sanitizeTokenOverrides({ '--radius-nope': '10px' })).toEqual({})
    expect(sanitizeTokenOverrides({ '--font-nope': 'Sora' })).toEqual({})

    // Contrast: white body text on warm paper, a white series line on it, and an
    // action colour too light to carry its own white label.
    expect(tokenOverridesPassContrast({ '--foreground': '0 0% 100%' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--chart-1': '0 0% 100%' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--primary': '28 100% 85%' })).toBe(false)
    // One bad member poisons the whole set — a partially-applied theme is worse
    // than none, because the operator sees some of their change and trusts it.
    expect(
      sanitizeTokenOverrides({
        '--primary': '28 85% 30%',
        '--primary-foreground': '0 0% 100%',
        '--foreground': '0 0% 100%',
      }),
    ).toEqual({})
    // ...and the same set without the unreadable member goes through, so the test
    // above cannot pass merely because sanitize rejects everything.
    expect(
      sanitizeTokenOverrides({
        '--primary': '28 85% 30%',
        '--primary-foreground': '0 0% 100%',
      }),
    ).toEqual({ '--primary': '28 85% 30%', '--primary-foreground': '0 0% 100%' })
  })
})
