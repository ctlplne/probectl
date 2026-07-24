// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { afterEach, describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse } from './fetchStub'
import {
  applyBrand,
  DEFAULT_BRAND,
  sanitizeTokenOverrides,
  tokenOverridesPassContrast,
} from '../api/brand'

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
          '--color-accent': '#6a4cf0',
          '--color-accent-hover': '#7054f6',
          '--color-accent-strong': '#6a4cf0',
          '--color-accent-contrast': '#ffffff',
        },
      }),
    )
    renderApp('/targets')
    // Scoped to the shell's primary nav: the transient auth boot screen also
    // says "probectl", so an unscoped text query races the boot unmount.
    const nav = await screen.findByRole('navigation', { name: 'Primary' })
    expect(within(nav).getByText('probectl')).toBeInTheDocument()
    await waitFor(() => {
      expect(document.documentElement.style.getPropertyValue('--color-accent')).toBe('#6a4cf0')
    })
    expect(document.title).toBe('probectl')
  })

  test('rejects a response that attempts to replace the product identity', async () => {
    vi.stubGlobal(
      'fetch',
      brandingStub({
        product_name: 'OtherProduct',
        token_overrides: {
          '--color-accent': '#6a4cf0',
          '--color-accent-hover': '#7054f6',
          '--color-accent-strong': '#684af0',
          '--color-accent-contrast': '#ffffff',
        },
      }),
    )
    renderApp('/targets')
    const nav = await screen.findByRole('navigation', { name: 'Primary' })
    expect(within(nav).getByText('probectl')).toBeInTheDocument()
    await waitFor(() =>
      expect(document.documentElement.style.getPropertyValue('--color-accent')).toBe(''),
    )
    expect(screen.queryByText('OtherProduct')).not.toBeInTheDocument()
    expect(document.title).toBe('probectl')
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

  test('reapplying deployment config removes tokens omitted by the next config', () => {
    applyBrand({
      product_name: 'probectl',
      token_overrides: {
        '--color-accent': '#6a4cf0',
        '--color-accent-hover': '#7054f6',
        '--color-accent-strong': '#6a4cf0',
        '--color-accent-contrast': '#ffffff',
        '--color-focus': '#6a4cf0',
      },
    })
    applyBrand({
      product_name: 'probectl',
      token_overrides: {
        '--color-accent': '#7054f6',
        '--color-accent-hover': '#6a4cf0',
        '--color-accent-strong': '#6a4cf0',
        '--color-accent-contrast': '#ffffff',
      },
    })
    expect(document.documentElement.style.getPropertyValue('--color-accent')).toBe('#7054f6')
    expect(document.documentElement.style.getPropertyValue('--color-focus')).toBe('')
    expect(document.title).toBe('probectl')
  })

  test('client defense ignores unsafe tokens and unreadable sets', () => {
    applyBrand({
      product_name: 'probectl',
      token_overrides: {
        '--space-4': '999px',
        '--color-accent': 'url(https://evil.example)',
        '--color-info': '24px',
        '--color-ok': '#00aa55',
      },
    })
    expect(document.documentElement.style.getPropertyValue('--space-4')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--color-accent')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--color-info')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--color-ok')).toBe('#00aa55')

    expect(tokenOverridesPassContrast({ '--color-text': '#ffffff' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--color-accent': '#ff3300' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--color-chart-1': '#ffffff' })).toBe(false)
    expect(
      sanitizeTokenOverrides({
        '--color-accent': '#6a4cf0',
        '--color-accent-hover': '#7054f6',
        '--color-accent-strong': '#6a4cf0',
        '--color-accent-contrast': '#ffffff',
        '--color-text': '#ffffff',
      }),
    ).toEqual({})
  })
})
