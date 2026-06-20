import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import { LOCALES, messages, type MessageKey } from '../i18n/messages'
import type { OutagesResponse } from '../api/outages'

function outageFixture(): OutagesResponse {
  return {
    outage_running: true,
    feeds_enabled: true,
    scope_resolution: true,
    events: [
      {
        id: 'ioda:bgp:asn:AS64500:1',
        source: 'ioda',
        scope: { kind: 'asn', code: 'AS64500', name: 'Testland Telecom' },
        severity: 'critical',
        confidence: 1,
        title: 'Internet outage: Testland Telecom (AS64500)',
        summary: 'IODA bgp signal, score 620',
        start: '2026-06-05T10:00:00Z',
        evidence_url: 'https://ioda.inetintel.cc.gatech.edu/asn/64500',
        ongoing: true,
        affected_tests: [
          {
            canary_type: 'http',
            target: 'web.testland.example:443',
            failures: 3,
            last_failure: '2026-06-05T10:20:00Z',
          },
        ],
      },
    ],
    vantage_events: [],
    feeds: [
      {
        name: 'ioda',
        status: 'ok',
        last_success: '2026-06-05T10:30:00Z',
        events: 12,
        license: 'IODA data-usage terms',
        attribution: 'IODA, Georgia Institute of Technology',
        commercial_use: 'unknown',
        url: 'https://ioda.inetintel.cc.gatech.edu/',
      },
    ],
    coverage_notes: ['coverage note from the control plane'],
  }
}

function stubWith(resp: OutagesResponse) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = requestURL(input)
    if (url.endsWith('/v1/outages')) return jsonResponse(resp)
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
}

function requestURL(input: RequestInfo | URL) {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.href
  return input.url
}

describe('i18n catalog', () => {
  test('every shipped locale has every user-facing catalog key', () => {
    const keys = Object.keys(messages.en) as MessageKey[]
    for (const locale of LOCALES) {
      for (const key of keys) {
        expect(messages[locale][key], `${locale}.${key}`).toBeTruthy()
      }
    }
  })

  test('localized surfaces do not reintroduce the cited raw English labels', () => {
    const sources = [
      resolve(process.cwd(), 'src/nav/ia.ts'),
      resolve(process.cwd(), 'src/shell/CommandPalette.tsx'),
      resolve(process.cwd(), 'src/routes/OutagesPage.tsx'),
    ]
    const banned = [
      'Targets & Tests',
      'Internet outages',
      'Collective outage view',
      'External outage events',
      'Vantage-detected outages',
      'No outage signals',
      'Search commands',
      'No matching commands',
      'Go to ',
    ]

    for (const source of sources) {
      const body = readFileSync(source, 'utf8')
      for (const text of banned) {
        expect(body, `${source} must use the i18n catalog for ${text}`).not.toContain(text)
      }
    }
  })

  test('Spanish locale renders nav, command search, outage tables, and statuses', async () => {
    const user = userEvent.setup()
    vi.stubGlobal('fetch', stubWith(outageFixture()))

    renderApp('/outages', { locale: 'es' })

    expect(await screen.findByRole('heading', { name: 'Cortes de Internet' })).toBeInTheDocument()
    expect(screen.getByText('Monitorear')).toBeInTheDocument()
    expect(document.documentElement.lang).toBe('es')
    expect(document.documentElement.dir).toBe('ltr')

    const events = await screen.findByRole('table', { name: 'Eventos externos de cortes' })
    expect(within(events).getByText('Corte')).toBeInTheDocument()
    expect(within(events).getByText('critica')).toBeInTheDocument()
    expect(within(events).getByText('en curso')).toBeInTheDocument()
    expect(within(events).getByRole('link', { name: 'evidencia' })).toHaveAttribute(
      'href',
      'https://ioda.inetintel.cc.gatech.edu/asn/64500',
    )
    expect(within(events).getByText(/3 fallos/)).toBeInTheDocument()

    const feeds = await screen.findByRole('table', { name: 'Fuentes de cortes' })
    expect(within(feeds).getByText('correcta')).toBeInTheDocument()
    expect(within(feeds).getByText(/uso comercial: unknown/)).toBeInTheDocument()

    await user.keyboard('{Meta>}k{/Meta}')
    const input = await screen.findByRole('combobox', { name: 'Buscar comandos' })
    expect(input).toHaveAttribute('placeholder', 'Buscar comandos...')
    expect(screen.getByRole('listbox', { name: 'Comandos' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: /Ir a Cortes de Internet/ })).toBeInTheDocument()
  })

  test('Spanish locale renders the outage empty state from the catalog', async () => {
    vi.stubGlobal('fetch', stubWith({ outage_running: false }))

    renderApp('/outages', { locale: 'es' })

    expect(await screen.findByText('Vista de cortes no conectada')).toBeInTheDocument()
    expect(screen.getByText(/motor de cortes desactivado/)).toBeInTheDocument()
  })
})
