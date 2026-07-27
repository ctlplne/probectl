// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { readFileSync, readdirSync } from 'node:fs'
import { extname, join, resolve } from 'node:path'
import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse } from './fetchStub'
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

function localizedSourceFiles() {
  const roots = [
    resolve(process.cwd(), 'src/nav'),
    resolve(process.cwd(), 'src/shell'),
    resolve(process.cwd(), 'src/routes'),
    resolve(process.cwd(), 'src/components'),
  ]

  function walk(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) return walk(full)
      if (!entry.isFile()) return []
      if (!['.ts', '.tsx'].includes(extname(entry.name))) return []
      if (entry.name.endsWith('.test.ts') || entry.name.endsWith('.test.tsx')) return []
      if (entry.name.endsWith('.d.ts')) return []
      return [full]
    })
  }

  return roots.flatMap(walk).sort()
}

function sourceForScan(source: string) {
  return readFileSync(source, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*$/gm, '')
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

  test('iteration-two Spanish cost, SLO, and journal copy keeps natural diacritics', () => {
    expect(messages.es['cost.egress.description']).toContain('Atribución')
    expect(messages.es['slo.card.description']).toContain('rápida')
    expect(messages.es['slo.card.description']).toContain('señales')
    expect(messages.es['slo.coldStart']).toBe('arranque frío')
    expect(messages.es['slo.unwired.description']).toContain('inició')

    const journalCopy = [
      messages.es['incidents.journal.title'],
      messages.es['incidents.journal.description'],
      messages.es['incidents.journal.body'],
      messages.es['incidents.journal.placeholder.note'],
      messages.es['incidents.journal.placeholder.checkpoint'],
      messages.es['incidents.journal.citation.required'],
      messages.es['incidents.journal.empty'],
      messages.es['incidents.journal.truncated'],
      messages.es['incidents.journal.citation.unavailable'],
    ].join(' ')

    for (const expected of [
      'investigación',
      'remediación',
      'hipótesis',
      'observación',
      'conclusión',
      'qué',
      'referenciará',
      'Aún',
      'está',
    ]) {
      expect(journalCopy).toContain(expected)
    }
  })

  test('localized route and shared UI sources do not reintroduce cited raw English labels', () => {
    const existingLocalizedSources = [
      resolve(process.cwd(), 'src/nav/ia.ts'),
      resolve(process.cwd(), 'src/shell/CommandPalette.tsx'),
      resolve(process.cwd(), 'src/routes/OutagesPage.tsx'),
      resolve(process.cwd(), 'src/routes/AlertsPage.tsx'),
      resolve(process.cwd(), 'src/routes/SLOsPage.tsx'),
      resolve(process.cwd(), 'src/routes/CostPage.tsx'),
      resolve(process.cwd(), 'src/routes/admin/AdminCards.tsx'),
    ]
    const existingLocalizedBanned = [
      'Targets & Tests',
      'Internet outages',
      'Collective outage view',
      'External outage events',
      'Vantage-detected outages',
      'No outage signals',
      'Search commands',
      'No matching commands',
      'Go to ',
      'Create alert rule',
      'Rule updated',
      'Window (samples)',
      'Delivery channel',
      'Secrets stay write-only',
      'Service-level objectives',
      'SLO engine not wired',
      'No SLOs defined',
      'AI remediation proposals',
      'Approvals are disabled',
      'Approved (not executed)',
      'Native attribution, showback, budgets, and hourly trends; use Dashboards or Explorer for cross-plane drilldown.',
    ]
    const planesBanned = [
      'First-class workspaces for routing, flow, device, and host/L7 telemetry.',
      'Telemetry planes',
      'BGP routing events',
      'BGP routing edges',
      'Origin AS to prefix evidence folded into the tenant graph.',
      'BGP events appear here after the analyzer publishes tenant-scoped routing events.',
      'Top talkers',
      'Sampling-corrected flow contributors from the tenant flow store.',
      'Flow top talkers',
      'Flow capacity anomalies',
      'No interface departed from baseline in the current window.',
      'Network devices',
      'Managed device nodes and device-to-hop links in the topology graph.',
      'Topology device nodes',
      'Endpoint telemetry',
      'Device syslog events',
      'Authenticated device syslog rows appear here.',
      'Device config versions',
      'Versioned and redacted network configs appear here.',
      'Host/L7 service edges',
      'eBPF service edges',
      'The eBPF agent has not reported service-to-service traffic yet.',
    ]
    const highUseSources = [
      resolve(process.cwd(), 'src/routes/AskPage.tsx'),
      resolve(process.cwd(), 'src/routes/OnboardingPage.tsx'),
      resolve(process.cwd(), 'src/routes/IncidentsPage.tsx'),
      resolve(process.cwd(), 'src/routes/admin/AdminPage.tsx'),
      resolve(process.cwd(), '../ee/web/provider/ProviderConsole.tsx'),
    ]
    const highUseBanned = [
      'Ask probectl',
      'Your question',
      'Ask a question to begin',
      'Root cause cited:',
      'Investigation plan',
      'Raw signal',
      'Was this answer helpful?',
      'First-run setup',
      'Choose a producer plane',
      'Enroll an agent',
      'Create the first test',
      'Invite teammates',
      'Related signals across planes',
      'Ask about this incident',
      'Incidents by severity and recent activity',
      'Admin & Settings',
      'Register collector',
      'Secret backends',
      'Registered agents',
      'Provider plane not enabled',
      'No provider license',
      'Operator sign-in',
      'Authenticator code',
    ]

    for (const source of existingLocalizedSources) {
      const body = sourceForScan(source)
      for (const text of existingLocalizedBanned) {
        expect(body, `${source} must use the i18n catalog for ${text}`).not.toContain(text)
      }
    }

    for (const source of localizedSourceFiles()) {
      const body = sourceForScan(source)
      for (const text of planesBanned) {
        expect(body, `${source} must use the i18n catalog for ${text}`).not.toContain(text)
      }
    }

    for (const source of highUseSources) {
      const body = sourceForScan(source)
      for (const text of highUseBanned) {
        expect(body, `${source} must use the i18n catalog for ${text}`).not.toContain(text)
      }
    }
  })

  test.each([
    ['/ask', 'es', 'Preguntar (IA)', 'ltr'],
    ['/onboarding', 'es', 'Configuracion inicial', 'ltr'],
    ['/incidents', 'es', 'Incidentes', 'ltr'],
    ['/admin', 'es', 'Admin y ajustes', 'ltr'],
    ['/provider', 'es', 'Plano proveedor no habilitado', 'ltr'],
    ['/ask', 'ar-EG', 'اسأل (الذكاء الاصطناعي)', 'rtl'],
    ['/onboarding', 'ar-EG', 'إعداد التشغيل الأول', 'rtl'],
    ['/incidents', 'ar-EG', 'الحوادث', 'rtl'],
    ['/admin', 'ar-EG', 'الإدارة والإعدادات', 'rtl'],
    ['/provider', 'ar-EG', 'مستوى المزوّد غير مفعّل', 'rtl'],
  ])('locale %s renders route %s from the catalog', async (path, locale, heading, dir) => {
    vi.stubGlobal('fetch', defaultFetch())

    renderApp(path, { locale })

    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument()
    expect(document.documentElement.dir).toBe(dir)
  })

  test.each([
    [
      'es',
      'Atribución nativa, reparto de costos, presupuestos y tendencias por hora; usa Paneles o Explorador para profundizar entre planos.',
    ],
    [
      'ar-EG',
      'إسناد محلي للتكلفة، وعرض داخلي للاستهلاك، وميزانيات واتجاهات بالساعة؛ استخدم لوحات المعلومات أو المستكشف للتحليل عبر المستويات.',
    ],
  ])('Cost drilldown description uses the %s catalog', async (locale, description) => {
    vi.stubGlobal('fetch', defaultFetch())

    renderApp('/cost', { locale })

    expect(await screen.findByText(description)).toBeInTheDocument()
  })

  test('Cost drilldown description is transformed by the pseudo-locale', async () => {
    vi.stubGlobal('fetch', defaultFetch())

    renderApp('/cost', { locale: 'en-XA' })

    expect(
      await screen.findByText((text) => text.startsWith('[!! Nå') && text.endsWith('!!]')),
    ).toBeInTheDocument()
  })

  test.each(['/ask', '/onboarding', '/incidents', '/admin', '/provider', '/planes/bgp'])(
    'pseudo-locale renders %s without English route chrome',
    async (path) => {
      vi.stubGlobal('fetch', defaultFetch())

      renderApp(path, { locale: 'en-XA' })

      const headings = await screen.findAllByRole('heading', {
        name: (name) => name.startsWith('[!!') && name.endsWith('!!]'),
      })
      expect(headings.length).toBeGreaterThan(0)
      expect(document.documentElement.lang).toBe('en-xa')
      expect(document.documentElement.dir).toBe('ltr')
    },
  )

  test('Spanish locale renders the native Planes surface from the catalog', async () => {
    renderApp('/planes/bgp', { locale: 'es' })

    expect(await screen.findByRole('heading', { name: 'Planos' })).toBeInTheDocument()
    expect(document.documentElement.lang).toBe('es')
    expect(document.documentElement.dir).toBe('ltr')
    expect(screen.getByRole('tablist', { name: 'Planos de telemetria' })).toBeInTheDocument()

    const routing = await screen.findByRole('table', { name: 'Aristas de enrutamiento BGP' })
    expect(within(routing).getByText('AS64500')).toBeInTheDocument()
    expect(screen.getByText('Cobertura de enrutamiento')).toBeInTheDocument()
  })

  test('Arabic locale renders the native Planes surface in RTL from the catalog', async () => {
    renderApp('/planes/bgp', { locale: 'ar-EG' })

    expect(await screen.findByRole('heading', { name: 'المستويات' })).toBeInTheDocument()
    expect(document.documentElement.lang).toBe('ar-eg')
    expect(document.documentElement.dir).toBe('rtl')
    expect(screen.getByRole('tablist', { name: 'مستويات القياس' })).toBeInTheDocument()

    const routing = await screen.findByRole('table', { name: 'حواف توجيه BGP' })
    expect(within(routing).getByText('AS64500')).toBeInTheDocument()
    expect(screen.getByText('تغطية التوجيه')).toBeInTheDocument()
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

  test('Arabic locale renders dense surfaces in RTL from the shipped catalog', async () => {
    const user = userEvent.setup()
    vi.stubGlobal('fetch', stubWith(outageFixture()))

    renderApp('/outages', { locale: 'ar-EG' })

    expect(await screen.findByRole('heading', { name: 'انقطاعات الإنترنت' })).toBeInTheDocument()
    expect(screen.getByText('المراقبة')).toBeInTheDocument()
    expect(document.documentElement.lang).toBe('ar-eg')
    expect(document.documentElement.dir).toBe('rtl')

    const events = await screen.findByRole('table', { name: 'أحداث الانقطاع الخارجية' })
    expect(within(events).getByText('الانقطاع')).toBeInTheDocument()
    expect(within(events).getByText('حرجة')).toBeInTheDocument()
    expect(within(events).getByText('مستمر')).toBeInTheDocument()
    expect(within(events).getByRole('link', { name: 'الدليل' })).toHaveAttribute(
      'href',
      'https://ioda.inetintel.cc.gatech.edu/asn/64500',
    )

    await user.keyboard('{Meta>}k{/Meta}')
    const input = await screen.findByRole('combobox', { name: 'البحث في الأوامر' })
    expect(input).toHaveAttribute('placeholder', 'ابحث في الأوامر...')
    expect(screen.getByRole('option', { name: /انتقل إلى انقطاعات الإنترنت/ })).toBeInTheDocument()
  })

  test('/v1/me tenant locale drives the app locale when no test override is set', async () => {
    vi.stubGlobal('fetch', stubWith(outageFixture()))

    renderApp('/outages', { me: { tenant_locale: 'es' } })

    expect(await screen.findByRole('heading', { name: 'Cortes de Internet' })).toBeInTheDocument()
    await waitFor(() => expect(document.documentElement.lang).toBe('es'))
    expect(document.documentElement.dir).toBe('ltr')
  })

  test('/v1/me user locale overrides the tenant locale and flips RTL direction', async () => {
    vi.stubGlobal('fetch', stubWith(outageFixture()))

    renderApp('/outages', { me: { tenant_locale: 'es', locale: 'ar-EG' } })

    expect(await screen.findByRole('heading', { name: 'انقطاعات الإنترنت' })).toBeInTheDocument()
    await waitFor(() => expect(document.documentElement.lang).toBe('ar'))
    expect(document.documentElement.dir).toBe('rtl')
  })

  test('Spanish locale renders the outage empty state from the catalog', async () => {
    vi.stubGlobal('fetch', stubWith({ outage_running: false }))

    renderApp('/outages', { locale: 'es' })

    expect(await screen.findByText('Vista de cortes no conectada')).toBeInTheDocument()
    expect(screen.getByText(/motor de cortes desactivado/)).toBeInTheDocument()
  })
})
