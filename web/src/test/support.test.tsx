// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

/** S-EE4 surface: the Support & diagnostics card — native local process
 *  posture, build identity, deep health, and the secret-stripped bundle. */

describe('support & diagnostics (S-EE4)', () => {
  test.each([
    {
      locale: 'es',
      direction: 'ltr',
      title: 'Autoobservabilidad local del despliegue',
      metricsCaption: 'Métricas del proceso local',
      metric: 'Memoria asignada',
      uptime: 'Tiempo activo',
      buildCaption: 'Identidad de compilación',
      buildField: 'Versión',
    },
    {
      locale: 'ar-EG',
      direction: 'rtl',
      title: 'المراقبة الذاتية المحلية للنشر',
      metricsCaption: 'مقاييس العملية المحلية',
      metric: 'الذاكرة المخصصة',
      uptime: 'مدة التشغيل',
      buildCaption: 'هوية البناء',
      buildField: 'الإصدار',
    },
  ])(
    'renders self-observability from the $locale catalog',
    async ({
      locale,
      direction,
      title,
      metricsCaption,
      metric,
      uptime,
      buildCaption,
      buildField,
    }) => {
      vi.stubGlobal('fetch', defaultFetch())
      renderApp('/admin', { locale })

      expect(await screen.findByText(title)).toBeInTheDocument()
      const processMetrics = screen.getByRole('table', { name: metricsCaption })
      expect(within(processMetrics).getByText(metric)).toBeInTheDocument()
      const uptimeText = within(processMetrics).getByText(uptime).closest('tr')?.textContent ?? ''
      expect(uptimeText).toMatch(/[0-9٠-٩]/)
      // DPR-186: uptime is a DURATION now ("2h 0min"), not a count of seconds,
      // and the units still come from the locale rather than a hard-coded
      // letter — Spanish "min" and Arabic "د" are the platform's wording, not
      // ours. What must not happen is one locale rendering the other's units.
      expect(uptimeText).toMatch(locale === 'es' ? /\d+\s*(h|min|s)/ : /[٠-٩0-9]\s*(س|د|ث)/)
      expect(uptimeText).not.toContain(locale === 'es' ? 'ث' : 'min')
      const build = screen.getByRole('table', { name: buildCaption })
      expect(within(build).getByText(buildField)).toBeInTheDocument()
      expect(document.documentElement.dir).toBe(direction)
    },
  )

  test('renders native self-observability, findings, component checks, and the bundle link', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/admin')

    expect(await screen.findByText('Support & diagnostics')).toBeInTheDocument()
    // The secret-stripped bundle download.
    expect(screen.getByRole('link', { name: /download support bundle/i })).toHaveAttribute(
      'href',
      '/v1/diagnostics/bundle',
    )
    const findings = await screen.findByRole('table', {
      name: /actionable readiness findings/i,
    })
    expect(
      within(findings).getByText('Control-plane writes are temporarily fenced'),
    ).toBeInTheDocument()
    expect(within(findings).getByText('Warning')).toBeInTheDocument()
    expect(
      within(findings).getByRole('link', { name: /download redacted support bundle/i }),
    ).toHaveAttribute('href', '/v1/diagnostics/bundle')
    expect(
      screen.getByRole('link', { name: /download support bundle/i }).closest('p'),
    ).toHaveTextContent(/1 finding/)
    expect(document.querySelector('time[datetime="2026-06-06T00:00:00.000Z"]')).toBeInTheDocument()
    const processMetrics = screen.getByRole('table', { name: /local process metrics/i })
    expect(within(processMetrics).getByText('Goroutines').closest('tr')).toHaveTextContent('12')
    expect(within(processMetrics).getByText('Allocated memory').closest('tr')).toHaveTextContent(
      '1 MiB',
    )
    expect(
      within(processMetrics).getByText('Process capacity (GOMAXPROCS)').closest('tr'),
    ).toHaveTextContent('8')
    const build = screen.getByRole('table', { name: /build identity/i })
    expect(within(build).getByText('Version').closest('tr')).toHaveTextContent('1.1.0')
    expect(within(build).getByText('Commit').closest('tr')).toHaveTextContent('abc1234')
    expect(within(build).getByText('Platform').closest('tr')).toHaveTextContent('linux/arm64')
    expect(screen.getByText(/administrator-only process posture/i)).toHaveTextContent(
      /no tenant identity or telemetry/i,
    )
    // Per-component deep health.
    const table = await screen.findByRole('table', {
      name: /component health/i,
    })
    const clusterRow = within(table).getByText('cluster').closest('tr')!
    expect(within(clusterRow).getByText('Degraded')).toBeInTheDocument()
    const dbRow = within(table).getByText('database').closest('tr')!
    expect(within(dbRow).getByText('OK')).toBeInTheDocument()
  })

  test('does not infer health when an older replica omits finding details', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
        pathOf(input) === '/v1/diagnostics'
          ? Promise.resolve(
              jsonResponse({
                status: 'degraded',
                checked_at: '2026-06-06T00:00:00Z',
                checks: [{ name: 'cluster', status: 'degraded', detail: 'writes are fenced' }],
              }),
            )
          : fallback(input, init),
      ),
    )

    renderApp('/admin')

    expect(await screen.findByRole('alert')).toHaveTextContent(/missing finding details/i)
    expect(screen.getByText('Finding details unavailable')).toBeInTheDocument()
    expect(screen.queryByText('No readiness findings')).not.toBeInTheDocument()
    expect(
      screen.getByText(/local process metrics are unavailable or incomplete/i),
    ).toHaveTextContent(/no healthy state is being inferred/i)
    expect(screen.getByText(/build identity is unavailable or incomplete/i)).toHaveTextContent(
      /no version is being guessed/i,
    )
    expect(screen.queryByRole('table', { name: /local process metrics/i })).not.toBeInTheDocument()
  })

  test('keeps a retry action when diagnostics cannot be loaded', async () => {
    const user = userEvent.setup()
    const fallback = defaultFetch()
    let diagnosticsCalls = 0
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        if (pathOf(input) !== '/v1/diagnostics') return fallback(input, init)
        diagnosticsCalls += 1
        if (diagnosticsCalls <= 2) {
          return Promise.resolve(
            jsonResponse({ error: { code: 'unavailable', message: 'local check failed' } }, 503),
          )
        }
        return fallback(input, init)
      }),
    )

    renderApp('/admin')

    expect(
      await screen.findByText(/could not load diagnostics.*no healthy state is being inferred/i, {
        selector: 'p',
      }),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /retry diagnostics/i }))
    expect(
      await screen.findByText('Control-plane writes are temporarily fenced'),
    ).toBeInTheDocument()
    expect(diagnosticsCalls).toBe(3)
  })
})
