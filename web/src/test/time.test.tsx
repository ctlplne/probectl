import { afterEach, describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { formatDateTime, resolveTimeZone } from '../time/format'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'

const INCIDENT_TIME = '2026-06-05T10:00:00Z'
const NEW_YORK_ZONE = /EDT|GMT-4/
const TOKYO_ZONE = /JST|GMT\+9/

const incident = {
  id: 'inc-time-1',
  tenant_id: 't',
  status: 'open',
  severity: 'critical',
  title: 'high loss to 192.0.2.10',
  target: '192.0.2.10',
  prefix: '',
  started_at: INCIDENT_TIME,
  last_seen_at: '2026-06-05T10:01:00Z',
  signal_count: 1,
  signals: [
    {
      plane: 'network',
      kind: 'alert.firing',
      severity: 'critical',
      title: 'high loss to 192.0.2.10',
      target: '192.0.2.10',
      occurred_at: INCIDENT_TIME,
    },
  ],
}

afterEach(() => {
  vi.unstubAllEnvs()
})

function stubIncidents() {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = requestURL(input)
      if (url.endsWith('/v1/incidents')) return jsonResponse({ items: [incident] })
      if (url.endsWith('/v1/incidents/inc-time-1')) return jsonResponse(incident)
      return jsonResponse({ error: { code: 'not_found', message: `unstubbed ${url}` } }, 404)
    }),
  )
}

function requestURL(input: RequestInfo | URL) {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.href
  return input.url
}

describe('timezone-aware DateTime rendering', () => {
  test.each(['America/New_York', 'Asia/Tokyo'])(
    'UTC fallback stays deterministic when browser TZ=%s',
    async (browserTZ) => {
      vi.stubEnv('TZ', browserTZ)
      stubIncidents()

      renderApp('/incidents')

      const table = await screen.findByRole('table', {
        name: /incidents by severity and recent activity/i,
      })
      expect(within(table).getAllByText(/UTC/).length).toBeGreaterThan(0)
      expect(screen.getByRole('button', { name: 'UTC' })).toHaveAttribute('aria-pressed', 'true')
    },
  )

  test('tenant timezone renders with a zone label and can toggle back to UTC', async () => {
    const user = userEvent.setup()
    vi.stubEnv('TZ', 'Asia/Tokyo')
    stubIncidents()

    renderApp('/incidents', { me: { tenant_time_zone: 'America/New_York' } })

    const table = await screen.findByRole('table', {
      name: /incidents by severity and recent activity/i,
    })
    expect(within(table).getAllByText(NEW_YORK_ZONE).length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: /New York/i })).toHaveAttribute(
      'aria-pressed',
      'true',
    )

    await user.click(screen.getByRole('button', { name: 'UTC' }))

    expect(within(table).getAllByText(/UTC/).length).toBeGreaterThan(0)
  })

  test('formatter always includes an explicit zone label', () => {
    expect(formatDateTime(INCIDENT_TIME, { locale: 'en', timeZone: 'UTC' }).text).toMatch(/UTC/)
    expect(
      formatDateTime(INCIDENT_TIME, { locale: 'en', timeZone: 'America/New_York' }).text,
    ).toMatch(NEW_YORK_ZONE)
    expect(formatDateTime(INCIDENT_TIME, { locale: 'en', timeZone: 'Asia/Tokyo' }).text).toMatch(
      TOKYO_ZONE,
    )
    expect(resolveTimeZone('Not/A_Zone')).toBe('UTC')
  })
})
