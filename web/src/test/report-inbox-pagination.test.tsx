// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { cleanup, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { expect, test, vi } from 'vitest'
import { defaultFetch, jsonResponse } from './fetchStub'
import { renderApp } from './renderApp'

for (const theme of ['light', 'dark'] as const) {
  for (const tenant of [
    '00000000-0000-4000-8000-000000000101',
    '00000000-0000-4000-8000-000000000102',
  ]) {
    test(`complete report inbox pages stay private: ${theme} ${tenant}`, async () => {
      const storage = Object.getOwnPropertyDescriptor(window, 'localStorage')
      Object.defineProperty(window, 'localStorage', {
        configurable: true,
        enumerable: true,
        value: { getItem: () => theme, setItem: vi.fn() },
      })
      try {
        const rest = defaultFetch()
        const requests: URL[] = []
        const artifact = (index: number) => ({
          id: `same-${index}`,
          dashboard_id: 'same-inbox',
          format: 'csv',
          filename: `${tenant}-private-${index}.csv`,
          media_type: 'text/csv',
          generated_by: 'owned-user',
          generated_at: '2026-11-05T00:00:00Z',
          absolute_from: '2026-11-04T23:00:00Z',
          absolute_to: '2026-11-05T00:00:00Z',
          provenance: [],
          coverage_limitations: [],
          redaction_state: 'none',
          download_url: `/v1/dashboard-report-artifacts/same-${index}`,
        })
        vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = new URL(
            typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
            'https://localhost',
          )
          if (url.pathname === '/v1/dashboard-report-artifacts') {
            requests.push(url)
            const cursor = url.searchParams.get('cursor')
            if (cursor && cursor !== `${tenant}-older`) {
              return jsonResponse({ error: { message: 'Cursor scope differs' } }, 400)
            }
            return jsonResponse({
              items: Array.from({ length: 5 }, (_, index) => artifact(index + (cursor ? 6 : 1))),
              ...(cursor ? {} : { next_cursor: `${tenant}-older` }),
            })
          }
          return rest(input, init)
        })
        renderApp('/dashboards', { me: { tenant_id: tenant, permissions: ['metrics.read'] } })
        await screen.findByRole('link', { name: `${tenant}-private-1.csv` })
        const inbox = screen
          .getByRole('heading', { name: 'Tenant report inbox' })
          .closest('section')!
        const page = within(inbox)
        expect(
          page.getAllByRole('link'),
          'complete inbox page still clipped to four records',
        ).toHaveLength(5)
        expect(page.getByRole('button', { name: 'Newer reports' })).toBeDisabled()
        const user = userEvent.setup()
        await user.click(page.getByRole('button', { name: 'Older reports' }))
        await page.findByRole('link', { name: `${tenant}-private-10.csv` })
        expect(
          page.queryByRole('link', { name: `${tenant}-private-1.csv` }),
        ).not.toBeInTheDocument()
        expect(page.getAllByRole('link')).toHaveLength(5)
        expect(page.getByRole('button', { name: 'Older reports' })).toBeDisabled()
        expect(requests.some((url) => url.searchParams.get('cursor') === `${tenant}-older`)).toBe(
          true,
        )
        await user.click(page.getByRole('button', { name: 'Newer reports' }))
        await page.findByRole('link', { name: `${tenant}-private-5.csv` })
        await waitFor(() =>
          expect(page.getByRole('button', { name: 'Older reports' })).toBeEnabled(),
        )
        expect(document.documentElement).toHaveAttribute('data-theme', theme)
        expect(await axe(inbox)).toHaveNoViolations()
      } finally {
        cleanup()
        if (storage) Object.defineProperty(window, 'localStorage', storage)
      }
    })
  }
}
