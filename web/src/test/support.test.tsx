import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderApp } from './renderApp'
import { defaultFetch } from './fetchStub'

/** S-EE4 surface: the Support & diagnostics card — deep health per component
 *  + the secret-stripped support-bundle download. */

describe('support & diagnostics (S-EE4)', () => {
  test('renders the aggregate status, per-component checks, and the bundle link', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/admin')

    expect(await screen.findByText('Support & diagnostics')).toBeInTheDocument()
    // The secret-stripped bundle download.
    expect(screen.getByRole('link', { name: /download support bundle/i })).toHaveAttribute(
      'href',
      '/v1/diagnostics/bundle',
    )
    // Per-component deep health.
    const table = (await screen.findByRole('table', { name: /component health/i })) as HTMLTableElement
    const clusterRow = within(table).getByText('cluster').closest('tr')!
    expect(within(clusterRow).getByText('Degraded')).toBeInTheDocument()
    const dbRow = within(table).getByText('database').closest('tr')!
    expect(within(dbRow).getByText('OK')).toBeInTheDocument()
  })
})
