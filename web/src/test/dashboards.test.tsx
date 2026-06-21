import { describe, expect, test } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderApp } from './renderApp'

describe('curated dashboards', () => {
  test('renders a native dashboard instead of the placeholder route', async () => {
    renderApp('/dashboards')

    expect(await screen.findByRole('heading', { name: /dashboards/i })).toBeInTheDocument()
    expect(screen.queryByText(/lands in a later sprint/i)).not.toBeInTheDocument()

    expect(await screen.findByText('Open incidents')).toBeInTheDocument()
    expect(screen.getByText('Synthetic success')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: /cost trend/i })).toBeInTheDocument()

    const flow = await screen.findByRole('table', { name: /top flow contributors dashboard/i })
    expect(within(flow).getByText('10.0.0.10')).toBeInTheDocument()

    const incidents = screen.getByRole('table', { name: /open incident dashboard/i })
    expect(within(incidents).getByText(/checkout latency/i)).toBeInTheDocument()
  })
})
