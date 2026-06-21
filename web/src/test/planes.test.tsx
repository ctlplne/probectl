import { describe, expect, test } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'

describe('plane workspaces', () => {
  test('renders native BGP, flow, device, and eBPF tabs', async () => {
    renderApp('/planes')

    expect(await screen.findByRole('heading', { name: /planes/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'BGP' })).toHaveAttribute('aria-selected', 'true')
    expect(await screen.findByRole('table', { name: /bgp routing edges/i })).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: 'Flow' }))
    const topTalkers = await screen.findByRole('table', { name: /flow top talkers/i })
    expect(within(topTalkers).getByText('10.0.0.10')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: 'Device' }))
    expect(await screen.findByRole('table', { name: /topology device nodes/i })).toBeInTheDocument()
    expect(screen.getByText('edge-r1')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: 'eBPF' }))
    const ebpf = await screen.findByRole('table', { name: /ebpf service edges/i })
    expect(within(ebpf).getByText('checkout')).toBeInTheDocument()
  })
})
