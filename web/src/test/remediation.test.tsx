import { describe, expect, test, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse, defaultFetch } from './fetchStub'
import type { Proposal } from '../api/remediation'

/** S-EE5 surface: the AI remediation proposals card on Admin. ee-backed:
 *  unlicensed deployments answer 404 and the card renders NOTHING
 *  (hidden-unlicensed). probectl NEVER executes — Approve is a recorded sign-off
 *  and is disabled entirely when approvals are advisory-only (the default). */

const proposals: Proposal[] = [
  {
    id: 'rem-1',
    kind: 'reroute_suggestion',
    title: 'Reroute around failing hop 10.0.0.1',
    target: 'hop:10.0.0.1',
    dry_run: { blast_radius: 3, impacted_services: ['checkout'] },
    state: 'proposed',
    proposed_by: 'ai:propose_remediation',
    created_at: '2026-06-05T00:00:00Z',
  },
]

function licensedFetch(opts?: { approvals?: boolean; onDecide?: (url: string, body: unknown) => void }) {
  const base = defaultFetch() as unknown as (i: RequestInfo | URL, n?: RequestInit) => Promise<Response>
  // Stateful: a decision persists so the post-mutation list refetch reflects it.
  let row = { ...proposals[0] }
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/v1/remediation/proposals') && (init?.method ?? 'GET') === 'GET')
      return jsonResponse({ items: [row], approvals_enabled: opts?.approvals ?? false })
    if (url.includes('/v1/remediation/proposals/rem-1/') && init?.method === 'POST') {
      opts?.onDecide?.(url, JSON.parse(String(init.body)))
      row = { ...row, state: url.endsWith('/approve') ? 'approved' : 'rejected', decided_by: 'user:dev@probectl.local' }
      return jsonResponse(row)
    }
    return base(input, init)
  }) as unknown as typeof fetch
}

describe('guarded remediation (S-EE5)', () => {
  test('hidden-unlicensed: the default 404 renders no card at all', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/admin')
    // Anchor on a sibling card so the page is fully rendered first.
    expect(await screen.findByText(/data lifecycle/i)).toBeInTheDocument()
    expect(screen.queryByText(/ai remediation proposals/i)).not.toBeInTheDocument()
  })

  test('advisory-only (default): proposals render but Approve is disabled', async () => {
    vi.stubGlobal('fetch', licensedFetch({ approvals: false }))
    renderApp('/admin')
    expect(await screen.findByText(/ai remediation proposals/i)).toBeInTheDocument()
    expect(screen.getByText(/reroute around failing hop/i)).toBeInTheDocument()
    expect(screen.getByText(/advisory-only/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /approve/i })).toBeDisabled()
  })

  test('approvals enabled: Approve posts to the approve route (human sign-off, no execution)', async () => {
    const calls: { url: string; body: unknown }[] = []
    vi.stubGlobal('fetch', licensedFetch({ approvals: true, onDecide: (url, body) => calls.push({ url, body }) }))
    renderApp('/admin')
    const approve = await screen.findByRole('button', { name: /approve/i })
    expect(approve).toBeEnabled()
    await userEvent.click(approve)
    expect(await screen.findByText(/approved \(not executed\)/i)).toBeInTheDocument()
    expect(calls).toHaveLength(1)
    expect(calls[0].url).toMatch(/\/remediation\/proposals\/rem-1\/approve$/)
  })
})
