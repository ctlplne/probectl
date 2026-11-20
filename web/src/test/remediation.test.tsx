// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { Providers } from '../App'
import { AuthContext } from '../auth/AuthProvider'
import { IncidentRoutingProposal } from '../routes/IncidentRoutingProposal'
import { TimeProvider } from '../time/TimeProvider'
import { renderApp } from './renderApp'
import { jsonResponse, defaultFetch, pathOf } from './fetchStub'
import type { Proposal } from '../api/remediation'
import type { RemediationRTBHReview } from '../api/sdk.gen'

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

function licensedFetch(opts?: {
  approvals?: boolean
  proposal?: Proposal
  currentRoutingReview?: () => Promise<RemediationRTBHReview | Response>
  onDecide?: (url: string, body: unknown) => void
}) {
  const base = defaultFetch()
  // Stateful: a decision persists so the post-mutation list refetch reflects it.
  let row = { ...(opts?.proposal ?? proposals[0]) }
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/v1/remediation/proposals') && (init?.method ?? 'GET') === 'GET')
      return jsonResponse({ items: [row], approvals_enabled: opts?.approvals ?? false })
    if (
      url.endsWith('/v1/remediation/proposals/rem-1/routing-review') &&
      opts?.currentRoutingReview
    ) {
      const review = await opts.currentRoutingReview()
      return review instanceof Response ? review : jsonResponse(review)
    }
    if (url.includes('/v1/remediation/proposals/rem-1/') && init?.method === 'POST') {
      opts?.onDecide?.(url, JSON.parse(String(init.body)))
      row = {
        ...row,
        state: url.endsWith('/approve') ? 'approved' : 'rejected',
        decided_by: 'user:dev@probectl.local',
      }
      return jsonResponse(row)
    }
    return base(input, init)
  }) as unknown as typeof fetch
}

async function tabUntil(user: ReturnType<typeof userEvent.setup>, target: HTMLElement) {
  for (let i = 0; i < 80; i++) {
    await user.tab()
    if (document.activeElement === target) return
  }
  throw new Error(
    `tab order did not reach ${target.textContent ?? target.getAttribute('aria-label')}`,
  )
}

describe('guarded remediation (S-EE5)', () => {
  test('hidden-unlicensed: the default 404 renders no card at all', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/admin')
    // Anchor on a sibling card so the page is fully rendered first.
    expect(await screen.findByText(/data lifecycle/i)).toBeInTheDocument()
    expect(screen.queryByText(/ai remediation proposals/i)).not.toBeInTheDocument()
  })

  test('advisory-only (default): the row never decides — a decision happens only in the review dialog, where Approve is disabled and Reject is keyboard reachable', async () => {
    const user = userEvent.setup()
    const calls: { url: string; body: unknown }[] = []
    vi.stubGlobal(
      'fetch',
      licensedFetch({ approvals: false, onDecide: (url, body) => calls.push({ url, body }) }),
    )
    const { container } = renderApp('/admin')
    expect(await screen.findByText(/ai remediation proposals/i)).toBeInTheDocument()
    expect(screen.getByText(/reroute around failing hop/i)).toBeInTheDocument()
    expect(screen.getByText(/advisory-only/i)).toBeInTheDocument()
    // WEB-21/G8: no decision control sits on the row; a single stray click
    // cannot approve or reject. Only a Review button that opens the gate.
    expect(screen.queryByRole('button', { name: /^approve$/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^reject$/i })).not.toBeInTheDocument()

    const review = screen.getByRole('button', { name: /review/i })
    await tabUntil(user, review)
    await user.keyboard('{Enter}')

    const dialog = await screen.findByRole('dialog')
    // The operator sees the dry-run blast radius and the never-executes guardrail.
    expect(within(dialog).getByText(/never executes/i)).toBeInTheDocument()
    expect(await axe(container)).toHaveNoViolations()

    const approve = within(dialog).getByRole('button', { name: /approve/i })
    expect(approve).toBeDisabled()
    const reject = within(dialog).getByRole('button', { name: /reject/i })
    expect(reject).toBeEnabled()
    await tabUntil(user, reject)
    expect(reject).toHaveFocus()
    await user.keyboard('{Enter}')

    expect(await screen.findByText(/rejected/i)).toBeInTheDocument()
    expect(calls).toHaveLength(1)
    expect(calls[0].url).toMatch(/\/remediation\/proposals\/rem-1\/reject$/)
  })

  test('approvals enabled: keyboard Approve in the review dialog posts to the approve route (human sign-off, no execution)', async () => {
    const user = userEvent.setup()
    const calls: { url: string; body: unknown }[] = []
    vi.stubGlobal(
      'fetch',
      licensedFetch({ approvals: true, onDecide: (url, body) => calls.push({ url, body }) }),
    )
    renderApp('/admin')
    const review = await screen.findByRole('button', { name: /review/i })
    await tabUntil(user, review)
    await user.keyboard('{Enter}')
    const dialog = await screen.findByRole('dialog')
    const approve = within(dialog).getByRole('button', { name: /approve/i })
    expect(approve).toBeEnabled()
    await tabUntil(user, approve)
    expect(approve).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(await screen.findByText(/approved \(not executed\)/i)).toBeInTheDocument()
    expect(calls).toHaveLength(1)
    expect(calls[0].url).toMatch(/\/remediation\/proposals\/rem-1\/approve$/)
  })

  test('the gate holds: cancelling the review dialog posts no decision (G8 human gate)', async () => {
    const user = userEvent.setup()
    const calls: { url: string; body: unknown }[] = []
    vi.stubGlobal(
      'fetch',
      licensedFetch({ approvals: true, onDecide: (url, body) => calls.push({ url, body }) }),
    )
    renderApp('/admin')
    await user.click(await screen.findByRole('button', { name: /review/i }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: /cancel/i }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(calls).toHaveLength(0)
    // Still proposed — nothing decided it.
    expect(screen.getByText(/reroute around failing hop/i)).toBeInTheDocument()
  })

  test('routing approval requires the fetched review handle covering the exact declared limit', async () => {
    const user = userEvent.setup()
    const decision = vi.fn()
    let allowReview: (() => void) | undefined
    const wait = new Promise<void>((release) => {
      allowReview = release
    })
    const fingerprint = 'a'.repeat(64)
    vi.stubGlobal(
      'fetch',
      licensedFetch({
        approvals: true,
        proposal: { ...proposals[0], kind: 'rtbh_review', title: 'Routing mitigation review' },
        currentRoutingReview: async () => {
          await wait
          return {
            candidate: {
              preview_fingerprint: 'b'.repeat(64),
              announcement: { family: 'ipv4', prefix: '192.0.2.0/26', community: '64512:100' },
              impact: {
                prefix: '192.0.2.0/26',
                from: '2026-11-19T07:00:00Z',
                to: '2026-11-19T07:05:00Z',
                observed_records: 6,
                observed_addresses: 2,
                sampled: true,
                matched: { bytes: '9007199254740993', packets: '101' },
                known_benign: { bytes: '23', packets: '3' },
                unclassified: { bytes: '9007199254740970', packets: '98' },
              },
            },
            max_known_benign_packets: '4',
            blast_radius: 64,
            expires_at: new Date(Date.now() + 60000).toISOString(),
            review_fingerprint: fingerprint,
          }
        },
        onDecide: decision,
      }),
    )
    renderApp('/admin', { me: { permissions: ['remediation.approve'] } })
    await user.click(await screen.findByRole('button', { name: /review/i }))
    const dialog = await screen.findByRole('dialog')
    const approve = within(dialog).getByRole('button', { name: /approve/i })
    expect(approve).toBeDisabled()
    expect(decision).not.toHaveBeenCalled()
    allowReview?.()
    expect(await within(dialog).findByText('9007199254740993 bytes · 101 packets')).toBeVisible()
    await waitFor(() => expect(approve).toBeEnabled())
    await user.click(approve)
    expect(await screen.findByText(/approved \(not executed\)/i)).toBeInTheDocument()
    expect(decision).toHaveBeenCalledWith(expect.stringMatching(/\/approve$/), {
      note: '',
      review_fingerprint: fingerprint,
    })
  })

  test('a stale routing review keeps approval disabled and lets the reviewer decline', async () => {
    const user = userEvent.setup()
    const decide = vi.fn()
    vi.stubGlobal(
      'fetch',
      licensedFetch({
        approvals: true,
        proposal: { ...proposals[0], kind: 'rtbh_review', title: 'Routing mitigation review' },
        currentRoutingReview: async () =>
          jsonResponse({ error: { code: 'review_changed', message: 'Evidence changed.' } }, 409),
        onDecide: decide,
      }),
    )
    renderApp('/admin', { me: { permissions: ['remediation.approve'] } })
    await user.click(await screen.findByRole('button', { name: /review/i }))
    const dialog = within(await screen.findByRole('dialog'))
    expect(await dialog.findByRole('alert')).toHaveTextContent(
      'Current routing evidence is unavailable.',
    )
    expect(dialog.getByRole('button', { name: /^approve$/i })).toBeDisabled()
    expect(decide).not.toHaveBeenCalled()
    await user.click(dialog.getByRole('button', { name: /^reject$/i }))
    expect(await screen.findByText(/rejected/i)).toBeVisible()
    expect(decide).toHaveBeenCalledExactlyOnceWith(expect.stringMatching(/\/reject$/), { note: '' })
  })
})

test('the routing form binds the current scoped preview and preserves an exact packet limit', async () => {
  const user = userEvent.setup()
  const onPreview = vi.fn()
  const onFile = vi.fn()
  const base = defaultFetch()
  const receipt = 'a'.repeat(64)
  const fingerprint = 'b'.repeat(64)
  const observedTo = '2026-11-19T07:05:00Z'
  const exactLimit = '9007199254740993'
  const view = {
    id: 'whole-view',
    version: 'v3',
    definition: { name: 'Whole prefix', time: { mode: 'lookback', lookback_seconds: 300 } },
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathOf(input)
      const laterPage = String(input).includes('cursor=next')
      if (path === '/v1/entity-contexts') {
        return jsonResponse(
          laterPage
            ? { items: [{ context_id: 'west', site_label: 'West', vrf_label: 'Edge' }] }
            : { items: [], next_cursor: 'next' },
        )
      }
      if (path === '/v1/entities') {
        expect(String(input)).toContain('context_id=west')
        return jsonResponse(
          laterPage
            ? {
                items: [
                  {
                    id: 'partner',
                    kind: 'prefix',
                    network_prefix: '198.51.100.0/24',
                    label: 'Partner',
                  },
                ],
              }
            : {
                items: [
                  {
                    id: 'protected',
                    kind: 'prefix',
                    network_prefix: '192.0.2.0/26',
                    label: 'Edge',
                  },
                ],
                next_cursor: 'next',
              },
        )
      }
      if (path === '/v1/explorer/flow-views') {
        return jsonResponse({
          items: [
            view,
            {
              ...view,
              id: 'filtered',
              definition: { ...view.definition, name: 'Filtered view', plan: { filter: {} } },
            },
          ],
        })
      }
      if (path === '/v1/remediation/rtbh-templates') return jsonResponse({ items: [] })
      if (path === '/v1/remediation/rtbh-preview' && init?.method === 'POST') {
        const body = JSON.parse(String(init.body))
        onPreview(body)
        return jsonResponse({
          announcement: { family: 'ipv4', prefix: '192.0.2.0/26', community: body.community },
          preview_fingerprint: fingerprint,
          impact: {
            to: observedTo,
            known_benign: { packets: exactLimit },
            unclassified: { packets: '98' },
          },
        })
      }
      if (path === '/v1/remediation/rtbh-proposals' && init?.method === 'POST') {
        const body = JSON.parse(String(init.body))
        onFile(body)
        return body.max_known_benign_packets === exactLimit
          ? jsonResponse({ id: 'routing-proposal', state: 'proposed' }, 201)
          : jsonResponse({ error: { message: 'The declared packet limit was exceeded.' } }, 409)
      }
      return base(input, init)
    }),
  )
  render(
    <Providers>
      <AuthContext.Provider
        value={{
          tenant: { id: 'tenant-a', name: 'Tenant A', slug: 'tenant-a' },
          tenants: [],
          user: { id: 'proposer', name: 'Proposer', email: 'proposer@local.test' },
          permissions: ['remediation.propose'],
          switchTenant: () => {},
          signOut: () => {},
        }}
      >
        <TimeProvider>
          <IncidentRoutingProposal
            rule="rule-a"
            receipt={receipt}
            prefix="192.0.2.0/26"
            windowSeconds={300}
          />
        </TimeProvider>
      </AuthContext.Provider>
    </Providers>,
  )
  const preview = screen.getByRole('button', { name: 'Preview scoped collateral' })
  expect(preview).toBeDisabled()
  await user.click(await screen.findByRole('button', { name: 'Load more routing contexts' }))
  await user.selectOptions(
    screen.getByLabelText('Routing context'),
    await screen.findByRole('option', { name: 'West / Edge' }),
  )
  const protectedPrefix = screen.getByLabelText('Protected prefix')
  await user.selectOptions(
    protectedPrefix,
    await within(protectedPrefix).findByRole('option', { name: '192.0.2.0/26 · Edge' }),
  )
  await user.click(await screen.findByRole('button', { name: 'Load more configured prefixes' }))
  await user.selectOptions(
    screen.getByLabelText('Known benign source prefix'),
    await screen.findByRole('option', { name: '198.51.100.0/24 · Partner' }),
  )
  await user.type(screen.getByLabelText('Search saved whole-prefix views'), 'Whole')
  await user.selectOptions(
    screen.getByLabelText('Whole-prefix flow view'),
    await screen.findByRole('option', { name: 'Whole prefix' }),
  )
  expect(screen.queryByRole('option', { name: 'Filtered view' })).not.toBeInTheDocument()
  await user.type(screen.getByLabelText('Community from your routing policy'), '64512:100')
  expect(preview).toBeDisabled()
  await user.click(screen.getByRole('checkbox', { name: /checked this community/i }))
  await user.click(preview)
  expect(await screen.findByText(`${exactLimit} packets`)).toBeVisible()
  const previewInput = {
    rule_id: 'rule-a',
    receipt_fingerprint: receipt,
    context_id: 'west',
    protected_entity_id: 'protected',
    benign_entity_id: 'partner',
    whole_view_id: 'whole-view',
    whole_view_version: 'v3',
    community: '64512:100',
    routing_policy_agreed: true,
  }
  expect(onPreview).toHaveBeenCalledExactlyOnceWith(previewInput)
  const file = screen.getByRole('button', { name: 'File exact routing proposal' })
  expect(file).toBeDisabled()
  const limit = screen.getByLabelText('Maximum known benign packets')
  await user.type(limit, '10')
  await user.click(file)
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'The declared packet limit was exceeded.',
  )
  await user.clear(limit)
  await user.type(limit, exactLimit)
  await user.click(file)
  expect(
    await screen.findByText('Routing proposal filed for independent review in Admin.'),
  ).toHaveAttribute('role', 'status')
  expect(file).toBeDisabled()
  expect(onFile).toHaveBeenLastCalledWith({
    preview: previewInput,
    observed_to: observedTo,
    preview_fingerprint: fingerprint,
    max_known_benign_packets: exactLimit,
  })
  await user.clear(screen.getByLabelText('Community from your routing policy'))
  expect(file).not.toBeInTheDocument()
  expect(preview).toBeDisabled()
})
