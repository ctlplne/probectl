// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
import { renderApp } from './renderApp'
import { assertNoDoublePrefix, defaultFetch, jsonResponse, pathOf } from './fetchStub'

const contextID = '00000000-0000-4000-8000-000000000072'
const kinds = ['device', 'interface', 'prefix', 'agent', 'test', 'exporter'] as const

function subjectFetch(resolve: (url: URL, init?: RequestInit) => Promise<Response>) {
  const base = defaultFetch()
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    assertNoDoublePrefix(input)
    if (pathOf(input) === '/v1/entity-contexts')
      return jsonResponse({
        items: [
          {
            context_id: contextID,
            site_id: contextID,
            vrf_id: contextID,
            site_label: 'site',
            vrf_label: 'vrf',
          },
        ],
      })
    if (pathOf(input).endsWith('/resolved-tags')) {
      const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      return resolve(new URL(raw, 'https://probectl.test'), init)
    }
    return base(input, init)
  })
}

function response(kind: string, value: string) {
  return jsonResponse({
    context_id: contextID,
    target_kind: kind,
    tag_revision: '9007199254740993',
    as_of: '2026-11-03T00:00:00Z',
    items: [{ tag_id: 'tag', key: 'customer', value, source: 'rule' }],
  })
}

async function chooseContext() {
  const card = (await screen.findByText('Effective subject tags')).closest(
    '[data-tag-subject-resolution]',
  ) as HTMLElement
  const select = within(card).getByLabelText('Effective-tag routing context')
  await waitFor(() =>
    expect(within(select).getByRole('option', { name: 'site / vrf' })).toBeInTheDocument(),
  )
  fireEvent.change(select, { target: { value: contextID } })
  return card
}

describe('effective subject tags', () => {
  test.each([
    { tenant: '00000000-0000-4000-8000-000000000001', theme: 'light' },
    { tenant: '00000000-0000-4000-8000-000000000002', theme: 'dark' },
  ])('resolves all six references for $tenant in $theme', async ({ tenant, theme }) => {
    const calls: URL[] = []
    vi.stubGlobal(
      'fetch',
      subjectFetch(async (url, init) => {
        expect(new Headers(init?.headers).get('X-Probectl-Tenant')).toBe(tenant)
        calls.push(url)
        return response(url.searchParams.get('target_kind') ?? '', `${tenant}-value`)
      }),
    )
    renderApp('/admin', { me: { tenant_id: tenant, permissions: ['tags.read', 'entities.read'] } })
    document.documentElement.setAttribute('data-theme', theme)
    document.documentElement.classList.toggle('dark', theme === 'dark')
    const card = await chooseContext()
    const user = userEvent.setup()
    for (const kind of kinds) {
      fireEvent.change(within(card).getByLabelText('Effective-tag subject kind'), {
        target: { value: kind },
      })
      if (kind === 'exporter') {
        fireEvent.change(within(card).getByLabelText('Effective-tag exporter agent ID'), {
          target: { value: 'registered-agent' },
        })
        fireEvent.change(within(card).getByLabelText('Effective-tag exporter source reference'), {
          target: { value: '192.0.2.9' },
        })
      } else {
        fireEvent.change(within(card).getByLabelText('Effective-tag subject ID'), {
          target: { value: `owned-${kind}` },
        })
      }
      expect(within(card).queryByText(`${tenant}-value`)).not.toBeInTheDocument()
      await user.click(within(card).getByRole('button', { name: 'Resolve effective tags' }))
      expect(await within(card).findByText(`${tenant}-value`)).toBeInTheDocument()
      expect(within(card).getByText(/9007199254740993/)).toBeInTheDocument()
      expect(within(card).getByText('2026-11-03T00:00:00Z')).toBeInTheDocument()
      const query = calls.at(-1)!.searchParams
      expect([...query.keys()].sort()).toEqual(
        kind === 'exporter'
          ? ['exporter_agent_id', 'exporter_source_ref', 'target_kind']
          : ['target_id', 'target_kind'],
      )
    }
    expect(calls).toHaveLength(6)
  })

  test('discards an old inflight result after the target changes', async () => {
    let finishOld: ((value: Response) => void) | undefined
    let oldSignal: AbortSignal | null | undefined
    vi.stubGlobal(
      'fetch',
      subjectFetch(async (url, init) => {
        if (url.searchParams.get('target_id') === 'old-target') {
          oldSignal = init?.signal
          return new Promise<Response>((resolve) => {
            finishOld = resolve
          })
        }
        return response('device', 'current-value')
      }),
    )
    renderApp('/admin', { me: { permissions: ['tags.read', 'entities.read'] } })
    const card = await chooseContext()
    const field = within(card).getByLabelText('Effective-tag subject ID')
    fireEvent.change(field, { target: { value: 'old-target' } })
    fireEvent.click(within(card).getByRole('button', { name: 'Resolve effective tags' }))
    await waitFor(() => expect(finishOld).toBeDefined())
    fireEvent.change(field, { target: { value: 'current-target' } })
    expect(oldSignal?.aborted).toBe(true)
    fireEvent.click(within(card).getByRole('button', { name: 'Resolve effective tags' }))
    expect(await within(card).findByText('current-value')).toBeInTheDocument()
    await act(async () => {
      finishOld?.(response('device', 'stale-value'))
    })
    expect(within(card).queryByText('stale-value')).not.toBeInTheDocument()
    expect(within(card).getByText('current-value')).toBeInTheDocument()
    fireEvent.change(within(card).getByLabelText('Effective-tag routing context'), {
      target: { value: '' },
    })
    expect(within(card).queryByText('current-value')).not.toBeInTheDocument()
  })

  test('keeps source/storage refusals visible without retaining the prior result', async () => {
    vi.stubGlobal(
      'fetch',
      subjectFetch(async () => jsonResponse({ error: { message: 'unavailable' } }, 503)),
    )
    renderApp('/admin', { me: { permissions: ['tags.read', 'entities.read'] } })
    const card = await chooseContext()
    fireEvent.change(within(card).getByLabelText('Effective-tag subject ID'), {
      target: { value: 'owned-target' },
    })
    fireEvent.click(within(card).getByRole('button', { name: 'Resolve effective tags' }))
    expect(
      await within(card).findByText(/Effective tags could not be resolved/),
    ).toBeInTheDocument()
    expect(within(card).queryByText(/Tag revision/)).not.toBeInTheDocument()
  })

  test('hides the inspector without tags.read', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/admin')
    await screen.findByRole('heading', { level: 1 })
    expect(screen.queryByText('Effective subject tags')).not.toBeInTheDocument()
  })
})
