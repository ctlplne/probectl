// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { describe, expect, test, vi } from 'vitest'
import { Providers } from '../App'
import { AuthContext, type AuthContextValue } from '../auth/AuthProvider'
import { NetBoxTagPreviewCard } from '../routes/admin/NetBoxTagPreviewCard'
import { assertNoDoublePrefix, defaultFetch, jsonResponse, pathOf } from './fetchStub'

const tenantA = '00000000-0000-0000-0000-000000000001'
const tenantB = '00000000-0000-0000-0000-000000000002'
const contextID = '00000000-0000-0000-0000-000000000072'
const otherContextID = '00000000-0000-0000-0000-000000000073'
const grants = [
  'tags.read',
  'cmdb.read',
  'entities.read',
  'flow.read',
  'metrics.read',
  'agent.read',
  'test.read',
]

function identity(tenantID = tenantA, permissions = grants): AuthContextValue {
  return {
    tenant: { id: tenantID, name: tenantID, slug: tenantID },
    user: { id: 'reader', name: 'Reader', email: 'reader@probectl.test' },
    tenants: [],
    permissions,
    switchTenant: vi.fn(),
    signOut: vi.fn(),
  }
}

function tree(auth: AuthContextValue) {
  return (
    <Providers>
      <AuthContext.Provider value={auth}>
        <NetBoxTagPreviewCard />
      </AuthContext.Provider>
    </Providers>
  )
}

function candidate(value: string, context = contextID, tagID = 'tag-1') {
  return {
    target: {
      context_id: context,
      tag_id: tagID,
      tag_key: tagID === 'tag-1' ? 'customer' : 'circuit',
      tag_revision: '9007199254740993',
      target_kind: 'exporter',
      target_id: 'opaque-owned-exporter',
      exporter_agent_id: 'collector',
      exporter_source_ref: '192.0.2.10',
    },
    candidate: {
      ci_id: '42',
      lookup_ci_id: '10',
      netbox_tenant_id: value === 'blue' ? '7' : '8',
      name: 'owned-edge',
      field: 'site',
      value,
      source_ref: 'netbox:t7:ip10:d42:site',
    },
  }
}

function sourceFetch(
  preview: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
  apply?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
) {
  const base = defaultFetch()
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    assertNoDoublePrefix(input)
    const path = pathOf(input)
    if (path === '/v1/tags')
      return jsonResponse({
        items: [
          { id: 'tag-1', key: 'customer', tenant_id: tenantA },
          { id: 'tag-2', key: 'circuit', tenant_id: tenantA },
        ],
      })
    if (path === '/v1/entity-contexts')
      return jsonResponse({
        items: [
          { context_id: contextID, site_label: 'iad1', vrf_label: 'default' },
          { context_id: otherContextID, site_label: 'iad2', vrf_label: 'default' },
        ],
      })
    if (path.endsWith('/tag-imports/netbox/preview')) return preview(input, init)
    if (path.endsWith('/tag-imports/netbox/apply') && apply) return apply(input, init)
    return base(input, init)
  })
}

async function chooseContext() {
  await waitFor(() =>
    expect(screen.getByRole('option', { name: 'iad1 / default' })).toBeInTheDocument(),
  )
  await userEvent.selectOptions(
    await screen.findByRole('combobox', { name: 'NetBox preview routing context' }),
    contextID,
  )
  await screen.findByRole('textbox', { name: 'NetBox exporter agent ID' })
}

async function submitPreview() {
  const user = userEvent.setup()
  await user.type(screen.getByRole('textbox', { name: 'NetBox exporter agent ID' }), 'collector')
  await user.type(screen.getByRole('textbox', { name: 'NetBox exporter address' }), '192.0.2.10')
  await user.click(screen.getByRole('button', { name: 'Preview NetBox value' }))
}

describe('Fresh tenant-scoped NetBox tag previews', () => {
  test.each([{ permissions: ['tags.read'] }, { permissions: ['cmdb.read'] }, { permissions: [] }])(
    'requires both grants: $permissions',
    async ({ permissions }) => {
      const fetcher = sourceFetch(async () => jsonResponse(candidate('blue')))
      vi.stubGlobal('fetch', fetcher)
      const app = render(tree(identity(tenantA, permissions)))
      expect(screen.queryByText('NetBox tag preview')).not.toBeInTheDocument()
      expect(
        fetcher.mock.calls.some(
          ([input]) => pathOf(input) === '/v1/tags' || pathOf(input).includes('/tag-imports/'),
        ),
      ).toBe(false)
      app.unmount()
    },
  )

  test('previews without writes, preserves decimal revisions, and clears a changed input', async () => {
    const requests: { path: string; tenant: string | null; body: unknown }[] = []
    const fetcher = sourceFetch(async (input, init) => {
      requests.push({
        path: pathOf(input),
        tenant: new Headers(init?.headers).get('X-Probectl-Tenant'),
        body: JSON.parse(String(init?.body)),
      })
      return jsonResponse(candidate('blue'))
    })
    vi.stubGlobal('fetch', fetcher)
    const app = render(tree(identity()))
    await chooseContext()
    await submitPreview()
    const result = await screen.findByRole('table', { name: 'Fresh NetBox tag preview' })
    expect(within(result).getByText('blue')).toBeInTheDocument()
    expect(within(result).getByText('9007199254740993')).toBeInTheDocument()
    expect(requests).toEqual([
      {
        path: `/v1/entity-contexts/${contextID}/tag-imports/netbox/preview`,
        tenant: tenantA,
        body: {
          tag_id: 'tag-1',
          exporter_agent_id: 'collector',
          exporter_source_ref: '192.0.2.10',
          field: 'site',
        },
      },
    ])
    expect(
      fetcher.mock.calls.filter(([, init]) => init?.method && init.method !== 'GET'),
    ).toHaveLength(1)
    await userEvent.selectOptions(
      screen.getByRole('combobox', { name: 'NetBox source field' }),
      'role',
    )
    expect(
      screen.queryByRole('table', { name: 'Fresh NetBox tag preview' }),
    ).not.toBeInTheDocument()
    app.unmount()
  })

  test('supports an explicit context without requiring inventory discovery and shows source refusal', async () => {
    const fetcher = sourceFetch(async () =>
      jsonResponse({ error: { message: 'Fresh source unavailable' } }, 503),
    )
    vi.stubGlobal('fetch', fetcher)
    const app = render(tree(identity(tenantA, ['tags.read', 'cmdb.read'])))
    await userEvent.type(
      screen.getByRole('textbox', { name: 'NetBox preview routing context ID' }),
      contextID,
    )
    await screen.findByRole('textbox', { name: 'NetBox exporter agent ID' })
    await submitPreview()
    expect(await screen.findByText('Fresh source unavailable')).toBeInTheDocument()
    expect(fetcher.mock.calls.some(([input]) => pathOf(input) === '/v1/entity-contexts')).toBe(
      false,
    )
    expect(
      screen.queryByRole('table', { name: 'Fresh NetBox tag preview' }),
    ).not.toBeInTheDocument()
    app.unmount()
  })

  test('imports only the unchanged preview after explicit review and confirmation', async () => {
    const observed = candidate('blue')
    const applied: unknown[] = []
    vi.stubGlobal(
      'fetch',
      sourceFetch(
        async () => jsonResponse(observed),
        async (_input, init) => {
          applied.push(JSON.parse(String(init?.body)))
          return jsonResponse({
            id: 'import-1',
            tenant_id: tenantA,
            context_id: contextID,
            tag_id: 'tag-1',
            target_kind: 'exporter',
            target_id: 'opaque-owned-exporter',
            source: 'netbox',
            source_ref: observed.candidate.source_ref,
            value: 'blue',
            reviewed_at: '2026-11-02T21:00:00Z',
          })
        },
      ),
    )
    const app = render(tree(identity(tenantA, [...grants, 'tags.write'])))
    await chooseContext()
    await submitPreview()
    await userEvent.click(await screen.findByRole('button', { name: 'Review NetBox import' }))
    const dialog = screen.getByRole('dialog', { name: 'Apply reviewed NetBox tag?' })
    expect(within(dialog).getByText(/netbox:t7:ip10:d42:site/)).toBeInTheDocument()
    expect(applied).toEqual([])
    await userEvent.click(within(dialog).getByRole('button', { name: 'Apply reviewed NetBox tag' }))
    expect(
      await screen.findByText('NetBox tag imported. Manual assignments retain precedence.'),
    ).toBeInTheDocument()
    expect(applied).toEqual([{ confirmed: true, preview: observed }])
    expect(screen.getByRole('button', { name: 'Review NetBox import' })).toBeDisabled()
    app.unmount()
  })

  test('a late tenant A response cannot replace tenant B with equal target identifiers', async () => {
    let resolveA!: (response: Response) => void
    const requestTenants: (string | null)[] = []
    vi.stubGlobal(
      'fetch',
      sourceFetch(async (_input, init) => {
        const tenant = new Headers(init?.headers).get('X-Probectl-Tenant')
        requestTenants.push(tenant)
        if (tenant === tenantA)
          return new Promise<Response>((resolve) => {
            resolveA = resolve
          })
        return jsonResponse(candidate('red'))
      }),
    )
    const app = render(tree(identity()))
    await chooseContext()
    await submitPreview()
    await waitFor(() => expect(resolveA).toBeDefined())
    app.rerender(tree(identity(tenantB)))
    await chooseContext()
    await submitPreview()
    expect(await screen.findByText('red')).toBeInTheDocument()
    await act(async () => {
      resolveA(jsonResponse(candidate('blue')))
    })
    expect(screen.queryByText('blue')).not.toBeInTheDocument()
    expect(screen.getByText('red')).toBeInTheDocument()
    expect(requestTenants).toEqual([tenantA, tenantB])
    app.unmount()
  })

  test.each(['context', 'tag'])(
    'changing %s discards an in-flight source result',
    async (boundary) => {
      let resolve!: (response: Response) => void
      vi.stubGlobal(
        'fetch',
        sourceFetch(
          async () =>
            new Promise<Response>((done) => {
              resolve = done
            }),
        ),
      )
      const app = render(tree(identity()))
      await chooseContext()
      await submitPreview()
      await waitFor(() => expect(resolve).toBeDefined())
      await userEvent.selectOptions(
        screen.getByRole('combobox', {
          name:
            boundary === 'context' ? 'NetBox preview routing context' : 'NetBox preview tag key',
        }),
        boundary === 'context' ? otherContextID : 'tag-2',
      )
      await act(async () => {
        resolve(jsonResponse(candidate('blue')))
      })
      expect(screen.queryByText('blue')).not.toBeInTheDocument()
      expect(
        screen.queryByRole('table', { name: 'Fresh NetBox tag preview' }),
      ).not.toBeInTheDocument()
      expect(screen.getByRole('textbox', { name: 'NetBox exporter agent ID' })).toHaveValue('')
      app.unmount()
    },
  )
})

for (const theme of ['light', 'dark'] as const) {
  for (const tenantID of [tenantA, tenantB]) {
    for (const kind of ['exporter', 'device', 'interface', 'prefix', 'agent', 'test'] as const) {
      test(`reviewed NetBox import retains exact subject/source selection: ${theme} ${tenantID} ${kind}`, async () => {
        const storage = Object.getOwnPropertyDescriptor(window, 'localStorage')
        Object.defineProperty(window, 'localStorage', {
          configurable: true,
          enumerable: true,
          value: { getItem: () => theme, setItem: vi.fn() },
        })
        let app: ReturnType<typeof render> | undefined
        try {
          const requests: Record<string, unknown>[] = []
          const applies: Record<string, unknown>[] = []
          const targetID = '00000000-0000-4000-8000-000000000301'
          const sourceID = '9007199254740993'
          const observed = candidate(tenantID === tenantA ? 'blue' : 'red')
          observed.target.target_kind = kind
          if (kind !== 'exporter') {
            observed.target.target_id = targetID
            observed.target.exporter_agent_id = ''
            observed.target.exporter_source_ref = ''
          }
          observed.candidate.lookup_ci_id = `netbox:ipam.${kind === 'prefix' ? 'prefix' : 'ip_address'}:${sourceID}`
          vi.stubGlobal(
            'fetch',
            sourceFetch(
              async (_input, init) => {
                expect(new Headers(init?.headers).get('X-Probectl-Tenant')).toBe(tenantID)
                requests.push(JSON.parse(String(init?.body)))
                return jsonResponse(observed)
              },
              async (_input, init) => {
                expect(new Headers(init?.headers).get('X-Probectl-Tenant')).toBe(tenantID)
                applies.push(JSON.parse(String(init?.body)))
                return jsonResponse({
                  id: 'assignment',
                  source: 'netbox',
                  value: observed.candidate.value,
                })
              },
            ),
          )
          app = render(tree(identity(tenantID, [...grants, 'tags.write'])))
          await chooseContext()
          expect(document.documentElement).toHaveAttribute('data-theme', theme)
          const card = screen
            .getByText('NetBox tag preview')
            .closest('[data-tenant-netbox-tag-preview]') as HTMLElement
          await userEvent.selectOptions(
            screen.getByRole('combobox', { name: 'NetBox target kind' }),
            kind,
          )
          if (kind === 'exporter') {
            await userEvent.type(
              screen.getByRole('textbox', { name: 'NetBox exporter agent ID' }),
              'collector',
            )
            await userEvent.type(
              screen.getByRole('textbox', { name: 'NetBox exporter address' }),
              '192.0.2.10',
            )
          } else {
            await userEvent.type(
              screen.getByRole('textbox', { name: 'NetBox target ID' }),
              targetID,
            )
          }
          await userEvent.type(
            screen.getByRole('textbox', { name: 'NetBox source object ID' }),
            sourceID,
          )
          await userEvent.click(screen.getByRole('button', { name: 'Preview NetBox value' }))
          await screen.findByRole('table', { name: 'Fresh NetBox tag preview' })
          const expected = {
            tag_id: 'tag-1',
            field: 'site',
            source_id: sourceID,
            ...(kind === 'exporter'
              ? { exporter_agent_id: 'collector', exporter_source_ref: '192.0.2.10' }
              : { target_kind: kind, target_id: targetID }),
          }
          expect(requests).toEqual([expected])
          expect(applies).toHaveLength(0)
          await userEvent.click(screen.getByRole('button', { name: 'Review NetBox import' }))
          await userEvent.click(screen.getByRole('button', { name: 'Apply reviewed NetBox tag' }))
          await screen.findByText('NetBox tag imported. Manual assignments retain precedence.')
          expect(applies).toEqual([{ confirmed: true, preview: observed }])
          expect(card).toBeInTheDocument()
          expect(await axe(card)).toHaveNoViolations()
          await userEvent.type(
            screen.getByRole('textbox', { name: 'NetBox source object ID' }),
            '1',
          )
          expect(
            screen.queryByRole('table', { name: 'Fresh NetBox tag preview' }),
          ).not.toBeInTheDocument()
          expect(
            screen.queryByRole('button', { name: 'Review NetBox import' }),
          ).not.toBeInTheDocument()
        } finally {
          app?.unmount()
          if (storage) Object.defineProperty(window, 'localStorage', storage)
        }
      })
    }
  }
}
