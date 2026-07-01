import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { assertNoDoublePrefix, defaultFetch, jsonResponse, pathOf } from './fetchStub'

function onboardingFetch(capture: {
  enroll?: Record<string, unknown>
  test?: Record<string, unknown>
  invite?: Record<string, unknown>
}) {
  const base = defaultFetch()
  const progress = {
    agent_enroll_token_created: false,
    agent_registered: false,
    first_test_created: false,
    scim_token_created: false,
  }
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    assertNoDoublePrefix(input)
    const path = pathOf(input)
    const method = init?.method ?? 'GET'
    if (path === '/v1/agents') return jsonResponse({ items: [] })
    if (path === '/v1/onboarding/progress') return jsonResponse(progress)
    if (path === '/v1/tests' && method === 'GET') return jsonResponse({ items: [] })
    if (path === '/v1/directory/scim-tokens' && method === 'GET') {
      return jsonResponse({ items: [] })
    }
    if (path === '/v1/agents/enroll-tokens' && method === 'POST') {
      capture.enroll = JSON.parse(String(init!.body)) as Record<string, unknown>
      progress.agent_enroll_token_created = true
      return jsonResponse(
        {
          token: 'pjt_onboarding_agent',
          id: 'enrtok_onboarding',
          tenant_id: '00000000-0000-0000-0000-000000000001',
          expires_at: '2026-06-21T20:00:00Z',
          server_cert_pin: 'abc123pin',
        },
        201,
      )
    }
    if (path === '/v1/tests' && method === 'POST') {
      const body = JSON.parse(String(init!.body)) as Record<string, unknown>
      capture.test = body
      progress.first_test_created = true
      return jsonResponse(
        {
          ...body,
          id: 'test_onboarding',
          params: body.params ?? {},
          created_at: '2026-06-21T20:01:00Z',
          updated_at: '2026-06-21T20:01:00Z',
        },
        201,
      )
    }
    if (path === '/v1/directory/scim-tokens' && method === 'POST') {
      capture.invite = JSON.parse(String(init!.body)) as Record<string, unknown>
      progress.scim_token_created = true
      return jsonResponse(
        {
          id: 'scim_onboarding',
          name: 'first-run-teammates',
          token: 'scim_once_visible',
        },
        201,
      )
    }
    return base(input, init)
  }) as unknown as typeof fetch
}

function cardByHeading(name: RegExp): HTMLElement {
  const heading = screen.getByRole('heading', { name })
  const card = heading.closest('section')
  if (!card) throw new Error(`no card section for ${String(name)}`)
  return card
}

describe('first-run onboarding journey (JOURNEY-001)', () => {
  test('starts at / and completes agent, first-test, and teammate provisioning without tenant spoofing', async () => {
    const user = userEvent.setup()
    const capture: {
      enroll?: Record<string, unknown>
      test?: Record<string, unknown>
      invite?: Record<string, unknown>
    } = {}
    vi.stubGlobal('fetch', onboardingFetch(capture))

    renderApp('/')

    expect(await screen.findByRole('heading', { name: /first-run setup/i })).toBeInTheDocument()

    const agent = cardByHeading(/enroll an agent/i)
    await user.clear(within(agent).getByLabelText(/agent label/i))
    await user.type(within(agent).getByLabelText(/agent label/i), 'edge first')
    await user.clear(within(agent).getByLabelText(/token ttl minutes/i))
    await user.type(within(agent).getByLabelText(/token ttl minutes/i), '45')
    await user.clear(within(agent).getByLabelText(/control plane url/i))
    await user.type(within(agent).getByLabelText(/control plane url/i), 'https://control.example')
    await user.click(within(agent).getByRole('button', { name: /mint enrollment token/i }))

    expect(await screen.findByDisplayValue('pjt_onboarding_agent')).toBeInTheDocument()
    expect(screen.getByLabelText<HTMLInputElement>(/enrollment command/i).value).toContain(
      'probectl-agent enroll --server https://control.example --token pjt_onboarding_agent',
    )

    const firstTest = cardByHeading(/create the first test/i)
    await user.clear(within(firstTest).getByLabelText(/test name/i))
    await user.type(within(firstTest).getByLabelText(/test name/i), 'checkout-health')
    await user.clear(within(firstTest).getByLabelText(/^target$/i))
    await user.type(
      within(firstTest).getByLabelText(/^target$/i),
      'https://checkout.example/health',
    )
    await user.click(within(firstTest).getByRole('button', { name: /create first test/i }))

    expect(await screen.findByText(/checkout-health is enabled/i)).toBeInTheDocument()

    const invite = cardByHeading(/invite teammates/i)
    await user.click(within(invite).getByRole('button', { name: /create scim token/i }))

    expect(await screen.findByDisplayValue('scim_once_visible')).toBeInTheDocument()
    expect(capture.enroll).toEqual({ name: 'edge first', ttl_seconds: 2700 })
    expect(capture.test).toMatchObject({
      name: 'checkout-health',
      type: 'http',
      target: 'https://checkout.example/health',
      interval_seconds: 60,
      timeout_seconds: 3,
      enabled: true,
    })
    expect(capture.invite).toEqual({ name: 'first-run-teammates' })
    expect(capture.enroll).not.toHaveProperty('tenant_id')
    expect(capture.test).not.toHaveProperty('tenant_id')
    expect(capture.invite).not.toHaveProperty('tenant_id')
  })

  test('resumes token-created progress after a reload without browser storage', async () => {
    const user = userEvent.setup()
    const capture: {
      enroll?: Record<string, unknown>
      test?: Record<string, unknown>
      invite?: Record<string, unknown>
    } = {}
    const fetchStub = onboardingFetch(capture)
    vi.stubGlobal('fetch', fetchStub)

    const firstRender = renderApp('/')
    expect(await screen.findByRole('heading', { name: /first-run setup/i })).toBeInTheDocument()

    const agent = cardByHeading(/enroll an agent/i)
    await user.click(within(agent).getByRole('button', { name: /mint enrollment token/i }))

    expect(await screen.findByDisplayValue('pjt_onboarding_agent')).toBeInTheDocument()
    expect(screen.getByText(/enrollment token minted/i)).toBeInTheDocument()

    firstRender.unmount()
    vi.stubGlobal('fetch', fetchStub)
    renderApp('/')

    expect(await screen.findByText(/enrollment token already minted/i)).toBeInTheDocument()
    expect(screen.queryByDisplayValue('pjt_onboarding_agent')).not.toBeInTheDocument()
    expect(capture.enroll).toMatchObject({ name: 'edge-canary-1', ttl_seconds: 3600 })
  })
})
