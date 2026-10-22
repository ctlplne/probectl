// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { messages, type Locale } from '../i18n/messages'
import { assertNoDoublePrefix, defaultFetch, jsonResponse, pathOf } from './fetchStub'

function onboardingFetch(
  capture: {
    enroll?: Record<string, unknown>
    register?: Record<string, unknown>
    test?: Record<string, unknown>
    invite?: Record<string, unknown>
  },
  // null: the server omits the profile (unknown).
  deploymentProfile: string | null = 'single',
) {
  const base = defaultFetch()
  const progress = {
    ...(deploymentProfile ? { deployment_profile: deploymentProfile } : {}),
    agent_enroll_token_created: false,
    agent_registered: false,
    agent_connected: false,
    producer_healthy: false,
    first_test_created: false,
    first_result_received: false,
    first_finding_visible: false,
    scim_token_created: false,
    readiness_steps_complete: 0,
    readiness_steps_total: 4,
    producers: ['synthetic', 'flow', 'bgp', 'device', 'ebpf', 'endpoint'].map((id) => ({
      id,
      state: 'blocked',
      detail: 'producer is not registered',
      next_action:
        id === 'synthetic' ? '/onboarding#first-run-agent' : `/admin?register_collector=${id}`,
    })),
    engines: [
      {
        id: 'synthetic-results',
        state: 'quiet',
        detail: 'engine is running and waiting for tenant data',
        next_action: '/targets',
      },
    ],
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
    if (path === '/v1/collectors/register' && method === 'POST') {
      capture.register = JSON.parse(String(init!.body)) as Record<string, unknown>
      const plane = String(capture.register.plane ?? 'flow')
      return jsonResponse(
        {
          tenant_id: '00000000-0000-0000-0000-000000000001',
          agent_id: '11111111-1111-4111-8111-111111111111',
          plane,
          hostname: capture.register.hostname ?? 'edge-flow-1',
          capabilities: ['collector', plane],
          config: {
            env: { PROBECTL_FLOW_AGENT_ID: '11111111-1111-4111-8111-111111111111' },
            yaml: { agent_id: '11111111-1111-4111-8111-111111111111' },
          },
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

const onboardingWriter = {
  permissions: ['agent.write', 'test.write', 'directory.write'],
}

describe('first-run onboarding journey (JOURNEY-001)', () => {
  test('makes every write-only first-run action visibly unavailable to a read-only role', async () => {
    const capture: {
      enroll?: Record<string, unknown>
      test?: Record<string, unknown>
      invite?: Record<string, unknown>
    } = {}
    vi.stubGlobal('fetch', onboardingFetch(capture))

    renderApp('/', {
      me: { permissions: ['agent.read', 'test.read', 'directory.read'] },
    })
    expect(await screen.findByRole('heading', { name: /first-run setup/i })).toBeInTheDocument()

    const agent = cardByHeading(/enroll an agent/i)
    expect(within(agent).getByRole('button', { name: /mint enrollment token/i })).toBeDisabled()
    expect(within(agent).getByText(/request agent\.write/i)).toBeInTheDocument()

    const firstTest = cardByHeading(/create the first test/i)
    expect(within(firstTest).getByRole('button', { name: /create first test/i })).toBeDisabled()
    expect(within(firstTest).getByText(/request test\.write/i)).toBeInTheDocument()

    const invite = cardByHeading(/invite teammates/i)
    expect(within(invite).getByRole('button', { name: /create scim token/i })).toBeDisabled()
    expect(within(invite).getByText(/request directory\.write/i)).toBeInTheDocument()
    expect(capture).toEqual({})
  })

  test('starts at / and completes agent, first-test, and teammate provisioning without tenant spoofing', async () => {
    const user = userEvent.setup()
    const capture: {
      enroll?: Record<string, unknown>
      register?: Record<string, unknown>
      test?: Record<string, unknown>
      invite?: Record<string, unknown>
    } = {}
    vi.stubGlobal('fetch', onboardingFetch(capture))

    renderApp('/', { me: onboardingWriter })

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
    expect(
      within(firstTest).getByRole('checkbox', { name: /private or loopback addresses/i }),
    ).toBeChecked()
    await user.clear(within(firstTest).getByLabelText(/test name/i))
    await user.type(within(firstTest).getByLabelText(/test name/i), 'checkout-health')
    await user.selectOptions(within(firstTest).getByLabelText(/type/i), 'http')
    expect(
      within(firstTest).getByRole('checkbox', { name: /private or loopback addresses/i }),
    ).not.toBeChecked()
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
      params: {},
      enabled: true,
    })
    expect(capture.invite).toEqual({ name: 'first-run-teammates' })
    expect(capture.enroll).not.toHaveProperty('tenant_id')
    expect(capture.test).not.toHaveProperty('tenant_id')
    expect(capture.invite).not.toHaveProperty('tenant_id')
  })

  test('makes the default loopback SSRF exception explicit, tenant-scoped, and per-test', async () => {
    const user = userEvent.setup()
    const capture: { test?: Record<string, unknown> } = {}
    vi.stubGlobal('fetch', onboardingFetch(capture))

    renderApp('/', { me: onboardingWriter })
    expect(await screen.findByRole('heading', { name: /first-run setup/i })).toBeInTheDocument()
    const firstTest = cardByHeading(/create the first test/i)
    expect(await within(firstTest).findByDisplayValue('127.0.0.1')).toBeInTheDocument()
    expect(within(firstTest).getByText(/admin-only, tenant-scoped/i)).toBeInTheDocument()
    // G9: the agent's own policy still gates private targets; say so up front.
    expect(
      within(firstTest).getByText(/test_sync\.allow_private_targets: true/i),
    ).toBeInTheDocument()

    await user.click(within(firstTest).getByRole('button', { name: /create first test/i }))

    expect(await screen.findByText(/first-loopback-check is enabled/i)).toBeInTheDocument()
    // G9: enrolled agents pull the test; the handout is the agent's own bound.
    expect(
      screen.getByText(/enrolled agents of this tenant pull this test automatically/i),
    ).toBeInTheDocument()
    // D-57: the pre-G9 local canaries block is gone; the handout is test_sync.
    expect(screen.queryByText(/canaries:/)).not.toBeInTheDocument()
    expect(screen.queryByText(/test_id: "test_onboarding"/i)).not.toBeInTheDocument()
    expect(screen.getByText('probectl-agent -config /etc/probectl/agent.yml')).toBeInTheDocument()
    expect(capture.test).toMatchObject({
      target: '127.0.0.1',
      params: { allow_private_targets: 'true' },
    })
    expect(capture.test).not.toHaveProperty('tenant_id')
  })

  test('resumes token-created progress after a reload without browser storage', async () => {
    const user = userEvent.setup()
    const capture: {
      enroll?: Record<string, unknown>
      register?: Record<string, unknown>
      test?: Record<string, unknown>
      invite?: Record<string, unknown>
    } = {}
    const fetchStub = onboardingFetch(capture)
    vi.stubGlobal('fetch', fetchStub)

    const firstRender = renderApp('/', { me: onboardingWriter })
    expect(await screen.findByRole('heading', { name: /first-run setup/i })).toBeInTheDocument()

    const agent = cardByHeading(/enroll an agent/i)
    await user.click(within(agent).getByRole('button', { name: /mint enrollment token/i }))

    expect(await screen.findByDisplayValue('pjt_onboarding_agent')).toBeInTheDocument()
    expect(screen.getByText(/credential exists; readiness is still 0/i)).toBeInTheDocument()

    firstRender.unmount()
    vi.stubGlobal('fetch', fetchStub)
    renderApp('/', { me: onboardingWriter })

    expect(await screen.findByText(/credential exists; readiness is still 0/i)).toBeInTheDocument()
    expect(screen.queryByDisplayValue('pjt_onboarding_agent')).not.toBeInTheDocument()
    expect(capture.enroll).toMatchObject({ name: 'edge-canary-1', ttl_seconds: 3600 })
  })

  test('guides every producer plane and routes flow through tenant-scoped collector registration', async () => {
    const user = userEvent.setup()
    const capture: {
      enroll?: Record<string, unknown>
      register?: Record<string, unknown>
      test?: Record<string, unknown>
      invite?: Record<string, unknown>
    } = {}
    vi.stubGlobal('fetch', onboardingFetch(capture))

    renderApp('/', { me: onboardingWriter })

    expect(
      await screen.findByRole('heading', { name: /choose a producer plane/i }),
    ).toBeInTheDocument()
    for (const plane of ['Synthetic', 'Flow', 'BGP', 'Device', 'eBPF', 'Endpoint']) {
      expect(screen.getByRole('heading', { name: plane })).toBeInTheDocument()
    }
    expect(screen.getByText(/CAP_BPF/)).toBeInTheDocument()
    expect(screen.getByText(/Planes > Flow shows top talkers/i)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /register flow collector/i }))
    const dialog = await screen.findByRole('dialog', { name: /register collector/i })
    expect(within(dialog).getByLabelText(/collector plane/i)).toHaveValue('flow')
    expect(within(dialog).getByText(/NetFlow\/IPFIX\/sFlow/i)).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText(/collector label/i), 'edge-flow-first')
    await user.click(within(dialog).getByRole('button', { name: /register collector/i }))

    expect(await screen.findByDisplayValue('flow')).toBeInTheDocument()
    expect(capture.enroll).toEqual({ name: 'edge-flow-first', ttl_seconds: 300 })
    expect(capture.register).toEqual({
      token: 'pjt_onboarding_agent',
      plane: 'flow',
      hostname: 'edge-flow-first',
    })
    expect(capture.enroll).not.toHaveProperty('tenant_id')
    expect(capture.register).not.toHaveProperty('tenant_id')
  })
})

// D-57 (decision of record 2026-10-22, option a): the agent config onboarding
// hands out opts in to private targets only for a single-tenant install, where
// the operator owns both ends. multi-tenant, regulated and an unknown profile
// keep false: there the agent-side guard is what stops a hosted control plane
// from making a customer's agent probe that customer's internal network.
describe('first-test agent handout follows the deployment profile (D-57)', () => {
  async function createFirstTest(profile: string | undefined, locale: Locale = 'en') {
    const user = userEvent.setup()
    vi.stubGlobal('fetch', onboardingFetch({}, profile ?? null))
    renderApp('/', { me: onboardingWriter, locale })
    const create = await screen.findByRole('button', {
      name: messages[locale]['onboarding.test.create'],
    })
    await waitFor(() => expect(create).toBeEnabled())
    await user.click(create)
    const snippet = await screen.findByText(/^test_sync:/)
    return snippet.textContent ?? ''
  }

  test.each([
    ['single', 'true'],
    ['multi-tenant', 'false'],
    ['regulated', 'false'],
    [undefined, 'false'],
  ])('profile %s hands out allow_private_targets: %s', async (profile, want) => {
    const yaml = await createFirstTest(profile)
    const values = [...yaml.matchAll(/^\s*allow_private_targets:\s*(\S+)\s*$/gm)].map((m) => m[1])
    expect(values).toEqual([want])
    // The YAML says why, in a comment right above the value.
    const lines = yaml.split('\n')
    const at = lines.findIndex((line) => /^\s*allow_private_targets:/.test(line))
    expect(lines[at - 1]).toMatch(/^\s*#/)
    if (want === 'true') {
      expect(yaml).toMatch(/operator owns both ends/)
    } else {
      expect(yaml).not.toMatch(/operator owns both ends/)
      expect(yaml).toMatch(/Only the operator of this agent may set true/)
    }
    const note = document.querySelector('[data-private-targets-handout]')
    expect(note?.getAttribute('data-private-targets-handout')).toBe(String(want === 'true'))
    const key =
      profile === 'single'
        ? 'onboarding.test.privateTargets.single'
        : profile
          ? 'onboarding.test.privateTargets.hosted'
          : 'onboarding.test.privateTargets.unknown'
    expect(note?.textContent).toBe(messages.en[key])
  })

  test.each([
    ['en', 'single', 'true'],
    ['es', 'single', 'true'],
    ['ar', 'single', 'true'],
    ['en', 'multi-tenant', 'false'],
    ['es', 'multi-tenant', 'false'],
    ['ar', 'multi-tenant', 'false'],
  ] as const)('%s renders the %s handout with %s', async (locale, profile, want) => {
    const yaml = await createFirstTest(profile, locale)
    expect(yaml).toMatch(new RegExp(`^  allow_private_targets: ${want}$`, 'm'))
    const reason =
      want === 'true'
        ? messages[locale]['onboarding.test.yamlReason.single']
        : messages[locale]['onboarding.test.yamlReason.hosted']
    const commentText = yaml
      .split('\n')
      .filter((line) => line.startsWith('  # ') && !line.includes('testsync.pub'))
      .map((line) => line.slice(4))
      .join(' ')
    expect(commentText).toBe(reason)
    expect(screen.getByText(messages[locale]['onboarding.test.configHint'])).toBeInTheDocument()
  })
})
