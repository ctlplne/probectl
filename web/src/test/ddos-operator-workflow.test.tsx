// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, test, vi } from 'vitest'
import type { Signal } from '../api/incidents'
import { AuthContext } from '../auth/AuthProvider'
import { I18nProvider } from '../i18n/I18nProvider'
import { IncidentDDoSReceipt } from '../routes/IncidentDDoSReceipt'
import { IncidentRoutingProposal } from '../routes/IncidentRoutingProposal'
import { SubscriberUsageCard } from '../routes/SubscriberUsageCard'
import { TimeProvider } from '../time/TimeProvider'
import { jsonResponse } from './fetchStub'

const from = '2026-11-20T01:00:00Z'
const to = '2026-11-20T01:01:00Z'
const fingerprint = 'f'.repeat(64)
const episode = 'a'.repeat(64)
const redSignal: Signal = {
  plane: 'flow',
  kind: 'alert.ddos_assessment',
  severity: 'warning',
  title: 'Owned DDoS pressure',
  occurred_at: to,
  attributes: {
    rule_id: 'rule-red',
    'probectl.alert.ddos.receipt_fingerprint': fingerprint,
    'probectl.alert.ddos.episode_id': episode,
  },
}
const redIncident = { id: 'incident-red', title: 'Red incident', signals: [redSignal] }

function mount(children: ReactNode, permissions: string[] = []) {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={cache}>
        <AuthContext.Provider
          value={{
            user: { id: 'user-red', email: 'red@example.test', name: 'Red tenant operator' },
            tenant: { id: 'red', name: 'Red', slug: 'red' },
            tenants: [],
            permissions,
            signOut: vi.fn(),
            switchTenant: vi.fn(),
          }}
        >
          <I18nProvider initialLocale="en">
            <TimeProvider>{children}</TimeProvider>
          </I18nProvider>
        </AuthContext.Provider>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } })
}

function click(name: string) {
  fireEvent.click(screen.getByRole('button', { name }))
}

function requestURL(input: RequestInfo | URL) {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
  return new URL(url, 'https://probectl.example.test')
}

function apiFixture(handler: (url: URL, init?: RequestInit) => Response) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => handler(requestURL(input), init)),
  )
}

function usageResult() {
  return {
    subscriber: 'alpha',
    from,
    to,
    total: { bytes: '9007199254740993', packets: '50' },
    download: { bytes: '400', packets: '12' },
    upload: { bytes: '600', packets: '24' },
    internal: { bytes: '40', packets: '14' },
    top_services: [
      {
        direction: 'download',
        status: 'attributed',
        service: 'Work chat',
        provider: 'Example',
        traffic: { bytes: '400', packets: '12' },
      },
      { direction: 'upload', status: 'ambiguous', traffic: { bytes: '200', packets: '8' } },
    ],
    other_services: { bytes: '2', packets: '1' },
    latency_included: true,
    latency: [
      {
        context_id: 'context-red',
        entity_id: 'destination-red',
        test_id: 'test-red',
        agent_id: 'source-red',
        test: 'Committed RTT',
        target: '192.0.2.7',
        coverage: 'partial_original_round_trip_coverage',
        samples: '3',
        mean_nanos: '3002/3',
        minimum_nanos: '1000',
        maximum_nanos: '1002',
      },
    ],
    incident: {
      incident_id: redIncident.id,
      prefix: '192.0.2.0/24',
      direction: 'ingress',
      from,
      to,
      actions_visible: true,
      actions: [
        {
          proposal_id: 'proposal-red',
          kind: 'rtbh_review',
          state: 'proposed',
          created_at: from,
          decided_at: to,
        },
      ],
    },
    exchange: {
      target: 'uisp',
      preview: true,
      csv: 'subscriber_id,total_bytes\ncustomer-42,9007199254740993\n',
    },
  }
}

function subscriberCard() {
  return (
    <SubscriberUsageCard
      view={{ id: 'view-red', version: '7' }}
      tenantID="red"
      identity="red:user-red"
      canReadLatency
      canReadIncident
    />
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

test('subscriber usage binds the exact receipt, renders reduced evidence and downloads the same CSV bytes', async () => {
  let sent: unknown
  const fixture = usageResult()
  apiFixture((url, init) => {
    switch (url.pathname) {
      case '/v1/tags':
        return jsonResponse({ items: [{ id: 'tag-red', key: 'subscriber' }] })
      case '/v1/entity-contexts':
        return jsonResponse({
          items: [{ context_id: 'context-red', site_label: 'Region', vrf_label: 'Red' }],
        })
      case '/v1/incidents':
        return jsonResponse({ items: [redIncident] })
      case '/v1/incidents/incident-red':
        return jsonResponse(redIncident)
      case '/v1/explorer/flow-views/view-red/subscriber-usage':
        expect(new Headers(init?.headers).get('x-probectl-tenant')).toBe('red')
        sent = JSON.parse(String(init?.body))
        return jsonResponse(fixture)
      default:
        throw new Error(`Unexpected test API path ${url.pathname}`)
    }
  })
  const createURL = vi.fn(() => 'blob:owned-exchange')
  const revokeURL = vi.fn()
  vi.stubGlobal(
    'URL',
    Object.assign(class extends URL {}, { createObjectURL: createURL, revokeObjectURL: revokeURL }),
  )
  const clickDownload = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  mount(subscriberCard())
  click('Open subscriber usage')
  await screen.findByRole('option', { name: 'subscriber' })
  fill('Subscriber prefix tag', 'tag-red')
  fill('Subscriber tag value', ' alpha ')
  fireEvent.click(screen.getByLabelText('Include original ICMP latency'))
  fireEvent.click(screen.getByLabelText('Include a DDoS incident'))
  await screen.findByRole('option', { name: 'Region · Red' })
  fill('Incident routing context', 'context-red')
  await screen.findByRole('option', { name: 'Red incident' })
  fill('Incident', 'incident-red')
  await screen.findByLabelText('DDoS observation')
  expect(screen.getByRole('button', { name: 'Run subscriber report' })).toBeDisabled()
  fill('DDoS observation', fingerprint)
  fill('ISP exchange preview', 'uisp')
  expect(screen.getByRole('button', { name: 'Run subscriber report' })).toBeDisabled()
  fill('External service or account ID', ' customer-42 ')
  click('Run subscriber report')
  await screen.findByText('Observed usage for alpha')
  expect(sent).toEqual({
    version: '7',
    tag_id: 'tag-red',
    tag_key: 'subscriber',
    subscriber: 'alpha',
    include_latency: true,
    incident: {
      context_id: 'context-red',
      incident_id: 'incident-red',
      rule_id: 'rule-red',
      receipt_fingerprint: fingerprint,
    },
    exchange: { target: 'uisp', external_id: 'customer-42' },
  })
  expect(screen.getByText('9007199254740993 bytes · 50 packets')).toBeInTheDocument()
  expect(screen.getByText('Ambiguous')).toBeInTheDocument()
  expect(screen.getByText('Partial round-trip coverage')).toBeInTheDocument()
  expect(
    within(screen.getByRole('table', { name: 'Recorded incident decisions' })).getByText(
      'rtbh review',
    ),
  ).toBeInTheDocument()
  click('Download exchange CSV')
  expect(createURL).toHaveBeenCalledWith(expect.any(Blob))
  expect(clickDownload).toHaveBeenCalledOnce()
  expect(revokeURL).toHaveBeenCalledWith('blob:owned-exchange')
  fill('Subscriber tag value', 'beta')
  expect(screen.queryByText('Observed usage for alpha')).not.toBeInTheDocument()
})

test('incident report accepts only its exact receipt and saves a private dashboard definition', async () => {
  let saved: unknown
  let receiptReads = 0
  const window = {
    from,
    to,
    source: 'raw',
    resolution_seconds: 1,
    bytes: '600000',
    packets: '6000',
    observed_records: 210,
    observed_addresses: 1,
    sampled: true,
    citation: 'retained-window',
  }
  const assessment = {
    view_id: 'view-red',
    version: '7',
    prefix: '192.0.2.0/24',
    direction: 'ingress',
    before: window,
    after: window,
    detection: {
      class: 'udp_reflection_suspected',
      service: 'dns',
      confidence: 'corroborated',
      contributing_packets: '5100',
    },
  }
  apiFixture((url, init) => {
    if (url.pathname === '/v1/alerts/rules/rule-red/ddos-receipt') {
      receiptReads++
      expect(url.searchParams.get('fingerprint')).toBe(fingerprint)
      expect(new Headers(init?.headers).get('x-probectl-tenant')).toBe('red')
      return jsonResponse({
        incident_id: redIncident.id,
        episode_id: episode,
        previous: assessment,
        current: assessment,
      })
    }
    if (url.pathname === '/v1/incidents/incident-red/ddos-report') {
      expect(url.searchParams.get('rule_id')).toBe('rule-red')
      return jsonResponse({
        from,
        to,
        observed_seconds: '60',
        peak_bit_rate: { per_second: '80000' },
        peak_packet_rate: { per_second: '100' },
        top_sources: [{ address: '198.51.100.12', bytes: '400000', packets: '4000' }],
        actions_visible: true,
        actions: [
          {
            proposal_id: 'proposal-rtbh',
            kind: 'rtbh_review',
            state: 'approved',
            created_at: from,
            decided_at: to,
          },
        ],
      })
    }
    if (url.pathname === '/v1/dashboards' && init?.method === 'POST') {
      saved = JSON.parse(String(init.body))
      return jsonResponse({ id: 'private-ddos-report' }, 201)
    }
    throw new Error(`Unexpected test API path ${url.pathname}`)
  })
  const denied = mount(<IncidentDDoSReceipt signal={redSignal} incidentID="incident-red" />, [
    'flow.read',
  ])
  expect(screen.queryByText('Show original traffic evidence')).not.toBeInTheDocument()
  expect(receiptReads).toBe(0)
  denied.unmount()
  const permissions = ['alert.read', 'ai.query', 'flow.read', 'metrics.write']
  const foreign = mount(
    <IncidentDDoSReceipt signal={redSignal} incidentID="incident-blue" />,
    permissions,
  )
  click('Show original traffic evidence')
  await screen.findByText('Traffic evidence does not match this incident')
  expect(screen.queryByText('Open DDoS incident report')).not.toBeInTheDocument()
  foreign.unmount()
  mount(<IncidentDDoSReceipt signal={redSignal} incidentID="incident-red" />, permissions)
  click('Show original traffic evidence')
  await screen.findByText('Second qualifying window')
  click('Open DDoS incident report')
  await screen.findByRole('region', { name: 'DDoS incident report' })
  expect(screen.getByText('80000 bits per second')).toBeInTheDocument()
  expect(screen.getByText('198.51.100.12')).toBeInTheDocument()
  click('Save incident report')
  await screen.findByText('Saved to your dashboards.')
  expect(saved).toMatchObject({
    shared: false,
    preset: 'operator',
    definition: {
      ddos_report: {
        incident_id: redIncident.id,
        rule_id: 'rule-red',
        receipt_fingerprint: fingerprint,
      },
    },
  })
})

const routingScope = {
  context_id: 'context-red',
  rule_id: 'rule-red',
  receipt_fingerprint: fingerprint,
  protected_entity_id: 'prefix-red',
  benign_entity_id: 'benign-red',
  whole_view_id: 'view-red',
  whole_view_version: '7',
}
const impact = {
  prefix: '192.0.2.0/24',
  from,
  to,
  sampled: true,
  observed_records: 210,
  observed_addresses: 1,
  matched: { bytes: '600000', packets: '6000' },
  known_benign: { bytes: '1200', packets: '12' },
  unclassified: { bytes: '598800', packets: '5988' },
}

test.each(['rtbh', 'flowspec', 'diversion'] as const)(
  'routing review files the exact %s preview after policy confirmation',
  async (method) => {
    let prepared: unknown
    let filed: unknown
    apiFixture((url, init) => {
      switch (url.pathname) {
        case '/v1/entity-contexts':
          return jsonResponse({
            items: [{ context_id: 'context-red', site_label: 'Region', vrf_label: 'Red' }],
          })
        case '/v1/entities':
          expect(url.searchParams.get('context_id')).toBe('context-red')
          return jsonResponse({
            items: [
              {
                id: 'prefix-red',
                kind: 'prefix',
                network_prefix: '192.0.2.0/24',
                label: 'Protected red',
              },
              {
                id: 'benign-red',
                kind: 'prefix',
                network_prefix: '198.51.100.0/24',
                label: 'Known benign red',
              },
              {
                id: 'prefix-other',
                kind: 'prefix',
                network_prefix: '203.0.113.0/24',
                label: 'Other prefix',
              },
            ],
          })
        case '/v1/explorer/flow-views':
          return jsonResponse({
            items: [
              {
                id: 'view-red',
                version: '7',
                definition: {
                  name: 'Exact complete view',
                  time: { mode: 'lookback', lookback_seconds: 60 },
                  plan: {},
                },
              },
              {
                id: 'view-other',
                version: '3',
                definition: {
                  name: 'Wrong coverage',
                  time: { mode: 'lookback', lookback_seconds: 300 },
                  plan: {},
                },
              },
            ],
          })
        case `/v1/remediation/${method}-preview`:
          prepared = JSON.parse(String(init?.body))
          if (method === 'rtbh') {
            return jsonResponse({
              announcement: { prefix: impact.prefix, family: 'ipv4', community: '64512:100' },
              impact,
              preview_fingerprint: episode,
            })
          }
          if (method === 'flowspec') {
            return jsonResponse({
              candidate: {
                destination: impact.prefix,
                transport: { protocol: 'udp', source_port: 123, destination_port: 18443 },
              },
              whole_scope: impact,
              matching: impact,
              preview_fingerprint: episode,
            })
          }
          return jsonResponse({
            action: 'start',
            connector: 'local_preview',
            prefix: impact.prefix,
            impact,
            preview_fingerprint: episode,
          })
        case `/v1/remediation/${method}-proposals`:
          filed = JSON.parse(String(init?.body))
          return jsonResponse({ id: 'proposal-red', state: 'proposed' }, 201)
        default:
          throw new Error(`Unexpected test API path ${url.pathname}`)
      }
    })
    mount(
      <IncidentRoutingProposal
        rule="rule-red"
        receipt={fingerprint}
        prefix={impact.prefix}
        windowSeconds={60}
      />,
    )
    fill('Proposal method', method)
    await screen.findByRole('option', { name: 'Region / Red' })
    fill('Routing context', 'context-red')
    await within(screen.getByLabelText('Protected prefix')).findByRole('option', {
      name: '192.0.2.0/24 · Protected red',
    })
    fill('Protected prefix', 'prefix-red')
    fill('Known benign source prefix', 'benign-red')
    fill('Search saved whole-prefix views', 'exact complete')
    await screen.findByRole('option', { name: 'Exact complete view' })
    fill('Whole-prefix flow view', 'view-red')
    const send = screen.getByRole('button', { name: 'Preview scoped collateral' })
    expect(send).toBeDisabled()
    if (method === 'rtbh') {
      fill('Community from your routing policy', '64512:100')
    } else if (method === 'flowspec') {
      fill('Transport protocol', 'udp')
      fill('Exact source port (optional)', '123')
      fill('Exact destination port (optional)', '65536')
      expect(send).toBeDisabled()
      fill('Exact destination port (optional)', '18443')
    }
    fireEvent.click(screen.getByRole('checkbox'))
    expect(send).toBeEnabled()
    fireEvent.click(send)
    await screen.findByLabelText('Scoped routing preview')
    expect(prepared).toEqual(
      method === 'rtbh'
        ? { ...routingScope, routing_policy_agreed: true, community: '64512:100' }
        : method === 'flowspec'
          ? {
              ...routingScope,
              routing_policy_agreed: true,
              transport: { protocol: 'udp', source_port: 123, destination_port: 18443 },
            }
          : { action: 'start', observation: routingScope },
    )
    const file = screen.getByRole('button', { name: 'File exact routing proposal' })
    expect(file).toBeDisabled()
    fill('Maximum known benign packets', '12')
    fireEvent.click(file)
    await screen.findByText('Routing proposal filed for independent review in Admin.')
    expect(filed).toEqual({
      ...(method === 'diversion' ? { selection: prepared } : { preview: prepared }),
      observed_to: to,
      preview_fingerprint: episode,
      max_known_benign_packets: '12',
    })
    await waitFor(() => expect(file).toBeDisabled())
  },
)
