// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import type { InstantTestAgent, InstantTestResult, InstantTestRunInput } from '../api/sdk.gen'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'

const launchPermissions = ['test.read', 'test.write', 'agent.read', 'metrics.read']
const testID = '10000000-0000-4000-8000-000000000001'
const agentID = '20000000-0000-4000-8000-000000000001'
const startedAt = '2026-11-24T12:00:00Z'

function savedTest(name: string, id = testID) {
  return { id, name, type: 'http', enabled: true, interval_seconds: 60 }
}

function enrolledAgent(name: string) {
  return {
    id: agentID,
    name,
    status: 'online',
    test_set: { applied_version: 1 },
    capabilities: ['agent.instant_tests.v1', 'http'],
  }
}

function summary(id: string, testId = testID) {
  return { id, test_id: testId, created_at: startedAt, dispatch_until: '2026-11-24T12:01:00Z' }
}

function measured(success: boolean, metrics?: Record<string, number>): InstantTestResult {
  return { started_at: startedAt, duration_nanos: 1, outcome: 'measured', success, metrics }
}

class RunStream extends EventTarget {
  static readonly CLOSED = 2
  readyState = 1
  onerror?: () => void
  readonly close = vi.fn(() => {
    this.readyState = RunStream.CLOSED
  })

  constructor(readonly url: string) {
    super()
  }

  publish(data: string) {
    this.dispatchEvent(new MessageEvent('run', { data }))
  }

  disconnect() {
    this.readyState = RunStream.CLOSED
    this.onerror?.()
  }
}

function stubRunStreams(failFirstOpen = false) {
  const streams: RunStream[] = []
  function open(url: string) {
    if (failFirstOpen) {
      failFirstOpen = false
      throw new Error('Stream unavailable')
    }
    const stream = new RunStream(url)
    streams.push(stream)
    return stream
  }
  vi.stubGlobal('EventSource', Object.assign(open, { CLOSED: RunStream.CLOSED }))
  return streams
}

test('runs a saved incident test on eligible agents, retries safely and renders final results', async () => {
  const user = userEvent.setup()
  const fallback = defaultFetch()
  const streams = stubRunStreams(true)
  const requests: InstantTestRunInput[] = []
  const run = summary('incident-run')
  const queued: InstantTestAgent = { agent_id: agentID, state: 'queued' }
  let snapshots = 0

  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'https://probectl.test')
    const after = url.searchParams.get('after')
    switch (url.pathname) {
      case '/v1/tests':
        return after
          ? jsonResponse({ items: [savedTest('Checkout')] })
          : jsonResponse({ items: [savedTest('Catalog', 'other-test')], next_cursor: 'more-tests' })
      case '/v1/agents':
        return after
          ? jsonResponse({ items: [enrolledAgent('East edge')] })
          : jsonResponse({
              items: [
                { ...enrolledAgent('Offline edge'), id: 'offline-agent', status: 'offline' },
                { ...enrolledAgent('Old agent'), id: 'old-agent', capabilities: ['http'] },
              ],
              next_cursor: 'more-agents',
            })
      case `/v1/tests/${testID}/runs`:
        expect(init?.method).toBe('POST')
        expect(init?.credentials).toBe('same-origin')
        requests.push(JSON.parse(String(init?.body)) as InstantTestRunInput)
        return requests.length === 1
          ? jsonResponse({ error: { message: 'Queue temporarily unavailable' } }, 503)
          : jsonResponse(run, 202)
      case `/v1/test-runs/${run.id}`:
        snapshots += 1
        return snapshots === 1
          ? jsonResponse({ error: { message: 'Status temporarily unavailable' } }, 503)
          : jsonResponse({ ...run, agents: [queued] })
      default:
        return fallback(input, init)
    }
  })

  renderApp('/incidents', { me: { permissions: ['incident.read', ...launchPermissions] } })
  await user.click(await screen.findByRole('button', { name: 'Run a test now' }))
  const dialog = within(screen.getByRole('dialog', { name: 'Run a test now' }))
  const queue = dialog.getByRole('button', { name: 'Queue test' })
  expect(queue).toBeDisabled()
  await user.click(await dialog.findByRole('button', { name: 'Load more tests' }))
  await user.selectOptions(
    dialog.getByLabelText('Saved test'),
    await dialog.findByRole('option', { name: 'Checkout' }),
  )
  const vantage = dialog.getByLabelText('Run from')
  await user.selectOptions(vantage, 'site')
  await user.type(dialog.getByLabelText('Exact site name'), 'east')
  expect(queue).toBeEnabled()
  await user.selectOptions(vantage, 'tag')
  await user.type(dialog.getByLabelText('Tag context ID'), 'site-context')
  await user.type(dialog.getByLabelText('Tag definition ID'), 'site-tag')
  expect(queue).toBeDisabled()
  await user.type(dialog.getByLabelText('Exact tag value'), 'east')
  expect(queue).toBeEnabled()
  await user.selectOptions(vantage, 'agents')
  await user.click(await dialog.findByRole('button', { name: 'Load more agents' }))
  const eligible = await dialog.findByRole('option', { name: 'East edge' })
  expect(dialog.queryByRole('option', { name: 'Offline edge' })).not.toBeInTheDocument()
  expect(dialog.queryByRole('option', { name: 'Old agent' })).not.toBeInTheDocument()
  await user.selectOptions(dialog.getByLabelText('Selected agents'), eligible)
  await user.click(queue)
  expect(await dialog.findByText('Queue temporarily unavailable')).toBeInTheDocument()
  await user.click(queue)
  expect(await dialog.findByText('Stream unavailable')).toBeInTheDocument()
  expect(requests).toHaveLength(2)
  expect(requests[0]).toEqual({
    idempotency_key: expect.any(String),
    selection: { agent_ids: [agentID] },
  })
  expect(requests[1]).toEqual(requests[0])

  await user.click(dialog.getByRole('button', { name: 'Reconnect' }))
  await waitFor(() => expect(streams).toHaveLength(1))
  expect(streams[0].url).toBe(`${window.location.origin}/v1/test-runs/${run.id}/events`)
  act(() =>
    streams[0].publish(JSON.stringify({ ...summary(run.id, 'other-test'), agents: [queued] })),
  )
  expect(dialog.queryByText('Queued')).not.toBeInTheDocument()
  act(() => streams[0].publish(JSON.stringify({ ...run, agents: [queued] })))
  expect(await dialog.findByText('Queued')).toBeInTheDocument()

  act(() => streams[0].disconnect())
  expect(await dialog.findByText('Status temporarily unavailable')).toBeInTheDocument()
  await user.click(dialog.getByRole('button', { name: 'Reconnect' }))
  await waitFor(() => expect(streams).toHaveLength(2))
  act(() => streams[1].publish('{incomplete'))
  expect(await dialog.findByText('The result stream disconnected.')).toBeInTheDocument()
  await user.click(dialog.getByRole('button', { name: 'Reconnect' }))
  await waitFor(() => expect(streams).toHaveLength(3))
  act(() => streams[2].disconnect())
  await waitFor(() => expect(snapshots).toBe(2))
  await user.click(dialog.getByRole('button', { name: 'Reconnect' }))
  await waitFor(() => expect(streams).toHaveLength(4))

  const agents: InstantTestAgent[] = [
    { agent_id: agentID, state: 'completed', result: measured(true, { latency_ms: 12.5 }) },
    { agent_id: 'failed-agent', state: 'completed', result: measured(false) },
    {
      agent_id: 'policy-agent',
      state: 'completed',
      result: { ...measured(false), outcome: 'policy_refused' },
    },
    { agent_id: 'expired-agent', state: 'expired' },
  ]
  act(() => streams[3].publish(JSON.stringify({ ...run, agents })))
  expect(await dialog.findByText('Passed')).toBeInTheDocument()
  expect(dialog.getByText('East edge')).toBeInTheDocument()
  expect(dialog.getByText('latency_ms')).toBeInTheDocument()
  expect(dialog.getByText('12.5')).toBeInTheDocument()
  expect(dialog.getByText('Failed')).toBeInTheDocument()
  expect(dialog.getByText('Agent policy refused the test')).toBeInTheDocument()
  expect(dialog.getByText('Expired')).toBeInTheDocument()
  expect(streams[3].close).toHaveBeenCalledOnce()
  await user.click(dialog.getByRole('button', { name: 'Close' }))
  expect(screen.queryByRole('dialog', { name: 'Run a test now' })).not.toBeInTheDocument()
})

test('closes the first tenant stream and discards its delayed results when a second tenant signs in', async () => {
  const user = userEvent.setup()
  const fallback = defaultFetch()
  const streams = stubRunStreams()
  const first = summary('first-run')
  const second = summary('second-run')
  let active = first
  let firstSnapshot: AbortSignal | null | undefined
  let finishFirst: ((response: Response) => void) | undefined
  const posts: string[] = []

  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const prefix = active === first ? 'First' : 'Second'
    switch (pathOf(input)) {
      case '/v1/tests':
        return Promise.resolve(jsonResponse({ items: [savedTest(`${prefix} synthetic`)] }))
      case '/v1/agents':
        return Promise.resolve(jsonResponse({ items: [enrolledAgent(`${prefix} agent`)] }))
      case `/v1/tests/${testID}/runs`:
        posts.push(active.id)
        return Promise.resolve(jsonResponse(active, 202))
      case `/v1/test-runs/${first.id}`:
        firstSnapshot = init?.signal
        return new Promise<Response>((resolve) => {
          finishFirst = resolve
        })
      default:
        return fallback(input, init)
    }
  })

  const tenantA = renderApp('/targets', { me: { permissions: launchPermissions } })
  await user.click((await screen.findAllByRole('button', { name: 'Run First synthetic now' }))[0])
  const firstDialog = within(screen.getByRole('dialog', { name: 'Run a test now' }))
  await user.selectOptions(
    firstDialog.getByLabelText('Selected agents'),
    await firstDialog.findByRole('option', { name: 'First agent' }),
  )
  await user.click(firstDialog.getByRole('button', { name: 'Queue test' }))
  expect(await firstDialog.findByText(first.id)).toBeInTheDocument()
  act(() => streams[0].disconnect())
  await waitFor(() => expect(firstSnapshot?.aborted).toBe(false))

  tenantA.unmount()
  expect(firstSnapshot?.aborted).toBe(true)
  expect(streams[0].close).toHaveBeenCalledOnce()
  active = second
  renderApp('/targets', {
    me: {
      tenant_id: '00000000-0000-4000-8000-000000000002',
      user_id: 'operator-b',
      permissions: launchPermissions,
    },
  })
  await user.click((await screen.findAllByRole('button', { name: 'Run Second synthetic now' }))[0])
  const secondDialog = within(screen.getByRole('dialog', { name: 'Run a test now' }))
  expect(secondDialog.queryByRole('option', { name: 'First agent' })).not.toBeInTheDocument()
  await user.selectOptions(
    secondDialog.getByLabelText('Selected agents'),
    await secondDialog.findByRole('option', { name: 'Second agent' }),
  )
  await user.click(secondDialog.getByRole('button', { name: 'Queue test' }))
  expect(await secondDialog.findByText(second.id)).toBeInTheDocument()

  const firstResult = {
    ...first,
    agents: [
      { agent_id: agentID, state: 'completed', result: measured(true, { first_latency: 29 }) },
    ],
  }
  await act(async () => {
    finishFirst?.(jsonResponse(firstResult))
    streams[0].publish(JSON.stringify(firstResult))
    streams[1].publish(JSON.stringify(firstResult))
  })
  expect(secondDialog.getByText('Waiting for agent results…')).toBeInTheDocument()
  expect(secondDialog.queryByText(first.id)).not.toBeInTheDocument()
  expect(secondDialog.queryByText('first_latency')).not.toBeInTheDocument()
  act(() =>
    streams[1].publish(
      JSON.stringify({
        ...second,
        agents: [
          { agent_id: agentID, state: 'completed', result: measured(true, { second_latency: 17 }) },
        ],
      }),
    ),
  )
  expect(await secondDialog.findByText('second_latency')).toBeInTheDocument()
  expect(secondDialog.getByText('Second agent')).toBeInTheDocument()
  expect(posts).toEqual([first.id, second.id])
})
