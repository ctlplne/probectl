// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { act, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import type { Incident } from '../api/incidents'
import type { IncidentDraftKind, IncidentDraftResponse } from '../api/sdk.gen'
import { AuthContext } from '../auth/AuthProvider'
import { I18nProvider } from '../i18n/I18nProvider'
import { IncidentDraftCard } from '../routes/IncidentDraftCard'
import { jsonResponse, pathOf } from './fetchStub'

const incident: Incident = {
  id: '11111111-1111-4111-8111-111111111111',
  tenant_id: 'red',
  status: 'open',
  severity: 'warning',
  title: 'Link change',
  started_at: '2026-11-01T00:00:00Z',
  last_seen_at: '2026-11-01T00:01:00Z',
  signal_count: 1,
}
const draftPath = `/v1/incidents/${incident.id}/drafts`
const permissions = [
  'incident.read',
  'ai.query',
  'entities.read',
  'metrics.read',
  'events.read',
  'test.read',
  'change.read',
  'flow.read',
]

function view(tenantID = 'red') {
  const tenant = { id: tenantID, name: tenantID, slug: tenantID }
  return (
    <I18nProvider initialLocale="en">
      <AuthContext.Provider
        value={{
          tenant,
          tenants: [tenant],
          user: { id: 'operator', name: 'Operator', email: 'operator@example.test' },
          permissions,
          switchTenant: () => {},
          signOut: () => {},
        }}
      >
        <IncidentDraftCard incident={{ ...incident, tenant_id: tenantID }} />
      </AuthContext.Provider>
    </I18nProvider>
  )
}

function draft(tenant: string, kind: IncidentDraftKind = 'postmortem'): IncidentDraftResponse {
  const packageID = `${tenant}-signed-source`
  const attachment = { digest: 'digest', content: { samples: [{ 'sample/rate~bps': 42 }] } }
  const signed = {
    manifest: {
      package_id: packageID,
      evidence: [{ id: 'observation', attachment_digest: attachment.digest }],
    },
    attachments: [attachment],
  }
  return {
    package_id: packageID,
    evidence_package: btoa(JSON.stringify(signed)),
    kind,
    model: 'builtin',
    degraded: true,
    sections: [
      {
        name: 'overview',
        sentences: [
          {
            state: 'observed',
            text: `${tenant} link observation`,
            citations: [
              { evidence_id: 'observation', pointer: '/samples/0/sample~1rate~0bps' },
              { pointer: '/package_id' },
            ],
          },
        ],
      },
      { name: 'follow_up', sentences: [] },
    ],
  }
}

test('uses the selected evidence window and downloads the matching draft and source', async () => {
  const user = userEvent.setup()
  const response = draft('red', 'executive_summary')
  const request = vi.fn<typeof fetch>(async () => jsonResponse(response))
  vi.stubGlobal('fetch', request)
  const createURL = vi.fn<(blob: Blob) => string>(() => 'blob:incident-draft')
  const revokeURL = vi.fn()
  vi.stubGlobal(
    'URL',
    Object.assign(class extends URL {}, { createObjectURL: createURL, revokeObjectURL: revokeURL }),
  )
  const filenames: string[] = []
  const download = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    filenames.push(this.download)
  })
  try {
    render(view())
    await user.selectOptions(screen.getByLabelText('Draft type'), 'executive_summary')
    await user.click(screen.getByLabelText('Include observed customer and traffic impact'))
    await user.click(screen.getByLabelText('Include the fault-domain evaluation'))
    const from = '2026-11-01T00:00:05Z'
    const to = '2026-11-01T00:00:45Z'
    fireEvent.change(screen.getByLabelText('Evidence start (ISO 8601 with offset)'), {
      target: { value: from },
    })
    fireEvent.change(screen.getByLabelText('Evidence end (exclusive, ISO 8601 with offset)'), {
      target: { value: to },
    })
    await user.click(screen.getByRole('button', { name: 'Generate draft' }))
    expect(await screen.findByText('red link observation')).toBeInTheDocument()
    const [input, init] = request.mock.calls[0]
    expect(pathOf(input)).toBe(draftPath)
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({
      kind: 'executive_summary',
      impact: { from, to },
      verdict: { from, to },
    })
    expect(
      screen.getByText('Draft ready. Model builtin. The local model was unavailable.'),
    ).toBeInTheDocument()
    expect(screen.getByText('No supported evidence for this section.')).toBeInTheDocument()
    await user.click(screen.getByText('View cited evidence'))
    expect(screen.getByText('/samples/0/sample~1rate~0bps')).toBeVisible()
    expect(screen.getByText('42')).toBeVisible()
    expect(screen.getByText('"red-signed-source"')).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Download draft and evidence' }))
    await user.click(screen.getByRole('button', { name: 'Download signed source' }))
    expect(filenames).toEqual([
      `probectl-incident-${incident.id}-executive_summary.json`,
      `probectl-incident-${incident.id}-executive_summary-evidence.json`,
    ])
    expect(createURL.mock.calls.map(([blob]) => blob.type)).toEqual([
      'application/json',
      'application/vnd.probectl.evidence+json',
    ])
    expect(revokeURL.mock.calls).toEqual([['blob:incident-draft'], ['blob:incident-draft']])
    fireEvent.focus(window)
    expect(screen.queryByText('red link observation')).toBeNull()
  } finally {
    download.mockRestore()
  }
})

test.each([
  ['an unmatched package', 'Draft evidence did not match'],
  ['a missing citation', 'Draft sentence has no evidence'],
  ['an unresolved pointer', 'Draft evidence reference could not be opened'],
] as const)('withholds the text and downloads for %s', async (fault, error) => {
  const response = draft('red')
  const sentence = response.sections[0].sentences[0]
  if (fault === 'an unmatched package') response.package_id = 'another-package'
  if (fault === 'a missing citation') sentence.citations = []
  if (fault === 'an unresolved pointer') sentence.citations[0].pointer = '/samples/0/absent'
  vi.stubGlobal(
    'fetch',
    vi.fn<typeof fetch>(async () => jsonResponse(response)),
  )
  render(view())
  await userEvent.click(screen.getByRole('button', { name: 'Generate draft' }))
  expect(await screen.findByText(error)).toBeVisible()
  expect(screen.queryByText('red link observation')).toBeNull()
  expect(screen.queryByRole('button', { name: 'Download signed source' })).toBeNull()
})

test('discards a late draft when the same incident ID opens in a sibling tenant', async () => {
  const user = userEvent.setup()
  let resolveRed!: (response: Response) => void
  const pendingRed = new Promise<Response>((resolve) => {
    resolveRed = resolve
  })
  const request = vi
    .fn<typeof fetch>()
    .mockReturnValueOnce(pendingRed)
    .mockResolvedValueOnce(jsonResponse(draft('blue')))
  vi.stubGlobal('fetch', request)
  const page = render(view('red'))
  await user.selectOptions(screen.getByLabelText('Draft type'), 'carrier_ticket')
  await user.click(screen.getByRole('button', { name: 'Generate draft' }))
  expect(screen.getByRole('status')).toHaveTextContent('Generating draft')
  const [input, init] = request.mock.calls[0]
  expect(pathOf(input)).toBe(draftPath)
  expect(JSON.parse(String(init?.body))).toEqual({
    kind: 'carrier_ticket',
    carrier: { from: incident.started_at, to: incident.last_seen_at },
  })

  page.rerender(view('blue'))
  expect(init?.signal?.aborted).toBe(true)
  expect(screen.getByLabelText('Draft type')).toHaveValue('postmortem')
  await user.click(screen.getByRole('button', { name: 'Generate draft' }))
  expect(await screen.findByText('blue link observation')).toBeInTheDocument()
  await act(async () => resolveRed(jsonResponse(draft('red', 'carrier_ticket'))))
  expect(screen.queryByText('red link observation')).toBeNull()
  expect(screen.getByText('blue link observation')).toBeInTheDocument()
})
