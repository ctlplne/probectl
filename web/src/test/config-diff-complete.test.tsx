// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { expect, test } from 'vitest'
import { I18nProvider } from '../i18n/I18nProvider'
import { ConfigDiffDialog } from '../routes/ConfigDiffDialog'
import type { DeviceConfigVersion } from '../api/planes'

function comparison(lane: string, count: number, sparse = false) {
  const before = Array.from({ length: count }, (_, index) => `${lane}-before-${index}`)
  const after = sparse ? [...before] : before.map((_line, index) => `${lane}-after-${index}`)
  if (sparse) after[count - 1] = `${lane}-last-change`
  const previous: DeviceConfigVersion = {
    id: `${lane}-prior`,
    device: lane,
    version: 1,
    content: before.join('\n'),
    content_hash: `${lane}-old-hash`,
    drifted: false,
    archived_at: '2026-11-14T00:00:00Z',
  }
  const current: DeviceConfigVersion = {
    ...previous,
    id: `${lane}-current`,
    version: 2,
    content: after.join('\n'),
    previous_hash: previous.content_hash,
    content_hash: `${lane}-new-hash`,
    drifted: true,
  }
  return { previous, current }
}

test('complete high-churn comparison reaches the last changed line and resets on a different source', async () => {
  const user = userEvent.setup()
  const view = (lane: string) => (
    <MemoryRouter>
      <I18nProvider initialLocale="en">
        <ConfigDiffDialog comparison={comparison(lane, 20000)} onClose={() => undefined} />
      </I18nProvider>
    </MemoryRouter>
  )
  const rendered = render(view('owned-a'))
  expect(screen.getByText('Rows 1–400 of 40000')).toBeInTheDocument()
  expect(screen.getByText('owned-a-before-0')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Last page' }))
  expect(screen.getByText('owned-a-after-19999')).toBeInTheDocument()
  expect(screen.getByText('Rows 39601–40000 of 40000')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled()
  rendered.rerender(view('owned-b'))
  expect(screen.getByText('owned-b-before-0')).toBeInTheDocument()
  expect(screen.queryByText('owned-a-after-19999')).toBeNull()
  expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled()
  expect(screen.getByText('Rows 1–400 of 40000')).toBeInTheDocument()
})

test('folded unchanged context can be fully inspected without discarding a late change', async () => {
  const user = userEvent.setup()
  render(
    <MemoryRouter>
      <I18nProvider initialLocale="en">
        <ConfigDiffDialog comparison={comparison('owned', 20000, true)} onClose={() => undefined} />
      </I18nProvider>
    </MemoryRouter>,
  )
  expect(screen.getByText('owned-last-change')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Show all unchanged context' }))
  expect(screen.getByText('Rows 1–400 of 20001')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Last page' }))
  expect(screen.getByText('owned-last-change')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Fold unchanged context' }))
  expect(screen.getByText('owned-last-change')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled()
})
