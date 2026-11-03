// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { expect, test } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Modal } from '../components/Modal'

function StaticRecord() {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button onClick={() => setOpen(true)}>Inspect record</button>
      <Modal open={open} title="Static record" onClose={() => setOpen(false)}>
        <p>A record can contain scrollable text and no action controls.</p>
      </Modal>
    </>
  )
}

test('static modal content is a named keyboard stop and preserves trap/restoration', async () => {
  const user = userEvent.setup()
  render(<StaticRecord />)
  const trigger = screen.getByRole('button', { name: 'Inspect record' })
  await user.click(trigger)
  const close = screen.getByRole('button', { name: 'Close dialog' })
  await waitFor(() => expect(document.activeElement).toBe(close))
  await user.tab()
  expect(document.activeElement).toBe(screen.getByRole('region', { name: 'Static record' }))
  await user.tab()
  expect(document.activeElement).toBe(close)
  await user.keyboard('{Escape}')
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  await waitFor(() => expect(document.activeElement).toBe(trigger))
})
