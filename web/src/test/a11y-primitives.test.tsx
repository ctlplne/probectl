// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useState } from 'react'
import { describe, expect, test } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Field, Modal, StatusDot } from '../components'
import { SkipLink } from '../shell/SkipLink'
import { renderApp } from './renderApp'

function ModalHarness() {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button onClick={() => setOpen(true)}>Open details</button>
      <Modal open={open} onClose={() => setOpen(false)} title="Connection details">
        <button>First action</button>
        <button>Last action</button>
      </Modal>
    </>
  )
}

function declareVisibility(el: HTMLElement, visible: boolean) {
  Object.defineProperty(el, 'offsetParent', {
    configurable: true,
    get: () => (visible ? document.body : null),
  })
  Object.defineProperty(el, 'checkVisibility', { configurable: true, value: () => visible })
}

// DPR-167 harness: the row the trigger lives in re-mounts WHILE the dialog is
// open — what a poll or refetch landing does in the real app — so the element
// captured when the dialog opened is detached by the time it closes. The
// responsive layout also renders the same control twice, with one copy hidden.
function RemountingModalHarness({
  duplicate = false,
  focusKey = 'row-1',
}: {
  duplicate?: boolean
  focusKey?: string
}) {
  const [open, setOpen] = useState(false)
  const [generation, setGeneration] = useState(0)
  return (
    <>
      <main id="main-content" tabIndex={0}>
        <div key={generation}>
          {duplicate ? (
            <button data-focus-key={focusKey} data-copy="hidden" onClick={() => setOpen(true)}>
              Compare versions
            </button>
          ) : null}
          <button data-focus-key={focusKey} data-copy="visible" onClick={() => setOpen(true)}>
            Compare versions
          </button>
        </div>
        <button onClick={() => setGeneration((g) => g + 1)}>Land a refetch</button>
      </main>
      <Modal open={open} onClose={() => setOpen(false)} title="Compare configuration">
        <button>Close comparison</button>
      </Modal>
    </>
  )
}

describe('accessible shell and component primitives', () => {
  test('skip link targets the main landmark', () => {
    render(
      <>
        <SkipLink />
        <main id="main-content">Main content</main>
      </>,
    )

    expect(screen.getByRole('link', { name: /skip to content/i })).toHaveAttribute(
      'href',
      '#main-content',
    )
    expect(screen.getByRole('main')).toHaveAttribute('id', 'main-content')
  })

  test('route navigation moves focus to the new main content', async () => {
    const user = userEvent.setup()
    renderApp('/targets')

    await screen.findByRole('heading', { name: /targets & tests/i })
    await user.click(screen.getByRole('link', { name: /path analysis/i }))

    await screen.findByRole('heading', { name: /path & topology/i })
    await waitFor(() => expect(screen.getByRole('main')).toHaveFocus())
  })

  test('field labels, descriptions, and errors are machine-readable', () => {
    render(
      <>
        <Field id="site" label="Site URL" hint="HTTPS only" />
        <Field id="token" label="API token" error="Token is required" />
      </>,
    )

    const site = screen.getByLabelText('Site URL')
    expect(site).toHaveAccessibleDescription('HTTPS only')
    expect(site).toHaveAttribute('aria-describedby', 'site-hint')

    const token = screen.getByLabelText('API token')
    expect(token).toHaveAttribute('aria-invalid', 'true')
    expect(token).toHaveAttribute('aria-describedby', 'token-err')
    expect(screen.getByRole('alert')).toHaveTextContent('Token is required')
  })

  test('status dot keeps the text label while hiding the decorative dot', () => {
    const { container } = render(<StatusDot tone="success" label="Ready" />)

    expect(screen.getByText('Ready')).toBeVisible()
    expect(container.querySelector('[aria-hidden="true"]')).toBeTruthy()
  })

  test('modal focus trap wraps and restores focus on close', async () => {
    const user = userEvent.setup()
    render(<ModalHarness />)

    const opener = screen.getByRole('button', { name: /open details/i })
    opener.focus()
    await user.click(opener)

    const dialog = await screen.findByRole('dialog', { name: /connection details/i })
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    await waitFor(() => expect(dialog).toHaveFocus())

    const close = within(dialog).getByRole('button', { name: /close dialog/i })
    const last = within(dialog).getByRole('button', { name: /last action/i })
    close.focus()
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true })
    expect(last).toHaveFocus()

    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(opener).toHaveFocus())
  })

  // DPR-167: focusing a detached node silently does nothing and drops focus to
  // <body>, where the next Tab restarts at the top of the page.
  test('modal restores focus to a trigger that re-rendered while it was open', async () => {
    const user = userEvent.setup()
    render(<RemountingModalHarness />)

    const opener = screen.getByRole('button', { name: /compare versions/i })
    await user.click(opener)
    await screen.findByRole('dialog', { name: /compare configuration/i })

    // A refetch lands while the dialog is open: same control, new DOM node.
    fireEvent.click(screen.getByRole('button', { name: /land a refetch/i }))
    expect(opener.isConnected).toBe(false)

    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    const restored = screen.getByRole('button', { name: /compare versions/i })
    expect(restored).not.toBe(opener)
    await waitFor(() => expect(restored).toHaveFocus())
  })

  // DPR-167: the responsive layout renders the same control twice, so a bare
  // re-query can land on the hidden copy — no better than focusing nothing.
  test('modal restores focus to the visible copy of a duplicated trigger', async () => {
    const user = userEvent.setup()
    render(<RemountingModalHarness duplicate />)

    await user.click(screen.getAllByRole('button', { name: /compare versions/i })[0])
    await screen.findByRole('dialog', { name: /compare configuration/i })
    fireEvent.click(screen.getByRole('button', { name: /land a refetch/i }))

    // jsdom does no layout, so every element reports itself invisible: declare
    // which copy a browser would paint. The real-browser half of this is the
    // rendered-a11y harness's "restore trigger focus" check.
    const visible = document.querySelector<HTMLElement>('[data-copy="visible"]')!
    const hidden = document.querySelector<HTMLElement>('[data-copy="hidden"]')!
    declareVisibility(visible, true)
    declareVisibility(hidden, false)

    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(visible).toHaveFocus())
  })

  // DPR-167: a trigger with no stable key cannot be re-found, but focus must
  // still not be abandoned on <body>.
  test('modal parks focus on the main landmark when the trigger cannot be re-found', async () => {
    const user = userEvent.setup()
    render(<RemountingModalHarness focusKey="" />)

    await user.click(screen.getByRole('button', { name: /compare versions/i }))
    await screen.findByRole('dialog', { name: /compare configuration/i })
    fireEvent.click(screen.getByRole('button', { name: /land a refetch/i }))

    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(screen.getByRole('main')).toHaveFocus())
    expect(document.body).not.toHaveFocus()
  })
})
