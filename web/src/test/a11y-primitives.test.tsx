import { useState } from 'react'
import { describe, expect, test } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Field, Modal, StatusDot } from '../components'
import { SkipLink } from '../shell/SkipLink'

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
})
