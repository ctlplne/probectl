import { describe, expect, test } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'

describe('mobile navigation drawer', () => {
  function useMobileViewport() {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    window.dispatchEvent(new Event('resize'))
  }

  function mobileTrigger() {
    const trigger = screen
      .getAllByRole('button', { hidden: true })
      .find((button) => button.getAttribute('aria-label') === 'Open navigation')
    if (!trigger) throw new Error('mobile navigation trigger not found')
    trigger.style.display = 'inline-flex'
    return trigger
  }

  test('opens from the TopBar, reuses primary nav items, and restores focus on Escape', async () => {
    const user = userEvent.setup()
    useMobileViewport()
    renderApp('/targets')

    await screen.findByRole('heading', { name: /targets & tests/i })
    const trigger = mobileTrigger()
    trigger.focus()

    await user.click(trigger)

    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    const dialog = await screen.findByRole('dialog', { name: /navigation/i })
    const mobileNav = within(dialog).getByRole('navigation', { name: /mobile primary/i })
    const firstLink = within(mobileNav).getByRole('link', { name: /targets & tests/i })
    await waitFor(() => expect(firstLink).toHaveFocus())
    expect(within(mobileNav).getByRole('link', { name: /targets & tests/i })).toBeInTheDocument()
    expect(within(mobileNav).getByRole('link', { name: /get started/i })).toBeInTheDocument()
    expect(within(mobileNav).getByRole('link', { name: /admin & settings/i })).toBeInTheDocument()

    await user.keyboard('{Escape}')

    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: /navigation/i })).not.toBeInTheDocument(),
    )
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
    expect(trigger).toHaveFocus()
  })

  test('closes after choosing a mobile nav route', async () => {
    const user = userEvent.setup()
    useMobileViewport()
    renderApp('/targets')

    await screen.findByRole('heading', { name: /targets & tests/i })
    const trigger = mobileTrigger()
    await user.click(trigger)
    const dialog = await screen.findByRole('dialog', { name: /navigation/i })
    await user.click(within(dialog).getByRole('link', { name: /^alerts$/i }))

    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: /navigation/i })).not.toBeInTheDocument(),
    )
    expect(await screen.findByRole('heading', { name: /^alerts$/i })).toBeInTheDocument()
  })
})
