import { describe, expect, test } from 'vitest'
import { waitFor } from '@testing-library/react'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'

// Structural WCAG 2.2 AA gate: roles, names, labels, landmarks, heading order.
// (Color-contrast is fixed at the token layer — see tokens.css — since jsdom
// cannot compute rendered contrast; a browser-based contrast check is PR2.)
describe('accessibility', () => {
  test('the targets page (app shell + table) has no axe violations', async () => {
    const { container, findByRole } = renderApp('/targets')
    await findByRole('heading', { name: /targets & tests/i })
    await waitFor(() => expect(container.querySelector('tbody tr')).toBeTruthy())
    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })

  test('the alerts page has no axe violations', async () => {
    const { container, findByText } = renderApp('/alerts')
    await findByText('Alert rules')
    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })

  test('the security/certificates page has no axe violations', async () => {
    const { container, findByText } = renderApp('/security')
    await findByText('Certificate inventory')
    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })

  test('the admin/agents page has no axe violations', async () => {
    const { container, findByRole } = renderApp('/admin')
    await findByRole('heading', { name: /admin & settings/i })
    await waitFor(() => expect(container.querySelector('tbody tr')).toBeTruthy())
    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })

  test('the design-system gallery has no axe violations', async () => {
    const { container, findByRole } = renderApp('/gallery')
    await findByRole('heading', { name: /design system/i })
    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })
})
