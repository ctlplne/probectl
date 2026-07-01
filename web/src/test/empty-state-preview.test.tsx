import { render, screen } from '@testing-library/react'
import { describe, expect, test } from 'vitest'
import {
  DashboardPreview,
  EmptyState,
  FirstRunPreview,
  PlanesPreview,
  TopologyPreview,
} from '../components'

describe('EmptyState preview slot', () => {
  test('renders an optional preview without replacing the action', () => {
    render(
      <EmptyState
        title="No tests yet"
        description="Create your first test to begin monitoring."
        action={<button type="button">New test</button>}
        preview={<FirstRunPreview />}
      />,
    )

    expect(screen.getByRole('heading', { name: /no tests yet/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /new test/i })).toBeInTheDocument()
    expect(screen.getByLabelText(/first-run sample preview/i)).toBeInTheDocument()
    expect(screen.getByText('checkout-http')).toBeInTheDocument()
  })

  test('ships reusable first-run, topology, planes, and dashboard previews', () => {
    render(
      <div>
        <FirstRunPreview />
        <TopologyPreview />
        <PlanesPreview />
        <DashboardPreview />
      </div>,
    )

    expect(screen.getByLabelText(/first-run sample preview/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/topology sample preview/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/planes sample preview/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/dashboard sample preview/i)).toBeInTheDocument()
    expect(screen.getByText('edge-r1')).toBeInTheDocument()
    expect(screen.getByText('Flow')).toBeInTheDocument()
    expect(screen.getByText('99.95%')).toBeInTheDocument()
  })
})
