// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
  test('uses an explicit h2 for a top-level page state while retaining the nested h3 default', () => {
    render(
      <div>
        <EmptyState title="Top-level empty state" headingLevel={2} />
        <EmptyState title="Nested empty state" />
      </div>,
    )

    expect(screen.getByRole('heading', { name: 'Top-level empty state', level: 2 })).toBeDefined()
    expect(screen.getByRole('heading', { name: 'Nested empty state', level: 3 })).toBeDefined()
  })

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
