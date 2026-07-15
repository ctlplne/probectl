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

  test('never renders an illustrative preview in live mode and preserves the action', () => {
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
    expect(screen.queryByLabelText(/first-run sample preview/i)).toBeNull()
    expect(screen.queryByText('checkout-http')).toBeNull()
  })

  test('all reusable sample previews fail closed outside the isolated demo provider', () => {
    render(
      <div>
        <FirstRunPreview />
        <TopologyPreview />
        <PlanesPreview />
        <DashboardPreview />
      </div>,
    )

    expect(screen.queryByLabelText(/first-run sample preview/i)).toBeNull()
    expect(screen.queryByLabelText(/topology sample preview/i)).toBeNull()
    expect(screen.queryByLabelText(/planes sample preview/i)).toBeNull()
    expect(screen.queryByLabelText(/dashboard sample preview/i)).toBeNull()
  })
})
