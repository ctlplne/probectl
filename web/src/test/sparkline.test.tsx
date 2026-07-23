// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Sparkline } from '../components/ChartShell'

describe('Sparkline honesty', () => {
  test('a single sample renders a point marker, never a trend shape', () => {
    const { container } = render(<Sparkline data={[85]} label="Flow capacity trend" />)
    expect(
      screen.getByRole('img', { name: /flow capacity trend \(single sample\)/i }),
    ).toBeInTheDocument()
    expect(container.querySelector('circle')).not.toBeNull()
    expect(container.querySelector('polygon')).toBeNull()
    expect(container.querySelector('polyline')).toBeNull()
  })

  test('two or more samples render the line and area', () => {
    const { container } = render(<Sparkline data={[10, 20]} label="Latency" />)
    expect(screen.getByRole('img', { name: 'Latency' })).toBeInTheDocument()
    expect(container.querySelector('polyline')).not.toBeNull()
    expect(container.querySelector('circle')).toBeNull()
  })
})
