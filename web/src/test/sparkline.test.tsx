// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
