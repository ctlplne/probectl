// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useState } from 'react'
import { getConfig, render, screen } from '@testing-library/react'
import { describe, expect, test } from 'vitest'

function LoadedRunnerRender() {
  const [ready, setReady] = useState(false)

  useEffect(() => {
    const timer = window.setTimeout(() => setReady(true), 1_100)
    return () => window.clearTimeout(timer)
  }, [])

  return ready ? <p>scheduled render completed</p> : <p>waiting for scheduled render</p>
}

describe('shared async query budget', () => {
  test('waits past the former one-second default but remains below the suite timeout', async () => {
    expect(getConfig().asyncUtilTimeout).toBe(5_000)
    expect(getConfig().asyncUtilTimeout).toBeLessThan(15_000)

    render(<LoadedRunnerRender />)

    expect(await screen.findByText('scheduled render completed')).toBeInTheDocument()
  })
})
