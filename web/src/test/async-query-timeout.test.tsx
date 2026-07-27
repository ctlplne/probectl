// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
