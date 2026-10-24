// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { act, render, screen } from '@testing-library/react'
import { useEffect } from 'react'
import { afterEach, describe, expect, test, vi } from 'vitest'
import { ToastProvider, useToast } from '../components/Toast'

function PushOnMount() {
  const { push } = useToast()
  useEffect(() => push({ tone: 'success', title: 'Saved the view' }), [push])
  return null
}

describe('toast auto-dismiss timers', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  test('a toast dismisses itself after its timeout', () => {
    vi.useFakeTimers()
    render(
      <ToastProvider>
        <PushOnMount />
      </ToastProvider>,
    )
    expect(screen.getByText('Saved the view')).toBeTruthy()
    act(() => {
      vi.advanceTimersByTime(4600)
    })
    expect(screen.queryByText('Saved the view')).toBeNull()
  })

  // CI run 40126593272: a dismiss timer outlived its provider and set state
  // after the test's window was gone ("window is not defined").
  test('unmounting the provider leaves no dismiss timer behind', () => {
    vi.useFakeTimers()
    const view = render(
      <ToastProvider>
        <PushOnMount />
      </ToastProvider>,
    )
    expect(vi.getTimerCount()).toBeGreaterThan(0)
    view.unmount()
    expect(vi.getTimerCount()).toBe(0)
  })
})
