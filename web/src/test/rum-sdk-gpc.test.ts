// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

// The RUM SDK is a browser IIFE keyed off document.currentScript's data-*
// attributes; load it by evaluating the shipped source in jsdom (WEB-12).
const sdkSource = readFileSync(resolve(__dirname, '../../public/probectl-rum.js'), 'utf8')

function loadSDK() {
  const script = document.createElement('script')
  script.setAttribute('data-key', 'pk_test')
  script.setAttribute('data-endpoint', 'https://probectl.example/ingest/rum')
  Object.defineProperty(document, 'currentScript', { value: script, configurable: true })
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  new Function(sdkSource)()
}

describe('probectl RUM SDK honours Global Privacy Control (WEB-12)', () => {
  afterEach(() => {
    delete (window as unknown as Record<string, unknown>).probectlRUM
    delete (navigator as unknown as Record<string, unknown>).globalPrivacyControl
  })

  it('does not arm when navigator.globalPrivacyControl is set', () => {
    Object.defineProperty(navigator, 'globalPrivacyControl', { value: true, configurable: true })
    loadSDK()
    expect((window as unknown as Record<string, unknown>).probectlRUM).toBeUndefined()
  })

  it('arms normally when no privacy signal is present', () => {
    loadSDK()
    expect((window as unknown as Record<string, unknown>).probectlRUM).toBeDefined()
  })
})
