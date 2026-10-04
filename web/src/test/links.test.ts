// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, it } from 'vitest'

import { appPath, safeHref, safeInternalTo } from '../lib/links'

// WEB-14: server-provided link targets must pass a scheme allow-list before
// being rendered as live links.
describe('link scheme allow-lists (WEB-14)', () => {
  it('safeHref admits only absolute https URLs', () => {
    expect(safeHref('https://trustctl.example/renew')).toBe('https://trustctl.example/renew')
    for (const hostile of [
      'javascript:alert(1)',
      'data:text/html,evil',
      'http://phish.example',
      '//evil.example',
      '/relative/path',
      'vbscript:x',
      '',
      undefined,
      null,
    ]) {
      expect(safeHref(hostile)).toBeUndefined()
    }
  })

  it('appPath prefixes the /ui basename so copyable links resolve (WEB-07)', () => {
    expect(new URL(appPath('/incidents'), 'https://probectl.example').pathname).toBe(
      '/ui/incidents',
    )
    expect(appPath('/dashboards')).toBe('/ui/dashboards')
  })

  it('safeInternalTo admits only single-slash in-app paths', () => {
    expect(safeInternalTo('/docs/api#rollouts')).toBe('/docs/api#rollouts')
    for (const hostile of [
      'javascript:alert(1)',
      'http://evil.example',
      '//evil.example',
      'data:text/html,evil',
      'relative',
      '',
      undefined,
      null,
    ]) {
      expect(safeInternalTo(hostile)).toBeUndefined()
    }
  })
})
