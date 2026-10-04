// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, it } from 'vitest'

import { asYAML } from '../routes/codeExport'
import { shellSingleQuote } from '../lib/clientGuards'

// WEB-25: exported/copied formats must escape untrusted text so a hostile key
// or value cannot change the document's structure or type.
describe('export escaping (WEB-25)', () => {
  it('quotes hostile YAML keys and type-ambiguous values', () => {
    const out = asYAML({
      'a\nb': 'x',
      flag: 'true',
      at: '@x',
      numish: '123',
      url: 'https://e.example/p?q=1',
      plainkey: 'plainvalue',
    })
    // A key containing a newline must be quoted, not emitted raw (which would
    // break the document into stray lines).
    expect(out).toContain('"a\\nb":')
    // Values that would otherwise read back as a bool / number / indicator are
    // quoted so they round-trip as the original strings.
    expect(out).toContain('flag: "true"')
    expect(out).toContain('at: "@x"')
    expect(out).toContain('numish: "123"')
    expect(out).toContain('url: "https://e.example/p?q=1"')
    // An unambiguous key/value stays unquoted.
    expect(out).toContain('plainkey: plainvalue')
  })

  it('single-quotes shell arguments safely', () => {
    expect(shellSingleQuote('alice@example.com')).toBe("'alice@example.com'")
    // A value trying to break out of the quotes stays inert.
    expect(shellSingleQuote("a';id;'b")).toBe("'a'\\'';id;'\\''b'")
  })
})
