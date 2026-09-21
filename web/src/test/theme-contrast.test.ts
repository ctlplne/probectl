// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { buildContrastPairs, contrastRatioForPair, tokenOverridesPassContrast } from '../api/brand'

// DPR-247: escape EVERY regex metacharacter, not four of them. CodeQL
// js/incomplete-sanitization is right about the pattern even though the input here
// is a test literal: `[[\]'.]` misses ( ) * + ? { } | ^ $ - and backslash, so a
// selector containing any of them would build a regex that silently matches the
// wrong declaration block — a contrast test that passes while testing nothing.
const escapeForRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&')

function themeBlock(css: string, selector: string) {
  const escaped = escapeForRegExp(selector)
  const match = new RegExp(`([^}]*${escaped}[^{]*)\\{([^}]*)\\}`).exec(css)
  return match?.[2] ?? ''
}

/** Every custom property declared in the block, in the studio vocabulary (the
 *  names are unprefixed now, so a `--color-*` filter would match nothing). */
function colorTokens(css: string, selector: string) {
  const block = themeBlock(css, selector)
  const tokens: Record<string, string> = {}
  for (const match of block.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) {
    tokens[match[1]] = match[2].trim()
  }
  return tokens
}

describe('theme color contrast', () => {
  test('both shipped themes satisfy every text and non-text contrast pair', () => {
    const css = readFileSync(join(process.cwd(), 'src/styles/tokens.css'), 'utf8')
    const failures: string[] = []
    // The runtime's own list, not a second copy: a pair the product enforces on a
    // deployment override has to hold for the palette we ship as well.
    const pairs = buildContrastPairs()
    let checked = 0

    for (const [theme, selector] of Object.entries({
      // Light is :root, selected by its color-scheme declaration; dark overrides it.
      light: 'color-scheme: light',
      dark: "[data-theme='dark']",
    })) {
      const tokens = colorTokens(css, selector)
      for (const pair of pairs) {
        if (!tokens[pair.fg] || !tokens[pair.bg]) continue
        checked += 1
        // The runtime's own evaluator, so a wash pair is composited here exactly
        // as the product composites it.
        const ratio = contrastRatioForPair(tokens, pair)
        if (ratio === undefined || ratio < pair.min) {
          const on =
            pair.bgAlpha === undefined
              ? pair.bg
              : `${pair.bg} @${pair.bgAlpha} over ${pair.backdrop}`
          failures.push(
            `${theme}: ${pair.fg} on ${on} = ${ratio?.toFixed(2) ?? 'parse-failed'}:1, want ${pair.min}:1`,
          )
        }
      }
    }

    expect(failures).toEqual([])
    // The guard against the failure this test actually had: when the token names
    // changed, every pair was skipped and it passed while checking nothing. A
    // vacuous pass is worse than a red test, so assert the work happened.
    expect(checked).toBeGreaterThanOrEqual(2 * pairs.length)
  })

  test('bad deployment override fixtures fail the same contrast gate', () => {
    // White body text on warm paper, a brand orange too light to carry its own
    // label, and chart series indistinguishable from the card behind them.
    expect(tokenOverridesPassContrast({ '--foreground': '0 0% 100%' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--primary': '28 100% 92%' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--chart-1': '0 0% 100%' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--chart-6': '0 0% 100%' })).toBe(false)
    // And the shape the parser previously could not read at all must be rejected
    // on its merits, not silently accepted for being unparseable.
    expect(tokenOverridesPassContrast({ '--muted-foreground': '45 33% 96%' })).toBe(false)
  })

  test('a legitimate override still passes', () => {
    // Deployment theming has to remain usable, not just guarded. The constraint
    // is real and worth stating: applyBrand sets overrides as INLINE style on
    // <html>, so one value lands in both themes and has to clear its ratio in
    // both. That rules out most single-token brand swaps — warm paper wants a
    // dark brand with a light label, dark wants the reverse — and it admits
    // mid-tones, which clear 3:1 against near-white and near-black alike.
    expect(tokenOverridesPassContrast({ '--chart-2': '213 62% 48%' })).toBe(true)
  })
})
