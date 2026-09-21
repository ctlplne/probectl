// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'

// Enforces the design-system contract: product styling carries NO hardcoded
// colours — every colour resolves to a design token. That is what makes
// deployment theming a token override rather than a per-screen rewrite.
// styles/tokens.css is the one place colour literals may live.
//
// Two shapes are policed, because the Tailwind port created a second way to
// break the rule:
//
//   CSS   a colour function or hex in a .module.css. `hsl(var(--token))` is
//         FINE — that is the studio vocabulary, a token reference wrapped in the
//         function the value needs. `hsl(28 85% 30%)` is not.
//   TSX   a Tailwind arbitrary value such as `bg-[#ff0000]` or
//         `text-[hsl(28,85%,30%)]`, which bypasses the theme entirely and is
//         invisible to every CSS-side check.

/** A hex literal anywhere, or a colour function whose argument is not a var(). */
const CSS_COLOR_LITERAL = /#[0-9a-fA-F]{3,8}\b|\b(?:rgb|rgba|hsl|hsla)\(\s*(?!var\(\s*--)/

/** A Tailwind arbitrary value that carries a colour rather than a token. */
const TW_ARBITRARY_COLOR =
  /-\[\s*(?:#[0-9a-fA-F]{3,8}|(?:rgb|rgba|hsl|hsla)\((?!var\(\s*--)[^\]]*)\s*\]/

function filesUnder(dir: string, suffix: string): string[] {
  const out: string[] = []
  let entries
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return out
  }
  for (const entry of entries) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue
      out.push(...filesUnder(full, suffix))
    } else if (entry.name.endsWith(suffix)) {
      out.push(full)
    }
  }
  return out
}

// Core UI + the ee/web tree share one token contract; commercial surfaces obey
// it identically.
const ROOTS = [join(process.cwd(), 'src'), join(process.cwd(), '../ee/web')]

describe('design tokens', () => {
  test('no .module.css uses a hardcoded color literal', () => {
    const offenders: string[] = []
    let scanned = 0
    for (const dir of ROOTS) {
      for (const file of filesUnder(dir, '.module.css')) {
        scanned += 1
        readFileSync(file, 'utf8')
          .split('\n')
          .forEach((line, i) => {
            if (CSS_COLOR_LITERAL.test(line)) offenders.push(`${file}:${i + 1}  ${line.trim()}`)
          })
      }
    }
    expect(
      offenders,
      `hardcoded colors must move into tokens.css:\n${offenders.join('\n')}`,
    ).toEqual([])
    // A contract that scans nothing passes for the wrong reason.
    expect(scanned).toBeGreaterThan(20)
  })

  test('no component smuggles a color through a Tailwind arbitrary value', () => {
    const offenders: string[] = []
    let scanned = 0
    for (const dir of ROOTS) {
      for (const file of [...filesUnder(dir, '.tsx'), ...filesUnder(dir, '.ts')]) {
        if (file.includes('.test.') || file.endsWith('tokens.css')) continue
        scanned += 1
        readFileSync(file, 'utf8')
          .split('\n')
          .forEach((line, i) => {
            if (TW_ARBITRARY_COLOR.test(line)) offenders.push(`${file}:${i + 1}  ${line.trim()}`)
          })
      }
    }
    expect(
      offenders,
      `use a token-backed utility (bg-primary, text-status-warning) instead of an arbitrary color:\n${offenders.join('\n')}`,
    ).toEqual([])
    expect(scanned).toBeGreaterThan(50)
  })

  test('the contract rejects both shapes it is meant to catch', () => {
    // Bisect in-place: if these ever stop matching, the two tests above are
    // decoration.
    expect(CSS_COLOR_LITERAL.test('  color: #ff0000;')).toBe(true)
    expect(CSS_COLOR_LITERAL.test('  color: hsl(28 85% 30%);')).toBe(true)
    expect(CSS_COLOR_LITERAL.test('  color: hsl(var(--foreground));')).toBe(false)
    expect(CSS_COLOR_LITERAL.test('  color: hsl(var(--brand-accent) / 0.12);')).toBe(false)
    expect(TW_ARBITRARY_COLOR.test('className="bg-[#ff0000]"')).toBe(true)
    expect(TW_ARBITRARY_COLOR.test('className="text-[hsl(28,85%,30%)]"')).toBe(true)
    expect(TW_ARBITRARY_COLOR.test('className="bg-primary text-data"')).toBe(false)
    // A non-colour arbitrary value is legitimate and must not be flagged.
    expect(TW_ARBITRARY_COLOR.test('className="max-h-[70vh]"')).toBe(false)
    expect(TW_ARBITRARY_COLOR.test('className="[animation-duration:var(--motion-spinner)]"')).toBe(
      false,
    )
  })
})
