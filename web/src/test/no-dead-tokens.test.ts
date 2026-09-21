// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

/**
 * The design contract nothing was checking: every design token a shipped file
 * REFERENCES must be a token the stylesheets actually DEFINE.
 *
 * no-hardcoded-colors forbids literal values and theme-contrast checks the
 * palette, but neither notices a reference to a token that no longer exists —
 * and that is not an error in CSS: the reference resolves to nothing and the
 * whole declaration is dropped. The design-language port renamed the vocabulary
 * and left the entire EE provider console, the chart series strokes, and the
 * rendered-a11y gate pointing at retired names: styling that silently stopped
 * applying while every test stayed green.
 */
import { describe, expect, test } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

const webRoot = process.cwd()
const repoRoot = resolve(webRoot, '..')

// Trees that ship to a browser, plus the gates that assert about them.
const SCAN_ROOTS = [join(webRoot, 'src'), join(repoRoot, 'ee', 'web'), join(repoRoot, 'scripts')]
const STYLE_ROOTS = [join(webRoot, 'src'), join(repoRoot, 'ee', 'web')]
const CODE_EXTENSIONS = ['.css', '.ts', '.tsx', '.mjs', '.js']

function walk(dir: string, extensions: string[]): string[] {
  let found: string[] = []
  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return found
  }
  for (const entry of entries) {
    if (entry === 'node_modules' || entry === 'dist' || entry.startsWith('.')) continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      found = found.concat(walk(full, extensions))
    } else if (extensions.some((ext) => entry.endsWith(ext))) {
      found.push(full)
    }
  }
  return found
}

/** Every custom property any shipped stylesheet declares. */
function definedTokens(): Set<string> {
  const defined = new Set<string>()
  for (const root of STYLE_ROOTS) {
    for (const file of walk(root, ['.css'])) {
      for (const m of readFileSync(file, 'utf8').matchAll(/(^|[;{\s])(--[a-z0-9-]+)\s*:/g)) {
        defined.add(m[2])
      }
    }
  }
  return defined
}

interface Reference {
  token: string
  file: string
  /** A template literal builds the name at runtime: --chart-${index}. */
  family: boolean
}

function references(): Reference[] {
  const found: Reference[] = []
  for (const root of SCAN_ROOTS) {
    for (const file of walk(root, CODE_EXTENSIONS)) {
      const source = readFileSync(file, 'utf8')
      const where = relative(repoRoot, file)
      // var(--name ...) in CSS and in inline styles.
      for (const m of source.matchAll(/var\(\s*(--[a-z0-9-]*)(\$\{)?/g)) {
        found.push({ token: m[1], file: where, family: Boolean(m[2]) })
      }
      // The CSSOM path: getComputedStyle(...).getPropertyValue('--name').
      for (const m of source.matchAll(/getPropertyValue\(\s*[`'"](--[a-z0-9-]*)(\$\{)?/g)) {
        found.push({ token: m[1], file: where, family: Boolean(m[2]) })
      }
      // Indirections that read a token by name, e.g. a local read('--name') helper.
      for (const m of source.matchAll(/\bread(?:Color)?\(\s*[`'"](--[a-z0-9-]*)(\$\{)?/g)) {
        found.push({ token: m[1], file: where, family: Boolean(m[2]) })
      }
    }
  }
  return found
}

// Comments are scanned on purpose — a stale token name in prose is how the
// rendered-a11y gate documented a token that had not existed for a while. These
// two are generic stand-ins used when writing ABOUT the token grammar, not
// references to anything, so they are named explicitly rather than by exempting
// comments wholesale.
const PROSE_PLACEHOLDERS = new Set(['--token', '--name'])

const DEFINED = definedTokens()
const REFERENCES = references()

describe('design token references', () => {
  // Guards against the scanner quietly matching nothing, which is how a contract
  // test keeps passing after the thing it reads has moved.
  test('the scanner actually found the token vocabulary', () => {
    expect(DEFINED.size).toBeGreaterThan(100)
    expect(REFERENCES.length).toBeGreaterThan(200)
    expect(DEFINED.has('--background')).toBe(true)
    expect(DEFINED.has('--space-3')).toBe(true)
    // A token the port retired must NOT be defined, or "every reference resolves"
    // would be satisfiable by keeping the old names alive alongside the new ones.
    expect(DEFINED.has('--color-accent')).toBe(false)
  })

  test('every referenced token is defined by a shipped stylesheet', () => {
    const dead = REFERENCES.filter(
      (r) =>
        !r.family &&
        r.token.length > 2 &&
        !PROSE_PLACEHOLDERS.has(r.token) &&
        !DEFINED.has(r.token),
    )
    const report = [...new Set(dead.map((r) => `${r.file}: var(${r.token})`))].sort()
    expect(
      report,
      `these references resolve to nothing, so the declarations using them are silently dropped:\n${report.join('\n')}`,
    ).toEqual([])
  })

  test('every runtime-built token family has defined members', () => {
    // `var(--chart-${index})` cannot be checked by name, so the prefix is
    // required to match real tokens — which is what catches a renamed family.
    const prefixes = [...new Set(REFERENCES.filter((r) => r.family).map((r) => r.token))]
    expect(prefixes.length).toBeGreaterThan(0)
    const orphaned = prefixes.filter(
      (prefix) => ![...DEFINED].some((token) => token.startsWith(prefix)),
    )
    expect(
      orphaned,
      `no shipped token starts with these runtime-built prefixes: ${orphaned.join(', ')}`,
    ).toEqual([])
  })

  test('the EE provider console is inside the scanned surface', () => {
    // It was outside every design gate, which is why it rotted unnoticed.
    const eeFiles = REFERENCES.filter((r) => r.file.startsWith('ee/web/'))
    expect(eeFiles.length).toBeGreaterThan(10)
  })
})
