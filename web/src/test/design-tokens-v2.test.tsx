// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { readFileSync, readdirSync } from 'node:fs'
import { basename, join, relative } from 'node:path'
import { describe, expect, test } from 'vitest'

const repoRoot = join(process.cwd(), '..')
const tokenPath = join(process.cwd(), 'src/styles/tokens.css')

function cssFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...cssFiles(path))
    else if (entry.name.endsWith('.css')) out.push(path)
  }
  return out
}

function declarationBlock(css: string, selector: string): string {
  const escaped = selector.replace(/[[\]'.]/g, '\\$&')
  return new RegExp(`([^}]*${escaped}[^{]*)\\{([^}]*)\\}`).exec(css)?.[2] ?? ''
}

function tokenNames(block: string, prefix: string): string[] {
  return [...block.matchAll(new RegExp(`(${prefix}[a-z0-9-]+)\\s*:`, 'g'))].map((match) => match[1])
}

function hasRawNonzeroNumber(value: string): boolean {
  const withoutTokens = value.replace(/var\(--[a-z0-9-]+(?:\s*,[^)]+)?\)/g, '')
  return [...withoutTokens.matchAll(/-?(?:\d*\.)?\d+(?:[a-z%]+)?/gi)].some((match) => {
    const number = Number.parseFloat(match[0])
    return Number.isFinite(number) && number !== 0
  })
}

function hasRawMotion(value: string): boolean {
  const withoutTokens = value.replace(/var\(--[a-z0-9-]+(?:\s*,[^)]+)?\)/g, '')
  return (
    /-?(?:\d*\.)?\d+(?:ms|s)\b/i.test(withoutTokens) ||
    /\b(?:linear|ease|ease-in|ease-out|ease-in-out|step-start|step-end)\b|cubic-bezier\(/i.test(
      withoutTokens,
    )
  )
}

describe('expert design-token contract', () => {
  const tokens = readFileSync(tokenPath, 'utf8')

  test('comfortable and compact density expose the same complete override surface', () => {
    const comfortable = tokenNames(
      declarationBlock(tokens, "[data-density='comfortable']"),
      '--density-',
    )
    const compact = tokenNames(declarationBlock(tokens, "[data-density='compact']"), '--density-')
    expect(comfortable.sort()).toEqual(compact.sort())
    expect(compact).toEqual(
      expect.arrayContaining([
        '--density-control-block',
        '--density-control-block-sm',
        '--density-row-block',
        '--density-panel-padding',
        '--density-table-cell-block',
        '--density-table-cell-inline',
        '--density-touch-target',
      ]),
    )
    expect(declarationBlock(tokens, "[data-density='compact']")).toContain(
      '--density-touch-target: 44px',
    )

    // The primitives are Tailwind now, so the density chain runs
    // token -> tailwind.config theme -> utility on the component. Assert every
    // link: a token mapped in the theme but used by nothing is still dead, and a
    // utility whose theme entry is missing silently resolves to nothing.
    const tailwindConfig = readFileSync(join(process.cwd(), 'tailwind.config.js'), 'utf8')
    const primitiveNames = [
      'Button.tsx',
      'Input.tsx',
      'Table.tsx',
      'Card.tsx',
      'DataGrid.tsx',
      'controlStyles.ts',
    ]
    const primitives = primitiveNames
      .map((name) => readFileSync(join(process.cwd(), 'src/components', name), 'utf8'))
      .join('\n')
    for (const [token, utility] of [
      ['--density-control-block', 'h-control'],
      ['--density-row-block', 'h-row'],
      ['--density-panel-padding', 'panel-padding'],
      ['--density-table-cell-block', 'cell-block'],
      ['--density-table-cell-inline', 'cell-inline'],
    ]) {
      expect(tailwindConfig, `density token ${token} is not mapped in the theme`).toContain(
        `var(${token})`,
      )
      expect(primitives, `density utility ${utility} is mapped but unused`).toContain(utility)
    }

    const global = readFileSync(join(process.cwd(), 'src/styles/global.css'), 'utf8')
    expect(global).toContain('@media (pointer: coarse)')
    expect(global).toContain('min-block-size: var(--density-touch-target)')
    expect(global).toContain('width: var(--density-control-block-sm)')
    expect(global).toContain('min-width: var(--density-control-block-sm)')
    expect(global).toContain('flex: 0 0 var(--density-control-block-sm)')
  })

  test('visualization, focus, selection, layer, and motion tokens are explicit', () => {
    for (const name of [
      '--focus-ring-width',
      '--focus-ring-offset',
      '--selection-outline-width',
      '--viz-series-1-dash',
      '--viz-series-6-dash',
      '--viz-state-observed-border',
      '--viz-state-estimated-border',
      '--viz-state-missing-border',
      '--motion-fast',
      '--motion-spinner',
      '--easing-standard',
      '--z-sticky',
      '--z-overlay',
      '--z-modal',
      '--z-toast',
    ]) {
      expect(tokens, `missing ${name}`).toContain(`${name}:`)
    }
    for (let index = 1; index <= 6; index += 1) {
      expect(tokens).toContain(`--chart-${index}:`)
      expect(tokens).toContain(`--viz-series-${index}-dash:`)
    }

    const chart = readFileSync(join(process.cwd(), 'src/components/ChartShell.module.css'), 'utf8')
    const path = readFileSync(join(process.cwd(), 'src/viz/PathGraph.module.css'), 'utf8')
    expect(chart).toContain('stroke: hsl(var(--chart-1))')
    expect(chart).toContain('stroke-dasharray: var(--viz-series-1-dash)')
    expect(path).toContain('stroke-dasharray: var(--viz-series-2-dash)')
    expect(path).toContain('stroke: hsl(var(--brand-accent))')
    expect(path).toContain('stroke-width: var(--selection-outline-width)')
  })

  test('reduced motion zeros every duration and product CSS keeps an explicit fallback', () => {
    const reduced =
      /@media \(prefers-reduced-motion: reduce\)\s*\{\s*:root\s*\{([\s\S]*?)\}\s*\}/.exec(
        tokens,
      )?.[1] ?? ''
    for (const name of [
      '--motion-fast',
      '--motion-base',
      '--motion-slow',
      '--motion-spinner',
      '--motion-shimmer',
    ]) {
      expect(reduced).toContain(`${name}: 0ms`)
    }
    const product = cssFiles(join(process.cwd(), 'src'))
      .filter((path) => path !== tokenPath)
      .map((path) => readFileSync(path, 'utf8'))
      .join('\n')
    expect(product).toContain('@media (prefers-reduced-motion: reduce)')
    expect(product).toMatch(/animation:\s*none/)

    const states = readFileSync(join(process.cwd(), 'src/components/States.tsx'), 'utf8')
    expect(states).toContain("label = 'Loading…'")
    expect(states).toContain('{label}')
  })

  test('product CSS has no raw color, spacing, type, radius, layer, or motion values', () => {
    const failures: string[] = []
    const files = [join(process.cwd(), 'src'), join(repoRoot, 'ee/web')]
      .flatMap(cssFiles)
      .filter((path) => path !== tokenPath)
    const dimensional =
      /^(?:margin(?:-[a-z-]+)?|padding(?:-[a-z-]+)?|gap|row-gap|column-gap|scroll-margin(?:-[a-z-]+)?|font-size|line-height|letter-spacing|border-radius|z-index)$/
    const motion = /^(?:transition(?:-[a-z-]+)?|animation(?:-[a-z-]+)?)$/
    // A colour FUNCTION wrapping a token is the studio vocabulary and is fine;
    // a literal inside one is not. Matches no-hardcoded-colors.test.ts.
    const colorLiteral = /#[0-9a-f]{3,8}\b|\b(?:rgb|rgba|hsl|hsla)\(\s*(?!var\(\s*--)/i
    const declaration = /([a-z-]+)\s*:\s*([^;{}]+);/g

    for (const file of files) {
      const css = readFileSync(file, 'utf8')
      for (const match of css.matchAll(declaration)) {
        const [, property, value] = match
        const line = css.slice(0, match.index).split('\n').length
        if (
          colorLiteral.test(value) ||
          (dimensional.test(property) && hasRawNonzeroNumber(value)) ||
          (motion.test(property) && hasRawMotion(value))
        ) {
          failures.push(
            `${relative(repoRoot, file)}:${line}: ${property}: ${value.trim()} (${basename(file)})`,
          )
        }
      }
    }
    expect(failures).toEqual([])
  })

  test('Audit action links consume the shared weight, density, border, and focus tokens', () => {
    const audit = readFileSync(join(process.cwd(), 'src/routes/audit.module.css'), 'utf8')
    const target = declarationBlock(audit, '.auditTargetLink')
    const targetFocus = declarationBlock(audit, '.auditTargetLink:focus-visible')
    const button = declarationBlock(audit, '.linkButton')
    const buttonFocus = declarationBlock(audit, '.linkButton:focus-visible')

    expect(target).toContain('font-weight: var(--font-weight-bold)')
    expect(targetFocus).toContain('outline: var(--focus-ring-width) solid hsl(var(--focus))')
    expect(targetFocus).toContain('outline-offset: var(--focus-ring-offset)')
    expect(button).toContain('min-height: var(--density-control-block)')
    expect(button).toContain('border: var(--border-width-thin) solid hsl(var(--border))')
    expect(button).toContain('font-weight: var(--font-weight-bold)')
    expect(buttonFocus).toContain('outline: var(--focus-ring-width) solid hsl(var(--focus))')
    expect(buttonFocus).toContain('outline-offset: var(--focus-ring-offset)')
  })

  test('long dialogs stay inside the viewport with a scrollable body', () => {
    // The dialog is Tailwind now, so the assertion follows the implementation.
    // The property under test is unchanged: a dialog taller than the viewport
    // must scroll its BODY, never push its header and footer off-screen.
    const modal = readFileSync(join(process.cwd(), 'src/components/Modal.tsx'), 'utf8')

    // The overlay holds the dialog off the top edge by the layout token.
    expect(modal).toContain('pt-[var(--layout-dialog-inset-block)]')
    // The dialog is a clipped column, so only the body can scroll.
    expect(modal).toContain('flex w-full max-w-xl flex-col overflow-hidden')
    // And the body is the part with a bounded height and its own scrollbar.
    expect(modal).toContain('max-h-[var(--layout-dialog-scroll-max-block)] overflow-auto')
  })

  test('density and theme selectors stay deployment-level, never tenant-addressed', () => {
    expect(tokens).not.toMatch(/data-tenant|tenant[_-]id|tenant[_-]slug/i)
  })
})
