// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// @vitest-environment node

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import postcss, { type AcceptedPlugin } from 'postcss'
import { expect, test } from 'vitest'

async function compileTheme(candidates: string[] = []) {
  const configPath = join(process.cwd(), 'postcss.config.js')
  const config = (await import(configPath)) as {
    default: { plugins: AcceptedPlugin[] | Record<string, Record<string, unknown>> }
  }
  // PostCSS supports both its object and array configuration forms. Load the
  // actual build pipeline so its output, including final transforms, is tested.
  const plugins = Array.isArray(config.default.plugins)
    ? config.default.plugins
    : await Promise.all(
        Object.entries(config.default.plugins).map(async ([name, options]) => {
          const plugin = (await import(name)) as { default: (options: unknown) => AcceptedPlugin }
          return plugin.default(options)
        }),
      )
  const file = join(process.cwd(), 'src/styles/global.css')
  return postcss(plugins).process(
    readFileSync(file, 'utf8') + `\n@source inline("${candidates.join(' ')}");\n`,
    { from: file },
  )
}

// Exercise the actual CSS entrypoint and engine. Token declarations alone do
// not prove a build emits the utilities that keep controls readable and usable.
test('Tailwind 4 emits token-backed controls, opacity, motion and class-based dark mode', async () => {
  const installed = JSON.parse(
    readFileSync(join(process.cwd(), 'node_modules/tailwindcss/package.json'), 'utf8'),
  ) as { version: string }
  expect(installed.version.split('.')[0], 'the installed CSS engine must be Tailwind 4').toBe('4')

  const candidates = [
    'h-control',
    'h-row',
    'px-cell-inline',
    'py-cell-block',
    'p-panel-padding',
    'min-w-touch',
    'min-h-touch',
    'text-data',
    'text-primary-foreground',
    'bg-primary/90',
    'dark:bg-card',
    'font-sans',
    'font-display',
    'rounded-control',
    'z-modal',
    'duration-fast',
    'animate-panel-in',
  ]
  const result = await compileTheme(candidates)
  const declarations = new Map<string, string[]>()
  result.root.walkRules((rule) => {
    const values: string[] = []
    rule.walkDecls((declaration) => {
      values.push(`${declaration.prop}: ${declaration.value}`)
    })
    declarations.set(rule.selector, [...(declarations.get(rule.selector) ?? []), ...values])
  })
  for (const [utility, declaration] of [
    ['h-control', 'height: var(--density-control-block)'],
    ['h-row', 'height: var(--density-row-block)'],
    ['px-cell-inline', 'padding-inline: var(--density-table-cell-inline)'],
    ['py-cell-block', 'padding-block: var(--density-table-cell-block)'],
    ['p-panel-padding', 'padding: var(--density-panel-padding)'],
    ['min-w-touch', 'min-width: var(--density-touch-target)'],
    ['min-h-touch', 'min-height: var(--density-touch-target)'],
    ['text-data', 'font-size: var(--font-size-data)'],
    ['text-primary-foreground', 'color: hsl(var(--primary-foreground))'],
    ['font-sans', 'font-family: var(--font-sans)'],
    ['font-display', 'font-family: var(--font-display)'],
    ['rounded-control', 'border-radius: var(--radius-control)'],
    ['z-modal', 'z-index: var(--z-modal)'],
    ['duration-fast', 'transition-duration: var(--motion-fast)'],
  ]) {
    expect(declarations.get(`.${utility}`), `missing compiled ${utility}`).toContain(declaration)
  }
  expect(
    declarations.get('.text-data')?.find((value) => value.startsWith('line-height:')),
  ).toContain('var(--line-height-data)')
  expect(declarations.get('.bg-primary\\/90')?.join('\n')).toContain('var(--primary)')
  expect(declarations.get('.bg-primary\\/90')?.join('\n')).toContain('color-mix(')
  expect(declarations.get('.dark\\:bg-card:where(.dark, .dark *)')).toContain(
    'background-color: hsl(var(--card))',
  )
  expect(declarations.get('.animate-panel-in')).toContain(
    'animation: panel-in var(--motion-base) var(--easing-emphasized) both',
  )
  expect(result.css).not.toContain('@tailwind ')
}, 15_000)

test('keyboard focus remains above utility outline resets in the compiled cascade', async () => {
  const result = await compileTheme(['outline-none', 'outline-hidden'])
  const outlines: string[] = []
  result.root.walkRules(':focus-visible', (rule) => {
    // A base-layer focus rule loses to an outline utility even with greater
    // selector specificity. The shared keyboard treatment must outrank it.
    expect(rule.parent?.type, 'shared focus must outrank utility layers').toBe('root')
    rule.walkDecls('outline', (declaration) => {
      outlines.push(declaration.value)
    })
  })
  expect(outlines).toContain('var(--focus-ring-width) solid hsl(var(--focus))')
}, 15_000)
