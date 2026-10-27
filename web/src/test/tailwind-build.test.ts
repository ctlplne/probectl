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

// Exercise the actual CSS entrypoint and engine. Token declarations alone do
// not prove a build emits the utilities that keep controls readable and usable.
test('Tailwind 4 emits token-backed controls, opacity, motion and class-based dark mode', async () => {
  const installed = JSON.parse(
    readFileSync(join(process.cwd(), 'node_modules/tailwindcss/package.json'), 'utf8'),
  ) as { version: string }
  expect(installed.version.split('.')[0], 'the installed CSS engine must be Tailwind 4').toBe('4')

  const packageName = '@tailwindcss/postcss'
  const plugin = (await import(packageName)) as { default: () => AcceptedPlugin }
  const file = join(process.cwd(), 'src/styles/global.css')
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
  const result = await postcss([plugin.default()]).process(
    readFileSync(file, 'utf8') + `\n@source inline("${candidates.join(' ')}");\n`,
    { from: file },
  )
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
