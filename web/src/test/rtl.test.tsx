import { readFileSync, readdirSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { render } from '@testing-library/react'
import { describe, expect, test } from 'vitest'
import { directionForLocale, resolveLocale } from '../i18n/core'
import { I18nProvider } from '../i18n/I18nProvider'

const PHYSICAL_INLINE_DECLARATION =
  /^\s*(?:(?:left|right|inset-left|inset-right|padding-(?:left|right)|margin-(?:left|right)|border-(?:left|right)(?:-(?:width|style|color))?)\s*:|(?:text-align|float)\s*:\s*(?:left|right)\b)/gm

describe('RTL shell contract', () => {
  test('requested RTL locales set html direction while messages safely fall back', () => {
    render(
      <I18nProvider initialLocale="ar-EG">
        <span>probe</span>
      </I18nProvider>,
    )

    expect(resolveLocale('ar-EG')).toBe('en')
    expect(directionForLocale('ar-EG')).toBe('rtl')
    expect(document.documentElement.lang).toBe('ar-eg')
    expect(document.documentElement.dir).toBe('rtl')
  })

  test('the app starts with an explicit LTR direction and mirrors the shell in RTL', () => {
    const index = readFileSync(resolve(process.cwd(), 'index.html'), 'utf8')
    const shell = readFileSync(resolve(process.cwd(), 'src/shell/AppShell.module.css'), 'utf8')

    expect(index).toMatch(/<html[^>]*\bdir="ltr"/)
    expect(shell).toContain("html[dir='rtl']")
  })

  test('CSS modules use logical inline properties instead of physical left/right edges', () => {
    const roots = [resolve(process.cwd(), 'src'), resolve(process.cwd(), '../ee/web')]
    const failures: string[] = []

    for (const root of roots) {
      for (const file of cssFiles(root)) {
        const body = readFileSync(file, 'utf8')
        const matches = [...body.matchAll(PHYSICAL_INLINE_DECLARATION)]
        for (const match of matches) {
          const line = body.slice(0, match.index).split('\n').length
          failures.push(`${relative(process.cwd(), file)}:${line}: ${match[0].trim()}`)
        }
      }
    }

    expect(failures).toEqual([])
  })
})

function cssFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      out.push(...cssFiles(full))
      continue
    }
    if (entry.isFile() && entry.name.endsWith('.css')) out.push(full)
  }
  return out
}
