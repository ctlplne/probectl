import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { contrastRatioForTokenValues, tokenOverridesPassContrast } from '../api/brand'

interface Pair {
  fg: string
  bg: string
  min: number
  backdrop?: string
}

const TEXT_MIN = 4.5
const UI_MIN = 3

function themeBlock(css: string, selector: string) {
  const escaped = selector.replace(/[[\]'.]/g, '\\$&')
  const match = new RegExp(`([^}]*${escaped}[^{]*)\\{([^}]*)\\}`).exec(css)
  return match?.[2] ?? ''
}

function colorTokens(css: string, selector: string) {
  const block = themeBlock(css, selector)
  const tokens: Record<string, string> = {}
  const re = /(--color-[a-z0-9-]+)\s*:\s*([^;]+);/g
  for (const match of block.matchAll(re)) tokens[match[1]] = match[2].trim()
  return tokens
}

function contrastPairs(): Pair[] {
  const pairs: Pair[] = []
  const text = ['--color-text', '--color-text-muted', '--color-text-subtle']
  const backgrounds = [
    '--color-bg',
    '--color-surface',
    '--color-surface-raised',
    '--color-surface-high',
  ]
  for (const fg of text) {
    for (const bg of backgrounds) pairs.push({ fg, bg, min: TEXT_MIN })
  }
  for (const bg of ['--color-accent', '--color-accent-hover', '--color-accent-strong']) {
    pairs.push({ fg: '--color-accent-contrast', bg, min: TEXT_MIN })
  }
  for (const bg of [
    '--color-accent-soft',
    '--color-success-soft',
    '--color-warning-soft',
    '--color-danger-soft',
    '--color-info-soft',
  ]) {
    pairs.push({ fg: '--color-text', bg, min: TEXT_MIN, backdrop: '--color-surface' })
  }
  for (const fg of [
    '--color-accent',
    '--color-accent-hover',
    '--color-accent-strong',
    '--color-focus',
    '--color-success',
    '--color-warning',
    '--color-danger',
    '--color-info',
    '--color-chart-1',
    '--color-chart-2',
    '--color-chart-3',
    '--color-chart-4',
    '--color-chart-5',
  ]) {
    for (const bg of backgrounds) pairs.push({ fg, bg, min: UI_MIN })
  }
  return pairs
}

describe('theme color contrast', () => {
  test('every shipped theme satisfies text and non-text contrast pairs', () => {
    const css = readFileSync(join(process.cwd(), 'src/styles/tokens.css'), 'utf8')
    const failures: string[] = []

    for (const [theme, selector] of Object.entries({
      dark: "[data-theme='dark']",
      aurora: "[data-theme='aurora']",
    })) {
      const tokens = colorTokens(css, selector)
      for (const pair of contrastPairs()) {
        if (!tokens[pair.fg] || !tokens[pair.bg]) continue
        const ratio = contrastRatioForTokenValues(
          tokens[pair.fg],
          tokens[pair.bg],
          pair.backdrop ? tokens[pair.backdrop] : undefined,
        )
        if (ratio === undefined || ratio < pair.min) {
          failures.push(
            `${theme}: ${pair.fg} on ${pair.bg} = ${ratio?.toFixed(2) ?? 'parse-failed'}:1, want ${pair.min}:1`,
          )
        }
      }
    }

    expect(failures).toEqual([])
  })

  test('bad tenant override fixtures fail the same contrast gate', () => {
    expect(tokenOverridesPassContrast({ '--color-text': '#ffffff' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--color-accent': '#ff3300' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--color-chart-1': '#ffffff' })).toBe(false)
  })
})
