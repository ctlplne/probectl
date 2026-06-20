/**
 * The white-label brand (S-T4). Fetched PRE-AUTH from the public /branding
 * endpoint (Host-resolved: a custom domain answers its tenant's brand;
 * community/unlicensed deployments answer the probectl default). Branding is
 * a runtime override of the S8a design tokens — no screen knows about it.
 *
 * /branding lives OUTSIDE the /v1 API base, so it goes through publicFetch
 * (the single off-/v1 convention, UX-006) rather than a bare fetch().
 */
import { publicFetch } from './client'

export interface Brand {
  product_name: string
  logo_data_uri?: string
  login_message?: string
  token_overrides?: Record<string, string>
  email_from_name?: string
  email_footer?: string
}

export const DEFAULT_BRAND: Brand = { product_name: 'probectl' }

/** Only S8a brandable tokens may be touched at runtime (mirror of the core
 *  allowlist — defense in depth on the client). */
const TOKEN_NAME = /^--(color-[a-z0-9-]+|radius-(sm|md|lg)|font-sans|font-mono)$/
const COLOR_VALUE = /^(#[0-9a-fA-F]{3,8}|rgba?\([0-9.,/% ]+\)|hsla?\([0-9.,/% deg]+\))$/
const RADIUS_VALUE = /^[0-9]{1,3}(px|rem|em|%)$/
const FONT_VALUE = /^[A-Za-z0-9 ,'"-]{1,120}$/

const WCAG_TEXT_CONTRAST = 4.5
const WCAG_UI_CONTRAST = 3

interface ContrastColor {
  r: number
  g: number
  b: number
  a: number
}

interface ContrastPair {
  fg: string
  bg: string
  min: number
  backdrop?: string
}

const SHIPPED_CONTRAST_THEMES: Record<string, Record<string, string>> = {
  dark: {
    '--color-bg': '#0b0e14',
    '--color-surface': '#11151f',
    '--color-surface-raised': '#171c28',
    '--color-text': '#e7eaf2',
    '--color-text-muted': '#a6adbd',
    '--color-text-subtle': '#808a9b',
    '--color-text-inverse': '#0b0e14',
    '--color-accent': '#2fb6a8',
    '--color-accent-hover': '#3ccabb',
    '--color-accent-strong': '#23a394',
    '--color-accent-contrast': '#04130f',
    '--color-success': '#46c08a',
    '--color-success-soft': 'rgba(70, 192, 138, 0.14)',
    '--color-warning': '#e0b25a',
    '--color-warning-soft': 'rgba(224, 178, 90, 0.14)',
    '--color-danger': '#e8736b',
    '--color-danger-soft': 'rgba(232, 115, 107, 0.14)',
    '--color-info': '#5aa9e6',
    '--color-info-soft': 'rgba(90, 169, 230, 0.14)',
    '--color-focus': '#6fd2c6',
    '--color-chart-1': '#2fb6a8',
    '--color-chart-2': '#5aa9e6',
    '--color-chart-3': '#a78bff',
    '--color-chart-4': '#e0b25a',
    '--color-chart-5': '#e8736b',
  },
  aurora: {
    '--color-bg': '#f6f7fb',
    '--color-surface': '#ffffff',
    '--color-surface-raised': '#ffffff',
    '--color-text': '#1b1d2a',
    '--color-text-muted': '#50566b',
    '--color-text-subtle': '#676d80',
    '--color-text-inverse': '#ffffff',
    '--color-accent': '#6a4cf0',
    '--color-accent-hover': '#5a3ce0',
    '--color-accent-strong': '#4f33d6',
    '--color-accent-contrast': '#ffffff',
    '--color-success': '#1f9d63',
    '--color-success-soft': 'rgba(31, 157, 99, 0.12)',
    '--color-warning': '#b9821f',
    '--color-warning-soft': 'rgba(185, 130, 31, 0.12)',
    '--color-danger': '#d2463c',
    '--color-danger-soft': 'rgba(210, 70, 60, 0.12)',
    '--color-info': '#2f73c7',
    '--color-info-soft': 'rgba(47, 115, 199, 0.12)',
    '--color-focus': '#6a4cf0',
    '--color-chart-1': '#0e9e92',
    '--color-chart-2': '#2f73c7',
    '--color-chart-3': '#6a4cf0',
    '--color-chart-4': '#b9821f',
    '--color-chart-5': '#d2463c',
  },
}

const REQUIRED_CONTRAST_PAIRS = buildContrastPairs()

export async function fetchBrand(): Promise<Brand> {
  try {
    const res = await publicFetch('/branding')
    if (!res.ok) return DEFAULT_BRAND
    const b = (await res.json()) as Brand
    if (!b || typeof b.product_name !== 'string' || b.product_name === '') return DEFAULT_BRAND
    return b
  } catch {
    return DEFAULT_BRAND // branding must never take the app down
  }
}

/** Tracks which tokens we overrode so a brand change replaces CLEANLY —
 *  no residue from a previous brand (the client-side no-bleed property). */
let appliedTokens: string[] = []

export function applyBrand(b: Brand) {
  const root = document.documentElement
  for (const name of appliedTokens) root.style.removeProperty(name)
  appliedTokens = []
  for (const [name, value] of Object.entries(sanitizeTokenOverrides(b.token_overrides))) {
    root.style.setProperty(name, value)
    appliedTokens.push(name)
  }
  document.title = b.product_name
}

export function sanitizeTokenOverrides(overrides: Record<string, string> | undefined) {
  const safe: Record<string, string> = {}
  for (const [name, rawValue] of Object.entries(overrides ?? {})) {
    const value = rawValue.trim()
    if (!TOKEN_NAME.test(name) || !tokenValueIsSafe(name, value)) continue
    safe[name] = value
  }
  return tokenOverridesPassContrast(safe) ? safe : {}
}

function tokenValueIsSafe(name: string, value: string) {
  if (name.startsWith('--color-')) return COLOR_VALUE.test(value)
  if (name.startsWith('--radius-')) return RADIUS_VALUE.test(value)
  return FONT_VALUE.test(value)
}

export function tokenOverridesPassContrast(overrides: Record<string, string>) {
  for (const base of Object.values(SHIPPED_CONTRAST_THEMES)) {
    const tokens = { ...base }
    for (const [name, value] of Object.entries(overrides)) {
      if (name.startsWith('--color-')) tokens[name] = value
    }
    for (const pair of REQUIRED_CONTRAST_PAIRS) {
      const fgValue = tokens[pair.fg]
      const bgValue = tokens[pair.bg]
      if (!fgValue || !bgValue) continue
      const ratio = contrastRatioForTokenValues(
        fgValue,
        bgValue,
        pair.backdrop ? tokens[pair.backdrop] : undefined,
      )
      if (ratio === undefined || ratio < pair.min) return false
    }
  }
  return true
}

function buildContrastPairs(): ContrastPair[] {
  const pairs: ContrastPair[] = []
  const text = ['--color-text', '--color-text-muted', '--color-text-subtle']
  const backgrounds = [
    '--color-bg',
    '--color-surface',
    '--color-surface-raised',
    '--color-surface-high',
  ]
  for (const fg of text) {
    for (const bg of backgrounds) pairs.push({ fg, bg, min: WCAG_TEXT_CONTRAST })
  }
  for (const bg of ['--color-accent', '--color-accent-hover', '--color-accent-strong']) {
    pairs.push({ fg: '--color-accent-contrast', bg, min: WCAG_TEXT_CONTRAST })
  }
  for (const bg of [
    '--color-accent-soft',
    '--color-success-soft',
    '--color-warning-soft',
    '--color-danger-soft',
    '--color-info-soft',
  ]) {
    pairs.push({ fg: '--color-text', bg, min: WCAG_TEXT_CONTRAST, backdrop: '--color-surface' })
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
    for (const bg of backgrounds) pairs.push({ fg, bg, min: WCAG_UI_CONTRAST })
  }
  return pairs
}

function parseContrastColor(value: string): ContrastColor | undefined {
  const normalized = value.trim().toLowerCase()
  if (normalized.startsWith('#')) return parseHexColor(normalized)
  if (normalized.startsWith('rgb(') || normalized.startsWith('rgba('))
    return parseRGBColor(normalized)
  if (normalized.startsWith('hsl(') || normalized.startsWith('hsla('))
    return parseHSLColor(normalized)
  return undefined
}

export function contrastRatioForTokenValues(
  fgValue: string,
  bgValue: string,
  backdropValue?: string,
) {
  const fg = parseContrastColor(fgValue)
  let bg = parseContrastColor(bgValue)
  if (!fg || !bg) return undefined
  if (bg.a < 1) bg = composite(bg, backdropValue ? parseContrastColor(backdropValue) : undefined)
  const effectiveFg = fg.a < 1 ? composite(fg, bg) : fg
  return contrastRatio(effectiveFg, bg)
}

function parseHexColor(value: string): ContrastColor | undefined {
  let hex = value.slice(1)
  if (hex.length === 3 || hex.length === 4) {
    hex = [...hex].map((ch) => ch + ch).join('')
  }
  if (hex.length !== 6 && hex.length !== 8) return undefined
  const r = parseInt(hex.slice(0, 2), 16) / 255
  const g = parseInt(hex.slice(2, 4), 16) / 255
  const b = parseInt(hex.slice(4, 6), 16) / 255
  const a = hex.length === 8 ? parseInt(hex.slice(6, 8), 16) / 255 : 1
  return [r, g, b, a].every(Number.isFinite) ? { r, g, b, a } : undefined
}

function parseRGBColor(value: string): ContrastColor | undefined {
  const args = colorFunctionArgs(value)
  if (args.length < 3 || args.length > 4) return undefined
  const r = parseRGBComponent(args[0])
  const g = parseRGBComponent(args[1])
  const b = parseRGBComponent(args[2])
  const a = args[3] ? parseAlpha(args[3]) : 1
  if (r === undefined || g === undefined || b === undefined || a === undefined) return undefined
  return { r, g, b, a }
}

function parseHSLColor(value: string): ContrastColor | undefined {
  const args = colorFunctionArgs(value)
  if (args.length < 3 || args.length > 4) return undefined
  const h = parseHue(args[0])
  const s = parsePercent(args[1])
  const l = parsePercent(args[2])
  const a = args[3] ? parseAlpha(args[3]) : 1
  if (h === undefined || s === undefined || l === undefined || a === undefined) return undefined
  const [r, g, b] = hslToRGB(h, s, l)
  return { r, g, b, a }
}

function colorFunctionArgs(value: string) {
  const open = value.indexOf('(')
  const close = value.lastIndexOf(')')
  if (open < 0 || close <= open) return []
  return value
    .slice(open + 1, close)
    .replace(/[,/]/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
}

function parseRGBComponent(value: string) {
  if (value.endsWith('%')) return parsePercent(value)
  const n = Number(value)
  return Number.isFinite(n) && n >= 0 && n <= 255 ? n / 255 : undefined
}

function parseHue(value: string) {
  const n = Number(value.replace(/deg$/, ''))
  if (!Number.isFinite(n)) return undefined
  return (((n % 360) + 360) % 360) / 360
}

function parsePercent(value: string) {
  const n = Number(value.replace(/%$/, ''))
  return Number.isFinite(n) && n >= 0 && n <= 100 ? n / 100 : undefined
}

function parseAlpha(value: string) {
  if (value.endsWith('%')) return parsePercent(value)
  const n = Number(value)
  return Number.isFinite(n) && n >= 0 && n <= 1 ? n : undefined
}

function hslToRGB(h: number, s: number, l: number): [number, number, number] {
  if (s === 0) return [l, l, l]
  const q = l < 0.5 ? l * (1 + s) : l + s - l * s
  const p = 2 * l - q
  return [hueToRGB(p, q, h + 1 / 3), hueToRGB(p, q, h), hueToRGB(p, q, h - 1 / 3)]
}

function hueToRGB(p: number, q: number, t: number) {
  if (t < 0) t += 1
  if (t > 1) t -= 1
  if (t < 1 / 6) return p + (q - p) * 6 * t
  if (t < 1 / 2) return q
  if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6
  return p
}

function composite(over: ContrastColor, under: ContrastColor = { r: 1, g: 1, b: 1, a: 1 }) {
  const a = over.a + under.a * (1 - over.a)
  if (a === 0) return { r: 0, g: 0, b: 0, a: 0 }
  return {
    r: (over.r * over.a + under.r * under.a * (1 - over.a)) / a,
    g: (over.g * over.a + under.g * under.a * (1 - over.a)) / a,
    b: (over.b * over.a + under.b * under.a * (1 - over.a)) / a,
    a,
  }
}

function contrastRatio(fg: ContrastColor, bg: ContrastColor) {
  let l1 = relativeLuminance(fg)
  let l2 = relativeLuminance(bg)
  if (l1 < l2) [l1, l2] = [l2, l1]
  return (l1 + 0.05) / (l2 + 0.05)
}

function relativeLuminance(color: ContrastColor) {
  const linear = (value: number) =>
    value <= 0.03928 ? value / 12.92 : Math.pow((value + 0.055) / 1.055, 2.4)
  return 0.2126 * linear(color.r) + 0.7152 * linear(color.g) + 0.0722 * linear(color.b)
}
