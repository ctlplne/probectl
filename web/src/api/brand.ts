// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

/**
 * Deployment-level probectl theming. Fetched PRE-AUTH from /branding so the
 * login shell and tenant app use the same operator-configured token overrides.
 * The response is identical for every tenant and host; product identity is
 * always probectl.
 *
 * /branding lives OUTSIDE the /v1 API base, so it goes through publicFetch
 * (the single off-/v1 convention, UX-006) rather than a bare fetch().
 */
import { publicFetch } from './client'
import { readResponseJSON, responseBodyLimit } from './response'

export interface Brand {
  product_name: string
  token_overrides?: Record<string, string>
}

export const DEFAULT_BRAND: Brand = { product_name: 'probectl' }

/** Only S8a brandable tokens may be touched at runtime (mirror of the core
 *  allowlist in internal/branding — defense in depth on the client). */
// Overridable NON-colour tokens, named exhaustively. Colour tokens are absent on
// purpose: the allowlist for those is the shipped palette itself (isColorToken),
// so a new colour token becomes overridable the moment it ships and a name the
// palette does not define can never be set from a deployment config. An earlier
// version ended this pattern with a bare [a-z0-9-]+ catch-all, which let any
// --radius-* or --font-* name through — including ones that ship nowhere.
const OVERRIDABLE_NON_COLOR = new Set([
  '--radius-control',
  '--radius-panel',
  '--radius-pill',
  '--font-sans',
  '--font-mono',
  '--font-display',
])
// A colour value is the bare HSL triplet the tokens hold: "28 85% 30%", or
// "28 85% 30% / 0.12" for a tint. Hex and rgb() are deliberately REFUSED even
// though they are valid CSS colours: the stylesheet reads every colour token as
// hsl(var(--token) / <alpha-value>), so a hex value would make each rule that
// uses the token unparseable — a deployment painted wrong rather than differently.
// No var(), no url(), no arbitrary text.
const COLOR_VALUE = /^-?[0-9.]+ +-?[0-9.]+% +-?[0-9.]+%( *\/ *[0-9.]+%?)?$/
const RADIUS_VALUE = /^[0-9]{1,3}(px|rem|em|%)$/
const FONT_VALUE = /^[A-Za-z0-9 ,'"-]{1,120}$/

const WCAG_TEXT_CONTRAST = 4.5
const WCAG_UI_CONTRAST = 3
/** The tint alpha every shipped chip and tinted panel uses. */
const CHIP_WASH = 0.12
const CHIP_TONES = [
  '--brand-accent',
  '--status-success',
  '--status-warning',
  '--status-info',
  '--status-neutral',
  '--destructive',
  '--risk-critical',
  '--risk-high',
  '--risk-medium',
  '--risk-low',
  '--risk-none',
]

interface ContrastColor {
  r: number
  g: number
  b: number
  a: number
}

export interface ContrastPair {
  fg: string
  bg: string
  min: number
  backdrop?: string
  /** Check bg as a wash at this alpha over `backdrop`, the way a chip ships. */
  bgAlpha?: number
}

const SHIPPED_CONTRAST_THEMES: Record<string, Record<string, string>> = {
  light: {
    '--background': '45 33% 95%',
    '--foreground': '167 16% 11%',
    '--card': '48 100% 99%',
    '--card-foreground': '167 16% 11%',
    '--muted': '75 12% 94%',
    '--muted-foreground': '163 7% 35%',
    '--border': '120 7% 86%',
    '--sidebar': '60 15% 92%',
    '--sidebar-hover': '108 10% 89%',
    '--sidebar-active': '150 20% 89%',
    '--sidebar-foreground': '163 14% 22%',
    '--primary': '28 85% 30%',
    '--primary-foreground': '48 100% 99%',
    '--brand-accent': '28 85% 30%',
    '--brand-accent-foreground': '0 0% 100%',
    '--focus': '167 48% 33%',
    '--destructive': '3 53% 35%',
    '--destructive-foreground': '0 0% 100%',
    '--status-success': '166 55% 20%',
    '--status-warning': '40 86% 27%',
    '--status-info': '199 49% 31%',
    '--status-neutral': '163 7% 36%',
    '--monitor': '199 49% 31%',
    '--monitor-foreground': '0 0% 100%',
    '--analyze': '251 85% 62%',
    '--analyze-foreground': '0 0% 100%',
    '--secure': '3 53% 35%',
    '--secure-foreground': '0 0% 100%',
    '--operate': '28 85% 30%',
    '--operate-foreground': '0 0% 100%',
    '--risk-critical': '3 53% 35%',
    '--risk-high': '24 70% 34%',
    '--risk-medium': '40 86% 27%',
    '--risk-low': '166 55% 20%',
    '--risk-none': '163 7% 36%',
    '--chart-1': '28 85% 30%',
    '--chart-2': '213 62% 48%',
    '--chart-3': '251 85% 62%',
    '--chart-4': '174 72% 30%',
    '--chart-5': '350 62% 48%',
    '--chart-6': '314 42% 43%',
    '--chart-grid': '223 11% 55%',
    '--chart-axis': '227 14% 37%',
    '--chart-neutral': '226 11% 45%',
  },
  dark: {
    '--background': '165 17% 7%',
    '--foreground': '45 22% 93%',
    '--card': '160 16% 10%',
    '--card-foreground': '45 22% 93%',
    '--muted': '156 13% 15%',
    '--muted-foreground': '156 7% 70%',
    '--border': '156 10% 22%',
    '--sidebar': '165 18% 8%',
    '--sidebar-hover': '160 16% 12%',
    '--sidebar-active': '159 18% 16%',
    '--sidebar-foreground': '156 7% 70%',
    '--primary': '34 100% 66%',
    '--primary-foreground': '30 40% 8%',
    '--brand-accent': '34 100% 66%',
    '--brand-accent-foreground': '30 40% 8%',
    '--focus': '171 77% 64%',
    '--destructive': '0 100% 72%',
    '--destructive-foreground': '0 45% 6%',
    '--status-success': '158 64% 52%',
    '--status-warning': '32 95% 54%',
    '--status-info': '218 100% 77%',
    '--status-neutral': '207 12% 65%',
    '--monitor': '218 100% 77%',
    '--monitor-foreground': '223 30% 5%',
    '--analyze': '254 100% 77%',
    '--analyze-foreground': '223 30% 5%',
    '--secure': '0 100% 72%',
    '--secure-foreground': '0 45% 6%',
    '--operate': '34 100% 66%',
    '--operate-foreground': '30 40% 8%',
    '--risk-critical': '0 100% 72%',
    '--risk-high': '24 95% 58%',
    '--risk-medium': '45 93% 56%',
    '--risk-low': '158 64% 52%',
    '--risk-none': '207 12% 64%',
    '--chart-1': '34 100% 66%',
    '--chart-2': '206 74% 63%',
    '--chart-3': '254 100% 77%',
    '--chart-4': '174 62% 55%',
    '--chart-5': '350 82% 70%',
    '--chart-6': '312 51% 68%',
    '--chart-grid': '218 14% 48%',
    '--chart-axis': '219 16% 69%',
    '--chart-neutral': '218 12% 55%',
  },
}

const REQUIRED_CONTRAST_PAIRS = buildContrastPairs()

export async function fetchBrand(): Promise<Brand> {
  try {
    const res = await publicFetch('/branding')
    if (!res.ok) return DEFAULT_BRAND
    const b = await readResponseJSON<Brand>(res, responseBodyLimit(res))
    if (!b || b.product_name !== 'probectl') return DEFAULT_BRAND
    return b
  } catch {
    return DEFAULT_BRAND // theming must never take the app down
  }
}

/** Tracks which tokens we overrode so a deployment-config refresh is clean. */
let appliedTokens: string[] = []

export function applyBrand(b: Brand) {
  const root = document.documentElement
  for (const name of appliedTokens) root.style.removeProperty(name)
  appliedTokens = []
  for (const [name, value] of Object.entries(sanitizeTokenOverrides(b.token_overrides))) {
    root.style.setProperty(name, value)
    appliedTokens.push(name)
  }
  document.title = 'probectl'
}

export function sanitizeTokenOverrides(overrides: Record<string, string> | undefined) {
  const safe: Record<string, string> = {}
  for (const [name, rawValue] of Object.entries(overrides ?? {})) {
    const value = rawValue.trim()
    if (!tokenValueIsSafe(name, value)) continue
    safe[name] = value
  }
  return tokenOverridesPassContrast(safe) ? safe : {}
}

/** A token is a colour token iff the shipped palette defines it. That makes the
 *  palette the single allowlist, so a rename cannot silently open the door to
 *  overriding layout or stacking tokens — or silently close it on colour, which
 *  is how the contrast check came to be skipped entirely. */
function isColorToken(name: string) {
  return Object.values(SHIPPED_CONTRAST_THEMES).some((theme) => name in theme)
}

function tokenValueIsSafe(name: string, value: string) {
  if (isColorToken(name)) return COLOR_VALUE.test(value)
  if (!OVERRIDABLE_NON_COLOR.has(name)) return false
  if (name.startsWith('--radius-')) return RADIUS_VALUE.test(value)
  return FONT_VALUE.test(value)
}

/**
 * The ratio a pair actually resolves to for a given palette, including the wash
 * alpha and the backdrop it composites over. Both the deployment-override check
 * and the shipped-theme test call THIS, so neither can quietly evaluate a pair
 * differently from the other — the test had been ignoring bgAlpha and reporting a
 * tone against itself at 1.00:1.
 */
export function contrastRatioForPair(
  tokens: Record<string, string>,
  pair: ContrastPair,
): number | undefined {
  const fgValue = tokens[pair.fg]
  const rawBg = tokens[pair.bg]
  if (!fgValue || !rawBg) return undefined
  const bgValue = pair.bgAlpha === undefined ? rawBg : `${rawBg} / ${pair.bgAlpha}`
  return contrastRatioForTokenValues(
    fgValue,
    bgValue,
    pair.backdrop ? tokens[pair.backdrop] : undefined,
  )
}

export function tokenOverridesPassContrast(overrides: Record<string, string>) {
  for (const base of Object.values(SHIPPED_CONTRAST_THEMES)) {
    const tokens = { ...base }
    for (const [name, value] of Object.entries(overrides)) {
      if (isColorToken(name)) tokens[name] = value
    }
    for (const pair of REQUIRED_CONTRAST_PAIRS) {
      if (!tokens[pair.fg] || !tokens[pair.bg]) continue
      const ratio = contrastRatioForPair(tokens, pair)
      if (ratio === undefined || ratio < pair.min) return false
    }
  }
  return true
}

export function buildContrastPairs(): ContrastPair[] {
  const pairs: ContrastPair[] = []
  // Body text must clear 4.5:1 on every surface it can land on, including the
  // rail, which is its own tint rather than the page background.
  const text = ['--foreground', '--muted-foreground']
  const backgrounds = ['--background', '--card', '--muted', '--sidebar']
  for (const fg of text) {
    for (const bg of backgrounds) pairs.push({ fg, bg, min: WCAG_TEXT_CONTRAST })
  }
  // Text on a filled action or a filled status must clear 4.5:1 too — a button
  // label is body text.
  for (const [fg, bg] of [
    ['--primary-foreground', '--primary'],
    ['--brand-accent-foreground', '--brand-accent'],
    ['--destructive-foreground', '--destructive'],
    ['--monitor-foreground', '--monitor'],
    ['--analyze-foreground', '--analyze'],
    ['--secure-foreground', '--secure'],
    ['--operate-foreground', '--operate'],
  ] as const) {
    pairs.push({ fg, bg, min: WCAG_TEXT_CONTRAST })
  }
  // A chip is coloured text on a CHIP_WASH tint of itself, composited over
  // whatever it sits on — a card, a table header or hovered row (--muted), the
  // page, or the rail. The earlier version checked the tone against the plain
  // card, which is lighter than the tint that actually ships and therefore
  // flattering: five light tones measured 3.94-4.30 in the browser while this
  // function reported them passing. Both are checked now, because a tone is also
  // used as plain text on a plain surface.
  for (const tone of CHIP_TONES) {
    for (const bg of backgrounds) {
      pairs.push({ fg: tone, bg, min: WCAG_TEXT_CONTRAST })
      pairs.push({ fg: tone, bg: tone, min: WCAG_TEXT_CONTRAST, backdrop: bg, bgAlpha: CHIP_WASH })
    }
    // Secondary text inside a tinted panel, e.g. a <dt> label on an info wash.
    for (const bg of backgrounds) {
      pairs.push({
        fg: '--muted-foreground',
        bg: tone,
        min: WCAG_TEXT_CONTRAST,
        backdrop: bg,
        bgAlpha: CHIP_WASH,
      })
    }
  }
  // Non-text graphics — focus ring, series strokes, axes — need 3:1. Series also
  // carry dash patterns, so colour is never the only channel.
  for (const fg of [
    '--focus',
    '--chart-1',
    '--chart-2',
    '--chart-3',
    '--chart-4',
    '--chart-5',
    '--chart-6',
    '--chart-grid',
    '--chart-axis',
    '--chart-neutral',
  ]) {
    for (const bg of backgrounds) pairs.push({ fg, bg, min: WCAG_UI_CONTRAST })
  }
  return pairs
}

// A bare HSL triplet, the shape every design token now holds: "45 33% 95%", or
// "45 33% 95% / 0.12" for a soft tint. Tailwind wraps these as
// hsl(var(--token) / <alpha-value>), so the raw token value is never a colour
// function and the hex/rgb branches below would all miss it.
const HSL_TRIPLET = /^(-?[\d.]+)\s+(-?[\d.]+)%\s+(-?[\d.]+)%(?:\s*\/\s*([\d.]+%?))?$/

function parseHSLTriplet(value: string): ContrastColor | undefined {
  const m = HSL_TRIPLET.exec(value)
  if (!m) return undefined
  const alpha =
    m[4] === undefined ? 1 : m[4].endsWith('%') ? parseFloat(m[4]) / 100 : parseFloat(m[4])
  if (!Number.isFinite(alpha)) return undefined
  return parseHSLColor(`hsl(${m[1]} ${m[2]}% ${m[3]}% / ${alpha})`)
}

function parseContrastColor(value: string): ContrastColor | undefined {
  const normalized = value.trim().toLowerCase()
  if (normalized.startsWith('#')) return parseHexColor(normalized)
  if (normalized.startsWith('rgb(') || normalized.startsWith('rgba('))
    return parseRGBColor(normalized)
  if (normalized.startsWith('hsl(') || normalized.startsWith('hsla('))
    return parseHSLColor(normalized)
  return parseHSLTriplet(normalized)
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
