// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { createContext, useCallback, useEffect, useState, type ReactNode } from 'react'

export type ThemeName = 'light' | 'dark'

const THEMES: ThemeName[] = ['light', 'dark']
const STORAGE_KEY = 'probectl.theme'

export interface ThemeContextValue {
  theme: ThemeName
  themes: ThemeName[]
  setTheme: (t: ThemeName) => void
  toggleTheme: () => void
}

// eslint-disable-next-line react-refresh/only-export-components
export const ThemeContext = createContext<ThemeContextValue | null>(null)

function isTheme(v: unknown): v is ThemeName {
  return THEMES.includes(v as ThemeName)
}

function browserStorage(): Storage | undefined {
  if (typeof window === 'undefined') return undefined
  const descriptor = Object.getOwnPropertyDescriptor(window, 'localStorage')
  // Node 26 exposes a non-enumerable experimental global with this name. In a
  // jsdom fallback it can replace the browser Web Storage attribute, and merely
  // invoking its getter emits a warning. Web-IDL Window attributes are
  // enumerable, so reject the non-browser placeholder without touching it.
  if (descriptor && descriptor.enumerable === false) return undefined
  try {
    return window.localStorage
  } catch {
    return undefined
  }
}

function readInitial(fallback: ThemeName): ThemeName {
  try {
    const stored = browserStorage()?.getItem(STORAGE_KEY)
    if (isTheme(stored)) return stored
  } catch {
    /* storage unavailable — fall back */
  }
  return fallback
}

/**
 * ThemeProvider applies the active theme to <html>, which selects the token set.
 * It sets BOTH `data-theme` and the `dark` class, deliberately: the tokens accept
 * either selector, but Tailwind's `dark:` utilities only look at the class, and a
 * surface styled with one while the other is authoritative is how a theme ends up
 * half-applied.
 *
 * Light is the default operator theme; dark is a fully supported preference.
 * Deployment-level operator overrides layer onto these tokens with no component
 * changes. The single intentional use of localStorage is the operator's theme
 * preference (docs/guardrails.md G7-11).
 */
export function ThemeProvider({
  children,
  initialTheme = 'light',
}: {
  children: ReactNode
  initialTheme?: ThemeName
}) {
  const [theme, setThemeState] = useState<ThemeName>(() => readInitial(initialTheme))

  useEffect(() => {
    const root = document.documentElement
    root.setAttribute('data-theme', theme)
    root.classList.toggle('dark', theme === 'dark')
    try {
      browserStorage()?.setItem(STORAGE_KEY, theme)
    } catch {
      /* ignore */
    }
  }, [theme])

  const setTheme = useCallback((t: ThemeName) => setThemeState(t), [])
  // Cycles the shipped set in order (light → dark → light …).
  const toggleTheme = useCallback(
    () => setThemeState((t) => THEMES[(THEMES.indexOf(t) + 1) % THEMES.length]),
    [],
  )

  return (
    <ThemeContext.Provider value={{ theme, themes: THEMES, setTheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}
