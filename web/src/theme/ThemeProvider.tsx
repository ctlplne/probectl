import { createContext, useCallback, useEffect, useState, type ReactNode } from 'react'

export type ThemeName = 'dark' | 'aurora'

const THEMES: ThemeName[] = ['dark', 'aurora']
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
  return v === 'dark' || v === 'aurora'
}

function readInitial(fallback: ThemeName): ThemeName {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (isTheme(stored)) return stored
  } catch {
    /* storage unavailable — fall back */
  }
  return fallback
}

/**
 * ThemeProvider applies the active theme to <html data-theme>, which selects the
 * token set. Per-tenant white-label swaps this attribute (or supplies a tenant
 * token override) — no component changes. The single intentional use of
 * localStorage is the operator's theme preference (CLAUDE.md §7 guardrail 11).
 */
export function ThemeProvider({
  children,
  initialTheme = 'dark',
}: {
  children: ReactNode
  initialTheme?: ThemeName
}) {
  const [theme, setThemeState] = useState<ThemeName>(() => readInitial(initialTheme))

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try {
      localStorage.setItem(STORAGE_KEY, theme)
    } catch {
      /* ignore */
    }
  }, [theme])

  const setTheme = useCallback((t: ThemeName) => setThemeState(t), [])
  const toggleTheme = useCallback(
    () => setThemeState((t) => (t === 'dark' ? 'aurora' : 'dark')),
    [],
  )

  return (
    <ThemeContext.Provider value={{ theme, themes: THEMES, setTheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}
