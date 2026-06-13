import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist', 'coverage'] },
  {
    // CODE-009: type-CHECKED lint (recommendedTypeChecked) — catches the bugs a
    // syntax-only lint misses (floating promises, unsafe any, mis-typed
    // handlers). Uses the TS project service so rules can read types. Paired
    // with the existing `typecheck` (tsc --noEmit) + prettier formatting check.
    extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: { ...globals.browser, ...globals.node },
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      // CODE-009: type-checked rules are ENABLED (they run + surface issues) but
      // the high-noise ones start at "warn" so the gate goes green on adoption
      // and is ratcheted to "error" as the existing findings are burned down —
      // the standard gradual-adoption path, not a silent disable.
      '@typescript-eslint/no-base-to-string': 'warn',
      '@typescript-eslint/require-await': 'warn',
      '@typescript-eslint/no-unsafe-assignment': 'warn',
      '@typescript-eslint/no-unsafe-member-access': 'warn',
      '@typescript-eslint/no-unsafe-call': 'warn',
      '@typescript-eslint/no-unsafe-argument': 'warn',
      '@typescript-eslint/no-unsafe-return': 'warn',
      '@typescript-eslint/no-redundant-type-constituents': 'warn',
      '@typescript-eslint/no-misused-promises': 'warn',
      '@typescript-eslint/no-floating-promises': 'warn',
      // UX-006: apiFetch already prepends the /v1 API base, so a literal
      // apiFetch('/v1/...') produces a /v1/v1/... double-prefix (UX-001). Ban
      // the literal at lint time; off-/v1 surfaces use publicFetch instead.
      'no-restricted-syntax': [
        'error',
        {
          selector:
            "CallExpression[callee.name='apiFetch'] > Literal.arguments:first-child[value=/^\\/v1(\\/|$)/]",
          message:
            'apiFetch path must be relative to API_BASE — drop the /v1 prefix (it is prepended). Use publicFetch for off-/v1 surfaces. (UX-006)',
        },
        {
          selector:
            "CallExpression[callee.name='apiFetch'] > TemplateLiteral.arguments:first-child > TemplateElement:first-child[value.raw=/^\\/v1(\\/|$)/]",
          message:
            'apiFetch path must be relative to API_BASE — drop the /v1 prefix (it is prepended). Use publicFetch for off-/v1 surfaces. (UX-006)',
        },
      ],
    },
  },
  {
    // Test files lean on testing-library/jest matchers where strict type-aware
    // rules add noise without catching product bugs.
    files: ['**/*.test.{ts,tsx}', 'src/test/**'],
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
    },
  },
)
