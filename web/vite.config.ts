import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// HTTPS/CSP/HSTS are enforced by the serving ingress (CLAUDE.md §7 guardrail 12),
// not by Vite's dev server. No external origins are referenced anywhere in the
// build (sovereignty — guardrail 11).
export default defineConfig({
  plugins: [react()],
  resolve: {
    // The ee/ web seam (S-T1): commercial UI source lives in ee/web (the
    // editions boundary applies to the frontend too); the bundle always
    // includes it — visibility is runtime-gated (the API 404s unlicensed).
    alias: { '@ee': resolve(__dirname, '../ee/web') },
  },
  server: {
    port: 5173,
    // Dev convenience: proxy the versioned API to a locally-running control
    // plane (no production behavior; prod serves same-origin behind the ingress).
    proxy: { '/v1': 'http://localhost:8080', '/provider': 'http://localhost:8080' },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    css: true,
    // TEST-012: a coverage FLOOR so the UI test suite can't quietly rot. `npm
    // run coverage` fails the build if any metric drops below the threshold.
    // Start conservative and ratchet up as the suite grows.
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      // TEST-001/TEST-012: the floor is RATCHETED toward the measured number,
      // never lowered. The 31-file suite (src/test/*.test.tsx) exercises the
      // app shell, routing, and nearly every page, so real coverage sits well
      // above the original near-vacuous 20/15. These are raised to a still-
      // conservative band (a few points UNDER the measured number, never above —
      // a guessed-high floor that reds the build on an unmeasured number is the
      // anti-pattern we avoid). RATCHET RULE: when `npm run coverage` prints the
      // real total, bump each metric to (measured − 2); only ever increase it.
      // Deleting a tested component's test must drop coverage below the floor
      // and red the build — that is the gate doing its job.
      //
      // EXC-GATE-03 / TEST-001: floors set to the MEASURED total − 2pts from a
      // full vitest --coverage run (statements 87.38, branches 73.02, functions
      // 86.75, lines 89.53 → floor = measured − 2, rounded down). Ratchet up as
      // the suite grows; never lower these to make a regression pass.
      thresholds: { lines: 87, functions: 84, statements: 85, branches: 71 },
      exclude: ['**/*.test.{ts,tsx}', 'src/test/**', 'dist/**', '**/*.config.*'],
    },
  },
})
