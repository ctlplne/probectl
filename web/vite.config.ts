// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { fixtureApiPlugin } from './dev/fixtureApiPlugin'

// HTTPS/CSP/HSTS are enforced by the serving ingress (docs/guardrails.md G7-12),
// not by Vite's dev server. No external origins are referenced anywhere in the
// build (sovereignty — guardrail 11).
export default defineConfig({
  // The control plane mounts the embedded SPA at /ui/. Keep generated asset
  // URLs under that same prefix; root-relative /assets/* is not registered by
  // the HTTPS server and leaves the release shell blank.
  base: '/ui/',
  // fixtureApiPlugin is serve-only and inert unless PROBECTL_WEB_FIXTURES=1
  // (`npm run dev:fixtures`): the no-backend design loop. See web/dev/.
  plugins: [react(), fixtureApiPlugin()],
  build: {
    // The bundle-budget gate reads Vite's graph rather than guessing from
    // hashed filenames: isEntry is the app shell; isDynamicEntry marks the
    // route-level imports in AppRoutes.
    manifest: true,
  },
  resolve: {
    // The ee/ web seam (S-T1): commercial UI source lives in ee/web (the
    // editions boundary applies to the frontend too); the bundle always
    // includes it — visibility is runtime-gated (the API 404s unlicensed).
    alias: {
      '@ee': resolve(__dirname, '../ee/web'),
      // ee/web sources import react-query for the provider data layer; bare
      // specifiers don't node-resolve upward from ee/, so pin it to web's copy
      // (tsconfig `paths` carries the matching type resolution).
      '@tanstack/react-query': resolve(__dirname, 'node_modules/@tanstack/react-query'),
    },
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
    // A full coverage run instruments 65 files and executes the long-form
    // onboarding/admin journeys concurrently. Vitest's implicit 5s default is
    // shorter than those journeys under a loaded CI runner, so it can kill a
    // test after its assertions have been making normal progress. Keep a
    // finite 15s hang detector while giving V8 instrumentation bounded
    // headroom; individual exhaustive accessibility loops retain their tighter
    // explicit budgets.
    testTimeout: 15_000,
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
      // Generated API code is contract-checked by make sdk-gate. Counting its
      // thousands of machine-written branches as untested UI code would hide
      // the coverage signal for files engineers actually maintain.
      exclude: [
        '**/*.test.{ts,tsx}',
        'src/test/**',
        'src/api/sdk.gen.ts',
        'dist/**',
        '**/*.config.*',
        // Dev-server-only tooling (fixture design loop); never in the bundle,
        // so it must not dilute the UI coverage signal.
        'dev/**',
      ],
    },
  },
})
