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
  },
})
