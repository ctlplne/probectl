import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// HTTPS/CSP/HSTS are enforced by the serving ingress (CLAUDE.md §7 guardrail 12),
// not by Vite's dev server. No external origins are referenced anywhere in the
// build (sovereignty — guardrail 11).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Dev convenience: proxy the versioned API to a locally-running control
    // plane (no production behavior; prod serves same-origin behind the ingress).
    proxy: { '/v1': 'http://localhost:8080' },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    css: true,
  },
})
