// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import type { Connect, Plugin, ViteDevServer } from 'vite'

/**
 * probectl:fixture-api — the DESIGN LOOP, dev-only, never shipped.
 *
 * Answers the SPA's API calls inside `vite dev` from the same local
 * fixture catalog the unit suite uses (src/test/fixtureApi.ts), so design and
 * frontend iteration gets hot reload without a control plane, database, or
 * IdP on the laptop.
 *
 * Guardrails (SEC-001 / CLAUDE.md §7 stay intact):
 * - `apply: 'serve'` — `vite build` never evaluates this plugin; nothing here
 *   can reach the embedded production bundle.
 * - Opt-in only: inert unless PROBECTL_WEB_FIXTURES=1 (`npm run dev:fixtures`).
 *   Plain `npm run dev` keeps proxying /v1 to a real control plane, and the
 *   shipped SPA still hard-requires the backend session — this changes the
 *   laptop, not the product's auth model.
 * - Every response is labelled `x-probectl-fixture: 1`, and the fixture
 *   identity is the same obviously-fake operator the tests render.
 */
export function fixtureApiPlugin(): Plugin {
  return {
    name: 'probectl:fixture-api',
    apply: 'serve',
    configureServer(server: ViteDevServer) {
      if (process.env.PROBECTL_WEB_FIXTURES !== '1') return

      const FIXTURE_MODULE = '/src/test/fixtureApi.ts'
      // PROBECTL_WEB_FIXTURES_PROFILE=cold serves the install-day catalog
      // (fresh deployment, nothing enrolled) — `npm run dev:fixtures:cold`.
      const profile = process.env.PROBECTL_WEB_FIXTURES_PROFILE === 'cold' ? 'cold' : 'populated'
      const openapiPath = resolve(server.config.root, '../internal/control/openapi.json')
      let handler: Promise<typeof fetch> | undefined
      const loadHandler = () =>
        (handler ??= server.ssrLoadModule(FIXTURE_MODULE).then((moduleExports) => {
          const factory = (
            moduleExports as {
              fixtureFetch: (
                profile?: 'populated' | 'cold',
                options?: { providerPlane?: boolean },
              ) => typeof fetch
            }
          ).fixtureFetch
          return factory(profile, { providerPlane: true })
        }))

      // Editing the fixture catalog reloads it on the next request — the
      // design loop covers fixture data too.
      server.watcher.on('change', (file) => {
        if (file.endsWith('fixtureApi.ts')) handler = undefined
      })

      server.config.logger.info(
        'probectl fixture API: /v1 + /provider/v1 + /branding served from src/test/fixtureApi.ts (dev-only design loop; no control plane)',
      )

      const middleware: Connect.NextHandleFunction = (request, response, next) => {
        const url = request.url ?? ''
        const isApiPath =
          url === '/v1' ||
          url.startsWith('/v1/') ||
          url.startsWith('/provider/v1/') ||
          url.startsWith('/branding') ||
          url === '/openapi.json'
        if (!isApiPath) {
          next()
          return
        }
        // API docs are not synthetic fixture data: they render the exact
        // checked-in contract that the control plane embeds and serves.
        if (url === '/openapi.json') {
          void readFile(openapiPath)
            .then((body) => {
              response.statusCode = 200
              response.setHeader('content-type', 'application/json')
              response.setHeader('x-probectl-fixture', '1')
              response.end(body)
            })
            .catch(next)
          return
        }
        void (async () => {
          const fetchLike = await loadHandler()
          const chunks: Buffer[] = []
          for await (const chunk of request) {
            chunks.push(Buffer.from(chunk as Buffer))
          }
          const body = chunks.length > 0 ? Buffer.concat(chunks).toString('utf8') : undefined
          const fixtureResponse = await fetchLike(url, {
            method: request.method,
            headers: {
              'content-type': String(request.headers['content-type'] ?? 'application/json'),
            },
            body,
          })
          response.statusCode = fixtureResponse.status
          fixtureResponse.headers.forEach((value, key) => response.setHeader(key, value))
          response.setHeader('x-probectl-fixture', '1')
          response.end(Buffer.from(await fixtureResponse.arrayBuffer()))
        })().catch(next)
      }
      server.middlewares.use(middleware)
    },
  }
}
