// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { readFile } from 'node:fs/promises'
import { gzipSync } from 'node:zlib'
import { resolve } from 'node:path'

const MAIN_BUDGET = 400_000
const ROUTE_BUDGET = 250_000
const manifestPath = resolve('dist/.vite/manifest.json')

let manifest
try {
  manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
} catch (error) {
  console.error(`bundle budget: cannot read ${manifestPath}; run "npm run build" first`)
  console.error(error instanceof Error ? error.message : String(error))
  process.exit(1)
}

const entries = Object.entries(manifest).filter(([, item]) => item.file?.endsWith('.js'))
const main = entries.filter(([, item]) => item.isEntry)
const routes = entries.filter(([, item]) => item.isDynamicEntry)

if (main.length !== 1) {
  console.error(`bundle budget: expected exactly one JavaScript app entry, found ${main.length}`)
  process.exit(1)
}
if (routes.length === 0) {
  console.error(
    'bundle budget: found no dynamic route entries; route-level code splitting regressed',
  )
  process.exit(1)
}

let failed = false

async function check(label, records, budget) {
  for (const [source, item] of records) {
    const bytes = await readFile(resolve('dist', item.file))
    const gzipBytes = gzipSync(bytes, { level: 9 }).byteLength
    const sizeKB = (gzipBytes / 1000).toFixed(1)
    const budgetKB = (budget / 1000).toFixed(0)
    console.log(`${label.padEnd(5)} ${sizeKB.padStart(7)} kB gz / ${budgetKB} kB  ${source}`)
    if (gzipBytes >= budget) {
      failed = true
      console.error(`bundle budget: ${source} is ${sizeKB} kB gz; must be < ${budgetKB} kB gz`)
    }
  }
}

await check('main', main, MAIN_BUDGET)
await check('route', routes, ROUTE_BUDGET)

if (failed) process.exit(1)
console.log(`bundle budget: PASS (${main.length} main, ${routes.length} lazy routes)`)
