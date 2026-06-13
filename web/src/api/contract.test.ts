import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { API_BASE } from './client'

// UX-001 / UX-003 contract guard.
//
// apiFetch() prepends API_BASE ('/v1') to every path. Nine API files used to
// pass an already-'/v1'-prefixed path, producing '/v1/v1/...' on the wire — so
// the screens 404'd in production. The old test stubs matched the URL by
// substring (url.endsWith / includes), so '/v1/v1/topology' still satisfied
// '/v1/topology' and CI stayed green. This guard is the EXACT-path contract the
// stubs lacked: every apiFetch path must be RELATIVE to API_BASE (start with
// '/', never re-prefix '/v1'), so the wire URL has exactly one '/v1'.
const apiDir = dirname(fileURLToPath(import.meta.url))

function apiFetchPaths(src: string): string[] {
  // Match the literal path argument of every apiFetch<...>(<quote>...<quote>) call.
  const re = /apiFetch<[^>]*>\(\s*(['"`])([^'"`]*)\1/g
  const out: string[] = []
  for (let m = re.exec(src); m; m = re.exec(src)) out.push(m[2])
  return out
}

describe('API wire-path contract (UX-001)', () => {
  it("API_BASE is the single '/v1' version prefix", () => {
    expect(API_BASE).toBe('/v1')
  })

  const files = readdirSync(apiDir).filter(
    (f) => f.endsWith('.ts') && !f.endsWith('.test.ts') && f !== 'client.ts',
  )

  it('every API file is covered by this scan', () => {
    expect(files.length).toBeGreaterThan(0)
  })

  for (const file of files) {
    const src = readFileSync(join(apiDir, file), 'utf8')
    const paths = apiFetchPaths(src)
    for (const p of paths) {
      it(`${file}: apiFetch path "${p}" is relative to API_BASE (no double /v1)`, () => {
        expect(p.startsWith('/'), `path must start with '/': ${p}`).toBe(true)
        expect(
          p === '/v1' || p.startsWith('/v1/'),
          `path must NOT re-prefix '/v1' (apiFetch already prepends API_BASE) — would yield ${API_BASE}${p}`,
        ).toBe(false)
      })
    }
  }
})
