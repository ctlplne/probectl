// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'
import { fixtureFetch, jsonResponse, type FixtureProfile } from '../test/fixtureApi'
import { fixtureContractErrors, type FixtureContractRequest } from '../test/openapiFixtureContract'
import { API_BASE } from './client'
import { API_CALL_CONTRACTS, type APICallContract } from './openapi-contracts'

interface APIFetchCall {
  file: string
  method: string
  path: string
  response: string
}

const apiDir = dirname(fileURLToPath(import.meta.url))
const srcDir = join(apiDir, '..')
const fixturePath = join(srcDir, 'test', 'fixtureApi.ts')
const openAPI = JSON.parse(
  readFileSync(join(apiDir, '..', '..', '..', 'internal', 'control', 'openapi.json'), 'utf8'),
) as unknown

const FIXTURE_REQUESTS: readonly FixtureContractRequest[] = [
  { method: 'GET', path: '/branding' },
  { method: 'GET', path: '/v1/abac/policies' },
  { method: 'GET', path: '/v1/agents' },
  { method: 'POST', path: '/v1/ai/ask', body: { question: 'Why is checkout slow?' } },
  { method: 'POST', path: '/v1/ai/discover', body: {} },
  { method: 'GET', path: '/v1/alerts' },
  { method: 'GET', path: '/v1/alerts/active' },
  { method: 'GET', path: '/v1/alerts/maintenance' },
  { method: 'GET', path: '/v1/carbon' },
  { method: 'GET', path: '/v1/compliance' },
  { method: 'GET', path: '/v1/cost/summary' },
  { method: 'GET', path: '/v1/coverage/vantages' },
  { method: 'GET', path: '/v1/dashboard-report-artifacts' },
  { method: 'GET', path: '/v1/dashboard-report-schedules' },
  { method: 'GET', path: '/v1/dashboards' },
  { method: 'GET', path: '/v1/device/configs' },
  { method: 'GET', path: '/v1/device/syslog' },
  { method: 'GET', path: '/v1/diagnostics' },
  { method: 'GET', path: '/v1/directory/scim-tokens' },
  { method: 'GET', path: '/v1/editions' },
  { method: 'GET', path: '/v1/endpoints' },
  {
    method: 'POST',
    path: '/v1/explorer/compare',
    body: {
      query: {
        question: 'Show service dependencies',
        source: 'topology',
        from: '2026-06-04T11:00:00Z',
        to: '2026-06-04T12:00:00Z',
        dimensions: ['from', 'to', 'kind'],
        filters: {},
        groupings: ['kind'],
        measures: ['edges'],
        visualization: 'topology',
        limit: 50,
        template: 'service-dependencies',
      },
      previous_from: '2026-06-04T10:00:00Z',
      previous_to: '2026-06-04T11:00:00Z',
    },
  },
  {
    method: 'POST',
    path: '/v1/explorer/query',
    body: {
      question: 'Show service dependencies',
      source: 'topology',
      from: '2026-06-04T11:00:00Z',
      to: '2026-06-04T12:00:00Z',
      dimensions: ['from', 'to', 'kind'],
      filters: {},
      groupings: ['kind'],
      measures: ['edges'],
      visualization: 'topology',
      limit: 50,
      template: 'service-dependencies',
    },
  },
  { method: 'GET', path: '/v1/explorer/schema' },
  { method: 'GET', path: '/v1/flows/anomalies' },
  { method: 'GET', path: '/v1/flows/capacity' },
  { method: 'GET', path: '/v1/flows/top' },
  { method: 'GET', path: '/v1/incidents' },
  {
    method: 'GET',
    path: '/v1/incidents/30000000-0000-4000-8000-000000000001',
  },
  { method: 'GET', path: '/v1/inventory/views' },
  { method: 'GET', path: '/v1/lifecycle/retention' },
  { method: 'GET', path: '/v1/me' },
  { method: 'GET', path: '/v1/outages' },
  { method: 'GET', path: '/v1/results/history' },
  { method: 'GET', path: '/v1/results/latest' },
  { method: 'GET', path: '/v1/rollouts' },
  { method: 'GET', path: '/v1/rum' },
  { method: 'GET', path: '/v1/secrets/health' },
  { method: 'GET', path: '/v1/security/keys' },
  { method: 'GET', path: '/v1/slos' },
  { method: 'GET', path: '/v1/tests' },
  {
    method: 'GET',
    path: '/v1/tests/10000000-0000-4000-8000-000000000001/path',
  },
  {
    method: 'GET',
    path: '/v1/tests/10000000-0000-4000-8000-000000000001/path/history',
  },
  { method: 'GET', path: '/v1/threat/detections' },
  { method: 'GET', path: '/v1/threat/intel/status' },
  { method: 'GET', path: '/v1/tls/posture' },
  { method: 'GET', path: '/v1/topology' },
  { method: 'POST', path: '/v1/topology/whatif', body: { target: 'service:checkout' } },
]

function callKey(c: APIFetchCall): string {
  return `${c.file}|${c.method}|${c.path}|${c.response}`
}

function rel(path: string): string {
  return relative(srcDir, path).split(sep).join('/')
}

function sourceFiles(): string[] {
  const apiFiles = readdirSync(apiDir)
    .filter(
      (f) =>
        f.endsWith('.ts') &&
        !f.endsWith('.test.ts') &&
        !['client.ts', 'openapi-contracts.ts', 'queryClient.ts', 'sdk.gen.ts'].includes(f),
    )
    .map((f) => join(apiDir, f))
  return [...apiFiles, join(srcDir, 'auth', 'AuthProvider.tsx')]
}

function pathText(arg: ts.Expression, sf: ts.SourceFile): string {
  if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) return arg.text
  return arg.getText(sf)
}

function pathForPrefixCheck(path: string): string {
  if (path.startsWith('`') && path.endsWith('`')) return path.slice(1, -1)
  return path
}

function methodOf(arg: ts.Expression | undefined, sf: ts.SourceFile): string {
  if (!arg) return 'GET'
  if (ts.isObjectLiteralExpression(arg)) {
    for (const prop of arg.properties) {
      if (!ts.isPropertyAssignment(prop) || prop.name.getText(sf) !== 'method') continue
      const method = prop.initializer
      if (ts.isStringLiteral(method)) return method.text.toUpperCase()
    }
    return 'GET'
  }
  if (ts.isCallExpression(arg) && arg.expression.getText(sf) === 'jsonInit') {
    const method = arg.arguments[0]
    if (method && ts.isStringLiteral(method)) return method.text.toUpperCase()
  }
  return 'UNKNOWN'
}

function apiFetchCalls(path: string): APIFetchCall[] {
  const src = readFileSync(path, 'utf8')
  const sf = ts.createSourceFile(path, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const out: APIFetchCall[] = []

  function walk(node: ts.Node) {
    if (ts.isCallExpression(node) && node.expression.getText(sf) === 'apiFetch') {
      const first = node.arguments[0]
      out.push({
        file: rel(path),
        method: methodOf(node.arguments[1], sf),
        path: first ? pathText(first, sf) : '<missing>',
        response: node.typeArguments?.[0]?.getText(sf) ?? '<none>',
      })
    }
    ts.forEachChild(node, walk)
  }
  walk(sf)
  return out
}

function generatedSDKTypes(): Map<string, string> {
  const src = readFileSync(join(apiDir, 'sdk.gen.ts'), 'utf8')
  const out = new Map<string, string>()
  const re = /^export\s+(?:interface|type)\s+([A-Za-z0-9_]+)(?:\s*=\s*([^\n]+))?/gm
  for (let m = re.exec(src); m; m = re.exec(src)) out.set(m[1], (m[2] ?? 'interface').trim())
  return out
}

function generatedInterfaceMembers(name: string): Set<string> {
  const src = readFileSync(join(apiDir, 'sdk.gen.ts'), 'utf8')
  const sf = ts.createSourceFile('sdk.gen.ts', src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const members = new Set<string>()

  function walk(node: ts.Node) {
    if (ts.isInterfaceDeclaration(node) && node.name.text === name) {
      for (const member of node.members) {
        if (ts.isPropertySignature(member) && member.name) members.add(member.name.getText(sf))
      }
    }
    ts.forEachChild(node, walk)
  }
  walk(sf)
  return members
}

function literalFixturePaths(): string[] {
  const source = readFileSync(fixturePath, 'utf8')
  const paths = new Set<string>()
  const routePattern = /(?:path\s*===|case)\s*['"]([^'"]+)['"]/g
  for (let match = routePattern.exec(source); match; match = routePattern.exec(source)) {
    if (match[1]) paths.add(match[1])
  }
  return [...paths].sort()
}

function fixtureRequestInit(request: FixtureContractRequest): RequestInit {
  const init: RequestInit = { method: request.method }
  if (request.body !== undefined) {
    init.headers = { 'Content-Type': 'application/json' }
    init.body = JSON.stringify(request.body)
  }
  return init
}

describe('API wire and OpenAPI shape contracts', () => {
  const calls = sourceFiles().flatMap(apiFetchCalls)
  const contracts: readonly APICallContract[] = API_CALL_CONTRACTS

  it("API_BASE is the single '/v1' version prefix", () => {
    expect(API_BASE).toBe('/v1')
  })

  it('finds every apiFetch call in the tenant UI API surface', () => {
    expect(calls.length).toBeGreaterThan(0)
  })

  for (const call of calls) {
    it(`${call.file}: ${call.method} ${call.path} is relative to API_BASE`, () => {
      const p = pathForPrefixCheck(call.path)
      expect(p.startsWith('/'), `path must start with '/': ${call.path}`).toBe(true)
      expect(
        p === '/v1' || p.startsWith('/v1/'),
        `path must NOT re-prefix '/v1' (apiFetch already prepends API_BASE) - would yield ${API_BASE}${p}`,
      ).toBe(false)
    })
  }

  it('has one explicit OpenAPI contract row for every apiFetch call', () => {
    const observed = new Set(calls.map(callKey))
    const declared = new Set(contracts.map(callKey))
    expect([...observed].filter((k) => !declared.has(k))).toEqual([])
    expect([...declared].filter((k) => !observed.has(k))).toEqual([])
  })

  it('pins every UI call to a generated SDK response or a documented OpenAPI gap', () => {
    const sdk = generatedSDKTypes()
    for (const contract of contracts) {
      const generated = sdk.get(contract.generated)
      expect(generated, `${contract.generated} must be exported by sdk.gen.ts`).toBeTruthy()
      const weakGenerated = generated === 'JsonObject' || generated === 'void'
      const voidResponse = contract.response === 'void' || contract.response === 'undefined'
      if (weakGenerated && !voidResponse) {
        expect(
          contract.reason,
          `${contract.file} ${contract.method} ${contract.path} maps ${contract.response} to weak generated ${contract.generated}; add an explicit reason`,
        ).toBeTruthy()
      }
    }
  })

  it('exposes RCA grounding and degraded-state fields on AIAnswer', () => {
    const members = generatedInterfaceMembers('AIAnswer')
    expect([...members]).toEqual(
      expect.arrayContaining([
        'root_cause_citations',
        'root_cause_grounded',
        'degraded',
        'investigation_plan',
        'reasoning',
      ]),
    )
  })
})

describe('design-loop fixture to OpenAPI response contracts', () => {
  it('catalogs every literal fixture route exactly once', () => {
    expect(FIXTURE_REQUESTS.map((request) => request.path).sort()).toEqual(literalFixturePaths())
  })

  for (const profile of ['populated', 'cold'] satisfies FixtureProfile[]) {
    it(`${profile} responses use documented operations, statuses, parameters, and schemas`, async () => {
      const failures: string[] = []
      const fetchFixture = fixtureFetch(profile)
      for (const request of FIXTURE_REQUESTS) {
        const response = await fetchFixture(
          `https://fixture.probectl.test${request.path}`,
          fixtureRequestInit(request),
        )
        failures.push(...(await fixtureContractErrors(openAPI, request, response)))
      }
      expect(failures).toEqual([])
    })
  }

  it('fails closed on planted path, status, and response-shape drift', async () => {
    const unknownPath = await fixtureContractErrors(
      openAPI,
      { method: 'GET', path: '/v1/planted-phantom' },
      jsonResponse({}),
    )
    expect(unknownPath.join('\n')).toMatch(/no matching OpenAPI operation/)

    const undocumentedStatus = await fixtureContractErrors(
      openAPI,
      { method: 'GET', path: '/v1/tests' },
      jsonResponse({ error: { code: 'teapot', message: 'planted status drift' } }, 418),
    )
    expect(undocumentedStatus.join('\n')).toMatch(/status 418 is not documented/)

    const invalidShape = await fixtureContractErrors(
      openAPI,
      { method: 'GET', path: '/v1/tests' },
      jsonResponse({ items: [{ id: 'not-a-uuid', name: 'drifted', type: 'dns' }] }),
    )
    expect(invalidShape.join('\n')).toMatch(/format uuid/)
    expect(invalidShape.join('\n')).toMatch(/missing required property tenant_id/)
  })
})
