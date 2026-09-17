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
import type {
  DeviceCollectionOutcomeResponse,
  DeviceNeighborResponse,
  FlowIngestQualityResponse,
} from './planes'
import type { TopologyResponse } from './topology'
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
const providerOpenAPI = JSON.parse(
  readFileSync(join(apiDir, '..', '..', '..', 'ee', 'provider', 'openapi.json'), 'utf8'),
) as unknown

const FIXTURE_REQUESTS: readonly FixtureContractRequest[] = [
  { method: 'GET', path: '/branding' },
  { method: 'GET', path: '/v1/abac/policies' },
  { method: 'GET', path: '/v1/agents' },
  {
    method: 'POST',
    path: '/v1/agents/enroll-tokens',
    body: { name: 'fixture-agent', ttl_seconds: 3600 },
  },
  { method: 'POST', path: '/v1/ai/ask', body: { question: 'Why is checkout slow?' } },
  { method: 'POST', path: '/v1/ai/discover', body: {} },
  { method: 'GET', path: '/v1/alerts' },
  { method: 'GET', path: '/v1/alerts/active' },
  { method: 'GET', path: '/v1/alerts/maintenance' },
  {
    method: 'GET',
    path: '/v1/alerts/40000000-0000-4000-8000-000000000001/evaluations',
  },
  { method: 'GET', path: '/v1/carbon' },
  { method: 'GET', path: '/v1/compliance' },
  { method: 'GET', path: '/v1/cost/summary' },
  { method: 'GET', path: '/v1/coverage/debt' },
  { method: 'GET', path: '/v1/coverage/vantages' },
  { method: 'GET', path: '/v1/changes' },
  { method: 'GET', path: '/v1/dashboard-report-artifacts' },
  { method: 'GET', path: '/v1/dashboard-report-schedules' },
  { method: 'GET', path: '/v1/dashboards' },
  { method: 'GET', path: '/v1/device/configs' },
  { method: 'GET', path: '/v1/device/identity-conflicts' },
  { method: 'GET', path: '/v1/device/neighbors' },
  { method: 'GET', path: '/v1/device/collection-outcomes' },
  { method: 'GET', path: '/v1/device/syslog' },
  { method: 'GET', path: '/v1/diagnostics' },
  { method: 'GET', path: '/v1/directory/roles' },
  { method: 'GET', path: '/v1/directory/scim-tokens' },
  { method: 'GET', path: '/v1/directory/users' },
  { method: 'GET', path: '/v1/editions' },
  { method: 'GET', path: '/v1/endpoints' },
  { method: 'GET', path: '/v1/identity/settings' },
  { method: 'GET', path: '/v1/incident-shares/share_0123456789abcdef0123456789abcdef' },
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
  { method: 'GET', path: '/v1/flows/ingest-quality' },
  { method: 'GET', path: '/v1/flows/top' },
  { method: 'GET', path: '/v1/incidents' },
  {
    method: 'GET',
    path: '/v1/incidents/30000000-0000-4000-8000-000000000001',
  },
  {
    method: 'GET',
    path: '/v1/incidents/30000000-0000-4000-8000-000000000001/changes',
  },
  {
    method: 'GET',
    path: '/v1/incidents/30000000-0000-4000-8000-000000000001/journal',
  },
  {
    method: 'POST',
    path: '/v1/incidents/30000000-0000-4000-8000-000000000001/shares',
    body: { context: { selected_evidence_id: 'E1' } },
  },
  { method: 'GET', path: '/v1/inventory/views' },
  { method: 'GET', path: '/v1/lifecycle/retention' },
  { method: 'GET', path: '/v1/me' },
  { method: 'GET', path: '/v1/onboarding/progress' },
  { method: 'GET', path: '/v1/outages' },
  {
    method: 'GET',
    path: '/v1/remediation/proposals',
    allowMissingResponseSchema: 'legacy remediation operation has status-only OpenAPI',
  },
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

const PROVIDER_FIXTURE_REQUESTS: readonly FixtureContractRequest[] = [
  {
    method: 'GET',
    path: '/provider/v1/breakglass',
    allowMissingResponseSchema: 'provider contract currently documents status only',
  },
  {
    method: 'GET',
    path: '/provider/v1/consent',
    allowMissingResponseSchema: 'provider contract currently documents status only',
  },
  { method: 'GET', path: '/provider/v1/fairness' },
  {
    method: 'GET',
    path: '/provider/v1/fleet',
    allowMissingResponseSchema: 'provider contract currently documents status only',
  },
  {
    method: 'GET',
    path: '/provider/v1/license',
    allowMissingResponseSchema: 'provider contract currently documents status only',
  },
  {
    method: 'GET',
    path: '/provider/v1/me',
    allowMissingResponseSchema: 'provider contract currently documents status only',
  },
  {
    method: 'GET',
    path: '/provider/v1/operators',
    allowMissingResponseSchema: 'provider contract currently documents status only',
  },
  {
    method: 'GET',
    path: '/provider/v1/tenants',
    allowMissingResponseSchema: 'provider contract currently documents status only',
  },
  {
    method: 'GET',
    path: '/provider/v1/usage',
    allowMissingResponseSchema: 'provider contract currently documents status only',
  },
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

function literalFixturePaths(scope: 'core' | 'provider'): string[] {
  const source = readFileSync(fixturePath, 'utf8')
  const paths = new Set<string>()
  const routePattern = /(?:path\s*===|case)\s*['"]([^'"]+)['"]/g
  for (let match = routePattern.exec(source); match; match = routePattern.exec(source)) {
    if (!match[1]?.startsWith('/')) continue
    const provider = match[1].startsWith('/provider/v1/')
    if ((scope === 'provider') === provider) paths.add(match[1])
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
    expect(FIXTURE_REQUESTS.map((request) => request.path).sort()).toEqual(
      literalFixturePaths('core'),
    )
    expect(PROVIDER_FIXTURE_REQUESTS.map((request) => request.path).sort()).toEqual(
      literalFixturePaths('provider'),
    )
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

  it('provider responses use the separate documented provider contract', async () => {
    const failures: string[] = []
    const fetchFixture = fixtureFetch('populated', { providerPlane: true })
    for (const request of PROVIDER_FIXTURE_REQUESTS) {
      const response = await fetchFixture(
        `https://fixture.probectl.test${request.path}`,
        fixtureRequestInit(request),
      )
      failures.push(...(await fixtureContractErrors(providerOpenAPI, request, response)))
    }
    expect(failures).toEqual([])
  })

  it('keeps current device-neighbor rows aligned with physical topology edges', async () => {
    for (const [profile, expectedLinks] of [
      ['populated', 1],
      ['cold', 0],
    ] as const) {
      const fetchFixture = fixtureFetch(profile)
      const [neighborResponse, topologyResponse] = await Promise.all([
        fetchFixture('https://fixture.probectl.test/v1/device/neighbors'),
        fetchFixture('https://fixture.probectl.test/v1/topology'),
      ])
      const neighbors = (await neighborResponse.json()) as DeviceNeighborResponse
      const topology = (await topologyResponse.json()) as TopologyResponse
      const currentNeighbors = neighbors.items.filter(
        (neighbor) => neighbor.freshness === 'current',
      )
      const physicalEdges = topology.edges.filter((edge) => edge.kind === 'physical')
      const nodeIDs = new Set(topology.nodes.map((node) => node.id))

      expect(currentNeighbors, `${profile} current neighbor rows`).toHaveLength(expectedLinks)
      expect(physicalEdges, `${profile} physical topology edges`).toHaveLength(expectedLinks)
      expect(topology.coverage?.physical_edges, `${profile} physical coverage`).toBe(expectedLinks)

      for (const neighbor of currentNeighbors) {
        const remoteKey = neighbor.remote_management_address
          ? neighbor.remote_management_address
          : `${neighbor.protocol}:${neighbor.remote_chassis_id}`
        const expectedEdge = {
          from: `device:${neighbor.local_device_address}`,
          to: `device:${remoteKey}`,
          kind: 'physical',
          label: `${neighbor.local_port_id} ↔ ${neighbor.remote_port_id}`,
        }

        expect(physicalEdges, `${profile} edge for ${neighbor.id}`).toContainEqual(expectedEdge)
        expect(
          nodeIDs.has(expectedEdge.from),
          `${profile} local endpoint ${expectedEdge.from}`,
        ).toBe(true)
        expect(nodeIDs.has(expectedEdge.to), `${profile} remote endpoint ${expectedEdge.to}`).toBe(
          true,
        )
      }
    }
  })

  it('keeps populated and cold device-collection receipts versioned and explicit', async () => {
    for (const [profile, expectedRows] of [
      ['populated', 2],
      ['cold', 0],
    ] as const) {
      const response = await fixtureFetch(profile)(
        'https://fixture.probectl.test/v1/device/collection-outcomes',
      )
      const outcomes = (await response.json()) as DeviceCollectionOutcomeResponse
      expect(outcomes.contract_version).toBe('probectl.device-collection-outcomes/v1')
      expect(outcomes.collection_running).toBe(true)
      expect(outcomes.items).toHaveLength(expectedRows)
      expect(outcomes.retention).toEqual({ max_per_tenant: 4096, retention_days: 30 })
    }
  })

  it('keeps populated and cold flow-ingest receipts versioned, bounded, and secret-free', async () => {
    for (const [profile, expectedRows] of [
      ['populated', 2],
      ['cold', 0],
    ] as const) {
      const response = await fixtureFetch(profile)(
        'https://fixture.probectl.test/v1/flows/ingest-quality',
      )
      const quality = (await response.json()) as FlowIngestQualityResponse
      expect(quality.contract_version).toBe('probectl.flow-ingest-quality/v1')
      expect(quality.ingest_running).toBe(true)
      expect(quality.items).toHaveLength(expectedRows)
      expect(quality.retention).toEqual({ max_per_tenant: 4096, retention_days: 30 })
      expect(JSON.stringify(quality)).not.toMatch(
        /raw_datagram|src_addr|dst_addr|credential|error_message/,
      )
    }
  })

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
