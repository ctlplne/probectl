import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'
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
})
