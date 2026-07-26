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

const srcDir = join(dirname(fileURLToPath(import.meta.url)), '..')

interface HookUse {
  file: string
  hook: string
  binding: string
  line: number
  covered: boolean
}

function sourceFiles(dir = srcDir): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'test') return []
      return sourceFiles(path)
    }
    if (!entry.name.endsWith('.tsx') || entry.name.includes('.test.')) return []
    return [path]
  })
}

function rel(path: string): string {
  return relative(srcDir, path).split(sep).join('/')
}

function importedAPIHooks(sf: ts.SourceFile): Set<string> {
  const hooks = new Set<string>()
  for (const statement of sf.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) {
      continue
    }
    const module = statement.moduleSpecifier.text
    if (!module.includes('/api/') && !module.startsWith('../api')) continue
    const bindings = statement.importClause?.namedBindings
    if (!bindings || !ts.isNamedImports(bindings)) continue
    for (const element of bindings.elements) {
      const imported = element.propertyName?.text ?? element.name.text
      if (imported.startsWith('use')) hooks.add(element.name.text)
    }
  }
  return hooks
}

function enclosingDeclaration(node: ts.Node): ts.VariableDeclaration | undefined {
  for (let current: ts.Node | undefined = node; current; current = current.parent) {
    if (ts.isVariableDeclaration(current)) return current
    if (ts.isSourceFile(current)) return undefined
  }
  return undefined
}

function propertySignal(sf: ts.SourceFile, binding: string): boolean {
  let covered = false
  function walk(node: ts.Node) {
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === binding &&
      (node.name.text === 'isError' || node.name.text === 'error')
    ) {
      covered = true
    }
    if (!covered) ts.forEachChild(node, walk)
  }
  walk(sf)
  return covered
}

function hasOnErrorOption(call: ts.CallExpression): boolean {
  const options = call.arguments[1]
  if (!options || !ts.isObjectLiteralExpression(options)) return false
  return options.properties.some(
    (property) =>
      (ts.isPropertyAssignment(property) ||
        ts.isMethodDeclaration(property) ||
        ts.isShorthandPropertyAssignment(property)) &&
      property.name?.getText() === 'onError',
  )
}

function mutationSignal(sf: ts.SourceFile, binding: string): boolean {
  let covered = false
  function walk(node: ts.Node) {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === binding
    ) {
      if (node.expression.name.text === 'mutate' && hasOnErrorOption(node)) {
        covered = true
      }
      if (node.expression.name.text === 'mutateAsync') {
        for (let current: ts.Node | undefined = node.parent; current; current = current.parent) {
          if (ts.isTryStatement(current) && current.catchClause) {
            covered = true
            break
          }
          if (ts.isFunctionLike(current)) break
        }
      }
    }
    if (!covered) ts.forEachChild(node, walk)
  }
  walk(sf)
  return covered
}

function destructuredSignal(name: ts.BindingName): boolean {
  if (!ts.isObjectBindingPattern(name)) return false
  return name.elements.some((element) => {
    const property = element.propertyName?.getText() ?? element.name.getText()
    return property === 'isError' || property === 'error'
  })
}

function documentedSignal(source: string, binding: string): boolean {
  return source.split('\n').some((line) => {
    if (!line.includes('api-error-covered:')) return false
    const bindings = line
      .slice(line.indexOf('api-error-covered:') + 'api-error-covered:'.length)
      .split(/\s+[—-]\s+/)[0]
      .split(',')
      .map((value) => value.trim())
    return bindings.includes(binding)
  })
}

function usesInSource(path: string, source: string): HookUse[] {
  const sf = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const hooks = importedAPIHooks(sf)
  const uses: HookUse[] = []

  function walk(node: ts.Node) {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      hooks.has(node.expression.text)
    ) {
      const declaration = enclosingDeclaration(node)
      const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
      if (!declaration) {
        uses.push({
          file: rel(path),
          hook: node.expression.text,
          binding: '<unbound>',
          line,
          covered: false,
        })
      } else if (ts.isIdentifier(declaration.name)) {
        const binding = declaration.name.text
        uses.push({
          file: rel(path),
          hook: node.expression.text,
          binding,
          line,
          covered:
            propertySignal(sf, binding) ||
            mutationSignal(sf, binding) ||
            documentedSignal(source, binding),
        })
      } else {
        uses.push({
          file: rel(path),
          hook: node.expression.text,
          binding: declaration.name.getText(sf),
          line,
          covered: destructuredSignal(declaration.name),
        })
      }
    }
    ts.forEachChild(node, walk)
  }
  walk(sf)
  return uses
}

function usesFor(path: string): HookUse[] {
  return usesInSource(path, readFileSync(path, 'utf8'))
}

describe('API hook error-state coverage', () => {
  const uses = sourceFiles().flatMap(usesFor)

  it('censuses every production API hook binding', () => {
    expect(uses.length).toBeGreaterThan(80)
  })

  it('requires every API hook binding to expose or handle its failure signal', () => {
    const uncovered = uses
      .filter((use) => !use.covered)
      .map((use) => `${use.file}:${use.line} ${use.binding} = ${use.hook}(...)`)
    expect(uncovered).toEqual([])
  })

  it('rejects a planted hook that reads data without handling failure', () => {
    const planted = usesInSource(
      join(srcDir, 'PlantedSilentFailure.tsx'),
      `
        import { useTests } from './api/tests'

        export function PlantedSilentFailure() {
          const tests = useTests()
          return <p>{tests.data?.length ?? 0}</p>
        }
      `,
    )

    expect(planted).toMatchObject([
      {
        hook: 'useTests',
        binding: 'tests',
        covered: false,
      },
    ])
  })
})
