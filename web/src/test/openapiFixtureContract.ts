// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { isIP } from 'node:net'

type JSONObject = Record<string, unknown>

export interface FixtureContractRequest {
  method: 'GET' | 'POST'
  path: string
  body?: unknown
  /** Transitional route whose OpenAPI operation documents status but not a body schema. */
  allowMissingResponseSchema?: string
}

interface OperationMatch {
  operation: JSONObject
  parameters: unknown[]
  pathParameters: Record<string, string>
  template: string
}

function objectValue(value: unknown): JSONObject | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as JSONObject)
    : null
}

function deepEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right)
}

function resolvePointer(document: unknown, ref: string): unknown {
  if (!ref.startsWith('#/')) return undefined
  let current: unknown = document
  for (const encoded of ref.slice(2).split('/')) {
    const record = objectValue(current)
    if (!record) return undefined
    const key = encoded.replace(/~1/g, '/').replace(/~0/g, '~')
    current = record[key]
  }
  return current
}

function resolveObject(document: unknown, value: unknown): JSONObject | null {
  const record = objectValue(value)
  if (!record) return null
  const ref = record.$ref
  if (typeof ref !== 'string') return record
  return objectValue(resolvePointer(document, ref))
}

function valueMatchesType(value: unknown, type: string): boolean {
  switch (type) {
    case 'array':
      return Array.isArray(value)
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value)
    case 'null':
      return value === null
    case 'number':
      return typeof value === 'number' && Number.isFinite(value)
    case 'object':
      return objectValue(value) !== null
    default:
      return typeof value === type
  }
}

function validDateTime(value: string): boolean {
  return (
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) &&
    !Number.isNaN(Date.parse(value))
  )
}

function validUUID(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
}

function formatMatches(value: string, format: string): boolean {
  switch (format) {
    case 'date-time':
      return validDateTime(value)
    case 'email':
      return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)
    case 'hostname':
      return (
        value.length <= 253 &&
        value.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))
      )
    case 'ipv4':
      return isIP(value) === 4
    case 'ipv6':
      return isIP(value) === 6
    case 'uri':
      try {
        new URL(value)
        return true
      } catch {
        return false
      }
    case 'uuid':
      return validUUID(value)
    default:
      // Unknown custom formats remain annotations in OpenAPI 3.1. The formats
      // probectl relies on for fixture fidelity are enforced above.
      return true
  }
}

function numberKeyword(schema: JSONObject, key: string): number | undefined {
  const value = schema[key]
  return typeof value === 'number' ? value : undefined
}

export function openAPISchemaErrors(
  document: unknown,
  value: unknown,
  rawSchema: unknown,
  path = '$',
  depth = 0,
): string[] {
  if (depth > 100) return [`${path}: schema recursion exceeds 100 levels`]
  if (rawSchema === true) return []
  if (rawSchema === false) return [`${path}: false schema rejects every value`]

  const schema = objectValue(rawSchema)
  if (!schema) return [`${path}: response schema is missing or invalid`]

  const ref = schema.$ref
  if (typeof ref === 'string') {
    const target = resolvePointer(document, ref)
    if (target === undefined) return [`${path}: unresolved OpenAPI reference ${ref}`]
    const errors = openAPISchemaErrors(document, value, target, path, depth + 1)
    const siblings = { ...schema }
    delete siblings.$ref
    if (Object.keys(siblings).length > 0) {
      errors.push(...openAPISchemaErrors(document, value, siblings, path, depth + 1))
    }
    return errors
  }

  const errors: string[] = []
  const allOf = Array.isArray(schema.allOf) ? schema.allOf : []
  for (const branch of allOf) {
    errors.push(...openAPISchemaErrors(document, value, branch, path, depth + 1))
  }

  const anyOf = Array.isArray(schema.anyOf) ? schema.anyOf : []
  if (
    anyOf.length > 0 &&
    !anyOf.some(
      (branch) => openAPISchemaErrors(document, value, branch, path, depth + 1).length === 0,
    )
  ) {
    errors.push(`${path}: value does not match any OpenAPI anyOf branch`)
  }

  const oneOf = Array.isArray(schema.oneOf) ? schema.oneOf : []
  if (oneOf.length > 0) {
    const matches = oneOf.filter(
      (branch) => openAPISchemaErrors(document, value, branch, path, depth + 1).length === 0,
    ).length
    if (matches !== 1) errors.push(`${path}: value matches ${matches} OpenAPI oneOf branches`)
  }

  if (schema.nullable === true && value === null) return errors

  const rawTypes = Array.isArray(schema.type) ? schema.type : [schema.type]
  const types = rawTypes.filter((type): type is string => typeof type === 'string')
  if (types.length > 0 && !types.some((type) => valueMatchesType(value, type))) {
    errors.push(`${path}: expected OpenAPI type ${types.join('|')}`)
    return errors
  }

  const enumValues = Array.isArray(schema.enum) ? schema.enum : []
  if (enumValues.length > 0 && !enumValues.some((candidate) => deepEqual(candidate, value))) {
    errors.push(`${path}: value is outside its OpenAPI enum`)
  }
  if ('const' in schema && !deepEqual(schema.const, value)) {
    errors.push(`${path}: value does not match its OpenAPI const`)
  }

  if (typeof value === 'string') {
    const minLength = numberKeyword(schema, 'minLength')
    const maxLength = numberKeyword(schema, 'maxLength')
    if (minLength !== undefined && value.length < minLength) {
      errors.push(`${path}: string is shorter than minLength ${minLength}`)
    }
    if (maxLength !== undefined && value.length > maxLength) {
      errors.push(`${path}: string is longer than maxLength ${maxLength}`)
    }
    if (typeof schema.pattern === 'string' && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${path}: string does not match OpenAPI pattern ${schema.pattern}`)
    }
    if (typeof schema.format === 'string' && !formatMatches(value, schema.format)) {
      errors.push(`${path}: string does not match OpenAPI format ${schema.format}`)
    }
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    const minimum = numberKeyword(schema, 'minimum')
    const maximum = numberKeyword(schema, 'maximum')
    const exclusiveMinimum = numberKeyword(schema, 'exclusiveMinimum')
    const exclusiveMaximum = numberKeyword(schema, 'exclusiveMaximum')
    if (minimum !== undefined && value < minimum) {
      errors.push(`${path}: number is below minimum ${minimum}`)
    }
    if (maximum !== undefined && value > maximum) {
      errors.push(`${path}: number is above maximum ${maximum}`)
    }
    if (exclusiveMinimum !== undefined && value <= exclusiveMinimum) {
      errors.push(`${path}: number is not above exclusiveMinimum ${exclusiveMinimum}`)
    }
    if (exclusiveMaximum !== undefined && value >= exclusiveMaximum) {
      errors.push(`${path}: number is not below exclusiveMaximum ${exclusiveMaximum}`)
    }
  }

  if (Array.isArray(value)) {
    const minItems = numberKeyword(schema, 'minItems')
    const maxItems = numberKeyword(schema, 'maxItems')
    if (minItems !== undefined && value.length < minItems) {
      errors.push(`${path}: array has fewer than minItems ${minItems}`)
    }
    if (maxItems !== undefined && value.length > maxItems) {
      errors.push(`${path}: array has more than maxItems ${maxItems}`)
    }
    if (
      schema.uniqueItems === true &&
      new Set(value.map((item) => JSON.stringify(item))).size < value.length
    ) {
      errors.push(`${path}: array items are not unique`)
    }
    if (schema.items !== undefined) {
      value.forEach((item, index) => {
        errors.push(
          ...openAPISchemaErrors(document, item, schema.items, `${path}[${index}]`, depth + 1),
        )
      })
    }
  }

  const record = objectValue(value)
  if (record) {
    const required = Array.isArray(schema.required)
      ? schema.required.filter((key): key is string => typeof key === 'string')
      : []
    for (const key of required) {
      if (!(key in record)) errors.push(`${path}: missing required property ${key}`)
    }

    const properties = objectValue(schema.properties) ?? {}
    for (const [key, propertySchema] of Object.entries(properties)) {
      if (key in record) {
        errors.push(
          ...openAPISchemaErrors(
            document,
            record[key],
            propertySchema,
            `${path}.${key}`,
            depth + 1,
          ),
        )
      }
    }

    const additionalKeys = Object.keys(record).filter((key) => !(key in properties))
    if (schema.additionalProperties === false && additionalKeys.length > 0) {
      errors.push(`${path}: unexpected properties ${additionalKeys.join(', ')}`)
    } else if (schema.additionalProperties !== undefined && schema.additionalProperties !== true) {
      for (const key of additionalKeys) {
        errors.push(
          ...openAPISchemaErrors(
            document,
            record[key],
            schema.additionalProperties,
            `${path}.${key}`,
            depth + 1,
          ),
        )
      }
    }

    const minProperties = numberKeyword(schema, 'minProperties')
    const maxProperties = numberKeyword(schema, 'maxProperties')
    if (minProperties !== undefined && Object.keys(record).length < minProperties) {
      errors.push(`${path}: object has fewer than minProperties ${minProperties}`)
    }
    if (maxProperties !== undefined && Object.keys(record).length > maxProperties) {
      errors.push(`${path}: object has more than maxProperties ${maxProperties}`)
    }
  }

  return errors
}

function matchOperation(document: unknown, request: FixtureContractRequest): OperationMatch | null {
  const paths = objectValue(objectValue(document)?.paths)
  if (!paths) return null

  const candidates = Object.entries(paths).sort(([left], [right]) => {
    if (left === request.path) return -1
    if (right === request.path) return 1
    return right.length - left.length
  })

  for (const [template, rawPathItem] of candidates) {
    const pathItem = objectValue(rawPathItem)
    if (!pathItem) continue
    const templateParts = template.split('/')
    const actualParts = request.path.split('/')
    if (templateParts.length !== actualParts.length) continue

    const pathParameters: Record<string, string> = {}
    let matches = true
    for (let index = 0; index < templateParts.length; index += 1) {
      const expected = templateParts[index] ?? ''
      const actual = actualParts[index] ?? ''
      const parameter = /^\{(.+)\}$/.exec(expected)
      if (parameter?.[1]) pathParameters[parameter[1]] = decodeURIComponent(actual)
      else if (expected !== actual) matches = false
    }
    if (!matches) continue

    const operation = objectValue(pathItem[request.method.toLowerCase()])
    if (!operation) continue
    const pathItemParameters = Array.isArray(pathItem.parameters) ? pathItem.parameters : []
    const operationParameters = Array.isArray(operation.parameters) ? operation.parameters : []
    return {
      operation,
      parameters: [...pathItemParameters, ...operationParameters],
      pathParameters,
      template,
    }
  }
  return null
}

export async function fixtureContractErrors(
  document: unknown,
  request: FixtureContractRequest,
  response: Response,
): Promise<string[]> {
  const match = matchOperation(document, request)
  if (!match) return [`${request.method} ${request.path}: no matching OpenAPI operation`]

  const errors: string[] = []
  for (const rawParameter of match.parameters) {
    const parameter = resolveObject(document, rawParameter)
    if (!parameter || parameter.in !== 'path' || typeof parameter.name !== 'string') continue
    const value = match.pathParameters[parameter.name]
    if (value === undefined) {
      errors.push(`${request.method} ${request.path}: missing path parameter ${parameter.name}`)
      continue
    }
    errors.push(
      ...openAPISchemaErrors(document, value, parameter.schema, `path.${parameter.name}`).map(
        (error) => `${request.method} ${request.path}: ${error}`,
      ),
    )
  }

  const responses = objectValue(match.operation.responses)
  const responseContract = resolveObject(document, responses?.[String(response.status)])
  if (!responseContract) {
    errors.push(
      `${request.method} ${request.path}: status ${response.status} is not documented for ${match.template}`,
    )
    return errors
  }

  const content = objectValue(responseContract.content)
  const mediaType = objectValue(content?.['application/json'])
  if (!mediaType?.schema) {
    if (!request.allowMissingResponseSchema) {
      errors.push(
        `${request.method} ${request.path}: status ${response.status} has no application/json response schema`,
      )
    }
    return errors
  }

  let body: unknown
  try {
    body = await response.clone().json()
  } catch {
    errors.push(`${request.method} ${request.path}: response body is not valid JSON`)
    return errors
  }

  errors.push(
    ...openAPISchemaErrors(document, body, mediaType.schema).map(
      (error) => `${request.method} ${request.path}: ${error}`,
    ),
  )
  return errors
}
