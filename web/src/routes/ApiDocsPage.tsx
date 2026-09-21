// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import styles from './apiDocs.module.css'
import { Page } from './RoutePage'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  Table,
  type BadgeTone,
  type Column,
} from '../components'
import { readResponseJSON, readResponseText, responseBodyLimit } from '../api/response'

type HTTPMethod = 'get' | 'post' | 'put' | 'patch' | 'delete'

interface OpenAPIOperation {
  operationId?: string
  summary?: string
  description?: string
  tags?: string[]
  parameters?: OpenAPIParameter[]
  requestBody?: OpenAPIRequestBody
  responses?: Record<string, unknown>
}

interface OpenAPIParameter {
  name?: string
  in?: 'path' | 'query' | 'header' | 'cookie'
  required?: boolean
  description?: string
  schema?: unknown
  example?: unknown
}

interface OpenAPIRequestBody {
  content?: Record<
    string,
    { schema?: unknown; example?: unknown; examples?: Record<string, { value?: unknown }> }
  >
}

interface OpenAPIDoc {
  openapi: string
  info?: { title?: string; version?: string }
  paths: Record<string, Partial<Record<HTTPMethod, OpenAPIOperation>>>
  components?: { schemas?: Record<string, unknown> }
}

interface OperationRow {
  id: string
  method: HTTPMethod
  path: string
  operation: OpenAPIOperation
}

interface RequestResult {
  ok: boolean
  status: number
  statusText: string
  body: string
}

interface OperatorTopic {
  id: string
  title: string
  summary: string
  checks: string[]
  command?: string
}

const OPERATOR_TOPICS: OperatorTopic[] = [
  {
    id: 'install',
    title: 'Install',
    summary:
      'Choose the all-in-one Compose profile for one host or the Helm chart for Kubernetes. Both shipping profiles are HTTPS-only and require an immutable image digest in production.',
    checks: [
      'Set the Postgres password, envelope key, session HMAC key, TLS hosts, and OIDC settings before first boot.',
      'Trust the deployment CA or install a CA-issued certificate; never bypass certificate verification.',
      'Treat the envelope key and the persistent control-data volume as backup-grade key material.',
    ],
    command: 'curl --cacert ./ca.crt https://localhost:8443/readyz',
  },
  {
    id: 'first-data',
    title: 'First data',
    summary:
      'The control plane is a consumer: a green deployment stays honestly empty until a tenant-bound producer connects and sends a result.',
    checks: [
      'Open Get started, choose one producer plane, and satisfy the prerequisites shown for that plane.',
      'Enroll the agent once over mTLS, create one safe test, and wait for a current heartbeat.',
      'Confirm the same tenant sees the first result and first finding; registration alone is not evidence.',
    ],
  },
  {
    id: 'configuration',
    title: 'Configuration',
    summary:
      'Control-plane settings use the PROBECTL_ prefix. Missing transport, identity, signature, or secret prerequisites fail closed instead of silently weakening the deployment.',
    checks: [
      'Keep secrets in an operator-managed secret source, never in URLs, shell history, logs, or committed files.',
      'Use /readyz after every change; it reports each engine as ready, quiet, or blocked with a bounded reason.',
      'The offline distribution includes docs/configuration.md as the exhaustive key reference.',
    ],
  },
  {
    id: 'security',
    title: 'Security',
    summary:
      'Tenant isolation is the outer wall: storage scopes by tenant first, then RBAC. Every listener uses TLS and every agent identity is tenant-bound mTLS.',
    checks: [
      'Do not enable plaintext listeners, unverified outbound TLS, development authentication, or browser-side token storage.',
      'Keep remediation human-gated and detections observe-only; probectl is not an inline IPS.',
      'No telemetry phones home. Optional external feeds are read-only, cached, TLS-verified, and fail gracefully.',
    ],
    command: 'curl --cacert ./ca.crt https://localhost:8443/.well-known/security.txt',
  },
  {
    id: 'limitations',
    title: 'Limitations',
    summary:
      'probectl is self-hosted network observability, not a vendor-hosted SaaS, SIEM, log warehouse, inline firewall, or autonomous remediation system.',
    checks: [
      'Raw eBPF call-by-call history is not retained; durable derived service edges are the supported surface.',
      'Go in-runtime TLS metadata is not a supported eBPF source and remains encrypted_unknown.',
      'The chaos injector stays a local test harness and is not exposed as a production control-plane action.',
    ],
  },
  {
    id: 'backup-restore',
    title: 'Backup & restore',
    summary:
      'Back up Postgres, ClickHouse, and the object store. Normal artifacts are checksum-verified and envelope-encrypted; Kafka is transit, not the system of record.',
    checks: [
      'Keep the original envelope key with the backup and copy the sealed artifacts plus checksums off the failed host or region.',
      'Stop the control plane before restore: restore scripts drop and recreate stores, while agents buffer results locally.',
      'After restore, verify /readyz, one tenant-scoped pre-incident query, the audit chain, and the scheduled restore drill.',
    ],
    command: 'make backup-restore-drill',
  },
  {
    id: 'upgrade-rollback',
    title: 'Upgrade & rollback',
    summary:
      'Upgrade by immutable digest, after a verified backup. Schema migrations are sequential and idempotent, but rollback still requires an explicit data-compatibility check.',
    checks: [
      'Verify the release signature/SBOM, record /version, and take a restore-tested backup before changing the image digest.',
      'Roll agents in staged waves; probectl records decisions but your external orchestrator performs the rollout.',
      'After upgrade or rollback, compare /version, /readyz, tenant-scoped reads, ingestion, and audit continuity before reopening writes.',
    ],
    command: 'curl --cacert ./ca.crt https://localhost:8443/version',
  },
  {
    id: 'troubleshooting',
    title: 'Troubleshooting',
    summary:
      'Start with the visible readiness reason and the Admin support panel. Fix the named dependency; never clear browser state or weaken TLS as a recovery step.',
    checks: [
      'For a single-host Postgres outage, confirm the run-owned Postgres service is healthy, bring that service back, then retry the visible UI.',
      'Do not repeat a mutation while its result is unknown; first verify whether the original write committed.',
      'If readiness stays degraded, collect the secret-stripped support bundle and bounded control/Postgres logs.',
    ],
    command:
      'docker compose --env-file deploy/compose/.env -f deploy/compose/probectl.yml up -d postgres',
  },
  {
    id: 'editions',
    title: 'Editions',
    summary:
      'Core, Enterprise, and Provider/MSP use one codebase. Commercial features are offline-license gated; an unlicensed provider plane stays inactive without interrupting tenant telemetry.',
    checks: [
      'Use Admin & Settings to inspect the local tier, enabled features, expiry, and read-only degradation state.',
      'Provider operators have a separate privilege domain and never gain implicit access to tenant telemetry.',
      'License verification is local Ed25519 math and never phones home.',
    ],
  },
  {
    id: 'support',
    title: 'Support',
    summary:
      'Admin & Settings exposes deep health, exact build identity, local process posture, and a one-click secret-stripped support bundle.',
    checks: [
      'Include version, commit, build date, failing readiness component, UTC time window, and the support bundle.',
      'Do not paste credentials, join tokens, private keys, raw tenant telemetry, or browser-profile data into a case.',
      'Use the bundle before collecting broad logs; its allowlist is designed to minimize tenant and secret exposure.',
    ],
  },
]

async function fetchOpenAPI(): Promise<OpenAPIDoc> {
  const res = await fetch('/openapi.json', {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  })
  if (!res.ok) throw new Error(`OpenAPI load failed: ${res.status}`)
  return readResponseJSON<OpenAPIDoc>(res, responseBodyLimit(res))
}

function operationsOf(doc?: OpenAPIDoc): OperationRow[] {
  if (!doc) return []
  const methods: HTTPMethod[] = ['get', 'post', 'put', 'patch', 'delete']
  return Object.entries(doc.paths)
    .flatMap(([path, ops]) =>
      methods.flatMap((method) => {
        const operation = ops[method]
        return operation ? [{ id: `${method.toUpperCase()} ${path}`, method, path, operation }] : []
      }),
    )
    .sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method))
}

function methodTone(method: HTTPMethod): BadgeTone {
  if (method === 'get') return 'info'
  if (method === 'post') return 'success'
  if (method === 'delete') return 'danger'
  return 'warning'
}

function responseCodes(op: OpenAPIOperation): string {
  return Object.keys(op.responses ?? {}).join(', ')
}

function schemaName(v: unknown): string {
  const ref = (v as { $ref?: string } | undefined)?.$ref
  if (ref) return ref.split('/').at(-1) ?? ref
  if (v && typeof v === 'object') return 'inline schema'
  return 'none'
}

function requestSchema(op: OpenAPIOperation): string {
  return schemaName(jsonRequestContent(op)?.schema)
}

function jsonRequestContent(op: OpenAPIOperation) {
  const content = op.requestBody?.content
  return content?.['application/json'] ?? Object.values(content ?? {})[0]
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null
}

function derefSchema(
  doc: OpenAPIDoc | undefined,
  schema: unknown,
  seen = new Set<string>(),
): unknown {
  const rec = asRecord(schema)
  const ref = rec?.$ref
  if (!doc || typeof ref !== 'string' || seen.has(ref)) return schema
  seen.add(ref)
  const prefix = '#/components/schemas/'
  if (!ref.startsWith(prefix)) return schema
  return derefSchema(doc, doc.components?.schemas?.[ref.slice(prefix.length)] ?? schema, seen)
}

function sampleForSchema(doc: OpenAPIDoc | undefined, schema: unknown, name = 'value'): unknown {
  const resolved = derefSchema(doc, schema)
  const rec = asRecord(resolved)
  if (!rec) return {}
  if ('example' in rec) return rec.example
  if ('default' in rec) return rec.default
  const enumValues = Array.isArray(rec.enum) ? rec.enum : []
  if (enumValues.length > 0) return enumValues[0]
  const type =
    typeof rec.type === 'string' ? rec.type : asRecord(rec.properties) ? 'object' : 'string'
  if (type === 'object') {
    const props = asRecord(rec.properties)
    if (!props) return {}
    return Object.fromEntries(
      Object.entries(props).map(([key, child]) => [key, sampleForSchema(doc, child, key)]),
    )
  }
  if (type === 'array') return [sampleForSchema(doc, rec.items, name)]
  if (type === 'integer' || type === 'number') return 0
  if (type === 'boolean') return true
  if (name.toLowerCase().includes('id')) return '00000000-0000-0000-0000-000000000000'
  return 'string'
}

function sampleString(param: OpenAPIParameter): string {
  if (param.example !== undefined) return valueString(param.example)
  const rec = asRecord(param.schema)
  if (rec?.default !== undefined) return valueString(rec.default)
  if (Array.isArray(rec?.enum) && rec.enum.length > 0) return valueString(rec.enum[0])
  if (param.required) return param.name?.toLowerCase().includes('id') ? 'example-id' : 'value'
  return ''
}

function valueString(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(value)
}

function bodyTemplate(doc: OpenAPIDoc | undefined, op: OpenAPIOperation): string {
  const content = jsonRequestContent(op)
  if (!content) return ''
  const example = content.example ?? Object.values(content.examples ?? {})[0]?.value
  const sample = example ?? sampleForSchema(doc, content.schema)
  return JSON.stringify(sample, null, 2)
}

function paramsFor(row: OperationRow, location: OpenAPIParameter['in']): OpenAPIParameter[] {
  return (row.operation.parameters ?? []).filter((param) => param.in === location && param.name)
}

function initialParamValues(params: OpenAPIParameter[]): Record<string, string> {
  return params.reduce<Record<string, string>>((acc, param) => {
    if (param.name) acc[param.name] = sampleString(param)
    return acc
  }, {})
}

function operationNeedsBody(row: OperationRow): boolean {
  return Boolean(jsonRequestContent(row.operation))
}

function isMutating(method: HTTPMethod): boolean {
  return method !== 'get'
}

function pathWithParams(path: string, pathParams: Record<string, string>): string {
  return path.replace(/\{([^}]+)\}/g, (_, name: string) =>
    encodeURIComponent(pathParams[name] || `{${name}}`),
  )
}

function requestURL(
  row: OperationRow,
  pathParams: Record<string, string>,
  queryParams: Record<string, string>,
) {
  const path = pathWithParams(row.path, pathParams)
  const query = new URLSearchParams()
  Object.entries(queryParams).forEach(([key, value]) => {
    if (value.trim()) query.set(key, value.trim())
  })
  const qs = query.toString()
  return qs ? `${path}?${qs}` : path
}

function curlQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

function absoluteURL(path: string): string {
  const origin = typeof window === 'undefined' ? 'https://probectl.example' : window.location.origin
  return `${origin}${path}`
}

function generatedCurl(row: OperationRow, url: string, bodyText: string): string {
  const lines = [
    `curl -X ${row.method.toUpperCase()} ${curlQuote(absoluteURL(url))}`,
    "  -H 'Accept: application/json'",
  ]
  if (operationNeedsBody(row)) {
    lines.push(
      "  -H 'Content-Type: application/json'",
      `  --data ${curlQuote(bodyText.trim() || '{}')}`,
    )
  }
  return lines.join(' \\\n')
}

function generatedFetch(row: OperationRow, url: string, bodyText: string): string {
  const headers = operationNeedsBody(row)
    ? `\n    Accept: 'application/json',\n    'Content-Type': 'application/json',\n  `
    : `\n    Accept: 'application/json',\n  `
  const body = operationNeedsBody(row)
    ? `,\n  body: ${JSON.stringify(bodyText.trim() || '{}')}`
    : ''
  return `await fetch('${url}', {
  method: '${row.method.toUpperCase()}',
  credentials: 'same-origin',
  headers: {${headers}}${body},
})`
}

function formatBody(text: string): string {
  if (!text) return ''
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return text
  }
}

function OperationDetail({ row, doc }: { row: OperationRow | null; doc?: OpenAPIDoc }) {
  const [pathParams, setPathParams] = useState<Record<string, string>>({})
  const [queryParams, setQueryParams] = useState<Record<string, string>>({})
  const [bodyText, setBodyText] = useState('')
  const [confirmText, setConfirmText] = useState('')
  const [result, setResult] = useState<RequestResult | null>(null)
  const [runError, setRunError] = useState('')
  const [isRunning, setIsRunning] = useState(false)

  useEffect(() => {
    if (!row) return
    setPathParams(initialParamValues(paramsFor(row, 'path')))
    setQueryParams(initialParamValues(paramsFor(row, 'query')))
    setBodyText(bodyTemplate(doc, row.operation))
    setConfirmText('')
    setResult(null)
    setRunError('')
  }, [doc, row])

  if (!row) {
    return (
      <Card>
        <CardBody>
          <EmptyState title="No operation selected" description="Select an operation." />
        </CardBody>
      </Card>
    )
  }
  const activeRow = row
  const op = activeRow.operation
  const pathParameters = paramsFor(activeRow, 'path')
  const queryParameters = paramsFor(activeRow, 'query')
  const needsBody = operationNeedsBody(activeRow)
  const url = requestURL(activeRow, pathParams, queryParams)
  const curl = generatedCurl(activeRow, url, bodyText)
  const fetchExample = generatedFetch(activeRow, url, bodyText)

  async function runRequest() {
    setRunError('')
    setResult(null)
    if (isMutating(activeRow.method) && confirmText.trim() !== 'RUN') {
      setRunError('Type RUN before executing mutating requests.')
      return
    }
    let body: string | undefined
    if (needsBody) {
      try {
        JSON.parse(bodyText || '{}')
      } catch {
        setRunError('Request body must be valid JSON.')
        return
      }
      body = bodyText.trim() || '{}'
    }
    setIsRunning(true)
    try {
      const res = await fetch(url, {
        method: activeRow.method.toUpperCase(),
        credentials: 'same-origin',
        headers: needsBody
          ? { Accept: 'application/json', 'Content-Type': 'application/json' }
          : { Accept: 'application/json' },
        body,
      })
      const text = await readResponseText(res, responseBodyLimit(res))
      setResult({
        ok: res.ok,
        status: res.status,
        statusText: res.statusText,
        body: formatBody(text),
      })
    } catch (err) {
      setRunError(err instanceof Error ? err.message : 'Request failed.')
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <Card>
      <CardHeader
        title={op.summary ?? activeRow.id}
        description={op.operationId ? `operationId: ${op.operationId}` : undefined}
      />
      <CardBody className={styles.detail}>
        <div className={styles.operationTitle}>
          <Badge tone={methodTone(activeRow.method)}>{activeRow.method.toUpperCase()}</Badge>
          <code>{activeRow.path}</code>
        </div>
        {op.description ? <p className={styles.description}>{op.description}</p> : null}
        <dl className={styles.kv}>
          <dt>Tags</dt>
          <dd>{op.tags?.join(', ') || 'none'}</dd>
          <dt>Parameters</dt>
          <dd>{op.parameters?.length ?? 0}</dd>
          <dt>Request</dt>
          <dd>{requestSchema(op)}</dd>
          <dt>Responses</dt>
          <dd>{responseCodes(op) || 'none'}</dd>
        </dl>
        <div className={styles.runnerGrid}>
          <section className={styles.runnerPane} aria-labelledby="request-builder-title">
            <h3 id="request-builder-title" className={styles.sectionTitle}>
              Request builder
            </h3>
            <Field label="Request URL" value={url} readOnly />
            {pathParameters.map((param) => (
              <Field
                key={`path-${param.name}`}
                label={`Path: ${param.name}`}
                value={pathParams[param.name ?? ''] ?? ''}
                onChange={(e) =>
                  setPathParams((prev) => ({ ...prev, [param.name ?? '']: e.target.value }))
                }
              />
            ))}
            {queryParameters.map((param) => (
              <Field
                key={`query-${param.name}`}
                label={`Query: ${param.name}`}
                value={queryParams[param.name ?? ''] ?? ''}
                onChange={(e) =>
                  setQueryParams((prev) => ({ ...prev, [param.name ?? '']: e.target.value }))
                }
              />
            ))}
            {needsBody ? (
              <div className={styles.editorField}>
                <label className={styles.editorLabel} htmlFor="api-request-body">
                  Request body
                </label>
                <textarea
                  id="api-request-body"
                  className={styles.editor}
                  value={bodyText}
                  onChange={(e) => setBodyText(e.target.value)}
                  spellCheck={false}
                />
              </div>
            ) : null}
            {isMutating(activeRow.method) ? (
              <Field
                label="Mutation confirmation"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
                placeholder="RUN"
              />
            ) : null}
            <div className={styles.actions}>
              <Button
                variant={isMutating(activeRow.method) ? 'danger' : 'primary'}
                onClick={() => {
                  void runRequest()
                }}
                disabled={isRunning}
              >
                {isRunning ? 'Running…' : 'Run request'}
              </Button>
            </div>
            {runError ? (
              <p className={styles.error} role="alert">
                {runError}
              </p>
            ) : null}
            {result ? (
              <div className={styles.response} data-ok={result.ok}>
                <div className={styles.responseHeader}>
                  <Badge tone={result.ok ? 'success' : 'danger'}>{result.status}</Badge>
                  <span>{result.statusText || (result.ok ? 'OK' : 'Error')}</span>
                </div>
                <pre className={styles.codeBlock}>{result.body || '(empty response)'}</pre>
              </div>
            ) : null}
          </section>
          <section className={styles.runnerPane} aria-labelledby="examples-title">
            <h3 id="examples-title" className={styles.sectionTitle}>
              Generated examples
            </h3>
            <div className={styles.exampleBlock}>
              <div className={styles.exampleLabel}>curl</div>
              <pre className={styles.codeBlock}>{curl}</pre>
            </div>
            <div className={styles.exampleBlock}>
              <div className={styles.exampleLabel}>fetch</div>
              <pre className={styles.codeBlock}>{fetchExample}</pre>
            </div>
          </section>
        </div>
      </CardBody>
    </Card>
  )
}

export function ApiDocsPage() {
  const [searchParams] = useSearchParams()
  const spec = useQuery({ queryKey: ['openapi'], queryFn: fetchOpenAPI })
  const [query, setQuery] = useState(() => searchParams.get('filter') ?? '')
  const [guideQuery, setGuideQuery] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const operations = useMemo(() => operationsOf(spec.data), [spec.data])
  const guideTopics = useMemo(() => {
    const normalized = guideQuery.trim().toLowerCase()
    if (!normalized) return OPERATOR_TOPICS
    return OPERATOR_TOPICS.filter((topic) =>
      [topic.title, topic.summary, ...topic.checks, topic.command ?? '']
        .join(' ')
        .toLowerCase()
        .includes(normalized),
    )
  }, [guideQuery])
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return operations
    return operations.filter((op) =>
      [
        op.method,
        op.path,
        op.operation.summary,
        op.operation.operationId,
        ...(op.operation.tags ?? []),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
        .includes(q),
    )
  }, [operations, query])
  const selectedRow =
    filtered.find((op) => op.id === selected) ??
    filtered[0] ??
    operations.find((op) => op.id === selected) ??
    null

  const columns: Column<OperationRow>[] = [
    {
      key: 'method',
      header: 'Method',
      render: (op) => <Badge tone={methodTone(op.method)}>{op.method.toUpperCase()}</Badge>,
    },
    { key: 'path', header: 'Path', render: (op) => <code>{op.path}</code> },
    {
      key: 'summary',
      header: 'Summary',
      render: (op) => op.operation.summary ?? op.operation.operationId ?? '',
    },
    { key: 'responses', header: 'Responses', render: (op) => responseCodes(op.operation) },
    {
      key: 'actions',
      header: <span className="sr-only">Actions</span>,
      align: 'end',
      render: (op) => (
        <Button
          size="sm"
          variant="ghost"
          aria-label={`Open ${op.id}`}
          onClick={() => setSelected(op.id)}
        >
          Open
        </Button>
      ),
    },
  ]

  return (
    <Page
      title="API docs"
      subtitle="Offline operator guidance and OpenAPI served by this control plane."
    >
      <div className={styles.stack}>
        <Card>
          <CardHeader
            title="Operator guide"
            description="Find the safe day-0 and day-2 path without leaving this self-hosted deployment."
          />
          <CardBody>
            <div className={styles.stack}>
              <Field
                label="Filter operator guidance"
                value={guideQuery}
                onChange={(event) => setGuideQuery(event.target.value)}
                placeholder="install, backup, rollback, troubleshooting"
              />
              <nav className={styles.topicNav} aria-label="Operator guide topics">
                {OPERATOR_TOPICS.map((topic) => (
                  <a key={topic.id} href={`#${topic.id}`}>
                    {topic.title}
                  </a>
                ))}
              </nav>
              {guideTopics.length === 0 ? (
                <EmptyState
                  title="No operator topic matched"
                  description="Try install, security, backup, rollback, troubleshooting, editions, or support."
                />
              ) : (
                <div className={styles.guideGrid}>
                  {guideTopics.map((topic) => (
                    <article key={topic.id} id={topic.id} className={styles.guideTopic}>
                      <h3>{topic.title}</h3>
                      <p>{topic.summary}</p>
                      <ul>
                        {topic.checks.map((check) => (
                          <li key={check}>{check}</li>
                        ))}
                      </ul>
                      {topic.command ? (
                        <div className={styles.exampleBlock}>
                          <div className={styles.exampleLabel}>Safe checkpoint</div>
                          <pre className={styles.codeBlock}>{topic.command}</pre>
                        </div>
                      ) : null}
                    </article>
                  ))}
                </div>
              )}
            </div>
          </CardBody>
        </Card>
        <Card>
          <CardHeader
            title="Alert evaluator setup"
            description="How to turn stored alert rules into live evaluations."
          />
          <CardBody>
            <div id="alerting-setup" className={styles.stack}>
              <p>
                Alerting needs a query-capable metric store. Use the built-in memory TSDB for a
                lightweight deployment, or configure <code>PROBECTL_TSDB_MODE=prometheus</code> with
                a reachable <code>PROBECTL_TSDB_URL</code>. Then confirm that <code>/readyz</code>{' '}
                reports <code>alerting.evaluator_running=true</code>.
              </p>
            </div>
          </CardBody>
        </Card>
        <Card>
          <CardHeader
            title={spec.data?.info?.title ?? 'OpenAPI'}
            description={
              spec.data
                ? `${spec.data.openapi} · ${spec.data.info?.version ?? 'unversioned'} · ${operations.length} operations`
                : undefined
            }
          />
          <CardBody>
            {spec.isLoading ? (
              <LoadingState label="Loading OpenAPI…" />
            ) : spec.isError ? (
              <ErrorState description="Could not load /openapi.json." />
            ) : (
              <div className={styles.stack}>
                <Field
                  label="Filter operations"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="/v1/alerts, incidents, POST"
                />
                <Table
                  caption="API operations"
                  columns={columns}
                  rows={filtered}
                  rowKey={(op) => op.id}
                  empty={<EmptyState title="No operations" description="No operation matched." />}
                />
              </div>
            )}
          </CardBody>
        </Card>
        <OperationDetail row={selectedRow} doc={spec.data} />
      </div>
    </Page>
  )
}
