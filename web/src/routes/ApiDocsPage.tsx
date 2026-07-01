import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import styles from './apiDocs.module.css'
import { Page } from './pages'
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

type HTTPMethod = 'get' | 'post' | 'put' | 'patch' | 'delete'

interface OpenAPIOperation {
  operationId?: string
  summary?: string
  description?: string
  tags?: string[]
  parameters?: unknown[]
  requestBody?: unknown
  responses?: Record<string, unknown>
}

interface OpenAPIDoc {
  openapi: string
  info?: { title?: string; version?: string }
  paths: Record<string, Partial<Record<HTTPMethod, OpenAPIOperation>>>
}

interface OperationRow {
  id: string
  method: HTTPMethod
  path: string
  operation: OpenAPIOperation
}

async function fetchOpenAPI(): Promise<OpenAPIDoc> {
  const res = await fetch('/openapi.json', {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  })
  if (!res.ok) throw new Error(`OpenAPI load failed: ${res.status}`)
  return (await res.json()) as OpenAPIDoc
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
  const content = (op.requestBody as { content?: Record<string, { schema?: unknown }> } | undefined)
    ?.content
  return schemaName(content?.['application/json']?.schema)
}

function OperationDetail({ row }: { row: OperationRow | null }) {
  if (!row) {
    return (
      <Card>
        <CardBody>
          <EmptyState title="No operation selected" description="Select an operation." />
        </CardBody>
      </Card>
    )
  }
  const op = row.operation
  return (
    <Card>
      <CardHeader
        title={op.summary ?? row.id}
        description={op.operationId ? `operationId: ${op.operationId}` : undefined}
      />
      <CardBody className={styles.detail}>
        <div className={styles.operationTitle}>
          <Badge tone={methodTone(row.method)}>{row.method.toUpperCase()}</Badge>
          <code>{row.path}</code>
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
      </CardBody>
    </Card>
  )
}

export function ApiDocsPage() {
  const spec = useQuery({ queryKey: ['openapi'], queryFn: fetchOpenAPI })
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const operations = useMemo(() => operationsOf(spec.data), [spec.data])
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return operations
    return operations.filter((op) =>
      [op.method, op.path, op.operation.summary, op.operation.operationId, ...(op.operation.tags ?? [])]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
        .includes(q),
    )
  }, [operations, query])
  const selectedRow =
    filtered.find((op) => op.id === selected) ?? filtered[0] ?? operations.find((op) => op.id === selected) ?? null

  const columns: Column<OperationRow>[] = [
    {
      key: 'method',
      header: 'Method',
      render: (op) => <Badge tone={methodTone(op.method)}>{op.method.toUpperCase()}</Badge>,
    },
    { key: 'path', header: 'Path', render: (op) => <code>{op.path}</code> },
    { key: 'summary', header: 'Summary', render: (op) => op.operation.summary ?? op.operation.operationId ?? '' },
    { key: 'responses', header: 'Responses', render: (op) => responseCodes(op.operation) },
    {
      key: 'actions',
      header: <span className="sr-only">Actions</span>,
      align: 'end',
      render: (op) => (
        <Button size="sm" variant="ghost" onClick={() => setSelected(op.id)}>
          Open
        </Button>
      ),
    },
  ]

  return (
    <Page title="API docs" subtitle="OpenAPI served by this control plane.">
      <div className={styles.stack}>
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
        <OperationDetail row={selectedRow} />
      </div>
    </Page>
  )
}
