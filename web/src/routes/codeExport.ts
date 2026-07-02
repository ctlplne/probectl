import type { AlertRule, MaintenanceWindow } from '../api/alerts'
import type { CollectorRegistration } from '../api/agents'
import type { TestSpec } from '../api/authoring'
import type { SLOStatus } from '../api/slos'
import type { Test } from '../api/tests'

const REDACTED = '<redacted-by-probectl>'
const secretKey = /(secret|token|password|credential|private[_-]?key|api[_-]?key|hmac|bearer)/i

type Scalar = string | number | boolean | null
type YAMLValue = Scalar | YAMLValue[] | { [key: string]: YAMLValue }

function compactRecord(input: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(input).filter(([, value]) => value !== undefined))
}

function redact(value: unknown, key = ''): YAMLValue {
  if (secretKey.test(key)) return REDACTED
  if (value === null || value === undefined) return null
  if (typeof value === 'string') {
    if (/^bearer\s+/i.test(value)) return REDACTED
    return value
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value
  if (Array.isArray(value)) return value.map((item) => redact(item))
  if (typeof value === 'object') {
    const out: Record<string, YAMLValue> = {}
    for (const [childKey, childValue] of Object.entries(value as Record<string, unknown>)) {
      if (childValue !== undefined) out[childKey] = redact(childValue, childKey)
    }
    return out
  }
  return null
}

function scalar(value: Scalar): string {
  if (value === null) return 'null'
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (value === '') return '""'
  if (/^[A-Za-z0-9_.:/@+<>-]+$/.test(value)) return value
  return JSON.stringify(value)
}

function toYAML(value: YAMLValue, depth = 0): string {
  const pad = ' '.repeat(depth)
  if (value === null || typeof value !== 'object') return `${pad}${scalar(value)}`
  if (Array.isArray(value)) {
    if (value.length === 0) return `${pad}[]`
    return value
      .map((item) =>
        item !== null && typeof item === 'object'
          ? `${pad}-\n${toYAML(item, depth + 2)}`
          : `${pad}- ${scalar(item)}`,
      )
      .join('\n')
  }
  const entries = Object.entries(value)
  if (entries.length === 0) return `${pad}{}`
  return entries
    .map(([key, child]) => {
      if (child !== null && typeof child === 'object') {
        return `${pad}${key}:\n${toYAML(child, depth + 2)}`
      }
      return `${pad}${key}: ${scalar(child)}`
    })
    .join('\n')
}

export function asYAML(value: Record<string, unknown>): string {
  return `${toYAML(redact(value))}\n`
}

export function testAsCode(test: Test | TestSpec): string {
  return asYAML({
    apiVersion: 'probectl.io/tests/v1',
    kind: 'Test',
    metadata: {
      name: test.name,
    },
    spec: compactRecord({
      type: test.type,
      target: test.target,
      interval_seconds: test.interval_seconds,
      timeout_seconds: test.timeout_seconds,
      enabled: test.enabled,
      params: 'params' in test ? test.params : undefined,
    }),
  })
}

export function alertRuleAsCode(rule: AlertRule): string {
  return asYAML({
    apiVersion: 'probectl.io/alerts/v1',
    kind: 'AlertRule',
    metadata: {
      name: rule.name,
    },
    spec: compactRecord({
      enabled: rule.enabled,
      metric: rule.metric,
      match: rule.match,
      type: rule.type,
      comparison: rule.comparison,
      threshold: rule.threshold,
      window: rule.window,
      sensitivity: rule.sensitivity,
      for_n: rule.for_n,
      renotify_seconds: rule.renotify_seconds,
      severity: rule.severity,
      channels: rule.channels,
    }),
  })
}

export function maintenanceWindowAsCode(window: MaintenanceWindow): string {
  return asYAML({
    apiVersion: 'probectl.io/alerts/v1',
    kind: 'MaintenanceWindow',
    metadata: {
      name: window.name,
    },
    spec: compactRecord({
      starts_at: window.starts_at,
      ends_at: window.ends_at,
      recurrence: window.recurrence,
      rule_ids: window.rule_ids,
      match: window.match,
      reason: window.reason,
    }),
  })
}

export function sloAsCode(slo: SLOStatus): string {
  return asYAML({
    apiVersion: 'openslo/v1',
    kind: 'SLO',
    metadata: {
      name: slo.name,
      displayName: slo.display_name,
    },
    spec: compactRecord({
      service: slo.service,
      team: slo.team,
      objective: {
        target: slo.objective,
        timeWindow: slo.window,
      },
      burnRates: slo.burn_rates.map((burn) => ({
        window: burn.window,
        long: burn.long,
        short: burn.short,
        limit: burn.limit,
      })),
    }),
  })
}

export function collectorRegistrationAsCode(registered: CollectorRegistration): string {
  return asYAML({
    apiVersion: 'probectl.io/collectors/v1',
    kind: 'Collector',
    metadata: {
      name: registered.agent_id,
    },
    spec: {
      tenant_id: registered.tenant_id,
      plane: registered.plane,
      capabilities: registered.capabilities,
      env: registered.config.env,
      yaml: registered.config.yaml,
    },
  })
}
