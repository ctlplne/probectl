// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

export const JOURNEY_IDS = ['J1', 'J2', 'J3', 'J4', 'J5', 'J6'] as const

export type JourneyID = (typeof JOURNEY_IDS)[number]

export interface ActiveTimeProxy {
  min_ms: number
  max_ms: number
  basis: string
}

export type JourneyOutcome =
  | { status: 'complete'; evidence: string[] }
  | { status: 'incomplete'; reason: string }

export interface JourneyMeasurement {
  journey: JourneyID
  name: string
  pointer_interactions: number
  keyboard_interactions: number
  typed_characters: number
  context_breaks: number
  active_time_proxy: ActiveTimeProxy
  outcome: JourneyOutcome
}

export interface JourneyArtifact {
  schema_version: 1
  measured_at: string
  method: string
  measurements: JourneyMeasurement[]
}

export interface MeasuredRequest {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: unknown
}

interface BaselineFixture {
  journey: JourneyID
  name: string
  pointer: number
  keyboard: number
  typed: number
  contextBreaks: number
  activeTime: ActiveTimeProxy
  outcome: JourneyOutcome
}

const baselineFixtures: BaselineFixture[] = [
  {
    journey: 'J1',
    name: 'install to first real insight',
    pointer: 4,
    keyboard: 0,
    typed: 0,
    contextBreaks: 1,
    activeTime: {
      min_ms: 6 * 60_000,
      max_ms: 12 * 60_000,
      basis:
        'reference compose healthy; mint, shell enrollment, test creation, and finding receipt',
    },
    outcome: {
      status: 'complete',
      evidence: [
        'server reports connected and healthy producer separately from token creation',
        'real loopback result renders a named first-finding receipt',
        'finding opens from onboarding without tenant selection',
      ],
    },
  },
  {
    journey: 'J2',
    name: 'incident to cited RCA to share',
    pointer: 1,
    keyboard: 0,
    typed: 0,
    contextBreaks: 0,
    activeTime: {
      min_ms: 15_000,
      max_ms: 45_000,
      basis: 'auto-selected firing incident plus one inline likely-cause action',
    },
    outcome: {
      status: 'incomplete',
      reason: 'cited RCA is complete; stable incident share ships in X6',
    },
  },
  {
    journey: 'J3',
    name: 'explore to answer ten canonical questions',
    pointer: 20,
    keyboard: 0,
    typed: 480,
    contextBreaks: 7,
    activeTime: {
      min_ms: 10 * 60_000,
      max_ms: 20 * 60_000,
      basis: 'ten Ask submissions plus manual plane-page pivot proxy',
    },
    outcome: {
      status: 'incomplete',
      reason: 'only about three canonical questions are discoverable through one query surface',
    },
  },
  {
    journey: 'J4',
    name: 'debug a lossy ECMP path',
    pointer: 5,
    keyboard: 0,
    typed: 0,
    contextBreaks: 0,
    activeTime: {
      min_ms: 30_000,
      max_ms: 90_000,
      basis: 'above-fold branch triage, inline round diff, stable copy, and incident pivot',
    },
    outcome: {
      status: 'complete',
      evidence: [
        'lossy ECMP branch remains selected across round comparison',
        'stable link contains opaque rounds and no tenant selector',
        'incident pivot retains the X3 clock and branch evidence',
      ],
    },
  },
  {
    journey: 'J5',
    name: 'find and act on fleet health',
    pointer: 1,
    keyboard: 2,
    typed: 7,
    contextBreaks: 0,
    activeTime: {
      min_ms: 30_000,
      max_ms: 60_000,
      basis: 'command-palette navigation and Admin filtering proxy',
    },
    outcome: {
      status: 'incomplete',
      reason: 'agent rows lack a health reason, rollout state, and recommended safe action',
    },
  },
  {
    journey: 'J6',
    name: 'MSP multi-tenant operations under probectl',
    pointer: 10,
    keyboard: 0,
    typed: 32,
    contextBreaks: 0,
    activeTime: {
      min_ms: 2 * 60_000,
      max_ms: 4 * 60_000,
      basis: 'provider sign-in, fleet scan, siloed provisioning, and usage export proxy',
    },
    outcome: {
      status: 'complete',
      evidence: [
        'provider fleet table identifies unhealthy tenants',
        'tenant provisioning accepts isolation and residency',
        'usage CSV and JSONL exports are linked',
      ],
    },
  },
]

export class JourneyRecorder {
  private pointerInteractions = 0
  private keyboardInteractions = 0
  private typedCharacters = 0
  private contextBreaks = 0
  private activeTime: ActiveTimeProxy | undefined
  private outcome: JourneyOutcome | undefined

  constructor(
    private readonly journey: JourneyID,
    private readonly name: string,
  ) {}

  pointer(count = 1): this {
    this.pointerInteractions += nonNegativeInteger(count, 'pointer interaction count')
    return this
  }

  keyboard(count = 1): this {
    this.keyboardInteractions += nonNegativeInteger(count, 'keyboard interaction count')
    return this
  }

  typed(text: string): this {
    this.typedCharacters += [...text].length
    return this
  }

  typedCount(count: number): this {
    this.typedCharacters += nonNegativeInteger(count, 'typed character count')
    return this
  }

  contextBreak(count = 1): this {
    this.contextBreaks += nonNegativeInteger(count, 'context-break count')
    return this
  }

  activeTimeProxy(proxy: ActiveTimeProxy): this {
    validateActiveTime(proxy)
    this.activeTime = { ...proxy }
    return this
  }

  complete(...evidence: string[]): this {
    const clean = evidence.map((item) => item.trim()).filter(Boolean)
    if (clean.length === 0) throw new Error('a completed journey requires outcome evidence')
    this.outcome = { status: 'complete', evidence: clean }
    return this
  }

  incomplete(reason: string): this {
    const clean = reason.trim()
    if (!clean) throw new Error('an incomplete journey requires a reason')
    this.outcome = { status: 'incomplete', reason: clean }
    return this
  }

  snapshot(): JourneyMeasurement {
    if (!this.activeTime) throw new Error(`${this.journey} is missing an active-time proxy`)
    if (!this.outcome) throw new Error(`${this.journey} is missing an outcome`)
    return {
      journey: this.journey,
      name: this.name,
      pointer_interactions: this.pointerInteractions,
      keyboard_interactions: this.keyboardInteractions,
      typed_characters: this.typedCharacters,
      context_breaks: this.contextBreaks,
      active_time_proxy: { ...this.activeTime },
      outcome:
        this.outcome.status === 'complete'
          ? { status: 'complete', evidence: [...this.outcome.evidence] }
          : { ...this.outcome },
    }
  }
}

export function buildBaselineArtifact(): JourneyArtifact {
  return {
    schema_version: 1,
    measured_at: '2026-07-14T00:00:00Z',
    method: 'source-backed deterministic interaction proxy; secrets excluded from keystrokes',
    measurements: baselineFixtures.map((fixture) => {
      const recorder = new JourneyRecorder(fixture.journey, fixture.name)
        .pointer(fixture.pointer)
        .keyboard(fixture.keyboard)
        .typedCount(fixture.typed)
        .contextBreak(fixture.contextBreaks)
        .activeTimeProxy(fixture.activeTime)
      if (fixture.outcome.status === 'complete') recorder.complete(...fixture.outcome.evidence)
      else recorder.incomplete(fixture.outcome.reason)
      return recorder.snapshot()
    }),
  }
}

export function validateJourneyArtifact(artifact: JourneyArtifact): void {
  if (artifact.schema_version !== 1) throw new Error('unsupported journey artifact schema')
  if (Number.isNaN(Date.parse(artifact.measured_at))) throw new Error('invalid measured_at')
  if (!artifact.method.trim()) throw new Error('measurement method is required')
  if (artifact.measurements.length !== JOURNEY_IDS.length) {
    throw new Error(`expected ${JOURNEY_IDS.length} journey measurements`)
  }
  const seen = new Set<JourneyID>()
  for (const measurement of artifact.measurements) {
    if (seen.has(measurement.journey)) throw new Error(`duplicate ${measurement.journey}`)
    seen.add(measurement.journey)
    for (const [label, value] of [
      ['pointer interactions', measurement.pointer_interactions],
      ['keyboard interactions', measurement.keyboard_interactions],
      ['typed characters', measurement.typed_characters],
      ['context breaks', measurement.context_breaks],
    ] as const) {
      nonNegativeInteger(value, `${measurement.journey} ${label}`)
    }
    validateActiveTime(measurement.active_time_proxy)
    if (measurement.outcome.status === 'complete' && measurement.outcome.evidence.length === 0) {
      throw new Error(`${measurement.journey} complete outcome has no evidence`)
    }
    if (measurement.outcome.status === 'incomplete' && !measurement.outcome.reason.trim()) {
      throw new Error(`${measurement.journey} incomplete outcome has no reason`)
    }
  }
  for (const id of JOURNEY_IDS) {
    if (!seen.has(id)) throw new Error(`missing ${id}`)
  }
}

/** Incomplete journeys have no comparable time. A fast partial path must never
 * beat a slower complete product journey in the rubric. */
export function comparableActiveTimeMs(measurement: JourneyMeasurement): number | null {
  return measurement.outcome.status === 'complete' ? measurement.active_time_proxy.max_ms : null
}

/** The authenticated session owns tenant scope. This guard is reusable by
 * every journey fixture and rejects the common client-spoofing channels. */
export function assertRequestsUseSessionTenant(requests: MeasuredRequest[]): void {
  for (const request of requests) {
    const url = new URL(request.url, 'https://probectl.invalid')
    for (const key of url.searchParams.keys()) {
      if (key.toLowerCase() === 'tenant_id') {
        throw new Error(`${request.method ?? 'GET'} ${url.pathname} supplies tenant_id in URL`)
      }
    }
    for (const key of Object.keys(request.headers ?? {})) {
      if (['x-tenant-id', 'x-probectl-tenant'].includes(key.toLowerCase())) {
        throw new Error(`${request.method ?? 'GET'} ${url.pathname} supplies tenant in a header`)
      }
    }
    const body = parseBody(request.body)
    if (containsTenantID(body)) {
      throw new Error(`${request.method ?? 'GET'} ${url.pathname} supplies tenant_id in body`)
    }
  }
}

function parseBody(body: unknown): unknown {
  if (typeof body !== 'string') return body
  try {
    return JSON.parse(body) as unknown
  } catch {
    return body
  }
}

function containsTenantID(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsTenantID)
  if (!value || typeof value !== 'object') return false
  return Object.entries(value).some(
    ([key, child]) => key.toLowerCase() === 'tenant_id' || containsTenantID(child),
  )
}

function nonNegativeInteger(value: number, label: string): number {
  if (!Number.isInteger(value) || value < 0)
    throw new Error(`${label} must be a non-negative integer`)
  return value
}

function validateActiveTime(proxy: ActiveTimeProxy): void {
  nonNegativeInteger(proxy.min_ms, 'active-time min_ms')
  nonNegativeInteger(proxy.max_ms, 'active-time max_ms')
  if (proxy.max_ms < proxy.min_ms) throw new Error('active-time max_ms must be >= min_ms')
  if (!proxy.basis.trim()) throw new Error('active-time basis is required')
}
