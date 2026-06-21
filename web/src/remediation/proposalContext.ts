import type { Answer, Evidence } from '../api/ai'
import type { Incident, Signal } from '../api/incidents'
import type { CreateProposalInput } from '../api/remediation'

export interface ProposalContext {
  incidentID?: string
  target?: string
}

const REVIEW_ONLY =
  'This is an advisory proposal for human review only. probectl must not execute changes, block traffic, or bypass the operator change process.'

function compact(text: string | undefined, max = 120): string {
  const oneLine = (text ?? '').replace(/\s+/g, ' ').trim()
  if (oneLine.length <= max) return oneLine
  return `${oneLine.slice(0, max - 3).trimEnd()}...`
}

export function incidentTarget(incident: Incident): string {
  return incident.target || incident.prefix || incident.id
}

export function questionForIncident(incident: Incident): string {
  const label = incident.title || incidentTarget(incident)
  return `What caused incident ${incident.id}: ${label}?`
}

function signalSummary(s: Signal): string {
  const target = s.target || s.prefix ? ` target ${s.target || s.prefix}` : ''
  const summary = s.summary ? ` - ${s.summary}` : ''
  return `${s.plane}/${s.kind} ${s.severity}: ${s.title}${target}${summary}`
}

export function proposalFromIncident(incident: Incident): CreateProposalInput {
  const target = incidentTarget(incident)
  const signals =
    incident.signals && incident.signals.length > 0
      ? incident.signals.slice(0, 5).map(signalSummary).join(' | ')
      : `${incident.signal_count} correlated signal(s) recorded.`

  return {
    kind: 'open_ticket',
    title: `Review incident: ${compact(incident.title || target, 88)}`,
    target,
    incident_id: incident.id,
    rationale: [
      `Incident ${incident.id} is ${incident.status} with ${incident.severity} severity for ${target}.`,
      `Started ${incident.started_at}; last activity ${incident.last_seen_at}.`,
      `Evidence: ${signals}`,
      REVIEW_ONLY,
    ].join(' '),
  }
}

function incidentIDFromEvidence(evidence: Evidence[]): string | undefined {
  for (const e of evidence) {
    const field = e.fields?.incident_id
    if (typeof field === 'string' && field.trim()) return field.trim()
    if (e.ref?.startsWith('incident:')) return e.ref.slice('incident:'.length).trim() || undefined
  }
  return undefined
}

function targetFromEvidence(evidence: Evidence[]): string | undefined {
  for (const e of evidence) {
    const target = e.fields?.target
    if (typeof target === 'string' && target.trim()) return target.trim()
  }
  const first = evidence.find((e) => e.title || e.ref)
  return first ? compact(first.title || first.ref, 120) : undefined
}

function findingSummary(answer: Answer): string {
  return answer.findings
    .slice(0, 5)
    .map((f, i) => {
      const cites = f.citations.map((c) => c.evidence_id).join(', ')
      return `Finding ${i + 1}: ${compact(f.statement, 160)}${cites ? ` (cites ${cites})` : ''}`
    })
    .join(' | ')
}

function evidenceSummary(answer: Answer): string {
  return answer.evidence
    .slice(0, 5)
    .map((e) => {
      const plane = e.plane || e.domain || 'other'
      const sev = e.severity ? ` ${e.severity}` : ''
      const title = compact(e.title || e.ref || e.id, 140)
      const summary = e.summary ? ` - ${compact(e.summary, 160)}` : ''
      return `${e.id} ${plane}${sev}: ${title}${summary}`
    })
    .join(' | ')
}

export function proposalFromAnswer(answer: Answer, context: ProposalContext = {}): CreateProposalInput {
  const incidentID = context.incidentID || incidentIDFromEvidence(answer.evidence)
  const target = context.target || targetFromEvidence(answer.evidence)

  return {
    kind: 'open_ticket',
    title: `Review RCA: ${compact(answer.root_cause || answer.question, 86)}`,
    ...(target ? { target } : {}),
    ...(incidentID ? { incident_id: incidentID } : {}),
    rationale: [
      `Question: ${answer.question}`,
      `Root cause (${answer.confidence} confidence): ${answer.root_cause}`,
      answer.insufficient_evidence ? 'The assistant marked the evidence insufficient.' : '',
      answer.findings.length > 0 ? `Findings: ${findingSummary(answer)}` : '',
      answer.evidence.length > 0 ? `Evidence: ${evidenceSummary(answer)}` : '',
      REVIEW_ONLY,
    ]
      .filter(Boolean)
      .join(' '),
  }
}
