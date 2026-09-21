// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { Answer, Citation, Evidence, Finding, InvestigationStep } from '../api/ai'
import { resolveClaims } from '../routes/explanationGrounding'

export const HANDOFF_CONTRACT_VERSION = 'probectl-ai-handoff/v1'

type HandoffLocale = 'en' | 'es' | 'ar'

interface HandoffCopy {
  title: string
  pointInTime: string
  receipt: string
  contract: string
  answerID: string
  tenant: string
  question: string
  confidence: string
  insufficient: string
  degraded: string
  yes: string
  no: string
  model: string
  reasoningAdapter: string
  reasoningExecution: string
  egressConsent: string
  attemptedAdapter: string
  suppressedClaims: string
  rootCause: string
  rootWithheld: string
  citations: string
  findings: string
  noFindings: string
  plan: string
  noPlan: string
  status: string
  domain: string
  goal: string
  summary: string
  limit: string
  readOnly: string
  reason: string
  evidenceCount: string
  truncated: string
  selector: string
  node: string
  window: string
  evidence: string
  otherPlane: string
  occurrence: string
  source: string
  citedBy: string
  notRecorded: string
  rootCauseReference: string
  findingReference: string
  fields: string
  limitations: string
  nonAuthoritativeLimit: string
  direction: 'ltr' | 'rtl'
}

const copy: Record<HandoffLocale, HandoffCopy> = {
  en: {
    title: 'probectl Ask investigation handoff',
    pointInTime:
      'Point-in-time, non-authoritative investigation note. This file is a local copy of one tenant- and RBAC-scoped answer. Evidence can age, permissions can change, and source records may be retained or deleted. Re-open probectl and re-authorize every cited source before making a decision.',
    receipt: 'Receipt',
    contract: 'Contract',
    answerID: 'Answer ID',
    tenant: 'Tenant',
    question: 'Question',
    confidence: 'Confidence',
    insufficient: 'Insufficient evidence',
    degraded: 'Degraded fallback',
    yes: 'yes',
    no: 'no',
    model: 'Model',
    reasoningAdapter: 'Reasoning adapter',
    reasoningExecution: 'Reasoning execution',
    egressConsent: 'Egress consent',
    attemptedAdapter: 'Attempted adapter',
    suppressedClaims: 'Suppressed causal claims',
    rootCause: 'Grounded root cause',
    rootWithheld:
      'Not exported: the root-cause claim was insufficient or its citations did not resolve in this exact answer.',
    citations: 'Citations',
    findings: 'Grounded findings',
    noFindings: 'No grounded findings were available in this exact answer.',
    plan: 'Read-only investigation plan',
    noPlan: 'No investigation steps were recorded.',
    status: 'Status',
    domain: 'Domain',
    goal: 'Goal',
    summary: 'Summary',
    limit: 'Limit',
    readOnly: 'Read-only',
    reason: 'Reason',
    evidenceCount: 'Evidence count',
    truncated: 'Truncated',
    selector: 'Selector',
    node: 'Node',
    window: 'Window',
    evidence: 'Evidence by plane',
    otherPlane: 'other',
    occurrence: 'Occurred at',
    source: 'Source',
    citedBy: 'Cited by',
    notRecorded: 'not recorded',
    rootCauseReference: 'root cause',
    findingReference: 'finding {number}',
    fields: 'Fields',
    limitations: 'Limitations',
    nonAuthoritativeLimit:
      'This handoff is evidence, not live authoritative state, remediation approval, or permission to act. Validate current telemetry, authorization, and operating context in probectl.',
    direction: 'ltr',
  },
  es: {
    title: 'Entrega de investigación de Ask de probectl',
    pointInTime:
      'Nota de investigación puntual y no autoritativa. Este archivo es una copia local de una respuesta limitada por tenant y RBAC. La evidencia puede envejecer, los permisos pueden cambiar y los registros de origen pueden conservarse o eliminarse. Vuelve a abrir probectl y autoriza de nuevo cada fuente citada antes de tomar una decisión.',
    receipt: 'Recibo',
    contract: 'Contrato',
    answerID: 'ID de respuesta',
    tenant: 'Tenant',
    question: 'Pregunta',
    confidence: 'Confianza',
    insufficient: 'Evidencia insuficiente',
    degraded: 'Ruta de respaldo degradada',
    yes: 'sí',
    no: 'no',
    model: 'Modelo',
    reasoningAdapter: 'Adaptador de razonamiento',
    reasoningExecution: 'Ejecución del razonamiento',
    egressConsent: 'Consentimiento de salida',
    attemptedAdapter: 'Adaptador intentado',
    suppressedClaims: 'Afirmaciones causales suprimidas',
    rootCause: 'Causa raíz fundamentada',
    rootWithheld:
      'No se exportó: la afirmación de causa raíz era insuficiente o sus citas no se resolvieron en esta respuesta exacta.',
    citations: 'Citas',
    findings: 'Hallazgos fundamentados',
    noFindings: 'No había hallazgos fundamentados en esta respuesta exacta.',
    plan: 'Plan de investigación de solo lectura',
    noPlan: 'No se registraron pasos de investigación.',
    status: 'Estado',
    domain: 'Dominio',
    goal: 'Objetivo',
    summary: 'Resumen',
    limit: 'Límite',
    readOnly: 'Solo lectura',
    reason: 'Motivo',
    evidenceCount: 'Cantidad de evidencias',
    truncated: 'Truncado',
    selector: 'Selector',
    node: 'Nodo',
    window: 'Ventana',
    evidence: 'Evidencia por plano',
    otherPlane: 'otro',
    occurrence: 'Ocurrió en',
    source: 'Fuente',
    citedBy: 'Citado por',
    notRecorded: 'no registrado',
    rootCauseReference: 'causa raíz',
    findingReference: 'hallazgo {number}',
    fields: 'Campos',
    limitations: 'Limitaciones',
    nonAuthoritativeLimit:
      'Esta entrega es evidencia, no estado autoritativo en vivo, aprobación de remediación ni permiso para actuar. Valida la telemetría, la autorización y el contexto operativo actuales en probectl.',
    direction: 'ltr',
  },
  ar: {
    title: 'تسليم تحقيق Ask من probectl',
    pointInTime:
      'ملاحظة تحقيق آنية وغير مرجعية. هذا الملف نسخة محلية من إجابة واحدة مقيّدة بالمستأجر وصلاحيات RBAC. قد تتقادم الأدلة، وقد تتغير الصلاحيات، وقد تُحفظ سجلات المصدر أو تُحذف. أعد فتح probectl وأعد التحقق من صلاحية كل مصدر مستشهد به قبل اتخاذ قرار.',
    receipt: 'الإيصال',
    contract: 'العقد',
    answerID: 'معرّف الإجابة',
    tenant: 'المستأجر',
    question: 'السؤال',
    confidence: 'الثقة',
    insufficient: 'الأدلة غير كافية',
    degraded: 'مسار احتياطي متدهور',
    yes: 'نعم',
    no: 'لا',
    model: 'النموذج',
    reasoningAdapter: 'مهايئ الاستدلال',
    reasoningExecution: 'تنفيذ الاستدلال',
    egressConsent: 'موافقة خروج البيانات',
    attemptedAdapter: 'المهايئ الذي تمت محاولته',
    suppressedClaims: 'الادعاءات السببية المحجوبة',
    rootCause: 'السبب الجذري الموثق',
    rootWithheld:
      'لم يُصدّر: ادعاء السبب الجذري غير كاف أو لم تُحل استشهاداته ضمن هذه الإجابة نفسها.',
    citations: 'الاستشهادات',
    findings: 'النتائج الموثقة',
    noFindings: 'لا توجد نتائج موثقة ضمن هذه الإجابة نفسها.',
    plan: 'خطة التحقيق للقراءة فقط',
    noPlan: 'لم تُسجّل خطوات تحقيق.',
    status: 'الحالة',
    domain: 'النطاق',
    goal: 'الهدف',
    summary: 'الملخص',
    limit: 'الحد',
    readOnly: 'للقراءة فقط',
    reason: 'السبب',
    evidenceCount: 'عدد الأدلة',
    truncated: 'مقتطع',
    selector: 'المحدِّد',
    node: 'العقدة',
    window: 'النافذة الزمنية',
    evidence: 'الأدلة حسب المستوى',
    otherPlane: 'أخرى',
    occurrence: 'وقت الحدوث',
    source: 'المصدر',
    citedBy: 'مستشهد به في',
    notRecorded: 'غير مسجّل',
    rootCauseReference: 'السبب الجذري',
    findingReference: 'النتيجة {number}',
    fields: 'الحقول',
    limitations: 'القيود',
    nonAuthoritativeLimit:
      'هذا التسليم دليل، وليس حالة مرجعية مباشرة أو موافقة على معالجة أو إذنا بالتصرف. تحقّق من القياسات والصلاحيات والسياق التشغيلي الحالي في probectl.',
    direction: 'rtl',
  },
}

interface ResolvedHandoffClaims {
  rootCitations: Citation[]
  rootResolved: boolean
  findings: Finding[]
  suppressedCount: number
}

interface OrderedEvidence {
  evidence: Evidence
  anchor: number
}

/**
 * renderHandoff is a pure, local display transform over the already-authorized
 * Ask response. It never queries, persists, or sends anything. Citation
 * integrity is re-applied so unresolved causal prose cannot enter the file.
 */
export function renderHandoff(answer: Answer, requestedLocale: string): string {
  const locale = normalizeLocale(requestedLocale)
  const text = copy[locale]
  const claims = resolveHandoffClaims(answer)
  const { ordered, anchors } = orderEvidence(answer.evidence, text.otherPlane)
  const citedBy = handoffBacklinks(claims)
  const number = (value: number) => localizedNumber(locale, value)
  const lines: string[] = []

  lines.push(
    `<!-- ${HANDOFF_CONTRACT_VERSION}; lang=${locale}; dir=${text.direction} -->`,
    `# ${text.title}`,
    '',
    `> **${markdownText(text.pointInTime)}**`,
    '',
    `## ${text.receipt}`,
    '',
  )
  bullet(lines, text.contract, codeSpan(HANDOFF_CONTRACT_VERSION))
  bullet(lines, text.answerID, codeSpan(answer.id))
  bullet(lines, text.tenant, codeSpan(answer.tenant))
  bullet(lines, text.question, markdownText(answer.question))
  bullet(lines, text.confidence, codeSpan(answer.confidence))
  bullet(lines, text.insufficient, boolLabel(text, answer.insufficient_evidence))
  bullet(lines, text.degraded, boolLabel(text, Boolean(answer.degraded)))
  bullet(lines, text.model, codeSpan(answer.model))
  bullet(lines, text.reasoningAdapter, codeSpan(answer.reasoning.adapter))
  bullet(lines, text.reasoningExecution, codeSpan(answer.reasoning.execution))
  bullet(lines, text.egressConsent, codeSpan(answer.reasoning.egress_consent))
  if (answer.reasoning.attempted_adapter) {
    bullet(lines, text.attemptedAdapter, codeSpan(answer.reasoning.attempted_adapter))
  }
  bullet(lines, text.suppressedClaims, number(claims.suppressedCount))

  lines.push('', `## ${text.rootCause}`, '')
  if (claims.rootResolved) {
    lines.push(`> ${markdownText(answer.root_cause)}`, '')
    bullet(lines, text.citations, renderCitations(claims.rootCitations, anchors))
  } else {
    lines.push(`> ${markdownText(text.rootWithheld)}`)
  }

  lines.push('', `## ${text.findings}`, '')
  if (claims.findings.length === 0) {
    lines.push(markdownText(text.noFindings))
  } else {
    claims.findings.forEach((finding, index) => {
      lines.push(`${number(index + 1)}. ${markdownText(finding.statement)}`)
      nestedBullet(lines, text.citations, renderCitations(finding.citations, anchors))
    })
  }

  lines.push('', `## ${text.plan}`, '')
  const plan = [...(answer.investigation_plan ?? [])].sort(comparePlan)
  if (plan.length === 0) {
    lines.push(markdownText(text.noPlan))
  } else {
    for (const step of plan) {
      lines.push(`${number(step.step)}. ${markdownText(step.goal)}`)
      nestedBullet(lines, text.domain, codeSpan(step.domain))
      nestedBullet(lines, text.status, codeSpan(step.status))
      nestedBullet(lines, text.readOnly, boolLabel(text, step.read_only))
      nestedBullet(lines, text.limit, number(step.limit))
      nestedBullet(lines, text.evidenceCount, number(step.evidence_count ?? 0))
      nestedBullet(lines, text.truncated, boolLabel(text, Boolean(step.truncated)))
      if (step.reason) nestedBullet(lines, text.reason, markdownText(step.reason))
      if (step.selector && Object.keys(step.selector).length > 0) {
        nestedBullet(lines, text.selector, codeSpan(stableJSON(step.selector)))
      }
      if (step.node_id) nestedBullet(lines, text.node, codeSpan(step.node_id))
      if (step.window_start || step.window_end) {
        const window = `${formatTime(step.window_start)} — ${formatTime(step.window_end)}`
        nestedBullet(lines, text.window, codeSpan(window))
      }
    }
  }

  lines.push('', `## ${text.evidence}`)
  if (ordered.length === 0) {
    lines.push('', markdownText(text.notRecorded))
  } else {
    let currentPlane = ''
    for (const item of ordered) {
      const evidence = item.evidence
      const plane = evidencePlane(evidence, text.otherPlane)
      if (plane !== currentPlane) {
        lines.push('', `### ${markdownText(plane)}`)
        currentPlane = plane
      }
      const title = evidence.title || evidence.ref || evidence.id
      lines.push(
        '',
        `<a id="evidence-${item.anchor}"></a>`,
        `#### ${markdownText(evidence.id)} — ${markdownText(title)}`,
        '',
      )
      bullet(lines, text.domain, codeSpan(evidence.domain))
      if (evidence.severity) bullet(lines, text.status, codeSpan(evidence.severity))
      bullet(
        lines,
        text.occurrence,
        evidence.occurred_at ? codeSpan(formatTime(evidence.occurred_at)) : text.notRecorded,
      )
      bullet(lines, text.source, evidence.ref ? codeSpan(evidence.ref) : text.notRecorded)
      if (evidence.summary) bullet(lines, text.summary, markdownText(evidence.summary))
      const relations = citedBy.get(evidence.id) ?? []
      if (relations.length === 0) {
        bullet(lines, text.citedBy, text.notRecorded)
      } else {
        bullet(
          lines,
          text.citedBy,
          relations
            .map((relation) =>
              relation === 0
                ? text.rootCauseReference
                : text.findingReference.replace('{number}', number(relation)),
            )
            .join(', '),
        )
      }
      if (evidence.fields && Object.keys(evidence.fields).length > 0) {
        bullet(lines, text.fields, codeSpan(stableJSON(evidence.fields)))
      }
    }
  }

  lines.push('', `## ${text.limitations}`, '', `> **${markdownText(text.nonAuthoritativeLimit)}**`)
  return `${lines.join('\n')}\n`
}

/** A conservative ASCII filename avoids path separators and platform quirks. */
export function handoffFilename(answerID: string): string {
  const safe =
    answerID
      .normalize('NFKD')
      .replace(/[^A-Za-z0-9._-]+/g, '-')
      .replace(/^[._-]+|[._-]+$/g, '')
      .slice(0, 80) || 'answer'
  return `probectl-ask-handoff-${safe}.md`
}

/** Starts one browser-native local download. It creates no durable browser state. */
export function downloadHandoff(answer: Answer, locale: string): void {
  const blob = new Blob([renderHandoff(answer, locale)], {
    type: 'text/markdown;charset=utf-8',
  })
  const href = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = href
  anchor.download = handoffFilename(answer.id)
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(href)
}

function normalizeLocale(locale: string): HandoffLocale {
  const normalized = locale.trim().toLowerCase().split(/[-_.]/, 1)[0]
  return normalized === 'es' || normalized === 'ar' ? normalized : 'en'
}

function resolveHandoffClaims(answer: Answer): ResolvedHandoffClaims {
  const resolved = resolveClaims(answer)
  return {
    rootCitations: resolved.rootCitations,
    rootResolved: resolved.rootResolved,
    findings: resolved.findings,
    suppressedCount: resolved.suppressedClaims,
  }
}

function orderEvidence(
  evidence: Evidence[],
  otherPlane: string,
): { ordered: OrderedEvidence[]; anchors: Map<string, number> } {
  const sorted = [...evidence].sort((left, right) => {
    const planeOrder = compareCanonicalText(
      evidencePlane(left, otherPlane),
      evidencePlane(right, otherPlane),
    )
    if (planeOrder !== 0) return planeOrder
    const timeOrder = compareCanonicalText(
      formatTime(right.occurred_at),
      formatTime(left.occurred_at),
    )
    if (timeOrder !== 0) return timeOrder
    const idOrder = compareCanonicalText(left.id, right.id)
    if (idOrder !== 0) return idOrder
    return compareCanonicalText(left.title ?? '', right.title ?? '')
  })
  const anchors = new Map<string, number>()
  const ordered = sorted.map((item, index) => {
    const anchor = index + 1
    if (!anchors.has(item.id)) anchors.set(item.id, anchor)
    return { evidence: item, anchor }
  })
  return { ordered, anchors }
}

function evidencePlane(evidence: Evidence, otherPlane: string): string {
  return evidence.plane || evidence.domain || otherPlane
}

function handoffBacklinks(claims: ResolvedHandoffClaims): Map<string, number[]> {
  const backlinks = new Map<string, number[]>()
  const append = (evidenceID: string, relation: number) => {
    const existing = backlinks.get(evidenceID) ?? []
    if (!existing.includes(relation)) backlinks.set(evidenceID, [...existing, relation])
  }
  if (claims.rootResolved) {
    claims.rootCitations.forEach((citation) => append(citation.evidence_id, 0))
  }
  claims.findings.forEach((finding, index) => {
    finding.citations.forEach((citation) => append(citation.evidence_id, index + 1))
  })
  return backlinks
}

function renderCitations(citations: Citation[], anchors: Map<string, number>): string {
  return citations
    .flatMap((citation) => {
      const anchor = anchors.get(citation.evidence_id)
      return anchor ? [`[${markdownText(citation.evidence_id)}](#evidence-${anchor})`] : []
    })
    .join(', ')
}

function comparePlan(left: InvestigationStep, right: InvestigationStep): number {
  return (
    left.step - right.step ||
    compareCanonicalText(left.domain, right.domain) ||
    compareCanonicalText(left.goal, right.goal)
  )
}

function bullet(lines: string[], label: string, value: string): void {
  lines.push(`- **${label}:** ${value}`)
}

function nestedBullet(lines: string[], label: string, value: string): void {
  lines.push(`   - **${label}:** ${value}`)
}

function boolLabel(text: HandoffCopy, value: boolean): string {
  return value ? text.yes : text.no
}

function formatTime(value?: string): string {
  if (!value) return ''
  const parsed = new Date(value)
  if (Number.isNaN(parsed.valueOf())) return value
  return parsed.toISOString().replace(/\.000Z$/, 'Z')
}

function localizedNumber(locale: HandoffLocale, value: number): string {
  const raw = String(value)
  if (locale !== 'ar') return raw
  const digits: Record<string, string> = {
    '0': '٠',
    '1': '١',
    '2': '٢',
    '3': '٣',
    '4': '٤',
    '5': '٥',
    '6': '٦',
    '7': '٧',
    '8': '٨',
    '9': '٩',
  }
  return raw.replace(/[0-9]/g, (digit) => digits[digit] ?? digit)
}

/**
 * Locale collation is deliberately forbidden in the portable artifact: its
 * answer depends on the browser/OS locale and does not match Go string order.
 * Comparing Unicode scalar values matches lexical valid-UTF-8 order in Go.
 */
function compareCanonicalText(left: string, right: string): number {
  const leftScalars = Array.from(left)
  const rightScalars = Array.from(right)
  const length = Math.min(leftScalars.length, rightScalars.length)
  for (let index = 0; index < length; index += 1) {
    const delta = leftScalars[index].codePointAt(0)! - rightScalars[index].codePointAt(0)!
    if (delta !== 0) return delta
  }
  return leftScalars.length - rightScalars.length
}

function canonicalJSONString(value: unknown): string {
  const encoded = JSON.stringify(value) ?? 'null'
  // encoding/json always protects the two JavaScript line-separator scalars,
  // even with HTML escaping disabled. Normalize JSON.stringify to that rule.
  return encoded.replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029')
}

function stableJSON(value: unknown): string {
  if (value === null || typeof value !== 'object') return canonicalJSONString(value)
  if (Array.isArray(value)) return `[${value.map(stableJSON).join(',')}]`
  return `{${Object.keys(value as Record<string, unknown>)
    .sort(compareCanonicalText)
    .map(
      (key) => `${canonicalJSONString(key)}:${stableJSON((value as Record<string, unknown>)[key])}`,
    )
    .join(',')}}`
}

function markdownText(value: string): string {
  return value
    .replace(/\r\n?/g, '\n')
    .replace(/&/g, '&amp;')
    .replace(/[\\`*_[\]{}()<>#+\-.!|~]/g, '\\$&')
    .replace(/\n/g, '  \n')
}

function codeSpan(value: string): string {
  const content = value.replace(/\r\n?/g, '\n').replace(/\n/g, ' ')
  const maxRun = Math.max(0, ...[...content.matchAll(/`+/g)].map((match) => match[0].length))
  const fence = '`'.repeat(maxRun + 1)
  return `${fence} ${content} ${fence}`
}
