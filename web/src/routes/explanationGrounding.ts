import type { Answer, Citation, Finding } from '../api/ai'

export interface ResolvedClaims {
  rootCitations: Citation[]
  rootResolved: boolean
  findings: Finding[]
  suppressedClaims: number
}

/**
 * Treat the API's citation receipt as untrusted display input too. A causal
 * sentence is renderable only when every citation resolves to evidence in this
 * exact answer. This mirrors the server gate and keeps a stale proxy, malformed
 * fixture, or future client bug from turning an unresolved claim into prose.
 */
export function resolveClaims(answer: Answer): ResolvedClaims {
  const evidenceIDs = new Set(answer.evidence.map((item) => item.id))
  const citationsResolve = (citations: Citation[] | undefined) =>
    Boolean(citations?.length) &&
    citations!.every((citation) => evidenceIDs.has(citation.evidence_id))

  const rootCitations = answer.root_cause_citations ?? []
  const rootResolved = answer.root_cause_grounded === true && citationsResolve(rootCitations)
  const findings = answer.findings.filter((finding) => citationsResolve(finding.citations))
  const suppressedClaims =
    (rootResolved || answer.insufficient_evidence ? 0 : 1) +
    (answer.findings.length - findings.length)

  return { rootCitations, rootResolved, findings, suppressedClaims }
}
