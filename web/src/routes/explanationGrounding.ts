// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
  const evidence = answer.evidence ?? []
  const candidateFindings = answer.findings ?? []
  const evidenceIDs = new Map<string, number>()
  evidence.forEach((item) => evidenceIDs.set(item.id, (evidenceIDs.get(item.id) ?? 0) + 1))
  const citationsResolve = (citations: Citation[] | undefined) =>
    Boolean(citations?.length) &&
    citations!.every((citation) => evidenceIDs.get(citation.evidence_id) === 1)

  const rootCitations = answer.root_cause_citations ?? []
  const rootResolved = answer.root_cause_grounded === true && citationsResolve(rootCitations)
  const findings = candidateFindings.filter((finding) => citationsResolve(finding.citations))
  const suppressedClaims =
    (rootResolved || answer.insufficient_evidence ? 0 : 1) +
    (candidateFindings.length - findings.length)

  return { rootCitations, rootResolved, findings, suppressedClaims }
}

// Only uniquely resolved citations contribute lookup references. A target,
// title, uncited row or arbitrary source field cannot nominate a test.
export function citedTestTagReferences(answer: Answer): string[] {
  const claims = resolveClaims(answer)
  const cited = new Set(
    [
      ...(claims.rootResolved ? claims.rootCitations : []),
      ...claims.findings.flatMap((finding) => finding.citations),
    ].map((citation) => citation.evidence_id),
  )
  return Array.from(
    new Set(
      answer.evidence.flatMap((evidence) => {
        const id = evidence.fields?.test_id
        return cited.has(evidence.id) &&
          evidence.domain === 'metrics' &&
          typeof id === 'string' &&
          id.length > 0 &&
          id.length <= 128
          ? [id]
          : []
      }),
    ),
  ).sort()
}
