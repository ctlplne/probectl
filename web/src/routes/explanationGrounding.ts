// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
