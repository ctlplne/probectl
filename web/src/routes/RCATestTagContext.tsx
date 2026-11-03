// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { Answer } from '../api/ai'
import { useAuth } from '../auth/useAuth'
import { resolveClaims } from './explanationGrounding'
import { CurrentTestTagContext } from './TestResultTagContext'

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

export function RCATestTagContext({ answer }: { answer: Answer }) {
  const { tenant } = useAuth()
  if (answer.tenant !== tenant.id) return null
  return <CurrentTestTagContext ids={citedTestTagReferences(answer)} answerID={answer.id} />
}
