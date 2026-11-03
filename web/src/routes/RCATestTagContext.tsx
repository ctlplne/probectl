// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { Answer } from '../api/ai'
import { useAuth } from '../auth/useAuth'
import { citedTestTagReferences } from './explanationGrounding'
import { CurrentTestTagContext } from './TestResultTagContext'

export function RCATestTagContext({ answer }: { answer: Answer }) {
  const { tenant } = useAuth()
  if (answer.tenant !== tenant.id) return null
  return <CurrentTestTagContext ids={citedTestTagReferences(answer)} answerID={answer.id} />
}
