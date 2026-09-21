// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, test } from 'vitest'
import type { Answer } from '../api/ai'
import { handoffFilename, renderHandoff } from '../ai/handoff'

const fixtureDir = resolve(process.cwd(), '../test/fixtures/ai-handoff')
const answer = JSON.parse(readFileSync(resolve(fixtureDir, 'answer.json'), 'utf8')) as Answer
const adversarialAnswer = JSON.parse(
  readFileSync(resolve(fixtureDir, 'answer.adversarial.json'), 'utf8'),
) as Answer

describe('Ask investigation handoff contract', () => {
  test.each(['en', 'es', 'ar'])(
    'TypeScript renderer matches the shared %s Go/Markdown golden',
    (locale) => {
      const want = readFileSync(resolve(fixtureDir, `handoff.${locale}.md`), 'utf8')
      expect(renderHandoff(answer, locale)).toBe(want)
    },
  )

  test('matches the shared adversarial Unicode and JSON canonical golden', () => {
    const want = readFileSync(resolve(fixtureDir, 'handoff.adversarial.en.md'), 'utf8')
    expect(renderHandoff(adversarialAnswer, 'en')).toBe(want)
  })

  test('fails closed for insufficient and ambiguous causal claims', () => {
    const insufficient: Answer = {
      ...answer,
      root_cause: 'unresolved root must not leave the browser',
      root_cause_citations: [{ evidence_id: 'duplicate' }],
      root_cause_grounded: true,
      insufficient_evidence: true,
      degraded: false,
      findings: [
        {
          statement: 'ambiguous finding must not leave the browser',
          citations: [{ evidence_id: 'duplicate' }],
        },
      ],
      evidence: [
        { id: 'duplicate', domain: 'entities', title: 'one' },
        { id: 'duplicate', domain: 'entities', title: 'two' },
      ],
    }

    const got = renderHandoff(insufficient, 'en')
    expect(got).toContain('**Insufficient evidence:** yes')
    expect(got).toContain('Not exported:')
    expect(got).not.toContain(insufficient.root_cause)
    expect(got).not.toContain(insufficient.findings[0].statement)
    expect(got).not.toContain('[duplicate](#evidence-')
  })

  test('normalizes Arabic locale, marks RTL, and escapes untrusted Markdown', () => {
    const malicious: Answer = {
      ...answer,
      id: 'ans<script>',
      question: '# injected heading\n> injected quote',
      root_cause_grounded: false,
      root_cause_citations: [],
      insufficient_evidence: true,
      findings: [],
      evidence: [],
    }
    const got = renderHandoff(malicious, 'ar-EG')

    expect(got).toContain('lang=ar; dir=rtl')
    expect(got).toContain('\\# injected heading')
    expect(got).toContain('\\> injected quote')
    expect(got).toContain('` ans<script> `')
  })

  test('builds a bounded cross-platform-safe filename', () => {
    expect(handoffFilename('../../incident #42/')).toBe('probectl-ask-handoff-incident-42.md')
    expect(handoffFilename('***')).toBe('probectl-ask-handoff-answer.md')
    expect(handoffFilename('a'.repeat(100))).toBe(`probectl-ask-handoff-${'a'.repeat(80)}.md`)
  })
})
