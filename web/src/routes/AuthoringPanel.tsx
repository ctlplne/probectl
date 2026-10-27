// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import styles from './authoring.module.css'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  useToast,
} from '../components'
import {
  specToInput,
  useAuthorTest,
  useDiscover,
  type TestProposal,
  type TestSpec,
} from '../api/authoring'
import { useCreateTest } from '../api/tests'
import { useAuth } from '../auth/useAuth'
import { CodeExportPanel } from './CodeExportPanel'
import { testAsCode } from './codeExport'

function SpecSummary({ spec }: { spec: TestSpec }) {
  return (
    <dl className={styles.spec}>
      <div>
        <dt>Name</dt>
        <dd>{spec.name}</dd>
      </div>
      <div>
        <dt>Type</dt>
        <dd>
          <Badge tone="neutral">{spec.type}</Badge>
        </dd>
      </div>
      <div>
        <dt>Target</dt>
        <dd>
          <code>{spec.target || '—'}</code>
        </dd>
      </div>
      <div>
        <dt>Interval</dt>
        <dd>{spec.interval_seconds}s</dd>
      </div>
    </dl>
  )
}

/** Each proposal needs its own explicit consent; model output is not consent. */
function ApplyProposal({
  spec,
  onApply,
  creating,
  canCreate,
  label,
}: {
  spec: TestSpec
  onApply: (s: TestSpec) => void
  creating: boolean
  canCreate: boolean
  label: string
}) {
  const { permissions } = useAuth()
  const canAllowPrivate = permissions.includes('test.allow_private')
  const [allowPrivate, setAllowPrivate] = useState(false)
  function apply() {
    const params = { ...spec.params }
    delete params.allow_private_targets
    if (canAllowPrivate && allowPrivate) params.allow_private_targets = 'true'
    onApply({ ...spec, params })
  }
  return (
    <div>
      {canAllowPrivate ? (
        <label className={styles.privateConsent}>
          <input
            type="checkbox"
            checked={allowPrivate}
            onChange={(e) => setAllowPrivate(e.target.checked)}
            disabled={creating || !canCreate}
          />
          <span>Allow private or loopback targets for {spec.target}</span>
        </label>
      ) : null}
      <p className={styles.permissionHint}>
        Private targets require test.allow_private permission and explicit consent here. The agent
        must also enable test_sync.allow_private_targets.
      </p>
      <Button
        variant="secondary"
        onClick={apply}
        disabled={creating || !canCreate}
        title={!canCreate ? 'Requires test.write permission' : undefined}
      >
        {label}
      </Button>
    </div>
  )
}

function ProposalCard({
  proposal,
  onApply,
  onDismiss,
  creating,
  canCreate,
}: {
  proposal: TestProposal
  onApply: (s: TestSpec) => void
  onDismiss: () => void
  creating: boolean
  canCreate: boolean
}) {
  return (
    <div className={styles.proposal}>
      <SpecSummary spec={proposal.spec} />
      {proposal.rationale ? <p className={styles.rationale}>{proposal.rationale}</p> : null}
      <p className={styles.provenance}>Proposed by {proposal.source} — review before creating.</p>
      <CodeExportPanel title="View as YAML" code={testAsCode(proposal.spec)} />
      <div className={styles.actions}>
        <ApplyProposal
          key={JSON.stringify(proposal.spec)}
          spec={proposal.spec}
          onApply={onApply}
          creating={creating}
          canCreate={canCreate}
          label="Create test"
        />
        <Button variant="ghost" onClick={onDismiss}>
          Dismiss
        </Button>
      </div>
    </div>
  )
}

/** AuthoringPanel is the S26 review-and-apply surface on the Targets page: author
 *  a test from natural language, or add a suggested target. Nothing is created
 *  until the user confirms. */
export function AuthoringPanel() {
  const { permissions } = useAuth()
  const canAuthor = permissions.includes('ai.query')
  const canCreate = permissions.includes('test.write')
  const [prompt, setPrompt] = useState('')
  const author = useAuthorTest()
  const discover = useDiscover(canAuthor)
  const create = useCreateTest()
  const { push } = useToast()

  function propose(e: FormEvent) {
    e.preventDefault()
    if (!canAuthor) return
    const p = prompt.trim()
    if (p) author.mutate(p)
  }

  function apply(spec: TestSpec, label: string) {
    if (!canCreate) return
    create.mutate(specToInput(spec), {
      onSuccess: () => {
        push({ tone: 'success', title: 'Test created', message: label })
        author.reset()
      },
      onError: (err) => push({ tone: 'danger', title: 'Create failed', message: err.message }),
    })
  }

  return (
    <Card data-targets-authoring>
      <CardHeader
        title="Author with AI"
        description="Describe what to monitor, or add a suggested target. Nothing is created until you confirm."
      />
      <CardBody>
        {!canAuthor ? (
          <EmptyState
            title="Read-only access"
            description="AI authoring and telemetry suggestions require ai.query permission. Creating a proposed test also requires test.write permission."
          />
        ) : (
          <>
            <form className={styles.askForm} onSubmit={propose}>
              <Field
                label="Describe a test"
                placeholder="e.g. check Salesforce login from every branch"
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
              />
              <Button type="submit" disabled={author.isPending || prompt.trim() === ''}>
                {author.isPending ? 'Proposing…' : 'Propose a test'}
              </Button>
            </form>

            {author.isError ? (
              <ErrorState description={author.error?.message ?? 'Could not author a test.'} />
            ) : author.data ? (
              <ProposalCard
                proposal={author.data}
                onApply={(s) => apply(s, s.name)}
                onDismiss={() => author.reset()}
                creating={create.isPending}
                canCreate={canCreate}
              />
            ) : null}

            <div className={styles.suggestions}>
              <p className={styles.suggestionsLabel}>Suggested to monitor</p>
              {discover.isPending ? (
                <LoadingState label="Finding targets…" />
              ) : discover.isError ? (
                <ErrorState description="Could not load suggestions." />
              ) : !discover.data || discover.data.length === 0 ? (
                <EmptyState
                  title="No suggestions yet"
                  description="probectl proposes targets seen in your telemetry that aren't monitored."
                />
              ) : (
                <ul className={styles.suggestionList} aria-label="Suggested targets">
                  {discover.data.map((d) => (
                    <li key={JSON.stringify(d.spec)} className={styles.suggestion}>
                      <div className={styles.suggestionBody}>
                        <Badge tone="accent">{d.spec.type}</Badge>
                        <code className={styles.suggestionTarget}>{d.spec.target}</code>
                        <span className={styles.suggestionWhy}>{d.rationale}</span>
                      </div>
                      <ApplyProposal
                        spec={d.spec}
                        onApply={(s) => apply(s, s.target)}
                        creating={create.isPending}
                        canCreate={canCreate}
                        label="Add"
                      />
                    </li>
                  ))}
                </ul>
              )}
            </div>
            {!canCreate ? (
              <p className={styles.permissionHint} role="status">
                Creating a proposed test requires test.write permission.
              </p>
            ) : null}
          </>
        )}
      </CardBody>
    </Card>
  )
}
