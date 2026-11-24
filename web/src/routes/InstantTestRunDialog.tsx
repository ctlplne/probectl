// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useState } from 'react'
import { flattenAgents, useAgents } from '../api/agents'
import { apiFetch, openAPIEventStream } from '../api/client'
import { useTests, type Test } from '../api/tests'
import type {
  InstantTestAgent,
  InstantTestRun,
  InstantTestRunSummary,
  InstantTestSelection,
} from '../api/sdk.gen'
import { Button, ErrorState, Field, LoadingState, Modal, Select } from '../components'
import { formatNumber } from '../i18n/number'
import { useI18n } from '../i18n/useI18n'

function runPath(id: string): string {
  return `/test-runs/${encodeURIComponent(id)}`
}

function isFinished(view: InstantTestRun): boolean {
  return view.agents.every((agent) => agent.state === 'completed' || agent.state === 'expired')
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function useInstantResults(run: InstantTestRunSummary | undefined, attempt: number) {
  const [view, setView] = useState<InstantTestRun>()
  const [error, setError] = useState<string>()
  useEffect(() => {
    if (!run) return
    const controller = new AbortController()
    const path = runPath(run.id)
    let version = 0
    let stream: EventSource
    const apply = (next: InstantTestRun) => {
      if (controller.signal.aborted || next.id !== run.id || next.test_id !== run.test_id) return
      setView(next)
      setError(undefined)
      if (isFinished(next)) stream.close()
    }
    const refresh = async () => {
      const readVersion = version
      try {
        const current = await apiFetch<InstantTestRun>(path, {
          signal: controller.signal,
        })
        if (readVersion !== version || controller.signal.aborted) return
        apply(current)
        if (!isFinished(current) && stream.readyState === EventSource.CLOSED) {
          setError('')
        }
      } catch (err) {
        if (readVersion !== version || controller.signal.aborted) return
        stream.close()
        setView(undefined)
        setError(errorMessage(err))
      }
    }
    try {
      stream = openAPIEventStream(`${path}/events`)
    } catch (err) {
      setView(undefined)
      setError(errorMessage(err))
      return
    }
    stream.addEventListener('run', (event: MessageEvent<string>) => {
      version += 1
      try {
        apply(JSON.parse(event.data) as InstantTestRun)
      } catch {
        stream.close()
        setView(undefined)
        setError('')
      }
    })
    stream.onerror = () => {
      setView(undefined)
      void refresh()
    }
    return () => {
      controller.abort()
      stream.close()
    }
  }, [run, attempt])
  return { view, error }
}

function AgentResult({ agent }: { agent: InstantTestAgent }) {
  const { t, locale } = useI18n()
  const result = agent.result
  if (!result) return t(`instant.${agent.state}`)
  const message =
    result.outcome === 'measured'
      ? t(result.success ? 'instant.measuredOK' : 'instant.measuredFailed')
      : t(`instant.${result.outcome}`)
  return (
    <div>
      <span>{message}</span>
      <dl>
        {Object.entries(result.metrics ?? {}).map(([key, value]) => (
          <div key={key} className="flex justify-between gap-2">
            <dt>{key}</dt>
            <dd>{formatNumber(value, locale, { maximumFractionDigits: 6 })}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

export function InstantTestRunDialog({ test, onClose }: { test?: Test; onClose: () => void }) {
  const { t } = useI18n()
  const tests = useTests()
  const agents = useAgents()
  const [testID, setTestID] = useState(test?.id ?? '')
  const [mode, setMode] = useState<'agents' | 'site' | 'tag'>('agents')
  const [agentIDs, setAgentIDs] = useState<string[]>([])
  const [site, setSite] = useState('')
  const [contextID, setContextID] = useState('')
  const [tagID, setTagID] = useState('')
  const [tagValue, setTagValue] = useState('')
  const [pending, setPending] = useState(false)
  const [submitError, setSubmitError] = useState<string>()
  const [issued, setIssued] = useState<{ fingerprint: string; key: string }>()
  const [run, setRun] = useState<InstantTestRunSummary>()
  const [attempt, setAttempt] = useState(0)
  const { view, error: streamError } = useInstantResults(run, attempt)

  const configured = test ?? tests.data?.find((row) => row.id === testID)
  const loadedAgents = flattenAgents(agents.data?.pages)
  const eligible = loadedAgents.filter(
    (row) =>
      !!configured &&
      row.status === 'online' &&
      !!row.test_set?.applied_version &&
      row.capabilities.includes('agent.instant_tests.v1') &&
      row.capabilities.includes(configured.type),
  )
  const labels = new Map(loadedAgents.map((row) => [row.id, row.name || row.hostname]))
  const selection: InstantTestSelection =
    mode === 'agents'
      ? { agent_ids: agentIDs }
      : mode === 'site'
        ? { site }
        : { tag: { context_id: contextID, tag_id: tagID, value: tagValue } }
  const selectionReady =
    mode === 'agents'
      ? agentIDs.length > 0
      : mode === 'site'
        ? site.length > 0
        : !!(contextID && tagID && tagValue)

  async function queueTest() {
    setPending(true)
    setSubmitError(undefined)
    try {
      const fingerprint = JSON.stringify([testID, selection])
      const idempotency_key =
        issued?.fingerprint === fingerprint ? issued.key : window.crypto.randomUUID()
      setIssued({ fingerprint, key: idempotency_key })
      const result = await apiFetch<InstantTestRunSummary>(
        `/tests/${encodeURIComponent(testID)}/runs`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ idempotency_key, selection }),
        },
      )
      setRun(result)
    } catch (err) {
      setSubmitError(errorMessage(err))
    } finally {
      setPending(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={t('instant.run')}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t('instant.dismiss')}
          </Button>
          {run ? null : (
            <Button
              variant="primary"
              disabled={!configured || !selectionReady || pending}
              onClick={() => void queueTest()}
            >
              {t(pending ? 'instant.working' : 'instant.submit')}
            </Button>
          )}
        </>
      }
    >
      {run ? (
        <div className="space-y-3">
          <dl className="grid gap-2">
            <div>
              <dt>{t('instant.testID')}</dt>
              <dd>{configured?.name ?? run.test_id}</dd>
            </div>
            <div>
              <dt>{t('instant.runID')}</dt>
              <dd>
                <code>{run.id}</code>
              </dd>
            </div>
          </dl>
          {streamError !== undefined ? (
            <ErrorState
              title={t('instant.failure')}
              description={streamError || t('instant.disconnected')}
              action={
                <Button onClick={() => setAttempt((value) => value + 1)}>
                  {t('instant.retry')}
                </Button>
              }
            />
          ) : view ? (
            <ul aria-live="polite" className="space-y-2">
              {view.agents.map((agent) => (
                <li key={agent.agent_id} className="rounded-panel border border-border p-3">
                  <strong>{labels.get(agent.agent_id) || agent.agent_id}</strong>
                  <AgentResult agent={agent} />
                </li>
              ))}
            </ul>
          ) : (
            <LoadingState label={t('instant.waiting')} />
          )}
        </div>
      ) : (
        <fieldset className="space-y-3" disabled={pending}>
          {!test ? (
            <>
              {tests.isPending ? <LoadingState label={t('instant.loading')} /> : null}
              {tests.error ? <ErrorState description={tests.error.message} /> : null}
              <Select
                label={t('instant.chooseTest')}
                value={testID}
                options={[
                  { value: '', label: '—' },
                  ...(tests.data ?? []).map((row) => ({
                    value: row.id,
                    label: row.name,
                  })),
                ]}
                onChange={(event) => {
                  setTestID(event.target.value)
                  setAgentIDs([])
                }}
              />
              {tests.hasNextPage ? (
                <Button
                  disabled={tests.isFetchingNextPage}
                  onClick={() => void tests.fetchNextPage()}
                >
                  {t('instant.loadMoreTests')}
                </Button>
              ) : null}
            </>
          ) : (
            <p>{test.name}</p>
          )}
          <Select
            label={t('instant.chooseVantage')}
            options={(['agents', 'site', 'tag'] as const).map((value) => ({
              value,
              label: t(`instant.${value}`),
            }))}
            value={mode}
            onChange={(event) => setMode(event.target.value as typeof mode)}
          />
          {mode === 'agents' ? (
            <>
              {agents.isPending ? <LoadingState label={t('instant.loading')} /> : null}
              {agents.error ? <ErrorState description={agents.error.message} /> : null}
              <Select
                multiple
                label={t('instant.agents')}
                options={eligible.map((row) => ({
                  value: row.id,
                  label: row.name || row.hostname || row.id,
                }))}
                value={agentIDs}
                onChange={(event) =>
                  setAgentIDs(Array.from(event.target.selectedOptions, (option) => option.value))
                }
              />
              {agents.hasNextPage ? (
                <Button
                  disabled={agents.isFetchingNextPage}
                  onClick={() => void agents.fetchNextPage()}
                >
                  {t('instant.loadMoreAgents')}
                </Button>
              ) : null}
            </>
          ) : mode === 'site' ? (
            <Field
              label={t('instant.siteName')}
              value={site}
              onChange={(event) => setSite(event.target.value)}
            />
          ) : (
            <>
              <Field
                label={t('instant.contextID')}
                value={contextID}
                onChange={(event) => setContextID(event.target.value)}
              />
              <Field
                label={t('instant.tagID')}
                value={tagID}
                onChange={(event) => setTagID(event.target.value)}
              />
              <Field
                label={t('instant.tagValue')}
                value={tagValue}
                onChange={(event) => setTagValue(event.target.value)}
              />
            </>
          )}
          {submitError ? (
            <ErrorState title={t('instant.failure')} description={submitError} />
          ) : null}
        </fieldset>
      )}
    </Modal>
  )
}
