// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useId, useState, type FormEvent } from 'react'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingState,
  Select,
  useToast,
} from '../components'
import {
  useAppendIncidentJournal,
  useIncidentJournal,
  type IncidentJournalCitationRequest,
  type IncidentJournalKind,
} from '../api/incidents'
import { DateTime } from '../time/DateTime'
import { useI18n } from '../i18n/useI18n'
import styles from './incidentRoom.module.css'

const MAX_JOURNAL_CHARACTERS = 4000

export interface JournalCheckpointSource extends IncidentJournalCitationRequest {
  title: string
}

export function InvestigationJournal({
  incidentID,
  checkpointSource,
  canWrite,
}: {
  incidentID: string
  checkpointSource?: JournalCheckpointSource
  canWrite: boolean
}) {
  const { t } = useI18n()
  const { push } = useToast()
  const journal = useIncidentJournal(incidentID)
  const append = useAppendIncidentJournal(incidentID)
  const textareaID = useId()
  const hintID = `${textareaID}-hint`
  const [kind, setKind] = useState<IncidentJournalKind>('note')
  const [body, setBody] = useState('')
  const characterCount = Array.from(body).length
  const checkpointReady = kind !== 'checkpoint' || Boolean(checkpointSource)
  const canSubmit =
    canWrite &&
    body.trim().length > 0 &&
    characterCount <= MAX_JOURNAL_CHARACTERS &&
    checkpointReady &&
    !append.isPending

  function submit(event: FormEvent) {
    event.preventDefault()
    if (!canSubmit) return
    append.mutate(
      {
        kind,
        body,
        ...(kind === 'checkpoint' && checkpointSource
          ? {
              citation: {
                share_id: checkpointSource.share_id,
                evidence_id: checkpointSource.evidence_id,
              },
            }
          : {}),
      },
      {
        onSuccess: () => {
          setBody('')
          push({
            tone: 'success',
            title: t('incidents.journal.appended'),
            message: t('incidents.journal.appendedDescription'),
          })
        },
        onError: (error) =>
          push({
            tone: 'danger',
            title: t('incidents.journal.failed'),
            message:
              error instanceof Error ? error.message : t('incidents.journal.failedDescription'),
          }),
      },
    )
  }

  return (
    <Card>
      <CardHeader
        title={t('incidents.journal.title')}
        description={t('incidents.journal.description')}
      />
      <CardBody>
        {canWrite ? (
          <form className={styles.journalForm} onSubmit={submit}>
            <Select
              label={t('incidents.journal.kind')}
              value={kind}
              onChange={(event) => setKind(event.target.value as IncidentJournalKind)}
              options={[
                { value: 'note', label: t('incidents.journal.kind.note') },
                { value: 'checkpoint', label: t('incidents.journal.kind.checkpoint') },
              ]}
            />
            <div className={styles.textareaField}>
              <label htmlFor={textareaID}>{t('incidents.journal.body')}</label>
              <textarea
                id={textareaID}
                value={body}
                maxLength={MAX_JOURNAL_CHARACTERS}
                rows={4}
                aria-describedby={hintID}
                placeholder={
                  kind === 'checkpoint'
                    ? t('incidents.journal.placeholder.checkpoint')
                    : t('incidents.journal.placeholder.note')
                }
                onChange={(event) => setBody(event.target.value)}
              />
              <p id={hintID} className={styles.fieldHint}>
                {t('incidents.journal.hint', {
                  count: characterCount,
                  limit: MAX_JOURNAL_CHARACTERS,
                })}
              </p>
            </div>
            {kind === 'checkpoint' ? (
              checkpointSource ? (
                <p className={styles.citationReady} role="status">
                  {t('incidents.journal.citation.ready', {
                    evidence: checkpointSource.title,
                  })}
                </p>
              ) : (
                <p className={styles.coverageWarning} role="status">
                  {t('incidents.journal.citation.required')}
                </p>
              )
            ) : null}
            <div className={styles.actions}>
              <Button type="submit" disabled={!canSubmit}>
                {append.isPending
                  ? t('incidents.journal.appending')
                  : t('incidents.journal.append')}
              </Button>
            </div>
          </form>
        ) : (
          <p className={styles.coverageWarning}>{t('incidents.journal.readOnly')}</p>
        )}

        <div className={styles.journalEntries}>
          {journal.isLoading ? (
            <LoadingState label={t('incidents.journal.loading')} />
          ) : journal.isError ? (
            <ErrorState
              title={t('incidents.journal.error')}
              description={t('incidents.journal.errorDescription')}
            />
          ) : !journal.data || journal.data.items.length === 0 ? (
            <EmptyState
              title={t('incidents.journal.empty')}
              description={t('incidents.journal.emptyDescription')}
            />
          ) : (
            <>
              {journal.data.truncated ? (
                <p className={styles.coverageWarning} role="status">
                  {t('incidents.journal.truncated', { limit: journal.data.limit })}
                </p>
              ) : null}
              <ol aria-label={t('incidents.journal.entries')} className={styles.journalList}>
                {journal.data.items.map((entry) => (
                  <li key={entry.id}>
                    <div className={styles.journalMeta}>
                      <Badge tone={entry.kind === 'checkpoint' ? 'info' : 'neutral'}>
                        {entry.kind === 'checkpoint'
                          ? t('incidents.journal.kind.checkpoint')
                          : t('incidents.journal.kind.note')}
                      </Badge>
                      <span>{t('incidents.journal.by', { author: entry.created_by || '—' })}</span>
                      <DateTime value={entry.created_at} />
                    </div>
                    <p className={styles.journalBody}>{entry.body}</p>
                    {entry.citation ? (
                      entry.citation.state === 'available' ? (
                        <div className={styles.journalCitation}>
                          <Badge tone="success">{t('incidents.journal.citation.available')}</Badge>
                          <strong>{entry.citation.title || entry.citation.evidence_id}</strong>
                          {entry.citation.summary ? <span>{entry.citation.summary}</span> : null}
                          {entry.citation.occurred_at ? (
                            <DateTime value={entry.citation.occurred_at} />
                          ) : null}
                        </div>
                      ) : (
                        <p className={styles.coverageWarning} role="status">
                          {t('incidents.journal.citation.unavailable')}
                        </p>
                      )
                    ) : null}
                    <p className={styles.retention}>
                      {t('incidents.journal.expires')} <DateTime value={entry.expires_at} />
                    </p>
                  </li>
                ))}
              </ol>
            </>
          )}
        </div>
      </CardBody>
    </Card>
  )
}
