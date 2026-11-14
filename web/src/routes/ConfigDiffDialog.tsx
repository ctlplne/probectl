// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMemo, useState, type RefObject } from 'react'
import { Link } from 'react-router-dom'
import { Badge, Button, Modal } from '../components'
import type { DeviceConfigVersion } from '../api/planes'
import { useI18n } from '../i18n/useI18n'
import styles from './planes.module.css'
import { CONFIG_DIFF_PAGE_SIZE, createConfigDiff, type ConfigDiffStatus } from './configDiff'

export interface ConfigComparison {
  current: DeviceConfigVersion
  previous: DeviceConfigVersion
}

export function ConfigDiffDialog({
  comparison,
  onClose,
  returnHref,
  returnFocusRef,
}: {
  comparison: ConfigComparison
  onClose: () => void
  returnHref?: string
  returnFocusRef?: RefObject<HTMLElement | null>
}) {
  const { current, previous } = comparison
  const { t } = useI18n()
  const diff = useMemo(
    () => createConfigDiff(previous.content ?? '', current.content ?? ''),
    [current.content, previous.content],
  )
  const identity = JSON.stringify([
    previous.id,
    previous.content_hash,
    current.id,
    current.content_hash,
  ])
  const [selection, setSelection] = useState({ identity, page: 0, expanded: false })
  const selected =
    selection.identity === identity ? selection : { identity, page: 0, expanded: false }
  const rows = selected.expanded ? diff.completeRows : diff.rows
  const lastPage = Math.max(0, Math.ceil(rows.length / CONFIG_DIFF_PAGE_SIZE) - 1)
  const page = Math.min(selected.page, lastPage)
  const offset = page * CONFIG_DIFF_PAGE_SIZE
  const displayedRows = rows.slice(offset, offset + CONFIG_DIFF_PAGE_SIZE)
  const selectPage = (next: number) => setSelection({ ...selected, page: next })

  return (
    <Modal
      open
      onClose={onClose}
      returnFocusRef={returnFocusRef}
      title={t('planes.device.config.compare.title', {
        device: current.device,
        before: previous.version,
        after: current.version,
      })}
      footer={
        <>
          {returnHref ? (
            <Link to={returnHref}>{t('planes.device.config.compare.returnToIncident')}</Link>
          ) : null}
          <Button variant="secondary" onClick={onClose}>
            {t('planes.device.config.compare.close')}
          </Button>
        </>
      }
    >
      <div className={styles.configDiff}>
        <p className={styles.muted}>{t('planes.device.config.compare.description')}</p>
        <dl className={styles.configDiffMeta}>
          <dt>{t('planes.device.config.compare.before')}</dt>
          <dd>
            <span>{t('planes.device.config.compare.version', { number: previous.version })}</span>
            <code dir="ltr">{previous.content_hash}</code>
          </dd>
          <dt>{t('planes.device.config.compare.after')}</dt>
          <dd>
            <span>{t('planes.device.config.compare.version', { number: current.version })}</span>
            <code dir="ltr">{current.content_hash}</code>
          </dd>
        </dl>
        <div
          className={styles.configDiffSummary}
          aria-label={t('planes.device.config.compare.summary')}
        >
          <Badge tone="success">
            {t('planes.device.config.compare.addedCount', { count: diff.added })}
          </Badge>
          <Badge tone="danger">
            {t('planes.device.config.compare.removedCount', { count: diff.removed })}
          </Badge>
          <Badge tone="neutral">
            {t('planes.device.config.compare.unchangedCount', { count: diff.unchanged })}
          </Badge>
          <Badge tone="info">{t('planes.device.config.compare.complete')}</Badge>
        </div>
        {diff.replacement ? (
          <p className={styles.configDiffNotice} role="status">
            {t('planes.device.config.compare.replacement')}
          </p>
        ) : diff.contextFolded ? (
          <p className={styles.muted}>{t('planes.device.config.compare.contextFolded')}</p>
        ) : null}
        <nav
          className={styles.configDiffSummary}
          aria-label={t('planes.device.config.compare.paging')}
        >
          <Button variant="secondary" disabled={page === 0} onClick={() => selectPage(0)}>
            {t('planes.device.config.compare.first')}
          </Button>
          <Button variant="secondary" disabled={page === 0} onClick={() => selectPage(page - 1)}>
            {t('planes.device.config.compare.previous')}
          </Button>
          <span aria-live="polite">
            {t('planes.device.config.compare.pageRows', {
              from: offset + 1,
              to: offset + displayedRows.length,
              total: rows.length,
            })}
          </span>
          <Button
            variant="secondary"
            disabled={page === lastPage}
            onClick={() => selectPage(page + 1)}
          >
            {t('planes.device.config.compare.next')}
          </Button>
          <Button
            variant="secondary"
            disabled={page === lastPage}
            onClick={() => selectPage(lastPage)}
          >
            {t('planes.device.config.compare.last')}
          </Button>
          {diff.contextFolded ? (
            <Button
              variant="secondary"
              onClick={() => setSelection({ identity, page: 0, expanded: !selected.expanded })}
            >
              {t(
                selected.expanded
                  ? 'planes.device.config.compare.foldContext'
                  : 'planes.device.config.compare.allContext',
              )}
            </Button>
          ) : null}
        </nav>
        <div
          className={styles.configDiffViewport}
          dir="ltr"
          tabIndex={0}
          aria-label={t('planes.device.config.compare.region')}
        >
          <table className={styles.configDiffTable}>
            <caption className="sr-only">{t('planes.device.config.compare.caption')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('planes.device.config.compare.oldLine')}</th>
                <th scope="col">{t('planes.device.config.compare.newLine')}</th>
                <th scope="col">{t('planes.device.config.compare.redactedLine')}</th>
              </tr>
            </thead>
            <tbody>
              {displayedRows.map((row, index) =>
                row.status === 'omitted' ? (
                  <tr key={`omitted-${index}`} className={styles.configDiffOmitted}>
                    <td colSpan={3}>
                      {t('planes.device.config.compare.omitted', { count: row.omitted ?? 0 })}
                    </td>
                  </tr>
                ) : (
                  <tr
                    key={`${row.status}-${row.beforeLine ?? 'x'}-${row.afterLine ?? 'x'}-${index}`}
                    className={statusClass(row.status)}
                    data-config-diff-row={row.status}
                  >
                    <td className={styles.configDiffLineNumber}>{row.beforeLine ?? '—'}</td>
                    <td className={styles.configDiffLineNumber}>{row.afterLine ?? '—'}</td>
                    <td className={styles.configDiffContent}>
                      <span className="sr-only">{statusLabel(row.status, t)}</span>
                      <span className={styles.configDiffMarker} aria-hidden="true">
                        {statusMarker(row.status)}
                      </span>
                      <code>{row.text || '\u00a0'}</code>
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </table>
        </div>
      </div>
    </Modal>
  )
}

function statusClass(status: Exclude<ConfigDiffStatus, 'omitted'>): string {
  if (status === 'added') return styles.configDiffAdded
  if (status === 'removed') return styles.configDiffRemoved
  return styles.configDiffUnchanged
}

function statusMarker(status: Exclude<ConfigDiffStatus, 'omitted'>): string {
  if (status === 'added') return '+'
  if (status === 'removed') return '−'
  return ' '
}

function statusLabel(
  status: Exclude<ConfigDiffStatus, 'omitted'>,
  t: ReturnType<typeof useI18n>['t'],
): string {
  if (status === 'added') return t('planes.device.config.compare.added')
  if (status === 'removed') return t('planes.device.config.compare.removed')
  return t('planes.device.config.compare.unchanged')
}
