// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMemo, type RefObject } from 'react'
import { Link } from 'react-router-dom'
import { Badge, Button, Modal } from '../components'
import type { DeviceConfigVersion } from '../api/planes'
import { useI18n } from '../i18n/useI18n'
import styles from './planes.module.css'
import { createConfigDiff, type ConfigDiffStatus } from './configDiff'

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
          {diff.bounded ? (
            <Badge tone="warning">{t('planes.device.config.compare.bounded')}</Badge>
          ) : (
            <Badge tone="info">{t('planes.device.config.compare.complete')}</Badge>
          )}
        </div>
        {diff.bounded ? (
          <p className={styles.configDiffNotice} role="status">
            {t('planes.device.config.compare.boundedDescription')}
          </p>
        ) : diff.contextFolded ? (
          <p className={styles.muted}>{t('planes.device.config.compare.contextFolded')}</p>
        ) : null}
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
              {diff.rows.map((row, index) =>
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
