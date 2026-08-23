// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import styles from './slos.module.css'
import { Page } from './RoutePage'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingState,
  Modal,
  Table,
  type Column,
} from '../components'
import { pct, useSLOs, type SLOStatus } from '../api/slos'
import { useI18n } from '../i18n/useI18n'
import { formatInteger, formatMultiplier } from '../i18n/number'
import { CodeExportPanel } from './CodeExportPanel'
import { sloAsCode } from './codeExport'
import { DateTime } from '../time/DateTime'

function sloEvidenceHref(name: string) {
  const params = new URLSearchParams({ template: 'slo-budget-burn' })
  params.append('filter', `slo:${name}`)
  return `/explore?${params.toString()}`
}

/** SLOsPage (S45): the exec-grade reliability view — attainment vs objective,
 * error budgets, and multi-window burn rates per service/team. Definitions
 * are OpenSLO YAML (import/export via the API). */
export function SLOsPage() {
  const { locale, t } = useI18n()
  const navigate = useNavigate()
  const { data, isPending, isError } = useSLOs()
  const [codeExport, setCodeExport] = useState<{ title: string; code: string } | null>(null)

  const columns: Column<SLOStatus>[] = [
    {
      key: 'name',
      header: t('slo.column.slo'),
      render: (s) => (
        <div>
          <strong>{s.display_name || s.name}</strong>
          <div className={styles.meta}>
            {s.service}
            {s.team ? ` · ${s.team}` : ''} · {s.window}
          </div>
        </div>
      ),
    },
    {
      key: 'objective',
      header: t('slo.column.objective'),
      render: (s) => pct(s.objective, locale),
    },
    {
      key: 'attainment',
      header: t('slo.column.attainment'),
      render: (s) =>
        s.cold_start ? (
          <Badge tone="neutral">{t('slo.coldStart')}</Badge>
        ) : (
          pct(s.attainment, locale)
        ),
    },
    {
      key: 'budget',
      header: t('slo.column.errorBudget'),
      render: (s) => {
        if (s.cold_start) return '—'
        const remaining = Math.max(0, Math.min(1, s.error_budget_remaining))
        const remainingText = pct(remaining, locale)
        const cls = remaining <= 0 ? styles.budgetGone : remaining < 0.25 ? styles.budgetLow : ''
        return (
          <div className={`${styles.budgetCell} ${cls}`}>
            {t('slo.budget.left', { value: remainingText })}
            <div
              className={styles.budgetBar}
              role="img"
              aria-label={t('slo.budget.aria', { value: remainingText })}
            >
              <div className={styles.budgetFill} style={{ width: `${remaining * 100}%` }} />
            </div>
          </div>
        )
      },
    },
    {
      key: 'burn',
      header: t('slo.column.burnRates'),
      render: (s) => (
        <div className={styles.burns}>
          {s.burn_rates.map((b) => (
            <Badge key={b.window} tone={b.firing ? 'danger' : 'neutral'}>
              {b.window} {formatMultiplier(b.burn, locale)}
            </Badge>
          ))}
        </div>
      ),
    },
    {
      key: 'events',
      header: t('slo.column.events'),
      render: (s) => formatInteger(s.total_events, locale),
    },
    {
      key: 'actions',
      header: <span className="sr-only">Actions</span>,
      align: 'end',
      render: (s) => (
        <div className={styles.actions}>
          <Button variant="ghost" size="sm" onClick={() => void navigate(sloEvidenceHref(s.name))}>
            Inspect evidence
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() =>
              setCodeExport({ title: `Export as code: ${s.name}`, code: sloAsCode(s) })
            }
          >
            View as YAML
          </Button>
        </div>
      ),
    },
  ]

  return (
    <Page title={t('slo.page.title')} subtitle={t('slo.page.subtitle')}>
      <Card>
        <CardHeader title={t('slo.card.title')} description={t('slo.card.description')} />
        <CardBody>
          {isPending ? (
            <LoadingState label={t('slo.loading')} />
          ) : isError ? (
            <ErrorState description={t('slo.error')} />
          ) : !data?.slo_running ? (
            <EmptyState
              icon="slo"
              title={t('slo.unwired.title')}
              description={t('slo.unwired.description')}
              action={
                <Button variant="secondary" onClick={() => void navigate('/docs/api?filter=slos')}>
                  {t('slo.setup.action')}
                </Button>
              }
            />
          ) : (
            <>
              {data.data_since ? (
                <div className={styles.window} role="note" aria-label="SLO evaluation window">
                  <strong>Tenant evaluation opened:</strong> <DateTime value={data.data_since} /> ·
                  in-memory attainment and error budgets reset on control-plane restart; cold start
                  is not a healthy verdict
                </div>
              ) : null}
              <Table
                caption={t('slo.table.caption')}
                columns={columns}
                rows={data.items}
                rowKey={(s) => s.name}
                empty={
                  <EmptyState
                    icon="slo"
                    title={t('slo.empty.title')}
                    description={t('slo.empty.description')}
                    action={
                      <Button
                        variant="secondary"
                        onClick={() => void navigate('/docs/api?filter=slos')}
                      >
                        {t('slo.setup.action')}
                      </Button>
                    }
                  />
                }
              />
            </>
          )}
        </CardBody>
      </Card>
      {codeExport ? (
        <Modal open onClose={() => setCodeExport(null)} title={codeExport.title}>
          <CodeExportPanel title="OpenSLO YAML" code={codeExport.code} />
        </Modal>
      ) : null}
    </Page>
  )
}
