// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import styles from './cost.module.css'
import { Page } from './RoutePage'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  ChartShell,
  EmptyState,
  ErrorState,
  LoadingState,
  Select,
  Table,
  type Column,
} from '../components'
// Direct import (not the components barrel): uplot must ride only in lazy
// route chunks so the app-shell entry stays inside its bundle budget.
import { TimeSeries } from '../components/TimeSeries'
import {
  gib,
  usd,
  usdPerGiB,
  useCostSummary,
  type BudgetStatus,
  type ChattyPair,
} from '../api/cost'
import { useCarbon, type CarbonAgg } from '../api/carbon'
import { useI18n } from '../i18n/useI18n'
import { formatDecimal, formatUnit } from '../i18n/number'
import { useAuth } from '../auth/useAuth'
import { DateTime } from '../time/DateTime'

type CostWindow = 'accumulation' | '1h' | '24h' | '168h'

const COST_WINDOWS: { value: CostWindow; label: string }[] = [
  { value: 'accumulation', label: 'Accumulation window' },
  { value: '1h', label: 'Last 1 hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '168h', label: 'Last 7 days' },
]

/** CostPage (S44): the native FinOps surface — spend by team/service
 * (showback), chatty cross-AZ conversations, budget status, and an hourly
 * trend. The first-party Dashboards and Explorer routes provide cross-plane
 * drilldown without an external dashboard runtime. S48 folds the carbon/ESG
 * estimate in below — same traffic, same owners, grams instead of dollars. */
export function CostPage() {
  const { locale, t } = useI18n()
  const { tenant } = useAuth()
  const navigate = useNavigate()
  const { data, isPending, isError } = useCostSummary()
  const [window, setWindow] = useState<CostWindow>('accumulation')
  const s = data?.summary
  const fmtGiB = (bytes: number) => gib(bytes, locale)
  const fmtUSD = (value: number) => usd(value, locale)

  const windowHours = window === 'accumulation' ? null : Number.parseInt(window, 10)
  const trendInWindow =
    windowHours == null
      ? (s?.trend ?? [])
      : (s?.trend ?? []).filter(
          (point) => Date.parse(point.hour) >= Date.now() - windowHours * 60 * 60 * 1000,
        )
  const displayedBytes =
    windowHours == null
      ? (s?.total_bytes ?? 0)
      : trendInWindow.reduce((total, point) => total + point.bytes, 0)
  const displayedUSD =
    windowHours == null
      ? (s?.total_usd ?? 0)
      : trendInWindow.reduce((total, point) => total + point.usd, 0)

  const owners: Array<{ name: string; agg: { bytes: number; usd: number } }> = Object.entries(
    s?.by_team ?? {},
  )
    .map(([name, agg]) => ({ name, agg }))
    .sort((a, b) => b.agg.usd - a.agg.usd || b.agg.bytes - a.agg.bytes)

  // DPR-183: a team with MORE egress can cost LESS, because the engine prices
  // each flow by its zone — intra-AZ traffic is nearly free next to
  // cross-region egress. The table showed only GiB and dollars, so the honest
  // answer looked like an arithmetic error (43.9 GiB at $2.44 above 65.5 GiB at
  // $0.44). The effective rate is what makes it a fact rather than a puzzle.
  const teamColumns: Column<(typeof owners)[number]>[] = [
    { key: 'team', header: 'Team', render: (r) => <strong>{r.name}</strong> },
    { key: 'gib', header: 'Egress (GiB)', render: (r) => fmtGiB(r.agg.bytes) },
    {
      key: 'usd',
      header: 'Cost',
      render: (r) => (s?.priced ? fmtUSD(r.agg.usd) : '—'),
    },
    {
      key: 'rate',
      header: 'Effective $/GiB',
      render: (r) => {
        if (!s?.priced) return '—'
        const gibs = r.agg.bytes / 1024 ** 3
        if (gibs <= 0) return '—'
        return `${usdPerGiB(r.agg.usd / gibs, locale)}`
      },
    },
  ]

  const pairColumns: Column<ChattyPair>[] = [
    { key: 'svc', header: 'Service', render: (p) => p.service },
    {
      key: 'pair',
      header: 'Zones',
      render: (p) => (
        <code>
          {p.src_zone} → {p.dst_zone}
        </code>
      ),
    },
    { key: 'class', header: 'Class', render: (p) => p.class },
    { key: 'gib', header: 'GiB', render: (p) => fmtGiB(p.bytes) },
    { key: 'usd', header: 'Cost', render: (p) => (s?.priced ? fmtUSD(p.usd) : '—') },
    {
      key: 'chatty',
      header: 'Chatty',
      render: (p) =>
        p.chatty ? <Badge tone="warning">chatty</Badge> : <Badge tone="neutral">ok</Badge>,
    },
  ]

  const budgetColumns: Column<BudgetStatus>[] = [
    {
      key: 'target',
      header: 'Budget',
      render: (b) => (
        <span>
          <strong>{b.name}</strong> <span className={styles.kind}>({b.kind})</span>
        </span>
      ),
    },
    { key: 'cap', header: 'Monthly', render: (b) => fmtUSD(b.monthly_usd) },
    { key: 'spent', header: 'Spent', render: (b) => fmtUSD(b.spent_usd) },
    {
      key: 'state',
      header: 'Status',
      render: (b) =>
        b.exceeded ? <Badge tone="danger">exceeded</Badge> : <Badge tone="success">within</Badge>,
    },
  ]

  return (
    <Page
      title="Cost"
      subtitle="Network egress dollars — volume × public pricing, attributed to services and teams."
    >
      <Card>
        <CardHeader title="Egress spend" description={t('cost.egress.description')} />
        <CardBody>
          {isPending ? (
            <LoadingState label="Loading cost summary…" />
          ) : isError ? (
            <ErrorState description="Could not load the cost summary." />
          ) : !data?.cost_running || !s ? (
            <EmptyState
              icon="cost"
              title="Cost engine not wired"
              description="The control plane started without the cost engine."
              action={
                <Button variant="secondary" onClick={() => void navigate('/planes/flow')}>
                  {t('cost.unwired.action')}
                </Button>
              }
            />
          ) : (
            <>
              <div className={styles.scope} role="note" aria-label="cost scope and window">
                <div>
                  <strong>Scope:</strong> tenant {tenant.name} · all mapped teams and services ·
                  project attribution unavailable in this summary
                </div>
                <div>
                  <strong>Accumulation opened:</strong> <DateTime value={s.data_since} /> · control
                  restart resets this in-memory boundary
                </div>
                <div>
                  <strong>Retention:</strong> exact range totals use the retained hourly trend (up
                  to 7 days); showback is full accumulation and budgets are month-to-date
                </div>
              </div>
              <div className={styles.filters} aria-label="Cost view controls">
                <Select
                  label="Cost window"
                  value={window}
                  options={COST_WINDOWS}
                  onChange={(event) => setWindow(event.target.value as CostWindow)}
                />
                <Button
                  variant="secondary"
                  onClick={() => void navigate('/explore?template=cross-az-cost')}
                >
                  Refine in Explorer
                </Button>
              </div>
              {!s.priced && (
                <div className={styles.notice} role="note" aria-label="volume-only mode">
                  Volume-only mode: no price table is loaded, so byte volumes are attributed but
                  dollars are not invented.
                </div>
              )}
              {!s.zones_mapped && (
                <div className={styles.notice} role="note" aria-label="zones unmapped">
                  No CIDR→zone rules configured (PROBECTL_COST_ZONES) — locality classes are
                  unknown, so cross-AZ detection is inactive.
                </div>
              )}
              <dl className={styles.totals}>
                <div>
                  <dt>Total egress</dt>
                  <dd>{fmtGiB(displayedBytes)} GiB</dd>
                </div>
                <div>
                  <dt>Total cost</dt>
                  <dd>{s.priced ? fmtUSD(displayedUSD) : 'volume-only'}</dd>
                </div>
                <div>
                  <dt>Displayed window</dt>
                  <dd>{COST_WINDOWS.find((option) => option.value === window)?.label}</dd>
                </div>
                <div>
                  <dt>Pricing</dt>
                  <dd>
                    {s.priced ? (
                      <span>
                        {s.pricing_source}{' '}
                        <span className={styles.kind}>(as of {s.pricing_as_of})</span>
                      </span>
                    ) : (
                      'none'
                    )}
                  </dd>
                </div>
              </dl>
              <Table
                caption="Spend by team (showback)"
                columns={teamColumns}
                rows={owners}
                rowKey={(r) => r.name}
                empty={
                  <EmptyState
                    icon="cost"
                    title="No attributed traffic yet"
                    description="Map service CIDRs with PROBECTL_COST_SERVICES to attribute spend."
                  />
                }
              />
            </>
          )}
        </CardBody>
      </Card>

      {data?.cost_running && s && s.trend.length >= 2 && (
        <Card>
          <CardHeader
            title="Hourly egress cost"
            description="The same attributed traffic on the incident clock's time axis."
          />
          <CardBody>
            <ChartShell
              title="Egress cost per hour"
              height={220}
              legend={
                <span>
                  {fmtGiB(s.total_bytes)} GiB total ·{' '}
                  {s.priced ? fmtUSD(s.total_usd) : 'volume-only'}
                </span>
              }
            >
              <TimeSeries
                label="Hourly egress cost trend"
                timestamps={s.trend.map((point) => point.hour)}
                series={[
                  {
                    label: s.priced ? 'USD per hour' : 'GiB per hour',
                    values: s.trend.map((point) => (s.priced ? point.usd : point.bytes / 2 ** 30)),
                  },
                ]}
                formatValue={(value) =>
                  s.priced ? fmtUSD(value) : `${formatDecimal(value, locale)} GiB`
                }
              />
            </ChartShell>
          </CardBody>
        </Card>
      )}

      {data?.cost_running && s && (
        <>
          <Card>
            <CardHeader
              title="Cross-AZ conversations"
              description="Chatty service pairs paying the inter-AZ/inter-region tax."
            />
            <CardBody>
              <Table
                caption="Chatty zone pairs"
                columns={pairColumns}
                rows={s.chatty_pairs}
                rowKey={(p) => `${p.service}|${p.src_zone}|${p.dst_zone}`}
                empty={
                  <EmptyState
                    icon="cost"
                    title="No paid cross-zone traffic observed"
                    description="Same-zone traffic is free; nothing chatty yet."
                  />
                }
              />
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title="Budgets"
              description="Monthly network budgets; a breach raises a cost-plane incident signal."
            />
            <CardBody>
              <Table
                caption="Budget status"
                columns={budgetColumns}
                rows={s.budgets}
                rowKey={(b) => `${b.kind}:${b.name}`}
                empty={
                  <EmptyState
                    icon="cost"
                    title="No budgets configured"
                    description="Set PROBECTL_COST_BUDGETS, e.g. team:payments=500."
                  />
                }
              />
            </CardBody>
          </Card>
        </>
      )}

      <CarbonCard />
    </Page>
  )
}

/** CarbonCard (S48): the ESG estimate folded into the FinOps page — same
 *  attribution as the dollars above, with the methodology stated plainly. */
function CarbonCard() {
  const { locale } = useI18n()
  const carbon = useCarbon()
  const s = carbon.data?.summary
  const fmtGiB = (bytes: number) => gib(bytes, locale)

  const rows: Array<{ name: string; agg: CarbonAgg }> = Object.entries(s?.by_team ?? {})
    .map(([name, agg]) => ({ name, agg }))
    .sort((x, y) => y.agg.gco2e - x.agg.gco2e)

  const columns: Column<{ name: string; agg: CarbonAgg }>[] = [
    { key: 'team', header: 'Team', render: (r) => r.name },
    { key: 'gb', header: 'Volume (GiB)', numeric: true, render: (r) => fmtGiB(r.agg.bytes) },
    {
      key: 'kwh',
      header: 'Energy (kWh, est.)',
      numeric: true,
      render: (r) =>
        formatDecimal(r.agg.kwh, locale, {
          minimumFractionDigits: 3,
          maximumFractionDigits: 3,
        }),
    },
    {
      key: 'g',
      header: 'Carbon (gCO2e, est.)',
      numeric: true,
      render: (r) =>
        formatDecimal(r.agg.gco2e, locale, {
          minimumFractionDigits: 1,
          maximumFractionDigits: 1,
        }),
    },
  ]

  return (
    <Card>
      <CardHeader
        title="Carbon / energy (estimate)"
        description="The ESG view of the same traffic: volume × transmission-energy coefficients × your grid intensity."
      />
      <CardBody>
        {carbon.isPending ? (
          <LoadingState label="Loading carbon estimate…" />
        ) : carbon.isError ? (
          <ErrorState description="Could not load the carbon estimate." />
        ) : !carbon.data?.carbon_running ? (
          <EmptyState
            icon="cost"
            title="Carbon engine not wired"
            description="The control plane started with PROBECTL_CARBON_ENABLED=false."
          />
        ) : (
          <>
            <p role="note" aria-label="carbon methodology" className={styles.notice}>
              <Badge tone="info">estimate</Badge>{' '}
              {formatUnit(s?.total_gco2e ?? 0, 'gCO2e', locale, {
                minimumFractionDigits: 1,
                maximumFractionDigits: 1,
              })}{' '}
              ·{' '}
              {formatUnit(s?.total_kwh ?? 0, 'kWh', locale, {
                minimumFractionDigits: 3,
                maximumFractionDigits: 3,
              })}{' '}
              over {fmtGiB(s?.total_bytes ?? 0)} GiB — coefficient-based estimate, not measured
              power · grid{' '}
              {formatUnit(s?.methodology.grid_gco2e_per_kwh ?? 0, 'gCO2e/kWh', locale, {
                maximumFractionDigits: 1,
              })}{' '}
              · {s?.methodology.source}
            </p>
            <Table
              caption="Carbon by team"
              columns={columns}
              rows={rows}
              rowKey={(r) => r.name}
              empty={
                <EmptyState
                  icon="cost"
                  title="No traffic observed yet"
                  description="Estimates appear once flow telemetry arrives."
                />
              }
            />
          </>
        )}
      </CardBody>
    </Card>
  )
}
