import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import styles from './incidents.module.css'
import { Page } from './pages'
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
  Select,
  StatusDot,
  Table,
  useToast,
  type Column,
} from '../components'
import {
  type Incident,
  type Signal,
  severityTone,
  useIncident,
  useIncidents,
  useResolveIncident,
} from '../api/incidents'
import { useCreateRemediationProposal, useRemediations } from '../api/remediation'
import {
  incidentTarget,
  proposalFromIncident,
  questionForIncident,
} from '../remediation/proposalContext'
import { DateTime } from '../time/DateTime'
import { FilterBar, SavedViews } from './listControls'
import { filterValue, filtersForSave, setURLFilters } from './urlFilters'
import { useI18n } from '../i18n/useI18n'
import type { MessageKey } from '../i18n/messages'

type TFn = (key: MessageKey, vars?: Record<string, string | number>) => string

function incidentStatusLabel(status: string, t: TFn) {
  if (status === 'open') return t('incidents.status.open')
  if (status === 'resolved') return t('incidents.status.resolvedLabel')
  return status
}

function incidentSeverityLabel(severity: string, t: TFn) {
  if (severity === 'critical') return t('severity.critical')
  if (severity === 'warning') return t('severity.warning')
  if (severity === 'info') return t('severity.info')
  return severity
}

/** Timeline overlays every plane's signals for one incident in time order. The
 *  rendering is plane-agnostic (it reads the generic Signal), so a new plane
 *  appears here with no UI change. */
function Timeline({ incidentId }: { incidentId: string }) {
  const navigate = useNavigate()
  const { t } = useI18n()
  const incident = useIncident(incidentId)
  const resolve = useResolveIncident(incidentId)
  const remediations = useRemediations()
  const createProposal = useCreateRemediationProposal()
  const { push } = useToast()

  if (incident.isLoading) return <LoadingState label={t('incidents.loadingOne')} />
  if (incident.isError || !incident.data)
    return <ErrorState description={t('incidents.errorOne')} />

  const inc = incident.data
  const signals = inc.signals ?? []
  const canPropose = Boolean(remediations.data)

  function askAboutIncident() {
    const params = new URLSearchParams({
      incident_id: inc.id,
      target: incidentTarget(inc),
      question: questionForIncident(inc),
    })
    navigate(`/ask?${params.toString()}`)
  }

  function proposeIncidentReview() {
    createProposal.mutate(proposalFromIncident(inc), {
      onSuccess: (p) =>
        push({
          tone: 'success',
          title: t('incidents.toast.proposalCreated'),
          message: t('incidents.toast.proposalCreatedMessage', { id: p.id }),
        }),
      onError: (err) =>
        push({
          tone: 'danger',
          title: t('incidents.toast.proposalFailed'),
          message: err instanceof Error ? err.message : t('incidents.toast.proposalFailedMessage'),
        }),
    })
  }

  return (
    <Card>
      <CardHeader
        title={inc.title || inc.target || t('incidents.fallbackTitle')}
        actions={
          <div className={styles.actionsRow}>
            <Button variant="secondary" onClick={askAboutIncident}>
              {t('incidents.action.ask')}
            </Button>
            {canPropose ? (
              <Button
                variant="secondary"
                onClick={proposeIncidentReview}
                disabled={createProposal.isPending}
              >
                {createProposal.isPending
                  ? t('incidents.action.proposing')
                  : t('incidents.action.propose')}
              </Button>
            ) : null}
            {inc.status === 'open' ? (
              <Button
                variant="secondary"
                onClick={() => resolve.mutate()}
                disabled={resolve.isPending}
              >
                {t('incidents.action.resolve')}
              </Button>
            ) : (
              <Badge tone="neutral">{t('incidents.status.resolved')}</Badge>
            )}
          </div>
        }
      />
      <CardBody>
        <dl className={styles.meta}>
          <div>
            <dt>{t('incidents.meta.severity')}</dt>
            <dd>
              <Badge tone={severityTone(inc.severity)}>
                {incidentSeverityLabel(inc.severity, t)}
              </Badge>
            </dd>
          </div>
          <div>
            <dt>{t('incidents.meta.target')}</dt>
            <dd>{inc.target || inc.prefix || '—'}</dd>
          </div>
          <div>
            <dt>{t('incidents.meta.signals')}</dt>
            <dd>{inc.signal_count}</dd>
          </div>
          <div>
            <dt>{t('incidents.meta.started')}</dt>
            <dd>
              <DateTime value={inc.started_at} />
            </dd>
          </div>
        </dl>

        <ol className={styles.timeline} aria-label={t('incidents.timeline.aria')}>
          {signals.map((s: Signal, i) => (
            <li key={`${s.plane}-${i}`} className={styles.event}>
              <DateTime value={s.occurred_at} className={styles.time} />
              <span className={styles.dot}>
                <StatusDot
                  tone={severityTone(s.severity)}
                  label={incidentSeverityLabel(s.severity, t)}
                />
              </span>
              <div className={styles.body}>
                <div className={styles.row}>
                  <Badge tone="accent">{s.plane}</Badge>
                  <code className={styles.kind}>{s.kind}</code>
                </div>
                <p className={styles.title}>{s.title || s.kind}</p>
                {s.summary ? <p className={styles.summary}>{s.summary}</p> : null}
                {s.target ? <p className={styles.target}>{s.target}</p> : null}
              </div>
            </li>
          ))}
        </ol>
      </CardBody>
    </Card>
  )
}

export function IncidentsPage() {
  const { t } = useI18n()
  const incidents = useIncidents()
  // Deep-link support (?incident=<id>): other surfaces (threat triage S-FE3,
  // alerts) pivot straight into a specific incident's timeline.
  const [params, setParams] = useSearchParams()
  const [selected, setSelected] = useState<string | null>(params.get('incident'))
  const defaults = { incident_q: '', incident_status: 'all', incident_severity: 'all' }
  const query = filterValue(params, 'incident_q')
  const status = filterValue(params, 'incident_status', 'all')
  const severity = filterValue(params, 'incident_severity', 'all')
  const setFilter = (patch: Record<string, string>) =>
    setURLFilters(params, setParams, defaults, patch)
  const filteredIncidents = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return (incidents.data ?? []).filter((inc) => {
      const haystack = [inc.title, inc.target ?? '', inc.prefix ?? '', inc.status, inc.severity]
        .join(' ')
        .toLowerCase()
      return (
        (!needle || haystack.includes(needle)) &&
        (status === 'all' || inc.status === status) &&
        (severity === 'all' || inc.severity === severity)
      )
    })
  }, [incidents.data, query, severity, status])

  useEffect(() => {
    if (filteredIncidents.length === 0) {
      setSelected(null)
      return
    }
    if (selected === null || !filteredIncidents.some((inc) => inc.id === selected)) {
      setSelected(filteredIncidents[0].id)
    }
  }, [filteredIncidents, selected])

  const columns: Column<Incident>[] = [
    {
      key: 'severity',
      header: t('incidents.column.severity'),
      render: (r) => (
        <Badge tone={severityTone(r.severity)}>{incidentSeverityLabel(r.severity, t)}</Badge>
      ),
    },
    {
      key: 'title',
      header: t('incidents.column.incident'),
      render: (r) => (
        <Button variant="ghost" onClick={() => setSelected(r.id)} aria-pressed={selected === r.id}>
          {r.title || r.target || r.id}
        </Button>
      ),
    },
    {
      key: 'target',
      header: t('incidents.column.target'),
      render: (r) => r.target || r.prefix || '—',
    },
    {
      key: 'status',
      header: t('incidents.column.status'),
      render: (r) => (
        <StatusDot
          tone={r.status === 'open' ? 'warning' : 'success'}
          label={incidentStatusLabel(r.status, t)}
        />
      ),
    },
    {
      key: 'signals',
      header: t('incidents.column.signals'),
      numeric: true,
      render: (r) => r.signal_count,
    },
    {
      key: 'last_seen',
      header: t('incidents.column.lastActivity'),
      render: (r) => <DateTime value={r.last_seen_at} />,
    },
  ]

  return (
    <Page title={t('incidents.page.title')} subtitle={t('incidents.page.subtitle')}>
      <FilterBar>
        <Field
          label={t('incidents.filter.find')}
          value={query}
          onChange={(e) => setFilter({ incident_q: e.target.value })}
          placeholder={t('incidents.filter.placeholder')}
        />
        <Select
          label={t('incidents.filter.status')}
          value={status}
          onChange={(e) => setFilter({ incident_status: e.target.value })}
          options={[
            { value: 'all', label: t('incidents.filter.allStatuses') },
            { value: 'open', label: t('incidents.filter.open') },
            { value: 'resolved', label: t('incidents.filter.resolved') },
          ]}
        />
        <Select
          label={t('incidents.filter.severity')}
          value={severity}
          onChange={(e) => setFilter({ incident_severity: e.target.value })}
          options={[
            { value: 'all', label: t('incidents.filter.allSeverities') },
            { value: 'critical', label: t('incidents.filter.critical') },
            { value: 'warning', label: t('incidents.filter.warning') },
            { value: 'info', label: t('incidents.filter.info') },
          ]}
        />
        <SavedViews
          surface="incidents"
          filters={filtersForSave(params, defaults)}
          onApply={(filters) =>
            setURLFilters(params, setParams, defaults, {
              incident_q: filters.incident_q ?? '',
              incident_status: filters.incident_status ?? 'all',
              incident_severity: filters.incident_severity ?? 'all',
            })
          }
          placeholder={t('incidents.saved.placeholder')}
        />
      </FilterBar>
      {incidents.isLoading ? (
        <LoadingState label={t('incidents.loading')} />
      ) : incidents.isError ? (
        <ErrorState description={t('incidents.error')} />
      ) : !incidents.data || incidents.data.length === 0 ? (
        <EmptyState
          title={t('incidents.empty.title')}
          description={t('incidents.empty.description')}
        />
      ) : filteredIncidents.length === 0 ? (
        <EmptyState
          title={t('incidents.empty.noMatchTitle')}
          description={t('incidents.empty.noMatchDescription')}
        />
      ) : (
        <div className={styles.layout}>
          <Table
            caption={t('incidents.table.caption')}
            columns={columns}
            rows={filteredIncidents}
            rowKey={(r) => r.id}
          />
          {selected ? <Timeline incidentId={selected} /> : null}
        </div>
      )}
    </Page>
  )
}
