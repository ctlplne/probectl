import { useEffect, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import styles from './incidents.module.css'
import { Page } from './pages'
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  Select,
  StatusDot,
  Table,
  type Column,
} from '../components'
import { type Incident, severityTone, useIncidents } from '../api/incidents'
import { DateTime } from '../time/DateTime'
import { FilterBar, SavedViews } from './listControls'
import { filterValue, filtersForSave, setURLFilters } from './urlFilters'
import { useI18n } from '../i18n/useI18n'
import type { MessageKey } from '../i18n/messages'
import { parsePivotContext, replacePivotContext, type PivotContext } from './pivotContext'
import { IncidentRoom } from './IncidentRoom'

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

export function IncidentsPage() {
  const { t } = useI18n()
  const incidents = useIncidents()
  // Deep-link support (?incident=<id>): other surfaces (threat triage S-FE3,
  // alerts) pivot straight into a specific incident's timeline.
  const [params, setParams] = useSearchParams()
  const defaults = { incident_q: '', incident_status: 'all', incident_severity: 'all' }
  const query = filterValue(params, 'incident_q')
  const status = filterValue(params, 'incident_status', 'all')
  const severity = filterValue(params, 'incident_severity', 'all')
  const parsedPivot = useMemo(
    () =>
      parsePivotContext(params, {
        authorize: (reference) =>
          reference.kind !== 'incident' ||
          !incidents.data ||
          incidents.data.some((incident) => incident.id === reference.id),
      }),
    [incidents.data, params],
  )
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
  const requestedIncident = parsedPivot.context.incidentId ?? params.get('incident')
  const selected =
    (requestedIncident && filteredIncidents.some((incident) => incident.id === requestedIncident)
      ? requestedIncident
      : filteredIncidents[0]?.id) ?? null
  const activeFilters = filtersForSave(params, defaults)
  const returnParams = new URLSearchParams(activeFilters)
  if (selected) returnParams.set('incident', selected)
  const pivotContext: PivotContext = {
    ...parsedPivot.context,
    filters: { ...parsedPivot.context.filters, ...activeFilters },
    returnTo: returnParams.size > 0 ? `/incidents?${returnParams.toString()}` : '/incidents',
  }

  useEffect(() => {
    if (incidents.data && parsedPivot.hasContract && !parsedPivot.referencesValid) {
      setParams(replacePivotContext(params, parsedPivot.context), { replace: true })
    }
  }, [incidents.data, params, parsedPivot, setParams])

  function selectIncident(incident: Incident) {
    const next = new URLSearchParams(
      replacePivotContext(params, {
        ...pivotContext,
        incidentId: incident.id,
        from: incident.started_at,
        to: incident.last_seen_at,
        selection: undefined,
      }),
    )
    next.delete('incident')
    setParams(next)
  }

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
        <Button variant="ghost" onClick={() => selectIncident(r)} aria-pressed={selected === r.id}>
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
          {selected ? <IncidentRoom incidentId={selected} pivotContext={pivotContext} /> : null}
        </div>
      )}
    </Page>
  )
}
