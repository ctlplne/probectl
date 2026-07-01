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

/** Timeline overlays every plane's signals for one incident in time order. The
 *  rendering is plane-agnostic (it reads the generic Signal), so a new plane
 *  appears here with no UI change. */
function Timeline({ incidentId }: { incidentId: string }) {
  const navigate = useNavigate()
  const incident = useIncident(incidentId)
  const resolve = useResolveIncident(incidentId)
  const remediations = useRemediations()
  const createProposal = useCreateRemediationProposal()
  const { push } = useToast()

  if (incident.isLoading) return <LoadingState label="Loading incident…" />
  if (incident.isError || !incident.data)
    return <ErrorState description="Could not load the incident." />

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
        push({ tone: 'success', title: 'Proposal created', message: `${p.id} is proposed` }),
      onError: (err) =>
        push({
          tone: 'danger',
          title: 'Proposal failed',
          message: err instanceof Error ? err.message : 'Could not create proposal',
        }),
    })
  }

  return (
    <Card>
      <CardHeader
        title={inc.title || inc.target || 'Incident'}
        actions={
          <div className={styles.actionsRow}>
            <Button variant="secondary" onClick={askAboutIncident}>
              Ask about this incident
            </Button>
            {canPropose ? (
              <Button
                variant="secondary"
                onClick={proposeIncidentReview}
                disabled={createProposal.isPending}
              >
                {createProposal.isPending ? 'Proposing...' : 'Propose remediation'}
              </Button>
            ) : null}
            {inc.status === 'open' ? (
              <Button
                variant="secondary"
                onClick={() => resolve.mutate()}
                disabled={resolve.isPending}
              >
                Resolve
              </Button>
            ) : (
              <Badge tone="neutral">resolved</Badge>
            )}
          </div>
        }
      />
      <CardBody>
        <dl className={styles.meta}>
          <div>
            <dt>Severity</dt>
            <dd>
              <Badge tone={severityTone(inc.severity)}>{inc.severity}</Badge>
            </dd>
          </div>
          <div>
            <dt>Target</dt>
            <dd>{inc.target || inc.prefix || '—'}</dd>
          </div>
          <div>
            <dt>Signals</dt>
            <dd>{inc.signal_count}</dd>
          </div>
          <div>
            <dt>Started</dt>
            <dd>
              <DateTime value={inc.started_at} />
            </dd>
          </div>
        </dl>

        <ol className={styles.timeline} aria-label="Incident timeline">
          {signals.map((s: Signal, i) => (
            <li key={`${s.plane}-${i}`} className={styles.event}>
              <DateTime value={s.occurred_at} className={styles.time} />
              <span className={styles.dot}>
                <StatusDot tone={severityTone(s.severity)} label={s.severity} />
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
      header: 'Severity',
      render: (r) => <Badge tone={severityTone(r.severity)}>{r.severity}</Badge>,
    },
    {
      key: 'title',
      header: 'Incident',
      render: (r) => (
        <Button variant="ghost" onClick={() => setSelected(r.id)} aria-pressed={selected === r.id}>
          {r.title || r.target || r.id}
        </Button>
      ),
    },
    { key: 'target', header: 'Target', render: (r) => r.target || r.prefix || '—' },
    {
      key: 'status',
      header: 'Status',
      render: (r) => (
        <StatusDot tone={r.status === 'open' ? 'warning' : 'success'} label={r.status} />
      ),
    },
    { key: 'signals', header: 'Signals', numeric: true, render: (r) => r.signal_count },
    {
      key: 'last_seen',
      header: 'Last activity',
      render: (r) => <DateTime value={r.last_seen_at} />,
    },
  ]

  return (
    <Page title="Incidents" subtitle="Related signals across planes, grouped into one timeline.">
      <FilterBar>
        <Field
          label="Find"
          value={query}
          onChange={(e) => setFilter({ incident_q: e.target.value })}
          placeholder="target, title, prefix"
        />
        <Select
          label="Status"
          value={status}
          onChange={(e) => setFilter({ incident_status: e.target.value })}
          options={[
            { value: 'all', label: 'All statuses' },
            { value: 'open', label: 'Open' },
            { value: 'resolved', label: 'Resolved' },
          ]}
        />
        <Select
          label="Severity"
          value={severity}
          onChange={(e) => setFilter({ incident_severity: e.target.value })}
          options={[
            { value: 'all', label: 'All severities' },
            { value: 'critical', label: 'Critical' },
            { value: 'warning', label: 'Warning' },
            { value: 'info', label: 'Info' },
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
          placeholder="Critical open"
        />
      </FilterBar>
      {incidents.isLoading ? (
        <LoadingState label="Loading incidents…" />
      ) : incidents.isError ? (
        <ErrorState description="Could not load incidents." />
      ) : !incidents.data || incidents.data.length === 0 ? (
        <EmptyState
          title="No incidents"
          description="Correlated signals will appear here as incidents."
        />
      ) : filteredIncidents.length === 0 ? (
        <EmptyState title="No matching incidents" description="No incidents matched." />
      ) : (
        <div className={styles.layout}>
          <Table
            caption="Incidents by severity and recent activity"
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
