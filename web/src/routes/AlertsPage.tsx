import { useMemo, useState, type FormEvent } from 'react'
import styles from './alerts.module.css'
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
  Modal,
  Select,
  Table,
  useToast,
  type Column,
} from '../components'
import { severityTone } from '../api/incidents'
import {
  alertStateOf,
  useAckAlert,
  useActiveAlerts,
  useAlertRules,
  useDeleteAlertRule,
  useSaveAlertRule,
  useSilenceAlert,
  type ActiveAlert,
  type AlertRule,
  type AlertRuleInput,
} from '../api/alerts'

function when(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function labelText(labels?: Record<string, string>): string {
  if (!labels) return ''
  return Object.entries(labels)
    .filter(([k]) => k !== 'tenant_id') // the tenant is ambient (always-visible indicator)
    .map(([k, v]) => `${k}=${v}`)
    .join(', ')
}

/** stateTone maps an active alert's display state to a Badge tone. */
function stateTone(s: 'firing' | 'silenced' | 'acked'): 'danger' | 'neutral' | 'info' {
  if (s === 'firing') return 'danger'
  if (s === 'acked') return 'info'
  return 'neutral'
}

/** ActiveAlertDetail shows one firing series with its operator actions —
 *  everything rendered comes from the engine response, never client state. */
function ActiveAlertDetail({ alert, onClose }: { alert: ActiveAlert; onClose: () => void }) {
  const { push } = useToast()
  const silence = useSilenceAlert()
  const ack = useAckAlert()
  const [minutes, setMinutes] = useState('60')
  const state = alertStateOf(alert)

  const act = (fn: () => Promise<unknown>, ok: string) => {
    void fn()
      .then(() => push({ tone: 'success', title: ok, message: alert.rule_name }))
      .catch((e) => push({ tone: 'danger', title: 'Action failed', message: (e as Error).message }))
  }

  return (
    <Modal open onClose={onClose} title={alert.rule_name}>
      <dl className={styles.kv}>
        <dt>State</dt>
        <dd>
          <Badge tone={stateTone(state)}>{state}</Badge>{' '}
          <Badge tone={severityTone(alert.severity)}>{alert.severity}</Badge>
        </dd>
        <dt>Reason</dt>
        <dd>{alert.reason}</dd>
        <dt>Metric</dt>
        <dd>
          {alert.metric}
          {alert.labels && labelText(alert.labels) ? ` {${labelText(alert.labels)}}` : ''}
        </dd>
        <dt>Value</dt>
        <dd>{alert.value}</dd>
        <dt>Firing since</dt>
        <dd>{when(alert.since)}</dd>
        {alert.silenced_until ? (
          <>
            <dt>Silenced until</dt>
            <dd>{when(alert.silenced_until)}</dd>
          </>
        ) : null}
        {alert.acked_by ? (
          <>
            <dt>Acknowledged</dt>
            <dd>
              {alert.acked_by} at {when(alert.acked_at)}
            </dd>
          </>
        ) : null}
      </dl>

      <div className={styles.actionsRow}>
        <Select
          label="Silence for"
          value={minutes}
          onChange={(e) => setMinutes(e.target.value)}
          options={[
            { value: '15', label: '15 minutes' },
            { value: '60', label: '1 hour' },
            { value: '240', label: '4 hours' },
            { value: '1440', label: '24 hours' },
          ]}
        />
        <Button
          variant="secondary"
          disabled={silence.isPending}
          onClick={() =>
            act(
              () =>
                silence.mutateAsync({ fingerprint: alert.fingerprint, minutes: Number(minutes) }),
              'Alert silenced',
            )
          }
        >
          Silence
        </Button>
        {alert.silenced_until ? (
          <Button
            variant="ghost"
            disabled={silence.isPending}
            onClick={() =>
              act(
                () => silence.mutateAsync({ fingerprint: alert.fingerprint, minutes: 0 }),
                'Silence cleared',
              )
            }
          >
            Unsilence
          </Button>
        ) : null}
        <Button
          variant="secondary"
          disabled={ack.isPending || !!alert.acked_by}
          onClick={() =>
            act(() => ack.mutateAsync({ fingerprint: alert.fingerprint }), 'Alert acknowledged')
          }
        >
          {alert.acked_by ? 'Acknowledged' : 'Acknowledge'}
        </Button>
      </div>
    </Modal>
  )
}

/** RuleForm creates or edits one alert rule (server-validated; errors surface
 *  inline via toast). */
function RuleForm({ rule, onClose }: { rule?: AlertRule; onClose: () => void }) {
  const { push } = useToast()
  const save = useSaveAlertRule()
  const [name, setName] = useState(rule?.name ?? '')
  const [metric, setMetric] = useState(rule?.metric ?? '')
  const [type, setType] = useState<'threshold' | 'baseline'>(rule?.type ?? 'threshold')
  const [comparison, setComparison] = useState(rule?.comparison ?? 'gt')
  const [threshold, setThreshold] = useState(String(rule?.threshold ?? '100'))
  const [windowN, setWindowN] = useState(String(rule?.window ?? '20'))
  const [sensitivity, setSensitivity] = useState(String(rule?.sensitivity ?? '3'))
  const [severity, setSeverity] = useState(rule?.severity ?? 'warning')
  const [forN, setForN] = useState(String(rule?.for_n ?? '1'))
  const [enabled, setEnabled] = useState(rule?.enabled ?? true)

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const input: AlertRuleInput = {
      name,
      metric,
      enabled,
      type,
      severity,
      for_n: Number(forN) || 1,
      ...(type === 'threshold'
        ? { comparison: comparison, threshold: Number(threshold) }
        : { window: Number(windowN) || 20, sensitivity: Number(sensitivity) || 3 }),
    }
    save.mutate(
      { id: rule?.id, input },
      {
        onSuccess: (saved) => {
          push({
            tone: 'success',
            title: rule ? 'Rule updated' : 'Rule created',
            message: saved.name,
          })
          onClose()
        },
        onError: (err) => push({ tone: 'danger', title: 'Save failed', message: err.message }),
      },
    )
  }

  return (
    <Modal open onClose={onClose} title={rule ? `Edit rule: ${rule.name}` : 'Create alert rule'}>
      <form onSubmit={submit} className={styles.formGrid}>
        <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} required />
        <Field
          label="Metric"
          value={metric}
          onChange={(e) => setMetric(e.target.value)}
          required
          hint="A TSDB series name, e.g. probectl_result_rtt_ms"
        />
        <Select
          label="Type"
          value={type}
          onChange={(e) => setType(e.target.value as 'threshold' | 'baseline')}
          options={[
            { value: 'threshold', label: 'Threshold' },
            { value: 'baseline', label: 'Baseline (anomaly)' },
          ]}
        />
        {type === 'threshold' ? (
          <>
            <Select
              label="Comparison"
              value={comparison}
              onChange={(e) => setComparison(e.target.value as typeof comparison)}
              options={[
                { value: 'gt', label: '> greater than' },
                { value: 'gte', label: '≥ at least' },
                { value: 'lt', label: '< less than' },
                { value: 'lte', label: '≤ at most' },
              ]}
            />
            <Field
              label="Threshold"
              type="number"
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
              required
            />
          </>
        ) : (
          <>
            <Field
              label="Window (samples)"
              type="number"
              value={windowN}
              onChange={(e) => setWindowN(e.target.value)}
              hint="History before the baseline evaluates"
            />
            <Field
              label="Sensitivity (σ)"
              type="number"
              value={sensitivity}
              onChange={(e) => setSensitivity(e.target.value)}
              hint="Deviation in standard deviations"
            />
          </>
        )}
        <Select
          label="Severity"
          value={severity}
          onChange={(e) => setSeverity(e.target.value as typeof severity)}
          options={[
            { value: 'info', label: 'Info' },
            { value: 'warning', label: 'Warning' },
            { value: 'critical', label: 'Critical' },
          ]}
        />
        <Field
          label="For N evaluations"
          type="number"
          value={forN}
          onChange={(e) => setForN(e.target.value)}
          hint="Consecutive breaches before firing (debounce)"
        />
        <label className={styles.check}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />{' '}
          Enabled
        </label>
        <div className={styles.actionsRow}>
          <Button type="submit" disabled={save.isPending}>
            {rule ? 'Save changes' : 'Create rule'}
          </Button>
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </div>
      </form>
    </Modal>
  )
}

type StateFilter = 'all' | 'firing' | 'silenced' | 'acked'
type SeverityFilter = 'all' | 'info' | 'warning' | 'critical'

/** AlertsPage is the S16 alerting surface (S-FE1): the engine's firing alerts
 *  (filter, detail, silence, acknowledge) over the durable rule config. */
export function AlertsPage() {
  const active = useActiveAlerts()
  const rules = useAlertRules()
  const del = useDeleteAlertRule()
  const { push } = useToast()
  const [stateFilter, setStateFilter] = useState<StateFilter>('all')
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all')
  const [detail, setDetail] = useState<string | null>(null) // fingerprint
  const [editing, setEditing] = useState<AlertRule | null>(null)
  const [creating, setCreating] = useState(false)

  const items = useMemo(() => {
    const all = active.data?.items ?? []
    return all.filter(
      (a) =>
        (stateFilter === 'all' || alertStateOf(a) === stateFilter) &&
        (severityFilter === 'all' || a.severity === severityFilter),
    )
  }, [active.data, stateFilter, severityFilter])

  const detailAlert = items.find((a) => a.fingerprint === detail) ?? null

  const activeColumns: Column<ActiveAlert>[] = [
    {
      key: 'state',
      header: 'State',
      render: (a) => <Badge tone={stateTone(alertStateOf(a))}>{alertStateOf(a)}</Badge>,
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (a) => <Badge tone={severityTone(a.severity)}>{a.severity}</Badge>,
    },
    { key: 'rule', header: 'Rule', render: (a) => a.rule_name },
    {
      key: 'series',
      header: 'Series',
      render: (a) => `${a.metric}${labelText(a.labels) ? ` {${labelText(a.labels)}}` : ''}`,
    },
    { key: 'value', header: 'Value', numeric: true, render: (a) => String(a.value) },
    { key: 'since', header: 'Since', render: (a) => when(a.since) },
    {
      key: 'actions',
      header: <span className="sr-only">Actions</span>,
      align: 'end',
      render: (a) => (
        <Button size="sm" variant="ghost" onClick={() => setDetail(a.fingerprint)}>
          Details
        </Button>
      ),
    },
  ]

  const ruleColumns: Column<AlertRule>[] = [
    { key: 'name', header: 'Name', render: (r) => r.name },
    { key: 'metric', header: 'Metric', render: (r) => r.metric },
    {
      key: 'condition',
      header: 'Condition',
      render: (r) =>
        r.type === 'threshold'
          ? `${r.comparison ?? 'gt'} ${r.threshold ?? 0}`
          : `baseline ±${r.sensitivity ?? 3}σ`,
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (r) => <Badge tone={severityTone(r.severity)}>{r.severity}</Badge>,
    },
    {
      key: 'enabled',
      header: 'Enabled',
      render: (r) => (
        <Badge tone={r.enabled ? 'success' : 'neutral'}>{r.enabled ? 'on' : 'off'}</Badge>
      ),
    },
    {
      key: 'actions',
      header: <span className="sr-only">Actions</span>,
      align: 'end',
      render: (r) => (
        <>
          <Button size="sm" variant="ghost" onClick={() => setEditing(r)}>
            Edit
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() =>
              del.mutate(r.id, {
                onSuccess: () => push({ tone: 'success', title: 'Rule deleted', message: r.name }),
                onError: (e) =>
                  push({ tone: 'danger', title: 'Delete failed', message: e.message }),
              })
            }
          >
            Delete
          </Button>
        </>
      ),
    },
  ]

  return (
    <Page title="Alerts" subtitle="Firing alerts (engine truth) and the rules that drive them.">
      <div className={styles.stack}>
        <Card>
          <CardHeader
            title="Active alerts"
            actions={
              <div className={styles.actionsRow}>
                <Select
                  label="State"
                  value={stateFilter}
                  onChange={(e) => setStateFilter(e.target.value as StateFilter)}
                  options={[
                    { value: 'all', label: 'All states' },
                    { value: 'firing', label: 'Firing' },
                    { value: 'silenced', label: 'Silenced' },
                    { value: 'acked', label: 'Acknowledged' },
                  ]}
                />
                <Select
                  label="Severity"
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
                  options={[
                    { value: 'all', label: 'All severities' },
                    { value: 'critical', label: 'Critical' },
                    { value: 'warning', label: 'Warning' },
                    { value: 'info', label: 'Info' },
                  ]}
                />
              </div>
            }
          />
          <CardBody>
            {active.isLoading ? (
              <LoadingState label="Loading active alerts…" />
            ) : active.isError ? (
              <ErrorState description="Could not load active alerts." />
            ) : (
              <>
                {active.data && !active.data.evaluator_running ? (
                  <p role="status" className={styles.notice}>
                    <Badge tone="warning">evaluator off</Badge> The alert evaluator is not running
                    for this tenant — firing state is unavailable (rules below remain editable).
                  </p>
                ) : null}
                <Table
                  caption="Active alerts"
                  columns={activeColumns}
                  rows={items}
                  rowKey={(a) => a.fingerprint}
                  empty={
                    <EmptyState
                      title="No active alerts"
                      description="Nothing is firing for this tenant."
                    />
                  }
                />
              </>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Alert rules"
            actions={<Button onClick={() => setCreating(true)}>Create rule</Button>}
          />
          <CardBody>
            {rules.isLoading ? (
              <LoadingState label="Loading rules…" />
            ) : rules.isError ? (
              <ErrorState description="Could not load alert rules." />
            ) : (
              <Table
                caption="Alert rules"
                columns={ruleColumns}
                rows={rules.data ?? []}
                rowKey={(r) => r.id}
                empty={
                  <EmptyState
                    title="No alert rules"
                    description="Create a rule to start alerting on any probectl metric."
                  />
                }
              />
            )}
          </CardBody>
        </Card>
      </div>
      {detailAlert ? (
        <ActiveAlertDetail alert={detailAlert} onClose={() => setDetail(null)} />
      ) : null}
      {creating ? <RuleForm onClose={() => setCreating(false)} /> : null}
      {editing ? <RuleForm rule={editing} onClose={() => setEditing(null)} /> : null}
    </Page>
  )
}
