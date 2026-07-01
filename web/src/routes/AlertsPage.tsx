import { useId, useMemo, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
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
  useDeleteMaintenanceWindow,
  useMaintenanceWindows,
  useDeleteAlertRule,
  useOncallStatus,
  useSaveMaintenanceWindow,
  useSaveAlertRule,
  useSilenceAlert,
  useTestAlertChannel,
  useTestOncallConnector,
  type ActiveAlert,
  type AlertRule,
  type AlertRuleInput,
  type ChannelSpec,
  type MaintenanceRecurrence,
  type MaintenanceWindow,
  type MaintenanceWindowInput,
  type OncallInboundWebhook,
  type OncallOutboundConnector,
} from '../api/alerts'
import { DateTime } from '../time/DateTime'
import { useI18n } from '../i18n/useI18n'
import { FilterBar, SavedViews } from './listControls'
import { filterValue, filtersForSave, setURLFilters } from './urlFilters'

function labelText(labels?: Record<string, string>): string {
  if (!labels) return ''
  return Object.entries(labels)
    .filter(([k]) => k !== 'tenant_id') // the tenant is ambient (always-visible indicator)
    .map(([k, v]) => `${k}=${v}`)
    .join(', ')
}

function recipientsText(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

function channelSummary(channels?: ChannelSpec[]): string {
  if (!channels || channels.length === 0) return 'none'
  return channels
    .map((c) => {
      if (c.type === 'webhook') return `webhook ${c.secret ? '(signed)' : '(unsigned)'}`
      return `email ${c.recipients?.length ?? 0}`
    })
    .join(', ')
}

function providerLabel(provider: string): string {
  return provider
    .split(/[-_]/)
    .map((s) => (s ? s[0].toUpperCase() + s.slice(1) : s))
    .join(' ')
}

function detectedTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

function dateTimeInputValue(iso?: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const local = new Date(d.getTime() - d.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}

function dateTimeInputToISO(value: string, timezone: string): string {
  if (!value) return ''
  if (timezone === 'UTC') return new Date(`${value}:00Z`).toISOString()
  return new Date(value).toISOString()
}

function splitCSV(value: string): string[] {
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

function formatMatch(match?: Record<string, string>): string {
  if (!match) return ''
  return Object.entries(match)
    .map(([k, v]) => `${k}=${v}`)
    .join('\n')
}

function parseMatch(value: string): Record<string, string> | undefined {
  const out: Record<string, string> = {}
  for (const raw of value.split(/[,\n]/)) {
    const item = raw.trim()
    if (!item) continue
    const i = item.indexOf('=')
    if (i <= 0) continue
    const key = item.slice(0, i).trim()
    const val = item.slice(i + 1).trim()
    if (key && val) out[key] = val
  }
  return Object.keys(out).length > 0 ? out : undefined
}

function recurrenceLabel(r?: MaintenanceRecurrence): string {
  if (r === 'daily') return 'daily'
  if (r === 'weekly') return 'weekly'
  return 'one-time'
}

function maintenanceScope(w: MaintenanceWindow): string {
  const parts = []
  if (w.rule_ids && w.rule_ids.length > 0) parts.push(`rules ${w.rule_ids.join(', ')}`)
  if (w.match && Object.keys(w.match).length > 0) parts.push(formatMatch(w.match).replace(/\n/g, ', '))
  return parts.length > 0 ? parts.join('; ') : 'all alerts'
}

function activeWindowEnd(w: MaintenanceWindow, at = Date.now()): string | null {
  const start = new Date(w.starts_at).getTime()
  const end = new Date(w.ends_at).getTime()
  if (Number.isNaN(start) || Number.isNaN(end) || end <= start) return null
  const duration = end - start
  if (!w.recurrence) return at >= start && at < end ? new Date(end).toISOString() : null

  const period = w.recurrence === 'daily' ? 86_400_000 : w.recurrence === 'weekly' ? 604_800_000 : 0
  if (period <= 0 || duration >= period || at < start) return null
  const n = Math.floor((at - start) / period)
  const occurrenceStart = start + n * period
  const occurrenceEnd = occurrenceStart + duration
  return at >= occurrenceStart && at < occurrenceEnd ? new Date(occurrenceEnd).toISOString() : null
}

function maintenanceMatchesAlert(w: MaintenanceWindow, a: ActiveAlert): boolean {
  if (w.rule_ids && w.rule_ids.length > 0 && !w.rule_ids.includes(a.rule_id)) return false
  for (const [key, want] of Object.entries(w.match ?? {})) {
    if (a.labels?.[key] !== want) return false
  }
  return true
}

function activeMaintenanceForAlert(a: ActiveAlert, windows: MaintenanceWindow[]): MaintenanceWindow[] {
  const now = Date.now()
  return windows.filter((w) => maintenanceMatchesAlert(w, a) && activeWindowEnd(w, now))
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
        <dd>
          <DateTime value={alert.since} />
        </dd>
        {alert.silenced_until ? (
          <>
            <dt>Silenced until</dt>
            <dd>
              <DateTime value={alert.silenced_until} />
            </dd>
          </>
        ) : null}
        {alert.acked_by ? (
          <>
            <dt>Acknowledged</dt>
            <dd>
              {alert.acked_by} at <DateTime value={alert.acked_at} />
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
  const { t } = useI18n()
  const { push } = useToast()
  const save = useSaveAlertRule()
  const testChannel = useTestAlertChannel()
  const initialChannel = rule?.channels?.[0]
  const [name, setName] = useState(rule?.name ?? '')
  const [metric, setMetric] = useState(rule?.metric ?? '')
  const [type, setType] = useState<'threshold' | 'baseline'>(rule?.type ?? 'threshold')
  const [comparison, setComparison] = useState(rule?.comparison ?? 'gt')
  const [threshold, setThreshold] = useState(String(rule?.threshold ?? '100'))
  const [windowN, setWindowN] = useState(String(rule?.window ?? '20'))
  const [sensitivity, setSensitivity] = useState(String(rule?.sensitivity ?? '3'))
  const [severity, setSeverity] = useState(rule?.severity ?? 'warning')
  const [forN, setForN] = useState(String(rule?.for_n ?? '1'))
  const [renotify, setRenotify] = useState(String(rule?.renotify_seconds ?? '0'))
  const [enabled, setEnabled] = useState(rule?.enabled ?? true)
  const [channelType, setChannelType] = useState<'none' | 'webhook' | 'email'>(
    initialChannel?.type ?? 'none',
  )
  const [channelURL, setChannelURL] = useState(initialChannel?.url ?? '')
  const [channelSecret, setChannelSecret] = useState(initialChannel?.secret ?? '')
  const [recipients, setRecipients] = useState(initialChannel?.recipients?.join(', ') ?? '')

  const currentChannel = (): ChannelSpec | null => {
    if (channelType === 'none') return null
    if (channelType === 'webhook') {
      return { type: 'webhook', url: channelURL.trim(), secret: channelSecret.trim() }
    }
    return { type: 'email', recipients: recipientsText(recipients) }
  }

  const canTestChannel = () => {
    const ch = currentChannel()
    if (!ch) return false
    if (ch.type === 'webhook') return !!ch.url
    return (ch.recipients?.length ?? 0) > 0
  }

  const testCurrentChannel = () => {
    const channel = currentChannel()
    if (!channel) return
    testChannel.mutate(
      { ruleName: name || 'probectl test alert', metric: metric || 'probectl_test_delivery', channel },
      {
        onSuccess: () =>
          push({ tone: 'success', title: 'Test delivery sent', message: channel.type }),
        onError: (err) =>
          push({ tone: 'danger', title: 'Test delivery failed', message: err.message }),
      },
    )
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const channel = currentChannel()
    const input: AlertRuleInput = {
      name,
      metric,
      enabled,
      type,
      severity,
      for_n: Number(forN) || 1,
      renotify_seconds: Number(renotify) || 0,
      channels: channel ? [channel] : [],
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
            title: rule ? t('alerts.rule.updated') : t('alerts.rule.created'),
            message: saved.name,
          })
          onClose()
        },
        onError: (err) => push({ tone: 'danger', title: t('alerts.rule.saveFailed'), message: err.message }),
      },
    )
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={rule ? t('alerts.rule.editTitle', { name: rule.name }) : t('alerts.rule.createTitle')}
    >
      <form onSubmit={submit} className={styles.formGrid}>
        <Field label={t('alerts.rule.name')} value={name} onChange={(e) => setName(e.target.value)} required />
        <Field
          label={t('alerts.rule.metric')}
          value={metric}
          onChange={(e) => setMetric(e.target.value)}
          required
          hint={t('alerts.rule.metricHint')}
        />
        <Select
          label={t('alerts.rule.type')}
          value={type}
          onChange={(e) => setType(e.target.value as 'threshold' | 'baseline')}
          options={[
            { value: 'threshold', label: t('alerts.rule.typeThreshold') },
            { value: 'baseline', label: t('alerts.rule.typeBaseline') },
          ]}
        />
        {type === 'threshold' ? (
          <>
            <Select
              label={t('alerts.rule.comparison')}
              value={comparison}
              onChange={(e) => setComparison(e.target.value as typeof comparison)}
              options={[
                { value: 'gt', label: t('alerts.rule.comparisonGt') },
                { value: 'gte', label: t('alerts.rule.comparisonGte') },
                { value: 'lt', label: t('alerts.rule.comparisonLt') },
                { value: 'lte', label: t('alerts.rule.comparisonLte') },
              ]}
            />
            <Field
              label={t('alerts.rule.threshold')}
              type="number"
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
              required
            />
          </>
        ) : (
          <>
            <Field
              label={t('alerts.rule.windowSamples')}
              type="number"
              value={windowN}
              onChange={(e) => setWindowN(e.target.value)}
              hint={t('alerts.rule.windowHint')}
            />
            <Field
              label={t('alerts.rule.sensitivity')}
              type="number"
              value={sensitivity}
              onChange={(e) => setSensitivity(e.target.value)}
              hint={t('alerts.rule.sensitivityHint')}
            />
          </>
        )}
        <Select
          label={t('alerts.rule.severity')}
          value={severity}
          onChange={(e) => setSeverity(e.target.value as typeof severity)}
          options={[
            { value: 'info', label: t('alerts.rule.severityInfo') },
            { value: 'warning', label: t('alerts.rule.severityWarning') },
            { value: 'critical', label: t('alerts.rule.severityCritical') },
          ]}
        />
        <Field
          label={t('alerts.rule.forEvaluations')}
          type="number"
          value={forN}
          onChange={(e) => setForN(e.target.value)}
          hint={t('alerts.rule.forEvaluationsHint')}
        />
        <label className={styles.check}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />{' '}
          {t('alerts.rule.enabled')}
        </label>
        <Field
          label={t('alerts.rule.renotify')}
          type="number"
          value={renotify}
          onChange={(e) => setRenotify(e.target.value)}
          hint={t('alerts.rule.renotifyHint')}
        />
        <div className={styles.formSection}>
          <Select
            label={t('alerts.rule.deliveryChannel')}
            value={channelType}
            onChange={(e) => setChannelType(e.target.value as typeof channelType)}
            options={[
              { value: 'none', label: t('alerts.rule.channelNone') },
              { value: 'webhook', label: t('alerts.rule.channelWebhook') },
              { value: 'email', label: t('alerts.rule.channelEmail') },
            ]}
          />
          {channelType === 'webhook' ? (
            <>
              <Field
                label={t('alerts.rule.webhookUrl')}
                value={channelURL}
                onChange={(e) => setChannelURL(e.target.value)}
                placeholder="https://hooks.example/alerts"
              />
              <Field
                label={t('alerts.rule.webhookSecret')}
                type="password"
                value={channelSecret}
                onChange={(e) => setChannelSecret(e.target.value)}
                hint={
                  initialChannel?.secret === '***'
                    ? t('alerts.rule.secretStoredHint')
                    : t('alerts.rule.secretNewHint')
                }
              />
            </>
          ) : null}
          {channelType === 'email' ? (
            <Field
              label={t('alerts.rule.recipients')}
              value={recipients}
              onChange={(e) => setRecipients(e.target.value)}
              placeholder="ops@example.com, noc@example.com"
            />
          ) : null}
          {channelType !== 'none' ? (
            <div className={styles.actionsRow}>
              <Button
                type="button"
                variant="secondary"
                disabled={testChannel.isPending || !canTestChannel()}
                onClick={testCurrentChannel}
              >
                {t('alerts.rule.testChannel')}
              </Button>
              <span className={styles.muted}>{t('alerts.rule.secretsWriteOnly')}</span>
            </div>
          ) : null}
        </div>
        <div className={styles.actionsRow}>
          <Button type="submit" disabled={save.isPending}>
            {rule ? t('alerts.rule.saveChanges') : t('alerts.rule.createRule')}
          </Button>
          <Button type="button" variant="ghost" onClick={onClose}>
            {t('alerts.rule.cancel')}
          </Button>
        </div>
      </form>
    </Modal>
  )
}

function TextAreaField({
  label,
  value,
  onChange,
  placeholder,
  hint,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  placeholder?: string
  hint?: string
}) {
  const id = useId()
  const hintId = `${id}-hint`
  return (
    <div className={styles.textareaField}>
      <label className={styles.textareaLabel} htmlFor={id}>
        {label}
      </label>
      <textarea
        id={id}
        className={styles.textarea}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-describedby={hint ? hintId : undefined}
      />
      {hint ? (
        <p id={hintId} className={styles.muted}>
          {hint}
        </p>
      ) : null}
    </div>
  )
}

function MaintenanceWindowForm({
  window,
  onClose,
}: {
  window?: MaintenanceWindow
  onClose: () => void
}) {
  const { push } = useToast()
  const save = useSaveMaintenanceWindow()
  const localZone = detectedTimeZone()
  const zoneOptions =
    localZone === 'UTC'
      ? [{ value: 'UTC', label: 'UTC' }]
      : [
          { value: localZone, label: localZone },
          { value: 'UTC', label: 'UTC' },
        ]
  const [name, setName] = useState(window?.name ?? '')
  const [startsAt, setStartsAt] = useState(dateTimeInputValue(window?.starts_at))
  const [endsAt, setEndsAt] = useState(dateTimeInputValue(window?.ends_at))
  const [timezone, setTimezone] = useState(localZone)
  const [recurrence, setRecurrence] = useState<MaintenanceRecurrence | 'none'>(
    window?.recurrence || 'none',
  )
  const [ruleIDs, setRuleIDs] = useState(window?.rule_ids?.join(', ') ?? '')
  const [match, setMatch] = useState(formatMatch(window?.match))
  const [reason, setReason] = useState(window?.reason ?? '')

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const input: MaintenanceWindowInput = {
      id: window?.id,
      name: name.trim(),
      starts_at: dateTimeInputToISO(startsAt, timezone),
      ends_at: dateTimeInputToISO(endsAt, timezone),
      recurrence: recurrence === 'none' ? undefined : recurrence,
      rule_ids: splitCSV(ruleIDs),
      match: parseMatch(match),
      reason: reason.trim(),
    }
    save.mutate(input, {
      onSuccess: (saved) => {
        push({
          tone: 'success',
          title: window ? 'Window updated' : 'Window scheduled',
          message: saved.name,
        })
        onClose()
      },
      onError: (err) => push({ tone: 'danger', title: 'Save failed', message: err.message }),
    })
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={window ? `Edit window: ${window.name}` : 'Schedule maintenance window'}
    >
      <form onSubmit={submit} className={styles.formGrid}>
        <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} required />
        <div className={styles.inlineGrid}>
          <Field
            label="Starts at"
            type="datetime-local"
            value={startsAt}
            onChange={(e) => setStartsAt(e.target.value)}
            required
          />
          <Field
            label="Ends at"
            type="datetime-local"
            value={endsAt}
            onChange={(e) => setEndsAt(e.target.value)}
            required
          />
        </div>
        <div className={styles.inlineGrid}>
          <Select
            label="Time zone"
            value={timezone}
            onChange={(e) => setTimezone(e.target.value)}
            options={zoneOptions}
          />
          <Select
            label="Recurrence"
            value={recurrence}
            onChange={(e) => setRecurrence(e.target.value as MaintenanceRecurrence | 'none')}
            options={[
              { value: 'none', label: 'One-time' },
              { value: 'daily', label: 'Daily' },
              { value: 'weekly', label: 'Weekly' },
            ]}
          />
        </div>
        <Field
          label="Rule IDs"
          value={ruleIDs}
          onChange={(e) => setRuleIDs(e.target.value)}
          placeholder="r1, r2"
        />
        <TextAreaField
          label="Match labels"
          value={match}
          onChange={setMatch}
          placeholder="target=db"
          hint="One key=value per line."
        />
        <TextAreaField label="Reason" value={reason} onChange={setReason} />
        <div className={styles.actionsRow}>
          <Button type="submit" disabled={save.isPending}>
            {window ? 'Save window' : 'Schedule window'}
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
  const maintenance = useMaintenanceWindows()
  const del = useDeleteAlertRule()
  const delMaintenance = useDeleteMaintenanceWindow()
  const { push } = useToast()
  const [params, setParams] = useSearchParams()
  const defaults = { alert_q: '', alert_state: 'all', alert_severity: 'all' }
  const query = filterValue(params, 'alert_q')
  const stateFilter = filterValue(params, 'alert_state', 'all') as StateFilter
  const severityFilter = filterValue(params, 'alert_severity', 'all') as SeverityFilter
  const setFilter = (patch: Record<string, string>) =>
    setURLFilters(params, setParams, defaults, patch)
  const [detail, setDetail] = useState<string | null>(null) // fingerprint
  const [editing, setEditing] = useState<AlertRule | null>(null)
  const [creating, setCreating] = useState(false)
  const [editingWindow, setEditingWindow] = useState<MaintenanceWindow | null>(null)
  const [creatingWindow, setCreatingWindow] = useState(false)
  const maintenanceWindows = maintenance.data?.items ?? []

  const items = useMemo(() => {
    const all = active.data?.items ?? []
    const needle = query.trim().toLowerCase()
    return all.filter((a) => {
      const haystack = [a.rule_name, a.metric, labelText(a.labels), a.reason].join(' ').toLowerCase()
      return (
        (!needle || haystack.includes(needle)) &&
        (stateFilter === 'all' || alertStateOf(a) === stateFilter) &&
        (severityFilter === 'all' || a.severity === severityFilter)
      )
    })
  }, [active.data, query, stateFilter, severityFilter])

  const detailAlert = items.find((a) => a.fingerprint === detail) ?? null

  const activeColumns: Column<ActiveAlert>[] = [
    {
      key: 'state',
      header: 'State',
      render: (a) => {
        const activeWindows = activeMaintenanceForAlert(a, maintenanceWindows)
        return (
          <span className={styles.badgeStack}>
            <Badge tone={stateTone(alertStateOf(a))}>{alertStateOf(a)}</Badge>
            {activeWindows.length > 0 ? <Badge tone="info">maintenance</Badge> : null}
          </span>
        )
      },
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
    { key: 'since', header: 'Since', render: (a) => <DateTime value={a.since} /> },
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
    { key: 'delivery', header: 'Delivery', render: (r) => channelSummary(r.channels) },
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

  const maintenanceColumns: Column<MaintenanceWindow>[] = [
    {
      key: 'name',
      header: 'Name',
      render: (w) => (
        <span className={styles.badgeStack}>
          <span>{w.name}</span>
          <Badge tone={w.recurrence ? 'info' : 'neutral'}>{recurrenceLabel(w.recurrence)}</Badge>
        </span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (w) => {
        const until = activeWindowEnd(w)
        return until ? <Badge tone="success">active</Badge> : <Badge tone="neutral">scheduled</Badge>
      },
    },
    {
      key: 'window',
      header: 'Window',
      render: (w) => (
        <span className={styles.dateRange}>
          <DateTime value={w.starts_at} />
          <span>to</span>
          <DateTime value={w.ends_at} />
        </span>
      ),
    },
    { key: 'scope', header: 'Scope', render: maintenanceScope },
    { key: 'reason', header: 'Reason', render: (w) => w.reason || 'none' },
    {
      key: 'actions',
      header: <span className="sr-only">Actions</span>,
      align: 'end',
      render: (w) => (
        <>
          <Button size="sm" variant="ghost" onClick={() => setEditingWindow(w)}>
            Edit
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={delMaintenance.isPending}
            onClick={() =>
              delMaintenance.mutate(w.id, {
                onSuccess: () =>
                  push({ tone: 'success', title: 'Window deleted', message: w.name }),
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
              <FilterBar>
                <Field
                  label="Find"
                  value={query}
                  onChange={(e) => setFilter({ alert_q: e.target.value })}
                  placeholder="rule, metric, target"
                />
                <Select
                  label="State"
                  value={stateFilter}
                  onChange={(e) => setFilter({ alert_state: e.target.value })}
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
                  onChange={(e) => setFilter({ alert_severity: e.target.value })}
                  options={[
                    { value: 'all', label: 'All severities' },
                    { value: 'critical', label: 'Critical' },
                    { value: 'warning', label: 'Warning' },
                    { value: 'info', label: 'Info' },
                  ]}
                />
                <SavedViews
                  surface="alerts"
                  filters={filtersForSave(params, defaults)}
                  onApply={(filters) =>
                    setURLFilters(params, setParams, defaults, {
                      alert_q: filters.alert_q ?? '',
                      alert_state: filters.alert_state ?? 'all',
                      alert_severity: filters.alert_severity ?? 'all',
                    })
                  }
                  placeholder="Critical database"
                />
              </FilterBar>
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
            title="Maintenance windows"
            actions={<Button onClick={() => setCreatingWindow(true)}>Schedule window</Button>}
          />
          <CardBody>
            {maintenance.isLoading ? (
              <LoadingState label="Loading maintenance windows…" />
            ) : maintenance.isError ? (
              <ErrorState description="Could not load maintenance windows." />
            ) : (
              <>
                {maintenance.data && !maintenance.data.evaluator_running ? (
                  <p role="status" className={styles.notice}>
                    <Badge tone="warning">evaluator off</Badge> Maintenance windows require the
                    alert evaluator for this tenant.
                  </p>
                ) : null}
                <Table
                  caption="Maintenance windows"
                  columns={maintenanceColumns}
                  rows={maintenanceWindows}
                  rowKey={(w) => w.id}
                  empty={
                    <EmptyState
                      title="No maintenance windows"
                      description="Scheduled suppressions for planned work appear here."
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

        <OncallRoutingCard />
      </div>
      {detailAlert ? (
        <ActiveAlertDetail alert={detailAlert} onClose={() => setDetail(null)} />
      ) : null}
      {creating ? <RuleForm onClose={() => setCreating(false)} /> : null}
      {editing ? <RuleForm rule={editing} onClose={() => setEditing(null)} /> : null}
      {creatingWindow ? <MaintenanceWindowForm onClose={() => setCreatingWindow(false)} /> : null}
      {editingWindow ? (
        <MaintenanceWindowForm window={editingWindow} onClose={() => setEditingWindow(null)} />
      ) : null}
    </Page>
  )
}

function OncallRoutingCard() {
  const status = useOncallStatus()
  const testConnector = useTestOncallConnector()
  const { push } = useToast()

  const outboundColumns: Column<OncallOutboundConnector>[] = [
    { key: 'provider', header: 'Provider', render: (c) => providerLabel(c.provider) },
    {
      key: 'route',
      header: 'Tenant routing',
      render: (c) => (
        <Badge tone={c.tenant_routed ? 'success' : 'danger'}>
          {c.tenant_routed ? 'current tenant' : 'not scoped'}
        </Badge>
      ),
    },
    {
      key: 'endpoint',
      header: 'Endpoint',
      render: (c) => c.endpoint_host || 'configured, redacted',
    },
    {
      key: 'tls',
      header: 'TLS',
      render: (c) => (
        <Badge tone={c.endpoint_tls_configured ? 'success' : 'warning'}>
          {c.endpoint_tls_configured ? 'https' : 'loopback/dev'}
        </Badge>
      ),
    },
    {
      key: 'secret',
      header: 'Credential',
      render: (c) => (
        <Badge tone={c.credential_configured ? 'success' : 'neutral'}>
          {c.credential_configured ? 'configured' : 'not used'}
        </Badge>
      ),
    },
    {
      key: 'actions',
      header: <span className="sr-only">Actions</span>,
      align: 'end',
      render: (c) => (
        <Button
          size="sm"
          variant="secondary"
          disabled={testConnector.isPending}
          onClick={() =>
            testConnector.mutate(c.id, {
              onSuccess: (r) =>
                push({
                  tone: 'success',
                  title: 'Connector test sent',
                  message: `${providerLabel(r.provider)} ${r.status ?? ''}`.trim(),
                }),
              onError: (err) =>
                push({ tone: 'danger', title: 'Connector test failed', message: err.message }),
            })
          }
        >
          Test
        </Button>
      ),
    },
  ]

  const inboundColumns: Column<OncallInboundWebhook>[] = [
    { key: 'id', header: 'ID', render: (c) => c.id },
    { key: 'provider', header: 'Provider', render: (c) => providerLabel(c.provider) },
    { key: 'path', header: 'Webhook path', render: (c) => c.path },
    {
      key: 'secret',
      header: 'Credential',
      render: (c) => (
        <Badge tone={c.credential_configured ? 'success' : 'danger'}>
          {c.credential_configured ? 'configured' : 'missing'}
        </Badge>
      ),
    },
  ]

  return (
    <Card>
      <CardHeader title="Notification routing" />
      <CardBody>
        {status.isLoading ? (
          <LoadingState label="Loading notification routing…" />
        ) : status.isError ? (
          <ErrorState description="Could not load notification routing." />
        ) : (
          <div className={styles.routingStack}>
            <p className={styles.notice}>
              <Badge tone={status.data?.configured ? 'success' : 'neutral'}>
                {status.data?.configured ? 'configured' : 'off'}
              </Badge>
              {status.data?.summary}
            </p>
            <p className={styles.muted}>
              Provider choices: {(status.data?.supported_providers ?? []).map(providerLabel).join(', ')}
            </p>
            <Table
              caption="Incident connectors"
              columns={outboundColumns}
              rows={status.data?.outbound ?? []}
              rowKey={(c) => c.id}
              empty={
                <EmptyState
                  title="No incident connectors"
                  description="Configured connectors for this tenant appear here with redacted endpoints and credentials."
                />
              }
            />
            <Table
              caption="Inbound status webhooks"
              columns={inboundColumns}
              rows={status.data?.inbound ?? []}
              rowKey={(c) => c.id}
              empty={
                <EmptyState
                  title="No inbound status webhooks"
                  description="Inbound resolution sync credentials for this tenant appear here."
                />
              }
            />
          </div>
        )}
      </CardBody>
    </Card>
  )
}
