// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  useCreateDashboard,
  useCreateReportSchedule,
  useDashboards,
  useGenerateDashboardReport,
  useImportDashboardManifest,
  useReportArtifacts,
  useReportSchedules,
  useUpdateReportSchedule,
  type DashboardDefinition,
  type ClientReportDefinition,
  type DashboardManifest,
  type DashboardManifestImportResponse,
  type DashboardPreset,
  type ReportCadence,
  type ReportFormat,
} from '../api/dashboardReporting'
import { apiURL } from '../api/client'
import { appPath } from '../lib/links'
import { useAuth } from '../auth/useAuth'
import { Badge, Button, Card, CardBody, CardHeader, Field, Select, useToast } from '../components'
import { DateTime } from '../time/DateTime'
import { FlowViewLibrary } from './FlowViewLibrary'
import {
  MonthlyClientReportEditor,
  emptyMonthlyReport,
  validMonthlyReport,
} from './MonthlyClientReportEditor'
import styles from './dashboards.module.css'

export function DashboardReportingCard({
  preset,
  definition,
}: {
  preset: DashboardPreset
  definition: DashboardDefinition
}) {
  const { push } = useToast()
  const { permissions, user, tenant, hasScopedGrants } = useAuth()
  const sourceIdentity = JSON.stringify([
    tenant.id,
    user.id,
    permissions.slice().sort(),
    hasScopedGrants,
  ])
  const [sourceMode, setSourceMode] = useState(false)
  const [monthlyMode, setMonthlyMode] = useState(false)
  const [monthlyDraft, setMonthlyDraft] = useState<{
    identity: string
    value: ClientReportDefinition
  }>({ identity: sourceIdentity, value: emptyMonthlyReport() })
  const monthlyDefinition =
    monthlyDraft.identity === sourceIdentity ? monthlyDraft.value : emptyMonthlyReport()
  const canReadMonthly = [
    'metrics.read',
    'entities.read',
    'test.read',
    'incident.read',
    'change.read',
    'events.read',
  ].every((permission) => permissions.includes(permission))
  const canMonthlyCapacity = permissions.includes('flow.read')
  const validMonthly =
    validMonthlyReport(monthlyDefinition) &&
    (monthlyDefinition.capacity_targets.length === 0 || canMonthlyCapacity)
  const [sourceDraft, setSourceDraft] = useState<{
    identity: string
    items: Array<{ id: string; version: string; name: string }>
  }>({ identity: sourceIdentity, items: [] })
  const sourceItems = sourceDraft.identity === sourceIdentity ? sourceDraft.items : []
  const canReadSources = permissions.includes('ai.query') && permissions.includes('flow.read')
  const [searchParams, setSearchParams] = useSearchParams()
  const dashboards = useDashboards()
  const schedules = useReportSchedules()
  const [artifactPaging, setArtifactPaging] = useState({
    identity: sourceIdentity,
    cursor: '',
    previous: [] as string[],
  })
  const artifactPage =
    artifactPaging.identity === sourceIdentity
      ? artifactPaging
      : { identity: sourceIdentity, cursor: '', previous: [] as string[] }
  const artifacts = useReportArtifacts(sourceIdentity, artifactPage.cursor)
  const createDashboard = useCreateDashboard()
  const createSchedule = useCreateReportSchedule()
  const updateSchedule = useUpdateReportSchedule()
  const generateReport = useGenerateDashboardReport()
  const importDashboard = useImportDashboardManifest()
  const [name, setName] = useState('Cross-plane posture')
  const [shared, setShared] = useState(false)
  const [selectedID, setSelectedID] = useState('')
  const [providerConsent, setProviderConsent] = useState({ identity: '', view: '', allowed: false })
  const [format, setFormat] = useState<ReportFormat>('pdf')
  const [cadence, setCadence] = useState<ReportCadence>('weekly')
  const [manifestText, setManifestText] = useState('')
  const [manifestPreview, setManifestPreview] = useState<DashboardManifestImportResponse>()
  const [nativeSlot, setNativeSlot] = useState('')
  const [bindingDraft, setBindingDraft] = useState<{
    identity: string
    manifest: string
    items: Record<string, { id: string; version: string; name: string }>
  }>({ identity: sourceIdentity, manifest: '', items: {} })
  const nativeSlots = useMemo(() => {
    try {
      const parsed = JSON.parse(manifestText) as {
        spec?: { definition?: { flow_sources?: unknown } }
      }
      const sources = parsed?.spec?.definition?.flow_sources
      if (!Array.isArray(sources)) return []
      return sources
        .filter(
          (item: unknown): item is { slot: string } =>
            item !== null &&
            typeof item === 'object' &&
            'slot' in item &&
            typeof item.slot === 'string' &&
            item.slot.length <= 80,
        )
        .slice(0, 1024)
        .map((item) => item.slot)
    } catch {
      return []
    }
  }, [manifestText])
  const nativeBindings =
    bindingDraft.identity === sourceIdentity && bindingDraft.manifest === manifestText
      ? bindingDraft.items
      : {}
  const activeNativeSlot = nativeSlots.includes(nativeSlot) ? nativeSlot : (nativeSlots[0] ?? '')
  const missingNativeBindings =
    nativeSlots.length > 0 && (!canReadSources || nativeSlots.some((slot) => !nativeBindings[slot]))
  const sourceBindingsInput = nativeSlots.length
    ? Object.fromEntries(
        Object.entries(nativeBindings).map(([slot, { id, version }]) => [slot, { id, version }]),
      )
    : undefined

  const views = dashboards.data?.items ?? []
  const requestedID = searchParams.get('view') ?? ''
  const requestedView = views.find((view) => view.id === requestedID)
  const activeID = selectedID || (requestedID ? (requestedView?.id ?? '') : (views[0]?.id ?? ''))
  const activeView = views.find((view) => view.id === activeID)
  const allowProvider =
    providerConsent.identity === sourceIdentity && providerConsent.view === activeID
      ? providerConsent.allowed
      : false
  const [destinationChoice, setDestinationChoice] = useState({ identity: '', view: '', id: '' })
  const readyDestinations = (schedules.data?.destinations ?? []).filter((item) => item.ready)
  const destination =
    readyDestinations.find(
      (item) =>
        destinationChoice.identity === sourceIdentity &&
        destinationChoice.view === activeID &&
        item.id === destinationChoice.id,
    ) ?? readyDestinations[0]
  const firstRun = useMemo(() => new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), [])
  const canWrite = permissions.includes('metrics.write')

  function selectView(id: string) {
    setSelectedID(id)
    const next = new URLSearchParams(searchParams)
    if (id) next.set('view', id)
    else next.delete('view')
    setSearchParams(next, { replace: true })
  }

  async function save() {
    try {
      const disclosures = {
        provenance: definition.provenance,
        redaction_state: definition.redaction_state,
        coverage_limitations: definition.coverage_limitations,
      }
      const savedDefinition: DashboardDefinition = monthlyMode
        ? { ...disclosures, client_report: monthlyDefinition }
        : sourceMode
          ? {
              ...disclosures,
              flow_sources: sourceItems.map(({ id, version }) => ({ id, version })),
            }
          : definition
      const view = await createDashboard.mutateAsync({
        name,
        preset,
        shared,
        definition: savedDefinition,
      })
      selectView(view.id)
      push({
        tone: 'success',
        title: 'Dashboard saved',
        message: shared
          ? 'Authorized users in this tenant can open the shared view.'
          : 'The view is private to you.',
      })
    } catch (error) {
      push({ tone: 'danger', title: 'Could not save dashboard', message: String(error) })
    }
  }

  async function exportReport() {
    if (!activeID) return
    try {
      await generateReport.mutateAsync({ dashboard_id: activeID, format })
      setArtifactPaging({ identity: sourceIdentity, cursor: '', previous: [] })
      push({
        tone: 'success',
        title: `${format.toUpperCase()} generated`,
        message: 'The audited artifact is ready in this tenant report inbox.',
      })
    } catch (error) {
      push({ tone: 'danger', title: 'Could not generate report', message: String(error) })
    }
  }

  async function scheduleReport() {
    if (!activeID || !destination) return
    try {
      await createSchedule.mutateAsync({
        dashboard_id: activeID,
        name: `${activeView?.name ?? 'Dashboard'} ${cadence}`,
        format,
        cadence,
        destination_id: destination.id,
        first_run_at: firstRun,
        provider_trigger_allowed: allowProvider,
      })
      push({
        tone: 'success',
        title: 'Report scheduled',
        message: destination.outbound
          ? `Delivery to ${destination.name} was explicitly selected; a copy remains in this tenant inbox.`
          : `Delivery is confined to ${destination.name}; no outbound default was enabled.`,
      })
    } catch (error) {
      push({ tone: 'danger', title: 'Could not schedule report', message: String(error) })
    }
  }

  async function setScheduleDestination(id: string) {
    if (!destination) return
    try {
      await updateSchedule.mutateAsync({ id, destination_id: destination.id })
      push({
        tone: 'success',
        title: 'Report destination updated',
        message: 'Pending email to the previous destination was withdrawn.',
      })
    } catch (error) {
      push({ tone: 'danger', title: 'Could not update report destination', message: String(error) })
    }
  }

  async function setScheduleEnabled(id: string, enabled: boolean) {
    try {
      await updateSchedule.mutateAsync({ id, enabled })
      push({
        tone: 'success',
        title: enabled ? 'Schedule resumed' : 'Schedule paused',
        message: enabled
          ? 'An overdue schedule delivers once on the next worker run.'
          : 'Future deliveries are paused. A delivery already in progress may finish; saved artifacts remain available.',
      })
    } catch (error) {
      push({ tone: 'danger', title: 'Could not update schedule', message: String(error) })
    }
  }

  function parseManifest(): DashboardManifest {
    const parsed = JSON.parse(manifestText) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('The manifest must be one JSON object.')
    }
    return parsed as DashboardManifest
  }

  async function previewManifest() {
    try {
      const result = await importDashboard.mutateAsync({
        manifest: parseManifest(),
        confirm: false,
        source_bindings: sourceBindingsInput,
      })
      setManifestPreview(result)
      const normalized = JSON.stringify(result.manifest, null, 2)
      setManifestText(normalized)
      setBindingDraft({ identity: sourceIdentity, manifest: normalized, items: nativeBindings })
      push({
        tone: 'success',
        title: 'Manifest validated',
        message: 'Review the normalized native dashboard below. Nothing has been created.',
      })
    } catch (error) {
      setManifestPreview(undefined)
      push({ tone: 'danger', title: 'Manifest preview failed', message: String(error) })
    }
  }

  async function confirmManifestImport() {
    if (!manifestPreview) return
    try {
      const result = await importDashboard.mutateAsync({
        manifest: manifestPreview.manifest,
        confirm: true,
        source_bindings: sourceBindingsInput,
      })
      if (!result.dashboard) throw new Error('The server did not return the created dashboard.')
      setManifestPreview(undefined)
      setManifestText(JSON.stringify(result.manifest, null, 2))
      selectView(result.dashboard.id)
      push({
        tone: 'success',
        title: 'Dashboard imported',
        message: 'A new tenant-scoped dashboard was created under your authenticated identity.',
      })
    } catch (error) {
      push({ tone: 'danger', title: 'Dashboard import failed', message: String(error) })
    }
  }

  const loading = dashboards.isLoading || schedules.isLoading || artifacts.isLoading
  const failed = dashboards.isError || schedules.isError || artifacts.isError

  return (
    <section id="saved-dashboard" className={styles.reportingSection}>
      <Card className={styles.reportingCard}>
        <CardHeader
          title="Saved views and report delivery"
          description="Save/share this exact tenant scope, then generate or schedule an audited PDF/CSV."
          actions={<Badge tone="success">no outbound default</Badge>}
        />
        <CardBody className={styles.reportingBody}>
          {failed ? (
            <p role="alert" className={styles.reportingError}>
              Reporting storage is unavailable. No save, schedule, or export was attempted.
            </p>
          ) : null}
          {requestedID && !loading && !requestedView ? (
            <p role="alert" className={styles.reportingError}>
              That saved dashboard is unavailable in this tenant or authorization scope.
            </p>
          ) : null}
          {canReadMonthly ? (
            <section aria-label="Monthly client report" className={styles.manifestSection}>
              <label className={styles.checkboxLabel}>
                <input
                  type="checkbox"
                  checked={monthlyMode}
                  disabled={!canWrite}
                  onChange={(event) => {
                    setMonthlyMode(event.target.checked)
                    if (event.target.checked) {
                      setSourceMode(false)
                      setCadence('monthly')
                    }
                  }}
                />
                Build a monthly client pack (preview)
              </label>
              {monthlyMode && (
                <MonthlyClientReportEditor
                  value={monthlyDefinition}
                  onChange={(value) => setMonthlyDraft({ identity: sourceIdentity, value })}
                  disabled={!canWrite}
                  canCapacity={canMonthlyCapacity}
                />
              )}
            </section>
          ) : null}
          {canReadSources ? (
            <section aria-label="Report saved flow sources" className={styles.manifestSection}>
              <label className={styles.checkboxLabel}>
                <input
                  type="checkbox"
                  checked={sourceMode}
                  disabled={!canWrite}
                  onChange={(event) => {
                    setSourceMode(event.target.checked)
                    if (event.target.checked) setMonthlyMode(false)
                  }}
                />
                Build from saved flow queries
              </label>
              {sourceMode ? (
                <>
                  <p>
                    Choose current saved queries. Each selected version stays fixed until you select
                    it again; reports use its complete selected rows and time range.
                  </p>
                  <FlowViewLibrary
                    identity={sourceIdentity}
                    onSelect={(item) =>
                      setSourceDraft((previous) => ({
                        identity: sourceIdentity,
                        items: [
                          ...(previous.identity === sourceIdentity
                            ? previous.items.filter((source) => source.id !== item.id)
                            : []),
                          { id: item.id, version: item.version, name: item.definition.name },
                        ],
                      }))
                    }
                  />
                  <ul aria-label="Selected report sources">
                    {sourceItems.map((source) => (
                      <li key={source.id}>
                        {source.name} · version {source.version}{' '}
                        <Button
                          onClick={() =>
                            setSourceDraft({
                              identity: sourceIdentity,
                              items: sourceItems.filter((item) => item.id !== source.id),
                            })
                          }
                        >
                          Remove {source.name}
                        </Button>
                      </li>
                    ))}
                  </ul>
                </>
              ) : null}
            </section>
          ) : null}
          <div className={styles.reportingControls} aria-busy={loading}>
            <Field
              label="Dashboard name"
              value={name}
              maxLength={120}
              onChange={(event) => setName(event.target.value)}
            />
            <label className={styles.checkboxLabel}>
              <input
                type="checkbox"
                checked={shared}
                disabled={!canWrite}
                onChange={(event) => setShared(event.target.checked)}
              />
              Share inside this tenant
            </label>
            <Button
              onClick={() => void save()}
              disabled={
                !canWrite ||
                !name.trim() ||
                createDashboard.isPending ||
                failed ||
                (sourceMode && (!canReadSources || sourceItems.length === 0)) ||
                (monthlyMode && (!canReadMonthly || !validMonthly))
              }
            >
              {createDashboard.isPending ? 'Saving…' : 'Save dashboard'}
            </Button>
            <Select
              label="Saved dashboard"
              value={activeID}
              onChange={(event) => selectView(event.target.value)}
              options={[
                ...(views.length === 0 ? [{ value: '', label: 'Save a dashboard first' }] : []),
                ...views.map((view) => ({
                  value: view.id,
                  label: `${view.name}${view.shared ? ' · shared' : ' · private'}`,
                })),
              ]}
            />
            <Select
              label="Format"
              value={format}
              onChange={(event) => setFormat(event.target.value as ReportFormat)}
              options={[
                { value: 'pdf', label: 'PDF' },
                { value: 'csv', label: 'CSV' },
              ]}
            />
            <Select
              label="Cadence"
              value={cadence}
              onChange={(event) => setCadence(event.target.value as ReportCadence)}
              options={[
                { value: 'daily', label: 'Daily' },
                { value: 'weekly', label: 'Weekly' },
                { value: 'monthly', label: 'Monthly' },
              ]}
            />
            <Select
              label="Configured destination"
              value={destination?.id ?? ''}
              disabled={!canWrite}
              onChange={(event) =>
                setDestinationChoice({
                  identity: sourceIdentity,
                  view: activeID,
                  id: event.target.value,
                })
              }
              options={
                readyDestinations.length > 0
                  ? readyDestinations.map((item) => ({
                      value: item.id,
                      label: `${item.name} · ${item.kind}${item.description ? ` · ${item.description}` : ''}`,
                    }))
                  : [{ value: '', label: 'No configured destination' }]
              }
            />
            {schedules.data?.provider_trigger_available && activeView?.definition.client_report ? (
              <label className={styles.checkboxLabel}>
                <input
                  type="checkbox"
                  disabled={!canWrite}
                  checked={allowProvider}
                  onChange={(event) =>
                    setProviderConsent({
                      identity: sourceIdentity,
                      view: activeID,
                      allowed: event.target.checked,
                    })
                  }
                />
                Allow provider-triggered monthly runs for this schedule
              </label>
            ) : null}
            <div className={styles.reportActions}>
              <Button
                variant="primary"
                onClick={() => void exportReport()}
                disabled={!activeID || generateReport.isPending || failed}
              >
                Generate {format.toUpperCase()}
              </Button>
              <Button
                onClick={() => void scheduleReport()}
                disabled={
                  !canWrite || !activeID || !destination || createSchedule.isPending || failed
                }
              >
                Schedule delivery
              </Button>
            </div>
          </div>

          {activeView?.shared ? (
            <p className={styles.shareLink}>
              Tenant-authenticated share link:{' '}
              <code>{`${window.location.origin}${appPath('/dashboards')}?view=${encodeURIComponent(activeView.id)}#saved-dashboard`}</code>
            </p>
          ) : null}

          {activeView ? (
            <section className={styles.savedSnapshot} aria-label="Selected saved snapshot">
              <strong>{activeView.name}</strong>
              <span>{activeView.preset} preset</span>
              {activeView.definition.client_report ? (
                <>
                  <span>
                    {activeView.definition.client_report.period === 'month_to_date'
                      ? 'Month to date · partial'
                      : 'Completed calendar month'}{' '}
                    · {activeView.definition.client_report.timezone || 'UTC'}
                  </span>
                  <span>
                    {activeView.definition.client_report.month || 'Month resolved at generation'} ·{' '}
                    {(activeView.definition.client_report.capacity_targets ?? []).length} capacity
                    targets
                  </span>
                  <span>Current source access is checked for every report.</span>
                </>
              ) : activeView.definition.flow_sources?.length ? (
                <span>
                  {activeView.definition.flow_sources.length} saved flow sources; current source
                  access is checked for every report.
                </span>
              ) : (
                <>
                  <span>
                    <DateTime value={activeView.definition.absolute_from} /> –{' '}
                    <DateTime value={activeView.definition.absolute_to} />
                  </span>
                  <span>
                    {Object.keys(activeView.definition.metrics ?? {}).length} exact values
                  </span>
                </>
              )}
            </section>
          ) : null}

          <section className={styles.manifestSection} aria-labelledby="dashboard-manifest-heading">
            <div className={styles.manifestHeading}>
              <div>
                <h3 id="dashboard-manifest-heading">Native dashboard manifest</h3>
                <p>
                  Export a versioned, identity-free JSON recipe or validate one locally before an
                  explicit import.
                </p>
              </div>
              {activeID ? (
                <a
                  className={styles.manifestDownload}
                  href={apiURL(`/dashboards/${encodeURIComponent(activeID)}/manifest`)}
                  download="probectl-dashboard.json"
                >
                  Export manifest
                </a>
              ) : null}
            </div>
            {!canWrite ? (
              <p className={styles.reportingEmpty}>
                Read-only access: export is available, but saving and importing require
                metrics.write.
              </p>
            ) : null}
            <label className={styles.manifestField}>
              <span>Manifest JSON</span>
              <textarea
                value={manifestText}
                rows={9}
                spellCheck={false}
                placeholder='Paste a probectl.io/dashboard/v1 manifest, then choose "Preview import".'
                onChange={(event) => {
                  setManifestText(event.target.value)
                  setManifestPreview(undefined)
                }}
              />
            </label>
            {nativeSlots.length ? (
              <section
                aria-label="Destination report source bindings"
                className={styles.manifestSection}
              >
                <p>
                  Bind each portable slot to a saved query in this tenant. These explicit selections
                  determine the imported report's data.
                </p>
                {canReadSources ? (
                  <>
                    <Select
                      label="Source slot to bind"
                      value={activeNativeSlot}
                      options={nativeSlots.map((slot) => ({ value: slot, label: slot }))}
                      onChange={(event) => setNativeSlot(event.target.value)}
                    />
                    <FlowViewLibrary
                      identity={sourceIdentity}
                      onSelect={(item) => {
                        setBindingDraft({
                          identity: sourceIdentity,
                          manifest: manifestText,
                          items: {
                            ...nativeBindings,
                            [activeNativeSlot]: {
                              id: item.id,
                              version: item.version,
                              name: item.definition.name,
                            },
                          },
                        })
                        setManifestPreview(undefined)
                      }}
                    />
                    <ul aria-label="Bound report source slots">
                      {nativeSlots.map((slot) => (
                        <li key={slot}>
                          {slot}:{' '}
                          {nativeBindings[slot]
                            ? `${nativeBindings[slot].name} · version ${nativeBindings[slot].version}`
                            : 'Not bound'}
                        </li>
                      ))}
                    </ul>
                  </>
                ) : (
                  <p role="alert">Current flow read access is required to bind report sources.</p>
                )}
              </section>
            ) : null}
            <div className={styles.reportActions}>
              <Button
                onClick={() => void previewManifest()}
                disabled={
                  !canWrite ||
                  !manifestText.trim() ||
                  importDashboard.isPending ||
                  failed ||
                  missingNativeBindings
                }
              >
                {importDashboard.isPending ? 'Validating…' : 'Preview import'}
              </Button>
              {manifestPreview ? (
                <Button
                  variant="primary"
                  onClick={() => void confirmManifestImport()}
                  disabled={!canWrite || importDashboard.isPending || missingNativeBindings}
                >
                  Confirm import
                </Button>
              ) : null}
            </div>
            {manifestPreview ? (
              <section className={styles.manifestPreview} aria-label="Dashboard import preview">
                <Badge tone="warning">preview only · not created</Badge>
                <strong>{manifestPreview.preview.name}</strong>
                <span>
                  {manifestPreview.preview.preset} ·{' '}
                  {manifestPreview.preview.shared ? 'shared in this tenant' : 'private'}
                </span>
                {manifestPreview.preview.source_count ? (
                  <span>
                    {manifestPreview.preview.source_count} explicitly bound saved flow sources
                  </span>
                ) : (
                  <>
                    <span>
                      <DateTime value={manifestPreview.preview.absolute_from} /> –{' '}
                      <DateTime value={manifestPreview.preview.absolute_to} />
                    </span>
                    <span>{manifestPreview.preview.metric_count} exact values</span>
                  </>
                )}
                <span>
                  {manifestPreview.preview.provenance_count} provenance ·{' '}
                  {manifestPreview.preview.coverage_limitation_count} coverage notes
                </span>
              </section>
            ) : null}
          </section>

          <div className={styles.reportingLists}>
            <section aria-labelledby="report-schedules-heading">
              <h3 id="report-schedules-heading">Schedules</h3>
              {(schedules.data?.items ?? []).length === 0 ? (
                <p className={styles.reportingEmpty}>No report schedules.</p>
              ) : (
                <ul className={styles.compactList}>
                  {schedules.data?.items.map((item) => (
                    <li key={item.id}>
                      <strong>{item.name}</strong> · {item.format.toUpperCase()} · {item.cadence} ·
                      {item.enabled ? (
                        <>
                          next <DateTime value={item.next_run_at} />
                        </>
                      ) : (
                        <Badge tone="neutral">Paused</Badge>
                      )}
                      <Button
                        disabled={
                          !canWrite ||
                          updateSchedule.isPending ||
                          !destination ||
                          destination.id === item.destination_id
                        }
                        onClick={() => void setScheduleDestination(item.id)}
                      >
                        Use selected destination for {item.name}
                      </Button>
                      {item.provider_trigger_allowed ? (
                        <Button
                          disabled={!canWrite || updateSchedule.isPending}
                          onClick={() =>
                            void updateSchedule
                              .mutateAsync({ id: item.id, provider_trigger_allowed: false })
                              .then(() =>
                                push({
                                  tone: 'success',
                                  title: 'Provider trigger revoked',
                                  message:
                                    'Pending provider work is withdrawn; normal delivery timing is preserved.',
                                }),
                              )
                              .catch((error) =>
                                push({
                                  tone: 'danger',
                                  title: 'Could not revoke provider trigger',
                                  message: String(error),
                                }),
                              )
                          }
                        >
                          Revoke provider trigger for {item.name}
                        </Button>
                      ) : null}
                      <Button
                        variant="secondary"
                        aria-label={`${item.enabled ? 'Pause' : 'Resume'} ${item.name}`}
                        disabled={!canWrite || updateSchedule.isPending}
                        onClick={() => void setScheduleEnabled(item.id, !item.enabled)}
                      >
                        {item.enabled ? 'Pause' : 'Resume'}
                      </Button>
                    </li>
                  ))}
                </ul>
              )}
            </section>
            <section aria-labelledby="report-inbox-heading">
              <h3 id="report-inbox-heading">Tenant report inbox</h3>
              {(artifacts.data?.items ?? []).length === 0 ? (
                <p className={styles.reportingEmpty}>No generated artifacts.</p>
              ) : (
                <ul className={styles.compactList}>
                  {artifacts.data?.items.map((item) => (
                    <li key={item.id}>
                      <a href={item.download_url}>{item.filename}</a> ·{' '}
                      <DateTime value={item.generated_at} />
                      {item.email_delivery ? (
                        <span>
                          {' '}
                          · Email {item.email_delivery.state} · attempts{' '}
                          {item.email_delivery.attempts}
                          {item.email_delivery.next_attempt_at ? (
                            <>
                              ; next attempt{' '}
                              <DateTime value={item.email_delivery.next_attempt_at} />
                            </>
                          ) : null}
                        </span>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
              <nav
                aria-label="Report inbox pages"
                className={styles.reportingControls}
                aria-busy={artifacts.isFetching}
              >
                <Button
                  variant="secondary"
                  disabled={artifactPage.previous.length === 0 || artifacts.isFetching}
                  onClick={() =>
                    setArtifactPaging({
                      identity: sourceIdentity,
                      cursor: artifactPage.previous.at(-1) ?? '',
                      previous: artifactPage.previous.slice(0, -1),
                    })
                  }
                >
                  Newer reports
                </Button>
                <Button
                  variant="secondary"
                  disabled={!artifacts.data?.next_cursor || artifacts.isFetching}
                  onClick={() =>
                    setArtifactPaging({
                      identity: sourceIdentity,
                      cursor: artifacts.data?.next_cursor ?? '',
                      previous: [...artifactPage.previous, artifactPage.cursor],
                    })
                  }
                >
                  Older reports
                </Button>
              </nav>
            </section>
          </div>
        </CardBody>
      </Card>
    </section>
  )
}
