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
  type DashboardDefinition,
  type DashboardManifest,
  type DashboardManifestImportResponse,
  type DashboardPreset,
  type ReportCadence,
  type ReportFormat,
} from '../api/dashboardReporting'
import { apiURL } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { Badge, Button, Card, CardBody, CardHeader, Field, Select, useToast } from '../components'
import { DateTime } from '../time/DateTime'
import styles from './dashboards.module.css'

export function DashboardReportingCard({
  preset,
  definition,
}: {
  preset: DashboardPreset
  definition: DashboardDefinition
}) {
  const { push } = useToast()
  const { permissions } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const dashboards = useDashboards()
  const schedules = useReportSchedules()
  const artifacts = useReportArtifacts()
  const createDashboard = useCreateDashboard()
  const createSchedule = useCreateReportSchedule()
  const generateReport = useGenerateDashboardReport()
  const importDashboard = useImportDashboardManifest()
  const [name, setName] = useState('Cross-plane posture')
  const [shared, setShared] = useState(false)
  const [selectedID, setSelectedID] = useState('')
  const [format, setFormat] = useState<ReportFormat>('pdf')
  const [cadence, setCadence] = useState<ReportCadence>('weekly')
  const [manifestText, setManifestText] = useState('')
  const [manifestPreview, setManifestPreview] = useState<DashboardManifestImportResponse>()

  const views = dashboards.data?.items ?? []
  const requestedID = searchParams.get('view') ?? ''
  const requestedView = views.find((view) => view.id === requestedID)
  const activeID = selectedID || (requestedID ? (requestedView?.id ?? '') : (views[0]?.id ?? ''))
  const activeView = views.find((view) => view.id === activeID)
  const readyDestinations = (schedules.data?.destinations ?? []).filter((item) => item.ready)
  const destination = readyDestinations[0]
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
      const view = await createDashboard.mutateAsync({ name, preset, shared, definition })
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
      })
      push({
        tone: 'success',
        title: 'Report scheduled',
        message: `Delivery is confined to ${destination.name}; no outbound default was enabled.`,
      })
    } catch (error) {
      push({ tone: 'danger', title: 'Could not schedule report', message: String(error) })
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
      })
      setManifestPreview(result)
      setManifestText(JSON.stringify(result.manifest, null, 2))
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
              disabled={!canWrite || !name.trim() || createDashboard.isPending || failed}
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
              disabled
              options={
                destination
                  ? [{ value: destination.id, label: `${destination.name} · local` }]
                  : [{ value: '', label: 'No configured destination' }]
              }
            />
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
              <code>{`${window.location.origin}/dashboards?view=${encodeURIComponent(activeView.id)}#saved-dashboard`}</code>
            </p>
          ) : null}

          {activeView ? (
            <section className={styles.savedSnapshot} aria-label="Selected saved snapshot">
              <strong>{activeView.name}</strong>
              <span>{activeView.preset} preset</span>
              <span>
                <DateTime value={activeView.definition.absolute_from} /> –{' '}
                <DateTime value={activeView.definition.absolute_to} />
              </span>
              <span>{Object.keys(activeView.definition.metrics).length} exact values</span>
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
            <div className={styles.reportActions}>
              <Button
                onClick={() => void previewManifest()}
                disabled={!canWrite || !manifestText.trim() || importDashboard.isPending || failed}
              >
                {importDashboard.isPending ? 'Validating…' : 'Preview import'}
              </Button>
              {manifestPreview ? (
                <Button
                  variant="primary"
                  onClick={() => void confirmManifestImport()}
                  disabled={!canWrite || importDashboard.isPending}
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
                <span>
                  <DateTime value={manifestPreview.preview.absolute_from} /> –{' '}
                  <DateTime value={manifestPreview.preview.absolute_to} />
                </span>
                <span>{manifestPreview.preview.metric_count} exact values</span>
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
                  {schedules.data?.items.slice(0, 4).map((item) => (
                    <li key={item.id}>
                      <strong>{item.name}</strong> · {item.format.toUpperCase()} · {item.cadence} ·
                      next <DateTime value={item.next_run_at} />
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
                  {artifacts.data?.items.slice(0, 4).map((item) => (
                    <li key={item.id}>
                      <a href={item.download_url}>{item.filename}</a> ·{' '}
                      <DateTime value={item.generated_at} />
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        </CardBody>
      </Card>
    </section>
  )
}
