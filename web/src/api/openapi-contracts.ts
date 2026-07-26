// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import type * as Agents from './agents'
import type * as AI from './ai'
import type * as Alerts from './alerts'
import type * as Authoring from './authoring'
import type * as Coverage from './coverage'
import type * as DashboardReporting from './dashboardReporting'
import type * as Identity from './identity'
import type * as Incidents from './incidents'
import type * as Lifecycle from './lifecycle'
import type * as Paths from './paths'
import type * as Planes from './planes'
import type * as SDK from './sdk.gen'
import type * as Tests from './tests'

export interface APICallContract {
  file: string
  method: string
  path: string
  response: string
  generated: string
  reason?: string
}

export const API_CALL_CONTRACTS = [
  {
    file: 'api/coverage.ts',
    method: 'GET',
    path: '/coverage/vantages',
    response: 'CoverageMatrixResponse',
    generated: 'ListVantageCoverageResponse',
  },
  {
    file: 'api/agents.ts',
    method: 'GET',
    path: '`/agents?${params.toString()}`',
    response: 'AgentsPage',
    generated: 'ListAgentsResponse',
  },
  {
    file: 'api/agents.ts',
    method: 'POST',
    path: '/agents/enroll-tokens',
    response: 'AgentEnrollToken',
    generated: 'MintAgentEnrollTokenResponse',
    reason:
      'OpenAPI currently emits JsonObject for the one-time token body; AgentEnrollToken is the explicit view model.',
  },
  {
    file: 'api/agents.ts',
    method: 'POST',
    path: '/collectors/register',
    response: 'CollectorRegistration',
    generated: 'RegisterCollectorResponse',
  },
  {
    file: 'api/agents.ts',
    method: 'GET',
    path: '/onboarding/progress',
    response: 'OnboardingProgress',
    generated: 'GetOnboardingProgressResponse',
  },
  {
    file: 'api/rollouts.ts',
    method: 'GET',
    path: '/rollouts',
    response: 'RolloutList',
    generated: 'ListRolloutsResponse',
    reason:
      'OpenAPI currently emits JsonObject for the rollout wave list; RolloutList is the explicit operator-console view model.',
  },
  {
    file: 'api/rollouts.ts',
    method: 'POST',
    path: '`/rollouts/${encodeURIComponent(id)}/${action}`',
    response: 'Rollout',
    generated: 'VerifyRolloutResponse',
    reason:
      'Advance, Verify, Halt, and Resume share the same generic rollout view; the closed RolloutAction union selects only those documented endpoints.',
  },
  {
    file: 'api/ai.ts',
    method: 'POST',
    path: '/ai/ask',
    response: 'Answer',
    generated: 'AiAskResponse',
  },
  {
    file: 'api/ai.ts',
    method: 'POST',
    path: '/ai/feedback',
    response: 'void',
    generated: 'AiFeedbackResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'GET',
    path: '/alerts/active',
    response: 'ActiveAlertsResponse',
    generated: 'ListActiveAlertsResponse',
    reason:
      'OpenAPI currently emits JsonObject for active-alert engine state; ActiveAlertsResponse is the explicit view model.',
  },
  {
    file: 'api/alerts.ts',
    method: 'GET',
    path: "`/alerts/active/${encodeURIComponent(fingerprint ?? '')}/workflow${suffix}`",
    response: 'AlertWorkflow',
    generated: 'GetAlertWorkflowResponse',
    reason:
      'OpenAPI intentionally keeps the joined workflow payload generic; AlertWorkflow is the explicit tenant-scoped receipt view model.',
  },
  {
    file: 'api/alerts.ts',
    method: 'GET',
    path: '/alerts',
    response: '{ items: AlertRule[] }',
    generated: 'ListAlertsResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'GET',
    path: '/alerts/maintenance',
    response: 'MaintenanceWindowsResponse',
    generated: 'ListMaintenanceWindowsResponse',
    reason:
      'OpenAPI currently emits JsonObject for maintenance-window lists; MaintenanceWindowsResponse is the explicit view model.',
  },
  {
    file: 'api/alerts.ts',
    method: 'GET',
    path: '/oncall/status',
    response: 'OncallStatus',
    generated: 'JsonObject',
    reason:
      'OpenAPI SDK generation is intentionally not run in the frontend gate; OncallStatus is the explicit redacted routing view model.',
  },
  {
    file: 'api/alerts.ts',
    method: 'PUT',
    path: '`/alerts/${id}`',
    response: 'AlertRule',
    generated: 'UpdateAlertResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'POST',
    path: '/alerts',
    response: 'AlertRule',
    generated: 'CreateAlertResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'POST',
    path: '/alerts/maintenance',
    response: 'MaintenanceWindow',
    generated: 'UpsertMaintenanceWindowResponse',
    reason:
      'OpenAPI currently emits JsonObject for maintenance-window upserts; MaintenanceWindow is the explicit view model.',
  },
  {
    file: 'api/alerts.ts',
    method: 'DELETE',
    path: '`/alerts/${id}`',
    response: 'undefined',
    generated: 'DeleteAlertResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'DELETE',
    path: '`/alerts/maintenance/${id}`',
    response: 'undefined',
    generated: 'DeleteMaintenanceWindowResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'POST',
    path: '/alerts/test-channel',
    response: '{ accepted: boolean; type: string }',
    generated: 'JsonObject',
    reason:
      'OpenAPI SDK generation is intentionally not run in the frontend gate; the response is a narrow test-delivery acknowledgement.',
  },
  {
    file: 'api/alerts.ts',
    method: 'POST',
    path: '/oncall/test',
    response: '{ accepted: boolean; connector_id: string; provider: string; status?: string }',
    generated: 'JsonObject',
    reason:
      'OpenAPI SDK generation is intentionally not run in the frontend gate; the response is a narrow connector-test acknowledgement.',
  },
  {
    file: 'api/alerts.ts',
    method: 'POST',
    path: '/alerts/active/silence',
    response: 'AlertActionResponse',
    generated: 'SilenceAlertResponse',
    reason:
      'OpenAPI currently emits JsonObject for active-alert actions; AlertActionResponse includes the engine view and durable receipt metadata.',
  },
  {
    file: 'api/alerts.ts',
    method: 'POST',
    path: '/alerts/active/ack',
    response: 'AlertActionResponse',
    generated: 'AcknowledgeAlertResponse',
    reason:
      'OpenAPI currently emits JsonObject for active-alert actions; AlertActionResponse includes the engine view and durable receipt metadata.',
  },
  {
    file: 'api/audit.ts',
    method: 'GET',
    path: '`/audit?${q.toString()}`',
    response: 'AuditList',
    generated: 'ListAuditResponse',
  },
  {
    file: 'api/audit.ts',
    method: 'GET',
    path: '/audit/verify',
    response: 'AuditVerify',
    generated: 'VerifyAuditResponse',
  },
  {
    file: 'api/authoring.ts',
    method: 'POST',
    path: '/ai/author',
    response: 'TestProposal',
    generated: 'AiAuthorResponse',
  },
  {
    file: 'api/authoring.ts',
    method: 'POST',
    path: '/ai/discover',
    response: '{ proposals: DiscoverProposal[] }',
    generated: 'AiDiscoverResponse',
  },
  {
    file: 'api/carbon.ts',
    method: 'GET',
    path: '/carbon',
    response: 'CarbonResponse',
    generated: 'GetCarbonResponse',
    reason:
      'OpenAPI currently emits JsonObject for carbon estimates; CarbonResponse is the explicit view model.',
  },
  {
    file: 'api/compliance.ts',
    method: 'GET',
    path: '/compliance',
    response: 'ComplianceResponse',
    generated: 'ListComplianceResultsResponse',
    reason:
      'OpenAPI currently emits JsonObject for compliance results; ComplianceResponse is the explicit view model.',
  },
  {
    file: 'api/cost.ts',
    method: 'GET',
    path: '/cost/summary',
    response: 'CostResponse',
    generated: 'GetCostSummaryResponse',
    reason:
      'OpenAPI currently emits JsonObject for cost summaries; CostResponse is the explicit view model.',
  },
  {
    file: 'api/dashboardReporting.ts',
    method: 'GET',
    path: '/dashboards',
    response: 'DashboardList',
    generated: 'ListDashboardsResponse',
    reason:
      'OpenAPI currently emits JsonObject for the saved-dashboard list; DashboardList is the explicit tenant-scoped view model.',
  },
  {
    file: 'api/dashboardReporting.ts',
    method: 'POST',
    path: '/dashboards',
    response: 'DashboardView',
    generated: 'CreateDashboardResponse',
  },
  {
    file: 'api/dashboardReporting.ts',
    method: 'GET',
    path: '/dashboard-report-schedules',
    response: 'ScheduleList',
    generated: 'ListDashboardReportSchedulesResponse',
  },
  {
    file: 'api/dashboardReporting.ts',
    method: 'POST',
    path: '/dashboard-report-schedules',
    response: 'ReportSchedule',
    generated: 'CreateDashboardReportScheduleResponse',
  },
  {
    file: 'api/dashboardReporting.ts',
    method: 'GET',
    path: '/dashboard-report-artifacts',
    response: 'ArtifactList',
    generated: 'ListDashboardReportArtifactsResponse',
    reason:
      'OpenAPI currently emits JsonObject for the artifact list wrapper; ArtifactList is the explicit tenant-scoped view model.',
  },
  {
    file: 'api/dashboardReporting.ts',
    method: 'POST',
    path: '/dashboard-reports',
    response: 'ReportArtifact',
    generated: 'GenerateDashboardReportResponse',
  },
  {
    file: 'api/diagnostics.ts',
    method: 'GET',
    path: '/diagnostics',
    response: 'DeepHealth',
    generated: 'GetV1DiagnosticsResponse',
  },
  {
    file: 'api/editions.ts',
    method: 'GET',
    path: '/editions',
    response: 'EditionsInfo',
    generated: 'GetEditionsResponse',
    reason:
      'OpenAPI currently emits JsonObject for editions; EditionsInfo is the explicit view model.',
  },
  {
    file: 'api/endpoints.ts',
    method: 'GET',
    path: '`/endpoints?${params.toString()}`',
    response: 'EndpointsResponse',
    generated: 'ListEndpointsResponse',
    reason:
      'OpenAPI currently emits JsonObject for endpoint DEM views; EndpointsResponse is the explicit view model.',
  },
  {
    file: 'api/endpoints.ts',
    method: 'GET',
    path: '/inventory/views?surface=endpoints',
    response: 'EndpointSavedViewsResponse',
    generated: 'ListInventoryViewsResponse',
  },
  {
    file: 'api/endpoints.ts',
    method: 'POST',
    path: '/inventory/views',
    response: 'SavedInventoryView',
    generated: 'CreateInventoryViewResponse',
  },
  {
    file: 'api/savedViews.ts',
    method: 'GET',
    path: '`/inventory/views?surface=${surface}`',
    response: 'SavedInventoryViewsResponse',
    generated: 'ListInventoryViewsResponse',
  },
  {
    file: 'api/savedViews.ts',
    method: 'POST',
    path: '/inventory/views',
    response: 'SavedInventoryView',
    generated: 'CreateInventoryViewResponse',
  },
  {
    file: 'api/explorer.ts',
    method: 'GET',
    path: '/explorer/schema',
    response: 'ExplorerSchema',
    generated: 'GetExplorerSchemaResponse',
  },
  {
    file: 'api/explorer.ts',
    method: 'POST',
    path: '/explorer/compare',
    response: 'ExplorerComparisonResult',
    generated: 'CompareExplorerPeriodsResponse',
  },
  {
    file: 'api/explorer.ts',
    method: 'POST',
    path: '/explorer/query',
    response: 'ExplorerResult',
    generated: 'QueryExplorerResponse',
  },
  {
    file: 'api/identity.ts',
    method: 'GET',
    path: '/identity/settings',
    response: 'TenantIdPSettings',
    generated: 'GetTenantIdentitySettingsResponse',
  },
  {
    file: 'api/identity.ts',
    method: 'PUT',
    path: '/identity/settings',
    response: 'TenantIdPSettings',
    generated: 'PutTenantIdentitySettingsResponse',
  },
  {
    file: 'api/identity.ts',
    method: 'GET',
    path: '/directory/scim-tokens',
    response: '{ items: ScimToken[] }',
    generated: 'ListScimTokensResponse',
  },
  {
    file: 'api/identity.ts',
    method: 'POST',
    path: '/directory/scim-tokens',
    response: 'CreatedScimToken',
    generated: 'CreateScimTokenResponse',
  },
  {
    file: 'api/identity.ts',
    method: 'DELETE',
    path: '`/directory/scim-tokens/${id}`',
    response: 'void',
    generated: 'RevokeScimTokenResponse',
  },
  {
    file: 'api/identity.ts',
    method: 'GET',
    path: '/abac/policies',
    response: '{ items: ABACPolicy[] }',
    generated: 'ListPoliciesResponse',
  },
  {
    file: 'api/identity.ts',
    method: 'POST',
    path: '/abac/policies',
    response: 'ABACPolicy',
    generated: 'CreatePolicyResponse',
  },
  {
    file: 'api/identity.ts',
    method: 'DELETE',
    path: '`/abac/policies/${id}`',
    response: 'void',
    generated: 'DeletePolicyResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'GET',
    path: '/incidents',
    response: '{ items: Incident[] }',
    generated: 'ListIncidentsResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'GET',
    path: '/changes',
    response: '{ items: ChangeEvent[] }',
    generated: 'ListChangesResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'GET',
    path: '`/incidents/${id}`',
    response: 'Incident',
    generated: 'GetIncidentResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'GET',
    path: '`/incidents/${id}/changes`',
    response: '{ items: ChangeCandidate[] }',
    generated: 'ListIncidentChangesResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'PATCH',
    path: '`/incidents/${id}`',
    response: 'Incident',
    generated: 'PatchIncidentResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'POST',
    path: '`/incidents/${id}/shares`',
    response: 'IncidentShareArtifact',
    generated: 'CreateIncidentShareResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'GET',
    path: '`/incident-shares/${id}`',
    response: 'IncidentShareArtifact',
    generated: 'GetIncidentShareResponse',
  },
  {
    file: 'api/keys.ts',
    method: 'GET',
    path: '/security/keys',
    response: 'TenantKeyList',
    generated: 'GetV1SecurityKeysResponse',
  },
  {
    file: 'api/keys.ts',
    method: 'POST',
    path: '/security/keys/rotate',
    response: 'KeyInfo',
    generated: 'PostV1SecurityKeysRotateResponse',
    reason:
      'OpenAPI currently emits void for key rotation response; KeyInfo is the explicit view model.',
  },
  {
    file: 'api/lifecycle.ts',
    method: 'GET',
    path: '/lifecycle/retention',
    response: 'LifecycleStatus',
    generated: 'GetV1LifecycleRetentionResponse',
  },
  {
    file: 'api/lifecycle.ts',
    method: 'PUT',
    path: '/lifecycle/retention',
    response: 'LifecycleStatus',
    generated: 'PutV1LifecycleRetentionResponse',
  },
  {
    file: 'api/lifecycle.ts',
    method: 'POST',
    path: '/lifecycle/erase',
    response: 'LifecycleEraseAttestation',
    generated: 'PostV1LifecycleEraseResponse',
    reason:
      'OpenAPI currently emits void for erasure attestations; LifecycleEraseAttestation is the explicit view model.',
  },
  {
    file: 'api/outages.ts',
    method: 'GET',
    path: '/outages',
    response: 'OutagesResponse',
    generated: 'GetOutagesResponse',
    reason:
      'OpenAPI currently emits JsonObject for outage views; OutagesResponse is the explicit view model.',
  },
  {
    file: 'api/paths.ts',
    method: 'GET',
    path: '`/tests/${testId}/path`',
    response: 'Path',
    generated: 'GetTestPathResponse',
  },
  {
    file: 'api/paths.ts',
    method: 'POST',
    path: '`/tests/${testId}/path`',
    response: 'Path',
    generated: 'DiscoverTestPathResponse',
  },
  {
    file: 'api/paths.ts',
    method: 'GET',
    path: '`/tests/${testId}/path/history?${params.toString()}`',
    response: '{ items: PathSnapshot[] }',
    generated: 'ListTestPathHistoryResponse',
  },
  {
    file: 'api/planes.ts',
    method: 'GET',
    path: '`/flows/top?${params.toString()}`',
    response: 'FlowTopResponse',
    generated: 'FlowTopTalkersResponse',
  },
  {
    file: 'api/planes.ts',
    method: 'GET',
    path: '`/flows/capacity?window=${encodeURIComponent(window)}&bucket=${encodeURIComponent(bucket)}`',
    response: 'FlowCapacityResponse',
    generated: 'FlowCapacityResponse',
  },
  {
    file: 'api/planes.ts',
    method: 'GET',
    path: '`/flows/anomalies?window=${encodeURIComponent(window)}&bucket=${encodeURIComponent(bucket)}`',
    response: 'FlowAnomalyResponse',
    generated: 'FlowAnomaliesResponse',
  },
  {
    file: 'api/planes.ts',
    method: 'GET',
    path: '`/device/syslog?limit=${limit}`',
    response: 'DeviceSyslogResponse',
    generated: 'JsonObject',
    reason:
      'OpenAPI SDK generation is intentionally not run in the frontend gate; DeviceSyslogResponse is the explicit view model for the bounded syslog list.',
  },
  {
    file: 'api/planes.ts',
    method: 'GET',
    path: '`/device/configs?limit=${limit}`',
    response: 'DeviceConfigResponse',
    generated: 'JsonObject',
    reason:
      'OpenAPI SDK generation is intentionally not run in the frontend gate; DeviceConfigResponse is the explicit view model for the bounded config archive list.',
  },
  {
    file: 'api/remediation.ts',
    method: 'GET',
    path: '/remediation/proposals',
    response: 'RemediationList',
    generated: 'GetV1RemediationProposalsResponse',
    reason:
      'OpenAPI currently emits void for remediation proposal lists; RemediationList is the explicit view model.',
  },
  {
    file: 'api/remediation.ts',
    method: 'POST',
    path: '/remediation/proposals',
    response: 'Proposal',
    generated: 'PostV1RemediationProposalsResponse',
    reason:
      'OpenAPI currently emits void for remediation proposal creation; Proposal is the explicit view model.',
  },
  {
    file: 'api/remediation.ts',
    method: 'POST',
    path: '`/remediation/proposals/${id}/${decision}`',
    response: 'Proposal',
    generated: 'PostV1RemediationProposalsIdApproveResponse',
    reason:
      'OpenAPI currently emits void for remediation decisions; Proposal is the explicit view model.',
  },
  {
    file: 'api/results.ts',
    method: 'GET',
    path: '/results/latest',
    response: 'LatestResultsResponse',
    generated: 'ListLatestResultsResponse',
    reason:
      'OpenAPI currently emits JsonObject for latest results; LatestResultsResponse is the explicit view model.',
  },
  {
    file: 'api/results.ts',
    method: 'GET',
    path: '`/results/history?window=${encodeURIComponent(window)}`',
    response: 'ResultsHistoryResponse',
    generated: 'ListResultsHistoryResponse',
    reason:
      'OpenAPI currently emits JsonObject for results history; ResultsHistoryResponse is the explicit view model.',
  },
  {
    file: 'api/rum.ts',
    method: 'GET',
    path: '/rum',
    response: 'RUMResponse',
    generated: 'GetRumResponse',
    reason:
      'OpenAPI currently emits JsonObject for RUM views; RUMResponse is the explicit view model.',
  },
  {
    file: 'api/secrets.ts',
    method: 'GET',
    path: '/secrets/health',
    response: 'SecretsHealthResponse',
    generated: 'GetSecretsHealthResponse',
    reason:
      'OpenAPI currently emits JsonObject for secret-backend health; SecretsHealthResponse is the explicit view model.',
  },
  {
    file: 'api/slos.ts',
    method: 'GET',
    path: '/slos',
    response: 'SLOsResponse',
    generated: 'ListSlOsResponse',
    reason:
      'OpenAPI currently emits JsonObject for SLO views; SLOsResponse is the explicit view model.',
  },
  {
    file: 'api/tests.ts',
    method: 'GET',
    path: '`/tests?${params}`',
    response: 'TestList',
    generated: 'ListTestsResponse',
  },
  {
    file: 'api/tests.ts',
    method: 'POST',
    path: '/tests',
    response: 'Test',
    generated: 'CreateTestResponse',
  },
  {
    file: 'api/tests.ts',
    method: 'DELETE',
    path: '`/tests/${id}`',
    response: 'void',
    generated: 'DeleteTestResponse',
  },
  {
    file: 'api/threat.ts',
    method: 'GET',
    path: '/threat/detections',
    response: 'DetectionsResponse',
    generated: 'ListThreatDetectionsResponse',
    reason:
      'OpenAPI currently emits JsonObject for threat detections; DetectionsResponse is the explicit view model.',
  },
  {
    file: 'api/threat.ts',
    method: 'GET',
    path: '/threat/intel/status',
    response: 'ThreatIntelStatusResponse',
    generated: 'GetThreatIntelStatusResponse',
    reason:
      'OpenAPI currently emits JsonObject for the nested AUP/feed matrix; ThreatIntelStatusResponse is the explicit view model.',
  },
  {
    file: 'api/tls.ts',
    method: 'GET',
    path: '/tls/posture',
    response: 'PostureResponse',
    generated: 'ListTlsPostureResponse',
    reason:
      'OpenAPI currently emits JsonObject for TLS posture; PostureResponse is the explicit view model.',
  },
  {
    file: 'api/topology.ts',
    method: 'GET',
    path: '`/topology${qs}`',
    response: 'TopologyResponse',
    generated: 'GetTopologyResponse',
    reason:
      'OpenAPI currently emits JsonObject for topology; TopologyResponse is the explicit view model.',
  },
  {
    file: 'api/topology.ts',
    method: 'POST',
    path: '/topology/whatif',
    response: 'WhatIfImpact',
    generated: 'SimulateWhatIfResponse',
    reason:
      'OpenAPI currently emits JsonObject for topology what-if; WhatIfImpact is the explicit view model.',
  },
  {
    file: 'auth/AuthProvider.tsx',
    method: 'GET',
    path: '/me',
    response: 'Me',
    generated: 'GetMeResponse',
    reason:
      'The UI identity view includes tenant/user timezone fields that are not yet present in OpenAPI Me.',
  },
] as const satisfies readonly APICallContract[]

type GeneratedHasViewKeys<Generated, View> =
  Exclude<keyof View, keyof Generated> extends never
    ? true
    : { missing_keys: Exclude<keyof View, keyof Generated> }

export const OPENAPI_TYPE_CONTRACTS = {
  agent: true,
  collectorRegisterRequest: true,
  collectorRegistration: true,
  coverageMatrixItem: true,
  onboardingProgress: true,
  aiAnswer: true,
  alertRule: true,
  alertRequest: true,
  authorProposal: true,
  discoverProposal: true,
  dashboardView: true,
  dashboardReportSchedule: true,
  dashboardReportArtifact: true,
  scimToken: true,
  scimTokenCreated: true,
  abacPolicy: true,
  tenantIdPSettings: true,
  incident: true,
  signal: true,
  changeEvent: true,
  incidentShareArtifact: true,
  incidentShareContext: true,
  lifecycleStatus: true,
  lifecycleRetentionInput: true,
  path: true,
  pathSnapshot: true,
  hop: true,
  hopNode: true,
  pathLink: true,
  flowTopRow: true,
  flowTopList: true,
  flowFilter: true,
  flowSeriesPoint: true,
  flowCapacityPoint: true,
  flowCapacityList: true,
  flowAnomaly: true,
  flowAnomalyList: true,
  test: true,
  testList: true,
  testRequest: true,
} satisfies {
  agent: GeneratedHasViewKeys<SDK.FleetAgent, Agents.Agent>
  collectorRegisterRequest: GeneratedHasViewKeys<
    SDK.CollectorRegisterRequest,
    Agents.RegisterCollectorInput
  >
  collectorRegistration: GeneratedHasViewKeys<
    SDK.CollectorRegistration,
    Agents.CollectorRegistration
  >
  coverageMatrixItem: GeneratedHasViewKeys<SDK.CoverageMatrixItem, Coverage.CoverageMatrixItem>
  onboardingProgress: GeneratedHasViewKeys<SDK.OnboardingProgress, Agents.OnboardingProgress>
  aiAnswer: GeneratedHasViewKeys<SDK.AIAnswer, AI.Answer>
  alertRule: GeneratedHasViewKeys<SDK.AlertRule, Alerts.AlertRule>
  alertRequest: GeneratedHasViewKeys<SDK.AlertRequest, Alerts.AlertRuleInput>
  authorProposal: GeneratedHasViewKeys<SDK.TestProposal, Authoring.TestProposal>
  discoverProposal: GeneratedHasViewKeys<SDK.DiscoverProposal, Authoring.DiscoverProposal>
  dashboardView: GeneratedHasViewKeys<SDK.DashboardView, DashboardReporting.DashboardView>
  dashboardReportSchedule: GeneratedHasViewKeys<
    SDK.DashboardReportSchedule,
    DashboardReporting.ReportSchedule
  >
  dashboardReportArtifact: GeneratedHasViewKeys<
    SDK.DashboardReportArtifact,
    DashboardReporting.ReportArtifact
  >
  scimToken: GeneratedHasViewKeys<SDK.SCIMToken, Identity.ScimToken>
  scimTokenCreated: GeneratedHasViewKeys<SDK.SCIMTokenCreated, Identity.CreatedScimToken>
  abacPolicy: GeneratedHasViewKeys<SDK.ABACPolicy, Identity.ABACPolicy>
  tenantIdPSettings: GeneratedHasViewKeys<SDK.TenantIdPSettings, Identity.TenantIdPSettings>
  incident: GeneratedHasViewKeys<SDK.Incident, Incidents.Incident>
  signal: GeneratedHasViewKeys<SDK.Signal, Incidents.Signal>
  changeEvent: GeneratedHasViewKeys<SDK.ChangeEvent, Incidents.ChangeEvent>
  incidentShareArtifact: GeneratedHasViewKeys<
    SDK.IncidentShareArtifact,
    Incidents.IncidentShareArtifact
  >
  incidentShareContext: GeneratedHasViewKeys<
    SDK.IncidentShareContext,
    Incidents.IncidentShareContext
  >
  lifecycleStatus: GeneratedHasViewKeys<SDK.LifecycleStatus, Lifecycle.LifecycleStatus>
  lifecycleRetentionInput: GeneratedHasViewKeys<
    SDK.LifecycleRetentionInput,
    Lifecycle.LifecycleRetentionInput
  >
  path: GeneratedHasViewKeys<SDK.Path, Paths.Path>
  pathSnapshot: GeneratedHasViewKeys<SDK.PathSnapshot, Paths.PathSnapshot>
  hop: GeneratedHasViewKeys<SDK.Hop, Paths.Hop>
  hopNode: GeneratedHasViewKeys<SDK.HopNode, Paths.HopNode>
  pathLink: GeneratedHasViewKeys<SDK.Link, Paths.Link>
  flowTopRow: GeneratedHasViewKeys<SDK.FlowTopRow, Planes.FlowTopRow>
  flowTopList: GeneratedHasViewKeys<SDK.FlowTopList, Planes.FlowTopResponse>
  flowFilter: GeneratedHasViewKeys<SDK.FlowFilter, Planes.FlowFilter>
  flowSeriesPoint: GeneratedHasViewKeys<SDK.FlowSeriesPoint, Planes.FlowSeriesPoint>
  flowCapacityPoint: GeneratedHasViewKeys<SDK.FlowCapacityPoint, Planes.FlowCapacityPoint>
  flowCapacityList: GeneratedHasViewKeys<SDK.FlowCapacityList, Planes.FlowCapacityResponse>
  flowAnomaly: GeneratedHasViewKeys<SDK.FlowAnomaly, Planes.FlowAnomaly>
  flowAnomalyList: GeneratedHasViewKeys<SDK.FlowAnomalyList, Planes.FlowAnomalyResponse>
  test: GeneratedHasViewKeys<SDK.Test, Tests.Test>
  testList: GeneratedHasViewKeys<SDK.TestList, SDK.TestList>
  testRequest: GeneratedHasViewKeys<SDK.TestRequest, Tests.TestInput>
}
