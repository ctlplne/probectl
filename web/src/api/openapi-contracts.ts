import type * as Agents from './agents'
import type * as AI from './ai'
import type * as Alerts from './alerts'
import type * as Authoring from './authoring'
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
    path: '/alerts',
    response: '{ items: AlertRule[] }',
    generated: 'ListAlertsResponse',
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
    method: 'DELETE',
    path: '`/alerts/${id}`',
    response: 'undefined',
    generated: 'DeleteAlertResponse',
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
    response: 'ActiveAlert',
    generated: 'SilenceAlertResponse',
    reason:
      'OpenAPI currently emits JsonObject for active-alert actions; ActiveAlert is the explicit view model.',
  },
  {
    file: 'api/alerts.ts',
    method: 'POST',
    path: '/alerts/active/ack',
    response: 'ActiveAlert',
    generated: 'AcknowledgeAlertResponse',
    reason:
      'OpenAPI currently emits JsonObject for active-alert actions; ActiveAlert is the explicit view model.',
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
    file: 'api/diagnostics.ts',
    method: 'GET',
    path: '/diagnostics',
    response: 'DeepHealth',
    generated: 'GetV1DiagnosticsResponse',
    reason: 'OpenAPI currently emits void for diagnostics; DeepHealth is the explicit view model.',
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
    path: '`/incidents/${id}`',
    response: 'Incident',
    generated: 'GetIncidentResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'PATCH',
    path: '`/incidents/${id}`',
    response: 'Incident',
    generated: 'PatchIncidentResponse',
  },
  {
    file: 'api/keys.ts',
    method: 'GET',
    path: '/security/keys',
    response: '{ items: KeyInfo[] }',
    generated: 'GetV1SecurityKeysResponse',
    reason: 'OpenAPI currently emits void for key inventory; KeyInfo is the explicit view model.',
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
    file: 'api/planes.ts',
    method: 'GET',
    path: '`/flows/top?by=${encodeURIComponent(by)}&window=${encodeURIComponent(window)}&limit=${limit}`',
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
  aiAnswer: true,
  alertRule: true,
  alertRequest: true,
  authorProposal: true,
  discoverProposal: true,
  scimToken: true,
  scimTokenCreated: true,
  abacPolicy: true,
  incident: true,
  signal: true,
  lifecycleStatus: true,
  lifecycleRetentionInput: true,
  path: true,
  hop: true,
  hopNode: true,
  pathLink: true,
  flowTopRow: true,
  flowTopList: true,
  flowCapacityPoint: true,
  flowCapacityList: true,
  flowAnomaly: true,
  flowAnomalyList: true,
  test: true,
  testList: true,
  testRequest: true,
} satisfies {
  agent: GeneratedHasViewKeys<SDK.Agent, Agents.Agent>
  collectorRegisterRequest: GeneratedHasViewKeys<
    SDK.CollectorRegisterRequest,
    Agents.RegisterCollectorInput
  >
  collectorRegistration: GeneratedHasViewKeys<
    SDK.CollectorRegistration,
    Agents.CollectorRegistration
  >
  aiAnswer: GeneratedHasViewKeys<SDK.AIAnswer, AI.Answer>
  alertRule: GeneratedHasViewKeys<SDK.AlertRule, Alerts.AlertRule>
  alertRequest: GeneratedHasViewKeys<SDK.AlertRequest, Alerts.AlertRuleInput>
  authorProposal: GeneratedHasViewKeys<SDK.TestProposal, Authoring.TestProposal>
  discoverProposal: GeneratedHasViewKeys<SDK.DiscoverProposal, Authoring.DiscoverProposal>
  scimToken: GeneratedHasViewKeys<SDK.SCIMToken, Identity.ScimToken>
  scimTokenCreated: GeneratedHasViewKeys<SDK.SCIMTokenCreated, Identity.CreatedScimToken>
  abacPolicy: GeneratedHasViewKeys<SDK.ABACPolicy, Identity.ABACPolicy>
  incident: GeneratedHasViewKeys<SDK.Incident, Incidents.Incident>
  signal: GeneratedHasViewKeys<SDK.Signal, Incidents.Signal>
  lifecycleStatus: GeneratedHasViewKeys<SDK.LifecycleStatus, Lifecycle.LifecycleStatus>
  lifecycleRetentionInput: GeneratedHasViewKeys<
    SDK.LifecycleRetentionInput,
    Lifecycle.LifecycleRetentionInput
  >
  path: GeneratedHasViewKeys<SDK.Path, Paths.Path>
  hop: GeneratedHasViewKeys<SDK.Hop, Paths.Hop>
  hopNode: GeneratedHasViewKeys<SDK.HopNode, Paths.HopNode>
  pathLink: GeneratedHasViewKeys<SDK.Link, Paths.Link>
  flowTopRow: GeneratedHasViewKeys<SDK.FlowTopRow, Planes.FlowTopRow>
  flowTopList: GeneratedHasViewKeys<SDK.FlowTopList, Planes.FlowTopResponse>
  flowCapacityPoint: GeneratedHasViewKeys<SDK.FlowCapacityPoint, Planes.FlowCapacityPoint>
  flowCapacityList: GeneratedHasViewKeys<SDK.FlowCapacityList, Planes.FlowCapacityResponse>
  flowAnomaly: GeneratedHasViewKeys<SDK.FlowAnomaly, Planes.FlowAnomaly>
  flowAnomalyList: GeneratedHasViewKeys<SDK.FlowAnomalyList, Planes.FlowAnomalyResponse>
  test: GeneratedHasViewKeys<SDK.Test, Tests.Test>
  testList: GeneratedHasViewKeys<SDK.TestList, SDK.TestList>
  testRequest: GeneratedHasViewKeys<SDK.TestRequest, Tests.TestInput>
}
