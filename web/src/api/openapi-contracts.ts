// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
    file: 'api/alertDependencies.ts',
    method: 'GET',
    path: '`/alerts/rules/${encodeURIComponent(ruleID)}/dependency-policy`',
    response: 'AlertDependencyPolicyState',
    generated: 'GetAlertDependencyPolicyResponse',
  },
  {
    file: 'api/alertDependencies.ts',
    method: 'PUT',
    path: '`/alerts/rules/${encodeURIComponent(ruleID)}/dependency-policy`',
    response: 'AlertDependencyPolicyState',
    generated: 'SetAlertDependencyPolicyResponse',
  },
  {
    file: 'api/alertDependencies.ts',
    method: 'DELETE',
    path: '`/alerts/rules/${encodeURIComponent(ruleID)}/dependency-policy`',
    response: 'AlertDependencyPolicyState',
    generated: 'ClearAlertDependencyPolicyResponse',
  },
  {
    file: 'api/alertDependencies.ts',
    method: 'GET',
    path: '`/entity-contexts?${query.toString()}`',
    response: 'EntityContextPage',
    generated: 'ListEntityContextsResponse',
  },
  {
    file: 'api/peering.ts',
    method: 'GET',
    path: '`/entity-contexts?${query}`',
    response: 'EntityContextPage',
    generated: 'ListEntityContextsResponse',
  },
  {
    file: 'api/peering.ts',
    method: 'GET',
    path: '`/entities?${query}`',
    response: 'EntityPage',
    generated: 'ListCanonicalEntitiesResponse',
  },
  {
    file: 'api/peering.ts',
    method: 'POST',
    path: '/flows/peering-estimate',
    response: 'PeeringEstimateResponse',
    generated: 'EstimateFlowPeeringResponse',
  },
  {
    file: 'api/bgpRoutingBindings.ts',
    method: 'GET',
    path: '`/entity-contexts/${encodeURIComponent(context)}/bgp-routing-bindings?${query.toString()}`',
    response: 'BGPRoutingBindingConfiguration',
    generated: 'GetBgpRoutingBindingsResponse',
  },
  {
    file: 'api/bgpRoutingBindings.ts',
    method: 'PUT',
    path: '`/entity-contexts/${encodeURIComponent(context)}/bgp-routing-bindings`',
    response: 'BGPRoutingBindingConfiguration',
    generated: 'ReplaceBgpRoutingBindingsResponse',
  },
  {
    file: 'api/interfaceRoles.ts',
    method: 'GET',
    path: '`/entity-contexts/${encodeURIComponent(context)}/interfaces/${encodeURIComponent(subject)}/role`',
    response: 'InterfaceRoleExplanation',
    generated: 'GetInterfaceRoleExplanationResponse',
  },
  {
    file: 'api/interfaceRoles.ts',
    method: 'GET',
    path: '`/entity-contexts/${encodeURIComponent(context)}/interface-role-policy`',
    response: 'InterfaceRolePolicy',
    generated: 'GetInterfaceRolePolicyResponse',
  },
  {
    file: 'api/interfaceRoles.ts',
    method: 'PUT',
    path: '`/entity-contexts/${encodeURIComponent(context)}/interface-role-policy`',
    response: 'InterfaceRolePolicy',
    generated: 'PutInterfaceRolePolicyResponse',
  },
  {
    file: 'api/interfaceRoles.ts',
    method: 'GET',
    path: '`/entity-contexts/${encodeURIComponent(context)}/interfaces/${encodeURIComponent(subject)}/role-override`',
    response: 'InterfaceRoleOverride',
    generated: 'GetInterfaceRoleOverrideResponse',
  },
  {
    file: 'api/interfaceRoles.ts',
    method: 'PUT',
    path: '`/entity-contexts/${encodeURIComponent(context)}/interfaces/${encodeURIComponent(subject)}/role-override`',
    response: 'InterfaceRoleOverride',
    generated: 'PutInterfaceRoleOverrideResponse',
  },
  {
    file: 'api/interfaceRoles.ts',
    method: 'DELETE',
    path: '`/entity-contexts/${encodeURIComponent(context)}/interfaces/${encodeURIComponent(subject)}/role-override`',
    response: 'void',
    generated: 'ResetInterfaceRoleOverrideResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'GET',
    path: '`/alerts/rules/${encodeURIComponent(ruleID)}/query-group?group=${encodeURIComponent(group)}`',
    response: 'AlertQueryGroupInspection',
    generated: 'GetAlertQueryGroupResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'GET',
    path: '`/alerts/rules/${encodeURIComponent(ruleID)}/query-source`',
    response: 'AlertQuerySourceState',
    generated: 'GetAlertQuerySourceResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'PUT',
    path: '`/alerts/rules/${encodeURIComponent(ruleID)}/query-source`',
    response: 'AlertQuerySourceState',
    generated: 'SetAlertQuerySourceResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'DELETE',
    path: '`/alerts/rules/${encodeURIComponent(ruleID)}/query-source`',
    response: 'AlertQuerySourceState',
    generated: 'ClearAlertQuerySourceResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'GET',
    path: '`/alerts/rules/${encodeURIComponent(ruleID)}/tag-filter`',
    response: 'AlertTagFilterState',
    generated: 'GetAlertTagFilterResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'PUT',
    path: '`/alerts/rules/${encodeURIComponent(ruleID)}/tag-filter`',
    response: 'AlertTagFilterState',
    generated: 'SetAlertTagFilterResponse',
  },
  {
    file: 'api/alerts.ts',
    method: 'DELETE',
    path: '`/alerts/rules/${encodeURIComponent(ruleID)}/tag-filter`',
    response: 'undefined',
    generated: 'ClearAlertTagFilterResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'POST',
    path: '/tags/tests/resolve',
    response: 'TestTagContextResolution',
    generated: 'ResolveTestTagContextResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'GET',
    path: '`/entity-contexts/${encodeURIComponent(input.contextId)}/resolved-tags?${query}`',
    response: 'TagSubjectResolution',
    generated: 'ResolveSubjectTagsResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'POST',
    path: '`/entity-contexts/${encodeURIComponent(contextID)}/tag-imports/netbox/preview`',
    response: 'NetBoxTagPreview',
    generated: 'PreviewNetBoxTagResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'POST',
    path: '`/entity-contexts/${encodeURIComponent(contextID)}/tag-imports/netbox/apply`',
    response: 'TagAssignment',
    generated: 'ApplyNetBoxTagResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'GET',
    path: '/tags',
    response: 'TagDefinitionList',
    generated: 'ListTagDefinitionsResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'POST',
    path: '/tags',
    response: 'TagDefinition',
    generated: 'CreateTagDefinitionResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'PUT',
    path: '`/tags/${encodeURIComponent(id)}`',
    response: 'TagDefinition',
    generated: 'RenameTagDefinitionResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'DELETE',
    path: '`/tags/${encodeURIComponent(id)}`',
    response: 'void',
    generated: 'DeleteTagDefinitionResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'GET',
    path: '`/entity-contexts/${encodeURIComponent(contextID)}/tag-rules?${query}`',
    response: 'TagRulePage',
    generated: 'ListTagRulesResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'POST',
    path: '`/entity-contexts/${encodeURIComponent(contextID)}/tag-rules`',
    response: 'TagRule',
    generated: 'CreateTagRuleResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'PUT',
    path: '`/entity-contexts/${encodeURIComponent(contextID)}/tag-rules/${encodeURIComponent(id)}`',
    response: 'TagRule',
    generated: 'UpdateTagRuleResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'DELETE',
    path: '`/entity-contexts/${encodeURIComponent(contextID)}/tag-rules/${encodeURIComponent(id)}`',
    response: 'void',
    generated: 'DeleteTagRuleResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'GET',
    path: '`/entity-contexts/${encodeURIComponent(contextID)}/tag-assignments?${query}`',
    response: 'TagAssignmentPage',
    generated: 'ListTagAssignmentsResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'POST',
    path: '`/entity-contexts/${encodeURIComponent(contextID)}/tag-assignments`',
    response: 'TagAssignment',
    generated: 'CreateManualTagAssignmentResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'PUT',
    path: '`/entity-contexts/${encodeURIComponent(contextID)}/tag-assignments/${encodeURIComponent(id)}`',
    response: 'TagAssignment',
    generated: 'UpdateManualTagAssignmentResponse',
  },
  {
    file: 'api/tags.ts',
    method: 'DELETE',
    path: '`/entity-contexts/${encodeURIComponent(contextID)}/tag-assignments/${encodeURIComponent(id)}`',
    response: 'void',
    generated: 'DeleteManualTagAssignmentResponse',
  },
  {
    file: 'api/flowFilters.ts',
    method: 'GET',
    path: '`/explorer/flow-filters?limit=100&after=${encodeURIComponent(after)}`',
    response: 'FlowFilterPage',
    generated: 'ListFlowQueryFiltersResponse',
  },
  {
    file: 'api/flowFilters.ts',
    method: 'PUT',
    path: '`/explorer/flow-filters/${encodeURIComponent(id)}`',
    response: 'SavedFlowFilter',
    generated: 'UpdateFlowQueryFilterResponse',
  },
  {
    file: 'api/flowFilters.ts',
    method: 'POST',
    path: '/explorer/flow-filters',
    response: 'SavedFlowFilter',
    generated: 'CreateFlowQueryFilterResponse',
  },
  {
    file: 'api/flowFilters.ts',
    method: 'DELETE',
    path: '`/explorer/flow-filters/${encodeURIComponent(id)}?version=${encodeURIComponent(version_text)}`',
    response: 'void',
    generated: 'DeleteFlowQueryFilterResponse',
  },
  {
    file: 'api/flowViews.ts',
    method: 'GET',
    path: '`/explorer/flow-views?${params}`',
    response: 'FlowQueryViewPage',
    generated: 'ListFlowQueryViewsResponse',
  },
  {
    file: 'api/flowViews.ts',
    method: 'GET',
    path: '`/explorer/flow-views/${encodeURIComponent(id!)}`',
    response: 'SavedFlowQueryView',
    generated: 'GetFlowQueryViewResponse',
  },
  {
    file: 'api/flowViews.ts',
    method: 'PUT',
    path: '`/explorer/flow-views/${encodeURIComponent(id)}`',
    response: 'SavedFlowQueryView',
    generated: 'UpdateFlowQueryViewResponse',
  },
  {
    file: 'api/flowViews.ts',
    method: 'POST',
    path: '/explorer/flow-views',
    response: 'SavedFlowQueryView',
    generated: 'CreateFlowQueryViewResponse',
  },
  {
    file: 'api/flowViews.ts',
    method: 'DELETE',
    path: '`/explorer/flow-views/${encodeURIComponent(id)}?version=${encodeURIComponent(version)}`',
    response: 'void',
    generated: 'DeleteFlowQueryViewResponse',
  },
  {
    file: 'api/flowViews.ts',
    method: 'PUT',
    path: '`/explorer/flow-views/${encodeURIComponent(id)}/preferences`',
    response: 'void',
    generated: 'SetFlowQueryViewFavoriteResponse',
  },
  {
    file: 'api/flowViews.ts',
    method: 'POST',
    path: '`/explorer/flow-views/${encodeURIComponent(id)}/query`',
    response: 'ExplorerResult | ExplorerComparisonResult',
    generated: 'RunFlowQueryViewResponse',
    reason:
      'OpenAPI returns either a current-period result or a comparison; the view model retains that discriminated native result union.',
  },
  {
    file: 'api/coverage.ts',
    method: 'GET',
    path: '/coverage/vantages',
    response: 'CoverageMatrixResponse',
    generated: 'ListVantageCoverageResponse',
  },
  {
    file: 'api/coverage.ts',
    method: 'GET',
    path: '/coverage/debt',
    response: 'CoverageDebtResponse',
    generated: 'ListCoverageDebtResponse',
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
    path: "`/alerts/${encodeURIComponent(ruleID ?? '')}/evaluations${suffix}`",
    response: 'AlertEvaluationsResponse',
    generated: 'ListAlertEvaluationsResponse',
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
    path: '`/alerts/maintenance/${encodeURIComponent(id)}`',
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
      'OpenAPI SDK generation is intentionally not run in the frontend gate; the response is a narrow test-delivery acknowledgment.',
  },
  {
    file: 'api/alerts.ts',
    method: 'POST',
    path: '/oncall/test',
    response: '{ accepted: boolean; connector_id: string; provider: string; status?: string }',
    generated: 'JsonObject',
    reason:
      'OpenAPI SDK generation is intentionally not run in the frontend gate; the response is a narrow connector-test acknowledgment.',
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
    file: 'api/hierarchy.ts',
    method: 'GET',
    path: '/hierarchy',
    response: 'HierarchyWire',
    generated: 'GetHierarchyResponse',
    reason:
      'HierarchyWire is the same shape with every array optional, because the server may omit an empty teams/projects list; normalizeHierarchy turns it into Hierarchy.',
  },
  {
    file: 'api/hierarchy.ts',
    method: 'POST',
    path: '/hierarchy/orgs',
    response: 'HierarchyOrganizationFlat',
    generated: 'CreateHierarchyOrganizationResponse',
  },
  {
    file: 'api/hierarchy.ts',
    method: 'POST',
    path: '`/hierarchy/orgs/${encodeURIComponent(orgID)}/teams`',
    response: 'HierarchyTeamFlat',
    generated: 'CreateHierarchyTeamResponse',
  },
  {
    file: 'api/hierarchy.ts',
    method: 'POST',
    path: '`/hierarchy/teams/${encodeURIComponent(teamID)}/projects`',
    response: 'HierarchyProject',
    generated: 'CreateHierarchyProjectResponse',
  },
  {
    file: 'api/siem.ts',
    method: 'GET',
    path: '/siem/status',
    response: 'SIEMStatusWire',
    generated: 'GetSiemStatusResponse',
    reason:
      'SIEMStatusWire is SIEMStatus with streams optional, because the server may omit an empty stream list; normalizeSIEMStatus makes it an array.',
  },
  {
    file: 'api/compliance.ts',
    method: 'GET',
    path: '/compliance',
    response: 'ComplianceWireResponse',
    generated: 'ListComplianceResultsResponse',
    reason:
      'OpenAPI currently emits JsonObject for compliance results; ComplianceWireResponse is the explicit wire model normalized into ComplianceResponse.',
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
    method: 'POST',
    path: '/dashboard-manifests/import',
    response: 'DashboardManifestImportResponse',
    generated: 'ImportDashboardManifestResponse',
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
    method: 'PATCH',
    path: '`/dashboard-report-schedules/${encodeURIComponent(id)}`',
    response: 'ReportSchedule',
    generated: 'UpdateDashboardReportScheduleResponse',
  },
  {
    file: 'api/dashboardReporting.ts',
    method: 'GET',
    path: '`/dashboard-report-artifacts${qs}`',
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
    file: 'api/explorer.ts',
    method: 'POST',
    path: '/explorer/query',
    response: '{ proposal: FlowQuestionProposal }',
    generated: 'QueryExplorerResponse',
    reason:
      'plan_only selects the FlowQuestionResult branch of the documented proposal/result union; the adapter narrows by its explicit request mode.',
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
    path: '/directory/users',
    response: '{ items: DirectoryUser[]; total: number }',
    generated: 'ListDirectoryUsersResponse',
  },
  {
    file: 'api/identity.ts',
    method: 'GET',
    path: '/directory/roles',
    response: '{ items: DirectoryRole[] }',
    generated: 'ListDirectoryRolesResponse',
  },
  {
    file: 'api/identity.ts',
    method: 'POST',
    path: '/directory/users',
    response: 'DirectoryUser',
    generated: 'CreateDirectoryUserResponse',
  },
  {
    file: 'api/identity.ts',
    method: 'POST',
    path: '`/directory/users/${id}/roles`',
    response: 'DirectoryUser',
    generated: 'BindDirectoryRoleResponse',
  },
  {
    file: 'api/identity.ts',
    method: 'DELETE',
    path: '`/directory/users/${id}/roles/${role}${query}`',
    response: 'void',
    generated: 'UnbindDirectoryRoleResponse',
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
    file: 'api/identity.ts',
    method: 'GET',
    path: '`/device/identity-conflicts?${qs}`',
    response: 'DeviceIdentityConflictResponse',
    generated: 'ListDeviceIdentityConflictsResponse',
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
    path: "`/incidents/${encodeURIComponent(id ?? '')}`",
    response: 'Incident',
    generated: 'GetIncidentResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'GET',
    path: "`/incidents/${encodeURIComponent(id ?? '')}/changes`",
    response: '{ items: ChangeCandidate[] }',
    generated: 'ListIncidentChangesResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'GET',
    path: "`/incidents/${encodeURIComponent(id ?? '')}/journal`",
    response: 'IncidentJournalList',
    generated: 'ListIncidentJournalResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'POST',
    path: "`/incidents/${encodeURIComponent(id ?? '')}/journal`",
    response: 'IncidentJournalEntry',
    generated: 'AppendIncidentJournalResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'PATCH',
    path: "`/incidents/${encodeURIComponent(id ?? '')}`",
    response: 'Incident',
    generated: 'PatchIncidentResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'POST',
    path: "`/incidents/${encodeURIComponent(id ?? '')}/shares`",
    response: 'IncidentShareArtifact',
    generated: 'CreateIncidentShareResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'GET',
    path: "`/incident-shares/${encodeURIComponent(id ?? '')}`",
    response: 'IncidentShareArtifact',
    generated: 'GetIncidentShareResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'POST',
    path: "`/incidents/${encodeURIComponent(id ?? '')}/correlation-overrides`",
    response:
      '{\n        override: IncidentCorrelationOverride\n        detached_incident: Incident\n      }',
    generated: 'CreateIncidentCorrelationOverrideResponse',
  },
  {
    file: 'api/incidents.ts',
    method: 'POST',
    path: "`/incidents/${encodeURIComponent(id ?? '')}/correlation-overrides/${encodeURIComponent(request.override_id)}/reverse`",
    response: 'IncidentCorrelationOverride',
    generated: 'ReverseIncidentCorrelationOverrideResponse',
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
    path: "`/tests/${encodeURIComponent(testId ?? '')}/path`",
    response: 'Path',
    generated: 'GetTestPathResponse',
  },
  {
    file: 'api/paths.ts',
    method: 'GET',
    path: "`/tests/${encodeURIComponent(testId ?? '')}/path/entities`",
    response: 'EntityPathResult',
    generated: 'GetPathEntitiesResponse',
  },
  {
    file: 'api/entities.ts',
    method: 'GET',
    path: '`/entity-contexts?${query.toString()}`',
    response: 'EntityContextPage',
    generated: 'ListEntityContextsResponse',
  },
  {
    file: 'api/entities.ts',
    method: 'GET',
    path: '`/entities?${query.toString()}`',
    response: 'EntityPage',
    generated: 'ListCanonicalEntitiesResponse',
  },
  {
    file: 'api/entities.ts',
    method: 'GET',
    path: '`/entities/${encodeURIComponent(id)}?context_id=${encodeURIComponent(contextID)}`',
    response: 'EntityRecord',
    generated: 'GetCanonicalEntityResponse',
  },
  {
    file: 'api/entities.ts',
    method: 'GET',
    path: '`/entities/${encodeURIComponent(id)}/evidence?${query.toString()}`',
    response: 'EntityEvidencePage',
    generated: 'ListCanonicalEntityEvidenceResponse',
  },
  {
    file: 'api/entities.ts',
    method: 'GET',
    path: '`/entities/${encodeURIComponent(id)}/links?${query.toString()}`',
    response: 'EntityLinkPage',
    generated: 'ListCanonicalEntityLinksResponse',
  },
  {
    file: 'api/entities.ts',
    method: 'GET',
    path: '`/entities/resolve?${query.toString()}`',
    response: 'EntityResolution',
    generated: 'ResolveEntityAliasResponse',
  },
  {
    file: 'api/entities.ts',
    method: 'POST',
    path: '/entity-contexts',
    response: 'EntityContext',
    generated: 'CreateEntityContextResponse',
  },
  {
    file: 'api/entities.ts',
    method: 'POST',
    path: '/entities',
    response: 'EntityRecord',
    generated: 'CreateCanonicalEntityResponse',
  },
  {
    file: 'api/entities.ts',
    method: 'PUT',
    path: '`/entities/${encodeURIComponent(id)}/network-prefix`',
    response: 'EntityRecord',
    generated: 'SetCanonicalEntityNetworkPrefixResponse',
  },
  {
    file: 'api/entities.ts',
    method: 'PUT',
    path: '/entity-source-contexts',
    response: 'EntitySourceAssignment',
    generated: 'AssignEntitySourceResponse',
  },
  {
    file: 'api/entities.ts',
    method: 'PUT',
    path: "`/tests/${encodeURIComponent(testID ?? '')}/entity-context`",
    response: 'EntityPathContextBinding',
    generated: 'AssignPathTestEntityContextResponse',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '/nms-imports/sources',
    response: 'ImportConfigureResponse',
    generated: 'ConfigureLibreNmsImportSourceResponse',
    reason: 'The SDK generator represents this inline source ID response as JsonObject.',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '/nms-imports/live-plans',
    response: 'ImportStartResponse',
    generated: 'StartConfiguredLibreNmsImportPlanResponse',
    reason: 'The SDK generator represents this inline plan ID response as JsonObject.',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '/nms-imports/export-plans',
    response: 'ImportExportStartResponse',
    generated: 'StartNmsImportExportPreviewPlanResponse',
    reason: 'The SDK generator represents this inline preview plan response as JsonObject.',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '`/nms-imports/${encodeURIComponent(planID)}/export-pages?${query.toString()}`',
    response: 'ImportExportPageResponse',
    generated: 'AppendNmsImportExportPreviewPageResponse',
    reason: 'The SDK generator represents this inline page receipt as JsonObject.',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '`/nms-imports/${encodeURIComponent(planID)}/export-seal`',
    response: 'ImportExportSealResponse',
    generated: 'SealNmsImportExportPreviewPlanResponse',
    reason: 'The SDK generator represents this inline snapshot response as JsonObject.',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '`/nms-imports/${encodeURIComponent(planID)}/advance`',
    response: 'ImportAdvanceResponse',
    generated: 'AdvanceConfiguredLibreNmsImportPlanResponse',
    reason: 'The SDK generator represents this inline progress response as JsonObject.',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'GET',
    path: '`/nms-imports/${encodeURIComponent(planID)}/rows?${query.toString()}`',
    response: 'ImportRowsPage',
    generated: 'ListNmsImportSealedRowsResponse',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'GET',
    path: '`/nms-imports/poll-proposals?${query.toString()}`',
    response: 'ImportPollProposalsPage',
    generated: 'ListNmsImportPollProposalsResponse',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '/nms-imports/poll-target-preview',
    response: 'ImportPollTargetPreview',
    generated: 'PreviewNmsImportPollTargetResponse',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '/nms-imports/alert-target-preview',
    response: 'ImportAlertTargetPreview',
    generated: 'PreviewNmsImportAlertTargetResponse',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '/nms-imports/alert-target-apply',
    response: 'ImportAlertTargetApplyResult',
    generated: 'ApplyNmsImportAlertTargetResponse',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'GET',
    path: '`/nms-imports/${encodeURIComponent(planID)}/dry-run?${query.toString()}`',
    response: 'ImportDiffPage',
    generated: 'ListNmsImportReviewDiffResponse',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '`/nms-imports/${encodeURIComponent(planID)}/review-choices`',
    response: 'void',
    generated: 'SetNmsImportReviewChoicesResponse',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '`/nms-imports/${encodeURIComponent(planID)}/finalize-review`',
    response: 'ImportFinalizeResponse',
    generated: 'FinalizeNmsImportReviewResponse',
    reason: 'The SDK generator represents this inline review hash response as JsonObject.',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '`/nms-imports/${encodeURIComponent(planID)}/verify-before-apply`',
    response: 'ImportVerificationResponse',
    generated: 'VerifyNmsImportBeforeApplyResponse',
    reason: 'The SDK generator represents this inline verification response as JsonObject.',
  },
  {
    file: 'api/nmsImport.ts',
    method: 'POST',
    path: '`/nms-imports/${encodeURIComponent(planID)}/apply`',
    response: 'ImportApplyResponse',
    generated: 'ApplyNmsImportReviewResponse',
    reason: 'The SDK generator represents this inline apply progress as JsonObject.',
  },
  {
    file: 'api/paths.ts',
    method: 'POST',
    path: "`/tests/${encodeURIComponent(testId ?? '')}/path`",
    response: 'Path',
    generated: 'DiscoverTestPathResponse',
  },
  {
    file: 'api/paths.ts',
    method: 'GET',
    path: "`/tests/${encodeURIComponent(testId ?? '')}/path/history?${params.toString()}`",
    response: '{ items: PathSnapshot[] }',
    generated: 'ListTestPathHistoryResponse',
  },
  {
    file: 'api/planes.ts',
    method: 'GET',
    path: '`/flows/ingest-quality?limit=${limit}`',
    response: 'FlowIngestQualityResponse',
    generated: 'ListFlowIngestQualityResponse',
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
    path: '`/bgp/events?limit=${limit}`',
    response: 'BgpEventsResponse',
    generated: 'ListBgpEventsResponse',
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
    file: 'api/planes.ts',
    method: 'GET',
    path: '`/device/metrics?limit=${limit}`',
    response: 'DeviceMetricsResponse',
    generated: 'ListDeviceMetricSummariesResponse',
  },
  {
    file: 'api/planes.ts',
    method: 'GET',
    path: '`/device/neighbors?limit=${limit}`',
    response: 'DeviceNeighborResponse',
    generated: 'ListDeviceNeighborsResponse',
  },
  {
    file: 'api/planes.ts',
    method: 'GET',
    path: '`/device/collection-outcomes?limit=${limit}`',
    response: 'DeviceCollectionOutcomeResponse',
    generated: 'ListDeviceCollectionOutcomesResponse',
  },
  {
    file: 'api/planes.ts',
    method: 'GET',
    path: '`/device/traps?limit=${limit}`',
    response: 'DeviceTrapResponse',
    generated: 'ListDeviceTrapsResponse',
  },
  {
    file: 'api/remediation.ts',
    method: 'GET',
    path: '/remediation/proposals',
    response: 'RemediationList',
    generated: 'ListRemediationProposalsResponse',
  },
  {
    file: 'api/remediation.ts',
    method: 'POST',
    path: '/remediation/proposals',
    response: 'Proposal',
    generated: 'ProposeRemediationResponse',
  },
  {
    file: 'api/remediation.ts',
    method: 'POST',
    path: '`/remediation/proposals/${id}/${decision}`',
    response: 'Proposal',
    generated: 'ApproveRemediationProposalResponse',
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
    method: 'GET',
    path: '`/tests/${encodeURIComponent(id)}`',
    response: 'Test',
    generated: 'GetTestResponse',
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
    path: '/threat/rules',
    response: 'ThreatRulesResponse',
    generated: 'ListThreatRulesResponse',
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
  coverageDebtItem: true,
  coverageDebtProducer: true,
  onboardingProgress: true,
  aiAnswer: true,
  alertRule: true,
  alertTagFilterState: true,
  alertQuerySourceState: true,
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
  pathMeasurementFidelity: true,
  pathSnapshot: true,
  hop: true,
  hopNode: true,
  pathLink: true,
  bgpEvent: true,
  bgpEventList: true,
  flowTopRow: true,
  flowTopList: true,
  flowIngestQualityReceipt: true,
  flowIngestQualityResponse: true,
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
  coverageDebtItem: GeneratedHasViewKeys<SDK.CoverageDebtItem, Coverage.CoverageDebtItem>
  coverageDebtProducer: GeneratedHasViewKeys<
    SDK.CoverageDebtProducer,
    Coverage.CoverageDebtProducer
  >
  onboardingProgress: GeneratedHasViewKeys<SDK.OnboardingProgress, Agents.OnboardingProgress>
  aiAnswer: GeneratedHasViewKeys<SDK.AIAnswer, AI.Answer>
  alertRule: GeneratedHasViewKeys<SDK.AlertRule, Alerts.AlertRule>
  alertTagFilterState: GeneratedHasViewKeys<SDK.AlertTagFilterState, Alerts.AlertTagFilterState>
  alertQuerySourceState: GeneratedHasViewKeys<
    SDK.AlertQuerySourceState,
    Alerts.AlertQuerySourceState
  >
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
  pathMeasurementFidelity: GeneratedHasViewKeys<
    SDK.PathMeasurementFidelity,
    Paths.PathMeasurementFidelity
  >
  pathSnapshot: GeneratedHasViewKeys<SDK.PathSnapshot, Paths.PathSnapshot>
  hop: GeneratedHasViewKeys<SDK.Hop, Paths.Hop>
  hopNode: GeneratedHasViewKeys<SDK.HopNode, Paths.HopNode>
  pathLink: GeneratedHasViewKeys<SDK.Link, Paths.Link>
  bgpEvent: GeneratedHasViewKeys<SDK.BGPEvent, Planes.BgpEvent>
  bgpEventList: GeneratedHasViewKeys<SDK.BGPEventList, Planes.BgpEventsResponse>
  flowTopRow: GeneratedHasViewKeys<SDK.FlowTopRow, Planes.FlowTopRow>
  flowTopList: GeneratedHasViewKeys<SDK.FlowTopList, Planes.FlowTopResponse>
  flowIngestQualityReceipt: GeneratedHasViewKeys<
    SDK.FlowIngestQualityReceipt,
    Planes.FlowIngestQualityReceipt
  >
  flowIngestQualityResponse: GeneratedHasViewKeys<
    SDK.FlowIngestQualityResponse,
    Planes.FlowIngestQualityResponse
  >
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
