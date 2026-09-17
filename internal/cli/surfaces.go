// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cli

import (
	"net/http"
	"strings"
)

type apiOp struct {
	Method      string
	Path        string
	ArgName     string
	Description string
	// SensitiveBody marks credential-bearing requests whose JSON must never be
	// supplied through --body (and therefore exposed in argv / shell history).
	// These operations accept only --body-file, with "-" meaning stdin.
	SensitiveBody bool
	// Columns (DPR-040) names the item keys the human table shows, in order,
	// for collections whose items are not id/name/status objects (audit
	// events, for one). Empty keeps the generic ID/NAME/STATUS/SUMMARY table.
	Columns []string
}

// auditColumns is the table shape of an audit event (tenant or provider stream).
var auditColumns = []string{"seq", "created_at", "actor", "action", "target"}

// argNames splits ArgName into the ordered positional path parameters.
func (op apiOp) argNames() []string {
	if op.ArgName == "" {
		return nil
	}
	var out []string
	for _, n := range strings.Split(op.ArgName, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

type surfaceCommand struct {
	Name    string
	Summary string
	Ops     map[string]apiOp
}

type cliCoverage struct {
	Method  string
	Path    string
	Command string
	Reason  string
}

var surfaceCommands = map[string]surfaceCommand{
	"a2a": {Name: "a2a", Summary: "A2A session bridge", Ops: map[string]apiOp{
		"create-session": {Method: http.MethodPost, Path: "/v1/a2a/sessions", Description: "create an A2A bridge session"},
		"start-mesh":     {Method: http.MethodPost, Path: "/v1/a2a/mesh", Description: "start a tenant A2A site mesh"},
	}},
	"abac": {Name: "abac", Summary: "ABAC policies", Ops: map[string]apiOp{
		"list":   {Method: http.MethodGet, Path: "/v1/abac/policies"},
		"create": {Method: http.MethodPost, Path: "/v1/abac/policies"},
		"delete": {Method: http.MethodDelete, Path: "/v1/abac/policies/{id}", ArgName: "id"},
	}},
	"ai": {Name: "ai", Summary: "AI/RCA and authoring", Ops: map[string]apiOp{
		"ask":      {Method: http.MethodPost, Path: "/v1/ai/ask", Description: "ask once; add --handoff for a deterministic local Markdown investigation receipt"},
		"author":   {Method: http.MethodPost, Path: "/v1/ai/author"},
		"discover": {Method: http.MethodPost, Path: "/v1/ai/discover", Description: "propose uncovered incident and authorized flow destinations; never creates tests"},
		"feedback": {Method: http.MethodPost, Path: "/v1/ai/feedback"},
	}},
	"alert": {Name: "alert", Summary: "alert rules and active alerts", Ops: map[string]apiOp{
		"list":                {Method: http.MethodGet, Path: "/v1/alerts"},
		"create":              {Method: http.MethodPost, Path: "/v1/alerts"},
		"get":                 {Method: http.MethodGet, Path: "/v1/alerts/{id}", ArgName: "id"},
		"update":              {Method: http.MethodPut, Path: "/v1/alerts/{id}", ArgName: "id"},
		"delete":              {Method: http.MethodDelete, Path: "/v1/alerts/{id}", ArgName: "id"},
		"evaluations":         {Method: http.MethodGet, Path: "/v1/alerts/{id}/evaluations", ArgName: "id", Description: "show bounded tenant-scoped evaluation receipts"},
		"active":              {Method: http.MethodGet, Path: "/v1/alerts/active"},
		"workflow":            {Method: http.MethodGet, Path: "/v1/alerts/active/{fingerprint}/workflow", ArgName: "fingerprint", Description: "show durable alert actions, incident context, and delivery receipts"},
		"ack":                 {Method: http.MethodPost, Path: "/v1/alerts/active/ack"},
		"silence":             {Method: http.MethodPost, Path: "/v1/alerts/active/silence"},
		"maintenance":         {Method: http.MethodGet, Path: "/v1/alerts/maintenance"},
		"maintenance-upsert":  {Method: http.MethodPost, Path: "/v1/alerts/maintenance"},
		"maintenance-preview": {Method: http.MethodPost, Path: "/v1/alerts/maintenance/preview"},
		"maintenance-delete":  {Method: http.MethodDelete, Path: "/v1/alerts/maintenance/{id}", ArgName: "id"},
		"test-channel":        {Method: http.MethodPost, Path: "/v1/alerts/test-channel", Description: "send a tenant-scoped test alert through one channel"},
	}},
	"audit": {Name: "audit", Summary: "audit log and verification", Ops: map[string]apiOp{
		"list":   {Method: http.MethodGet, Path: "/v1/audit", Columns: auditColumns},
		"reveal": {Method: http.MethodPost, Path: "/v1/audit/ir/{event_ref}/reveal", ArgName: "event_ref", Description: "reveal one encrypted IR attribution with a reason read from stdin or an owner-only file"},
		"verify": {Method: http.MethodGet, Path: "/v1/audit/verify"},
	}},
	"onboarding": {Name: "onboarding", Summary: "first-run setup progress", Ops: map[string]apiOp{
		"progress": {Method: http.MethodGet, Path: "/v1/onboarding/progress", Description: "show first-run checklist progress"},
	}},
	"bgp": {Name: "bgp", Summary: "BGP/routing events", Ops: map[string]apiOp{
		"events": {Method: http.MethodGet, Path: "/v1/bgp/events", Description: "list tenant BGP/routing events"},
		"setup":  {Method: http.MethodPost, Path: "/v1/collectors/register", Description: "register a tenant BGP source/collector"},
	}},
	"carbon": {Name: "carbon", Summary: "carbon and energy estimates", Ops: map[string]apiOp{
		"summary": {Method: http.MethodGet, Path: "/v1/carbon"},
	}},
	"billing": {Name: "billing", Summary: "provider usage, billing export, and quotas", Ops: map[string]apiOp{
		"usage":      {Method: http.MethodGet, Path: "/provider/v1/usage"},
		"export":     {Method: http.MethodGet, Path: "/provider/v1/usage/export"},
		"quotas":     {Method: http.MethodGet, Path: "/provider/v1/tenants/{id}/quotas", ArgName: "id"},
		"set-quotas": {Method: http.MethodPut, Path: "/provider/v1/tenants/{id}/quotas", ArgName: "id"},
	}},
	"device": {Name: "device", Summary: "device inventory and telemetry", Ops: map[string]apiOp{
		"list":           {Method: http.MethodGet, Path: "/v1/devices"},
		"metrics":        {Method: http.MethodGet, Path: "/v1/device/metrics", Description: "latest tenant device metric summaries"},
		"neighbors":      {Method: http.MethodGet, Path: "/v1/device/neighbors", Description: "list bounded tenant LLDP/CDP physical adjacency evidence"},
		"outcomes":       {Method: http.MethodGet, Path: "/v1/device/collection-outcomes", Description: "list bounded per-target LLDP/CDP collection outcome receipts"},
		"conflicts":      {Method: http.MethodGet, Path: "/v1/device/identity-conflicts", Description: "list bounded read-only cross-source device identity conflicts"},
		"syslog":         {Method: http.MethodGet, Path: "/v1/device/syslog", Description: "list bounded tenant device syslog events"},
		"ingest-syslog":  {Method: http.MethodPost, Path: "/v1/device/syslog", Description: "ingest one authenticated device syslog event"},
		"configs":        {Method: http.MethodGet, Path: "/v1/device/configs", Description: "list bounded tenant device config versions"},
		"archive-config": {Method: http.MethodPost, Path: "/v1/device/configs", Description: "archive one redacted device config version"},
	}},
	"ebpf": {Name: "ebpf", Summary: "eBPF host/L7 service map", Ops: map[string]apiOp{
		"service-map": {Method: http.MethodGet, Path: "/v1/ebpf/service-map", Description: "list tenant eBPF service edges"},
	}},
	"change": {Name: "change", Summary: "change correlation events", Ops: map[string]apiOp{
		"list": {Method: http.MethodGet, Path: "/v1/changes"},
	}},
	"cmdb": {Name: "cmdb", Summary: "CMDB lookup", Ops: map[string]apiOp{
		"lookup": {Method: http.MethodGet, Path: "/v1/cmdb/lookup"},
	}},
	"compliance": {Name: "compliance", Summary: "segmentation and evidence", Ops: map[string]apiOp{
		"summary":  {Method: http.MethodGet, Path: "/v1/compliance"},
		"evidence": {Method: http.MethodGet, Path: "/v1/compliance/evidence"},
	}},
	"collector": {Name: "collector", Summary: "collector registration", Ops: map[string]apiOp{
		"register": {Method: http.MethodPost, Path: "/v1/collectors/register", Description: "register a bus collector from a one-time token"},
	}},
	"cost": {Name: "cost", Summary: "network cost summary", Ops: map[string]apiOp{
		"summary": {Method: http.MethodGet, Path: "/v1/cost/summary"},
	}},
	"coverage": {Name: "coverage", Summary: "native tenant-local coverage", Ops: map[string]apiOp{
		"vantages": {Method: http.MethodGet, Path: "/v1/coverage/vantages", Description: "show bounded tenant coverage and execution-cadence receipts"},
		"debt":     {Method: http.MethodGet, Path: "/v1/coverage/debt", Description: "show bounded cross-plane coverage debt and exact local evidence"},
	}},
	"dashboard": {Name: "dashboard", Summary: "saved tenant dashboards", Ops: map[string]apiOp{
		"list":   {Method: http.MethodGet, Path: "/v1/dashboards"},
		"create": {Method: http.MethodPost, Path: "/v1/dashboards"},
		"get":    {Method: http.MethodGet, Path: "/v1/dashboards/{id}", ArgName: "id"},
		"export": {Method: http.MethodGet, Path: "/v1/dashboards/{id}/manifest", ArgName: "id", Description: "write one deterministic redacted native manifest to stdout"},
		"import": {Method: http.MethodPost, Path: "/v1/dashboard-manifests/import", Description: "read a native manifest from a file or stdin, preview by default, and create only with --confirm"},
	}},
	"dashboard-report": {Name: "dashboard-report", Summary: "local dashboard report inbox", Ops: map[string]apiOp{
		"schedules":       {Method: http.MethodGet, Path: "/v1/dashboard-report-schedules"},
		"create-schedule": {Method: http.MethodPost, Path: "/v1/dashboard-report-schedules"},
		"generate":        {Method: http.MethodPost, Path: "/v1/dashboard-reports"},
		"artifacts":       {Method: http.MethodGet, Path: "/v1/dashboard-report-artifacts"},
		"download":        {Method: http.MethodGet, Path: "/v1/dashboard-report-artifacts/{id}", ArgName: "id", Description: "download one audited PDF or CSV artifact"},
	}},
	"diagnostics": {Name: "diagnostics", Summary: "diagnostics and support bundle", Ops: map[string]apiOp{
		"status": {Method: http.MethodGet, Path: "/v1/diagnostics", Description: "show native local self-observability and actionable readiness findings"},
		"bundle": {Method: http.MethodGet, Path: "/v1/diagnostics/bundle"},
	}},
	"editions": {Name: "editions", Summary: "license and edition state", Ops: map[string]apiOp{
		"status": {Method: http.MethodGet, Path: "/v1/editions"},
	}},
	"explorer": {Name: "explorer", Summary: "structured and natural-language telemetry explorer", Ops: map[string]apiOp{
		"schema":  {Method: http.MethodGet, Path: "/v1/explorer/schema"},
		"query":   {Method: http.MethodPost, Path: "/v1/explorer/query", Description: "return exact rows plus a sanitized tenant-scoped logical execution receipt"},
		"compare": {Method: http.MethodPost, Path: "/v1/explorer/compare", Description: "return aligned windows plus sanitized source and alignment execution receipts"},
	}},
	"endpoint": {Name: "endpoint", Summary: "endpoint/DEM fleet", Ops: map[string]apiOp{
		"list": {Method: http.MethodGet, Path: "/v1/endpoints"},
	}},
	"fairness": {Name: "fairness", Summary: "tenant fairness posture", Ops: map[string]apiOp{
		"status": {Method: http.MethodGet, Path: "/v1/fairness"},
	}},
	"flow": {Name: "flow", Summary: "flow analytics", Ops: map[string]apiOp{
		"quality":   {Method: http.MethodGet, Path: "/v1/flows/ingest-quality", Description: "show bounded per-exporter ingest quality receipts"},
		"top":       {Method: http.MethodGet, Path: "/v1/flows/top", Description: "pivot top contributors with observed-by exporter counts and bucketed history; repeat --query filter=field:value to narrow"},
		"capacity":  {Method: http.MethodGet, Path: "/v1/flows/capacity"},
		"anomalies": {Method: http.MethodGet, Path: "/v1/flows/anomalies"},
	}},
	"governance": {Name: "governance", Summary: "provider data-governance policy", Ops: map[string]apiOp{
		"tenant":     {Method: http.MethodGet, Path: "/provider/v1/tenants/{id}/governance", ArgName: "id"},
		"set-tenant": {Method: http.MethodPut, Path: "/provider/v1/tenants/{id}/governance", ArgName: "id"},
	}},
	"hierarchy": {Name: "hierarchy", Summary: "tenant org/team/project hierarchy", Ops: map[string]apiOp{
		"show":           {Method: http.MethodGet, Path: "/v1/hierarchy"},
		"create-org":     {Method: http.MethodPost, Path: "/v1/hierarchy/orgs"},
		"create-team":    {Method: http.MethodPost, Path: "/v1/hierarchy/orgs/{id}/teams", ArgName: "id"},
		"create-project": {Method: http.MethodPost, Path: "/v1/hierarchy/teams/{id}/projects", ArgName: "id"},
	}},
	"identity": {Name: "identity", Summary: "tenant identity-provider settings", Ops: map[string]apiOp{
		"settings":     {Method: http.MethodGet, Path: "/v1/identity/settings"},
		"set-settings": {Method: http.MethodPut, Path: "/v1/identity/settings"},
	}},
	"incident": {Name: "incident", Summary: "incidents and correlations", Ops: map[string]apiOp{
		"list":   {Method: http.MethodGet, Path: "/v1/incidents"},
		"get":    {Method: http.MethodGet, Path: "/v1/incidents/{id}", ArgName: "id"},
		"update": {Method: http.MethodPatch, Path: "/v1/incidents/{id}", ArgName: "id"},
		"changes": {
			Method: http.MethodGet, Path: "/v1/incidents/{id}/changes", ArgName: "id",
		},
		"journal":        {Method: http.MethodGet, Path: "/v1/incidents/{id}/journal", ArgName: "id", Description: "list the tenant-local inert investigation journal"},
		"journal-append": {Method: http.MethodPost, Path: "/v1/incidents/{id}/journal", ArgName: "id", Description: "append a plain-text note or re-authorized cited checkpoint"},
		"cis":            {Method: http.MethodGet, Path: "/v1/incidents/{id}/cis", ArgName: "id"},
		"share": {
			Method: http.MethodPost, Path: "/v1/incidents/{id}/shares", ArgName: "id",
			Description: "create an expiring redacted cited-evidence snapshot",
		},
		"export": {
			Method: http.MethodPost, Path: "/v1/incidents/{id}/exports", ArgName: "id",
			Description: "export an immutable signed probectl-evidence/v1 package; use incident verify for offline verification",
		},
		"ungroup": {
			Method: http.MethodPost, Path: "/v1/incidents/{id}/correlation-overrides", ArgName: "id",
			Description: "detach one falsely grouped signal and persist an audited exclusion until explicit reversal",
		},
		"reverse-override": {
			Method: http.MethodPost, Path: "/v1/incidents/{id}/correlation-overrides/{override_id}/reverse", ArgName: "id",
			Description: "reverse one durable correlation override without deleting either incident timeline",
		},
		"shared": {
			Method: http.MethodGet, Path: "/v1/incident-shares/{id}", ArgName: "id",
			Description: "read an authenticated same-tenant incident snapshot",
		},
	}},
	"inventory-view": {Name: "inventory-view", Summary: "saved inventory list views", Ops: map[string]apiOp{
		"list":   {Method: http.MethodGet, Path: "/v1/inventory/views"},
		"create": {Method: http.MethodPost, Path: "/v1/inventory/views"},
		"get":    {Method: http.MethodGet, Path: "/v1/inventory/views/{id}", ArgName: "id"},
	}},
	"isolation": {Name: "isolation", Summary: "tenant and provider isolation model operations", Ops: map[string]apiOp{
		"status":       {Method: http.MethodGet, Path: "/v1/isolation/status", Description: "show this tenant's effective isolation posture"},
		"tenants":      {Method: http.MethodGet, Path: "/provider/v1/tenants"},
		"set-tenant":   {Method: http.MethodPatch, Path: "/provider/v1/tenants/{id}", ArgName: "id"},
		"governance":   {Method: http.MethodGet, Path: "/provider/v1/tenants/{id}/governance", ArgName: "id"},
		"set-fairness": {Method: http.MethodPut, Path: "/provider/v1/tenants/{id}/fairness", ArgName: "id"},
	}},
	"lifecycle": {Name: "lifecycle", Summary: "tenant data lifecycle", Ops: map[string]apiOp{
		"erase":          {Method: http.MethodPost, Path: "/v1/lifecycle/erase"},
		"export":         {Method: http.MethodGet, Path: "/v1/lifecycle/export"},
		"retention":      {Method: http.MethodGet, Path: "/v1/lifecycle/retention"},
		"set-retention":  {Method: http.MethodPut, Path: "/v1/lifecycle/retention"},
		"subject-erase":  {Method: http.MethodPost, Path: "/v1/lifecycle/subjects/erase"},
		"subject-export": {Method: http.MethodPost, Path: "/v1/lifecycle/subjects/export"},
	}},
	"me": {Name: "me", Summary: "current principal", Ops: map[string]apiOp{
		"show": {Method: http.MethodGet, Path: "/v1/me"},
	}},
	"metric": {Name: "metric", Summary: "Grafana/Prometheus query surfaces", Ops: map[string]apiOp{
		"labels":           {Method: http.MethodGet, Path: "/v1/grafana/api/v1/labels"},
		"labels-post":      {Method: http.MethodPost, Path: "/v1/grafana/api/v1/labels"},
		"label-values":     {Method: http.MethodGet, Path: "/v1/grafana/api/v1/label/{name}/values", ArgName: "name"},
		"metadata":         {Method: http.MethodGet, Path: "/v1/grafana/api/v1/metadata"},
		"query":            {Method: http.MethodGet, Path: "/v1/grafana/api/v1/query"},
		"query-post":       {Method: http.MethodPost, Path: "/v1/grafana/api/v1/query"},
		"query-range":      {Method: http.MethodGet, Path: "/v1/grafana/api/v1/query_range"},
		"query-range-post": {Method: http.MethodPost, Path: "/v1/grafana/api/v1/query_range"},
		"series":           {Method: http.MethodGet, Path: "/v1/grafana/api/v1/series"},
		"series-post":      {Method: http.MethodPost, Path: "/v1/grafana/api/v1/series"},
		"buildinfo":        {Method: http.MethodGet, Path: "/v1/grafana/api/v1/status/buildinfo"},
		"federate":         {Method: http.MethodGet, Path: "/v1/prometheus/federate"},
	}},
	"otlp": {Name: "otlp", Summary: "OTLP tokens and stored signals", Ops: map[string]apiOp{
		"tokens":       {Method: http.MethodGet, Path: "/v1/otlp-tokens"},
		"create-token": {Method: http.MethodPost, Path: "/v1/otlp-tokens"},
		"delete-token": {Method: http.MethodDelete, Path: "/v1/otlp-tokens/{id}", ArgName: "id"},
		"logs":         {Method: http.MethodGet, Path: "/v1/otlp/logs"},
		"traces":       {Method: http.MethodGet, Path: "/v1/otlp/traces"},
	}},
	"outage": {Name: "outage", Summary: "internet outage view", Ops: map[string]apiOp{
		"list": {Method: http.MethodGet, Path: "/v1/outages"},
	}},
	"oncall": {Name: "oncall", Summary: "on-call alert and incident view", Ops: map[string]apiOp{
		"status":    {Method: http.MethodGet, Path: "/v1/oncall/status"},
		"alerts":    {Method: http.MethodGet, Path: "/v1/alerts/active"},
		"ack":       {Method: http.MethodPost, Path: "/v1/alerts/active/ack"},
		"silence":   {Method: http.MethodPost, Path: "/v1/alerts/active/silence"},
		"incidents": {Method: http.MethodGet, Path: "/v1/incidents"},
		"changes":   {Method: http.MethodGet, Path: "/v1/changes"},
		"test":      {Method: http.MethodPost, Path: "/v1/oncall/test", Description: "send an on-call connector test notification"},
	}},
	"provider": {Name: "provider", Summary: "provider/MSP operator plane", Ops: map[string]apiOp{
		"bootstrap":          {Method: http.MethodPost, Path: "/provider/v1/auth/bootstrap", Description: "create the first provider admin from the single-use deployment bootstrap token", SensitiveBody: true},
		"enroll-start":       {Method: http.MethodPost, Path: "/provider/v1/auth/enroll/start", Description: "exchange an operator enrollment token for the one-time TOTP binding", SensitiveBody: true},
		"enroll-complete":    {Method: http.MethodPost, Path: "/provider/v1/auth/enroll/complete", Description: "verify TOTP, set the password, and activate the provider operator", SensitiveBody: true},
		"login":              {Method: http.MethodPost, Path: "/provider/v1/auth/login", Description: "authenticate a provider operator with password and TOTP", SensitiveBody: true},
		"logout":             {Method: http.MethodPost, Path: "/provider/v1/auth/logout", Description: "end the current provider operator session"},
		"me":                 {Method: http.MethodGet, Path: "/provider/v1/me"},
		"license":            {Method: http.MethodGet, Path: "/provider/v1/license"},
		"operators":          {Method: http.MethodGet, Path: "/provider/v1/operators"},
		"create-operator":    {Method: http.MethodPost, Path: "/provider/v1/operators"},
		"operator-status":    {Method: http.MethodPost, Path: "/provider/v1/operators/{id}/status", ArgName: "id"},
		"tenants":            {Method: http.MethodGet, Path: "/provider/v1/tenants"},
		"create-tenant":      {Method: http.MethodPost, Path: "/provider/v1/tenants"},
		"update-tenant":      {Method: http.MethodPatch, Path: "/provider/v1/tenants/{id}", ArgName: "id"},
		"suspend-tenant":     {Method: http.MethodPost, Path: "/provider/v1/tenants/{id}/suspend", ArgName: "id"},
		"resume-tenant":      {Method: http.MethodPost, Path: "/provider/v1/tenants/{id}/resume", ArgName: "id"},
		"offboard-tenant":    {Method: http.MethodPost, Path: "/provider/v1/tenants/{id}/offboard", ArgName: "id"},
		"erase-tenant":       {Method: http.MethodPost, Path: "/provider/v1/tenants/{id}/erase", ArgName: "id"},
		"fleet":              {Method: http.MethodGet, Path: "/provider/v1/fleet"},
		"provisioning":       {Method: http.MethodGet, Path: "/provider/v1/tenants/provisioning", Description: "list stranded tenant provisioning attempts"},
		"abandon-provision":  {Method: http.MethodPost, Path: "/provider/v1/tenants/provisioning/{id}/abandon", ArgName: "id", Description: "tear down and abandon one stranded tenant provisioning attempt"},
		"breakglass":         {Method: http.MethodGet, Path: "/provider/v1/breakglass"},
		"request-breakglass": {Method: http.MethodPost, Path: "/provider/v1/breakglass"},
		"revoke-breakglass":  {Method: http.MethodPost, Path: "/provider/v1/breakglass/{id}/revoke", ArgName: "id"},
		"breakglass-results": {Method: http.MethodGet, Path: "/provider/v1/breakglass/{id}/results", ArgName: "id"},
		"audit":              {Method: http.MethodGet, Path: "/provider/v1/audit", Description: "page the provider audit stream (admin): every operator action, break-glass step and provisioning outcome; ?order=desc for newest first, after=/before= cursors, actor=/action=/target= filters", Columns: auditColumns},
		"consent":            {Method: http.MethodGet, Path: "/provider/v1/consent"},
		"decide-consent":     {Method: http.MethodPost, Path: "/provider/v1/consent/{id}", ArgName: "id"},
		"fairness":           {Method: http.MethodGet, Path: "/provider/v1/fairness"},
		"set-fairness":       {Method: http.MethodPut, Path: "/provider/v1/tenants/{id}/fairness", ArgName: "id"},
	}},
	"remediation": {Name: "remediation", Summary: "human-gated remediation proposals", Ops: map[string]apiOp{
		"list":    {Method: http.MethodGet, Path: "/v1/remediation/proposals"},
		"create":  {Method: http.MethodPost, Path: "/v1/remediation/proposals"},
		"get":     {Method: http.MethodGet, Path: "/v1/remediation/proposals/{id}", ArgName: "id"},
		"approve": {Method: http.MethodPost, Path: "/v1/remediation/proposals/{id}/approve", ArgName: "id"},
		"reject":  {Method: http.MethodPost, Path: "/v1/remediation/proposals/{id}/reject", ArgName: "id"},
	}},
	"result": {Name: "result", Summary: "synthetic results", Ops: map[string]apiOp{
		"latest":  {Method: http.MethodGet, Path: "/v1/results/latest"},
		"history": {Method: http.MethodGet, Path: "/v1/results/history", Description: "recent results inside the trailing window (oldest first)"},
	}},
	"rollout": {Name: "rollout", Summary: "fleet rollouts", Ops: map[string]apiOp{
		"list":    {Method: http.MethodGet, Path: "/v1/rollouts"},
		"create":  {Method: http.MethodPost, Path: "/v1/rollouts"},
		"get":     {Method: http.MethodGet, Path: "/v1/rollouts/{id}", ArgName: "id"},
		"advance": {Method: http.MethodPost, Path: "/v1/rollouts/{id}/advance", ArgName: "id"},
		"halt":    {Method: http.MethodPost, Path: "/v1/rollouts/{id}/halt", ArgName: "id"},
		"resume":  {Method: http.MethodPost, Path: "/v1/rollouts/{id}/resume", ArgName: "id"},
		"verify":  {Method: http.MethodPost, Path: "/v1/rollouts/{id}/verify", ArgName: "id"},
	}},
	"rum": {Name: "rum", Summary: "real-user monitoring", Ops: map[string]apiOp{
		"summary": {Method: http.MethodGet, Path: "/v1/rum"},
	}},
	"secret": {Name: "secret", Summary: "secret backend health", Ops: map[string]apiOp{
		"health": {Method: http.MethodGet, Path: "/v1/secrets/health"},
	}},
	"siem": {Name: "siem", Summary: "SIEM export status", Ops: map[string]apiOp{
		"status": {Method: http.MethodGet, Path: "/v1/siem/status", Description: "show SIEM export posture"},
	}},
	"directory": {Name: "directory", Summary: "people and roles (tenant RBAC without SCIM)", Ops: map[string]apiOp{
		"users":       {Method: http.MethodGet, Path: "/v1/directory/users", Description: "list the tenant's users with their bound roles"},
		"roles":       {Method: http.MethodGet, Path: "/v1/directory/roles", Description: "list roles with permissions and member counts"},
		"create-user": {Method: http.MethodPost, Path: "/v1/directory/users", Description: "create a person before first login; --body '{\"email\":\"a@x\",\"role\":\"editor\"}'"},
		"grant":       {Method: http.MethodPost, Path: "/v1/directory/users/{id}/roles", ArgName: "id", Description: "bind a role: --body '{\"role\":\"editor\"}'"},
		"revoke":      {Method: http.MethodDelete, Path: "/v1/directory/users/{id}/roles/{role}", ArgName: "id,role", Description: "remove a role from a user (the last administrator is refused)"},
	}},
	"scim": {Name: "scim", Summary: "SCIM identity-provider tokens", Ops: map[string]apiOp{
		"tokens":       {Method: http.MethodGet, Path: "/v1/directory/scim-tokens"},
		"create-token": {Method: http.MethodPost, Path: "/v1/directory/scim-tokens"},
		"revoke-token": {Method: http.MethodDelete, Path: "/v1/directory/scim-tokens/{id}", ArgName: "id"},
	}},
	"key": {Name: "key", Summary: "security key posture", Ops: map[string]apiOp{
		"list":   {Method: http.MethodGet, Path: "/v1/security/keys"},
		"rotate": {Method: http.MethodPost, Path: "/v1/security/keys/rotate"},
	}},
	"slo": {Name: "slo", Summary: "SLO status and OpenSLO export", Ops: map[string]apiOp{
		"list":   {Method: http.MethodGet, Path: "/v1/slos"},
		"export": {Method: http.MethodGet, Path: "/v1/slos/openslo"},
	}},
	"threat": {Name: "threat", Summary: "threat detections and intel status", Ops: map[string]apiOp{
		"detections":   {Method: http.MethodGet, Path: "/v1/threat/detections"},
		"intel-status": {Method: http.MethodGet, Path: "/v1/threat/intel/status"},
	}},
	"opendata": {Name: "opendata", Summary: "open-data enrichment lookup", Ops: map[string]apiOp{
		"enrich": {Method: http.MethodGet, Path: "/v1/opendata/enrichment", Description: "open-data context for one IP (--query ip=<addr>)"},
	}},
	"tls": {Name: "tls", Summary: "TLS/certificate posture", Ops: map[string]apiOp{
		"posture": {Method: http.MethodGet, Path: "/v1/tls/posture"},
	}},
	"topology": {Name: "topology", Summary: "topology and what-if simulation", Ops: map[string]apiOp{
		"show":          {Method: http.MethodGet, Path: "/v1/topology"},
		"whatif":        {Method: http.MethodPost, Path: "/v1/topology/whatif"},
		"whatif-export": {Method: http.MethodGet, Path: "/v1/topology/whatif/export", Description: "export the tenant-scoped what-if evidence artifact"},
	}},
	"tenant": {Name: "tenant", Summary: "provider tenant lifecycle", Ops: map[string]apiOp{
		"list":     {Method: http.MethodGet, Path: "/provider/v1/tenants"},
		"create":   {Method: http.MethodPost, Path: "/provider/v1/tenants"},
		"update":   {Method: http.MethodPatch, Path: "/provider/v1/tenants/{id}", ArgName: "id"},
		"suspend":  {Method: http.MethodPost, Path: "/provider/v1/tenants/{id}/suspend", ArgName: "id"},
		"resume":   {Method: http.MethodPost, Path: "/provider/v1/tenants/{id}/resume", ArgName: "id"},
		"offboard": {Method: http.MethodPost, Path: "/provider/v1/tenants/{id}/offboard", ArgName: "id"},
		"erase":    {Method: http.MethodPost, Path: "/provider/v1/tenants/{id}/erase", ArgName: "id"},
	}},
}

var cliCoverageExceptions = []cliCoverage{
	{Method: http.MethodPost, Path: "/v1/prometheus/write", Command: "none-by-design", Reason: "Prometheus remote-write is a snappy/protobuf ingest endpoint; use Prometheus remote_write, not the JSON CLI."},
}

func cliImplementedCoverage() []cliCoverage {
	var out []cliCoverage
	out = append(out, specialCLICoverage()...)
	for _, spec := range surfaceCommands {
		for name, op := range spec.Ops {
			out = append(out, cliCoverage{
				Method:  op.Method,
				Path:    op.Path,
				Command: "probectl " + spec.Name + " " + name,
			})
		}
	}
	return out
}

func specialCLICoverage() []cliCoverage {
	return []cliCoverage{
		{Method: http.MethodGet, Path: "/v1/tests", Command: "probectl test list"},
		{Method: http.MethodPost, Path: "/v1/tests", Command: "probectl test create"},
		{Method: http.MethodGet, Path: "/v1/tests/{id}", Command: "probectl test get <id>"},
		{Method: http.MethodPut, Path: "/v1/tests/{id}", Command: "probectl test update <id>"},
		{Method: http.MethodDelete, Path: "/v1/tests/{id}", Command: "probectl test delete <id>"},
		{Method: http.MethodGet, Path: "/v1/tests/bundle", Command: "probectl test bundle"},
		{Method: http.MethodGet, Path: "/v1/tests/{id}/path", Command: "probectl test path <id>"},
		{Method: http.MethodPost, Path: "/v1/tests/{id}/path", Command: "probectl test path <id> --body"},
		{Method: http.MethodGet, Path: "/v1/tests/{id}/path/history", Command: "probectl test path-history <id>"},
		{Method: http.MethodGet, Path: "/v1/agents", Command: "probectl agent list"},
		{Method: http.MethodPost, Path: "/v1/agents/enroll-tokens", Command: "probectl agent enroll-token"},
		{Method: http.MethodGet, Path: "/v1/agents/{id}", Command: "probectl agent get <id>"},
		{Method: http.MethodPatch, Path: "/v1/agents/{id}", Command: "probectl agent patch <id>"},
		{Method: http.MethodDelete, Path: "/v1/agents/{id}", Command: "probectl agent delete <id>"},
		{Method: http.MethodGet, Path: "/v1/agents/{id}/ci", Command: "probectl agent ci <id>"},
		{Method: http.MethodPost, Path: "/v1/agents/{id}/revoke", Command: "probectl agent revoke <id>"},
	}
}
