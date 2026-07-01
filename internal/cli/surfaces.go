// SPDX-License-Identifier: LicenseRef-probectl-TBD

package cli

import "net/http"

type apiOp struct {
	Method      string
	Path        string
	ArgName     string
	Description string
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
	}},
	"abac": {Name: "abac", Summary: "ABAC policies", Ops: map[string]apiOp{
		"list":   {Method: http.MethodGet, Path: "/v1/abac/policies"},
		"create": {Method: http.MethodPost, Path: "/v1/abac/policies"},
		"delete": {Method: http.MethodDelete, Path: "/v1/abac/policies/{id}", ArgName: "id"},
	}},
	"ai": {Name: "ai", Summary: "AI/RCA and authoring", Ops: map[string]apiOp{
		"ask":      {Method: http.MethodPost, Path: "/v1/ai/ask"},
		"author":   {Method: http.MethodPost, Path: "/v1/ai/author"},
		"discover": {Method: http.MethodPost, Path: "/v1/ai/discover"},
		"feedback": {Method: http.MethodPost, Path: "/v1/ai/feedback"},
	}},
	"alert": {Name: "alert", Summary: "alert rules and active alerts", Ops: map[string]apiOp{
		"list":    {Method: http.MethodGet, Path: "/v1/alerts"},
		"create":  {Method: http.MethodPost, Path: "/v1/alerts"},
		"get":     {Method: http.MethodGet, Path: "/v1/alerts/{id}", ArgName: "id"},
		"update":  {Method: http.MethodPut, Path: "/v1/alerts/{id}", ArgName: "id"},
		"delete":  {Method: http.MethodDelete, Path: "/v1/alerts/{id}", ArgName: "id"},
		"active":  {Method: http.MethodGet, Path: "/v1/alerts/active"},
		"ack":     {Method: http.MethodPost, Path: "/v1/alerts/active/ack"},
		"silence": {Method: http.MethodPost, Path: "/v1/alerts/active/silence"},
	}},
	"audit": {Name: "audit", Summary: "audit log and verification", Ops: map[string]apiOp{
		"list":   {Method: http.MethodGet, Path: "/v1/audit"},
		"verify": {Method: http.MethodGet, Path: "/v1/audit/verify"},
	}},
	"bgp": {Name: "bgp", Summary: "BGP/routing events", Ops: map[string]apiOp{
		"events": {Method: http.MethodGet, Path: "/v1/bgp/events", Description: "list tenant BGP/routing events"},
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
	"branding": {Name: "branding", Summary: "provider and tenant white-label branding", Ops: map[string]apiOp{
		"provider":     {Method: http.MethodGet, Path: "/provider/v1/branding"},
		"set-provider": {Method: http.MethodPut, Path: "/provider/v1/branding"},
		"tenant":       {Method: http.MethodGet, Path: "/provider/v1/tenants/{id}/branding", ArgName: "id"},
		"set-tenant":   {Method: http.MethodPut, Path: "/provider/v1/tenants/{id}/branding", ArgName: "id"},
	}},
	"device": {Name: "device", Summary: "device inventory and telemetry", Ops: map[string]apiOp{
		"list":    {Method: http.MethodGet, Path: "/v1/devices"},
		"metrics": {Method: http.MethodGet, Path: "/v1/device/metrics", Description: "latest tenant device metric summaries"},
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
	"diagnostics": {Name: "diagnostics", Summary: "diagnostics and support bundle", Ops: map[string]apiOp{
		"status": {Method: http.MethodGet, Path: "/v1/diagnostics"},
		"bundle": {Method: http.MethodGet, Path: "/v1/diagnostics/bundle"},
	}},
	"editions": {Name: "editions", Summary: "license and edition state", Ops: map[string]apiOp{
		"status": {Method: http.MethodGet, Path: "/v1/editions"},
	}},
	"endpoint": {Name: "endpoint", Summary: "endpoint/DEM fleet", Ops: map[string]apiOp{
		"list": {Method: http.MethodGet, Path: "/v1/endpoints"},
	}},
	"fairness": {Name: "fairness", Summary: "tenant fairness posture", Ops: map[string]apiOp{
		"status": {Method: http.MethodGet, Path: "/v1/fairness"},
	}},
	"flow": {Name: "flow", Summary: "flow analytics", Ops: map[string]apiOp{
		"top":       {Method: http.MethodGet, Path: "/v1/flows/top"},
		"capacity":  {Method: http.MethodGet, Path: "/v1/flows/capacity"},
		"anomalies": {Method: http.MethodGet, Path: "/v1/flows/anomalies"},
	}},
	"governance": {Name: "governance", Summary: "provider data-governance policy", Ops: map[string]apiOp{
		"tenant":     {Method: http.MethodGet, Path: "/provider/v1/tenants/{id}/governance", ArgName: "id"},
		"set-tenant": {Method: http.MethodPut, Path: "/provider/v1/tenants/{id}/governance", ArgName: "id"},
	}},
	"incident": {Name: "incident", Summary: "incidents and correlations", Ops: map[string]apiOp{
		"list":    {Method: http.MethodGet, Path: "/v1/incidents"},
		"get":     {Method: http.MethodGet, Path: "/v1/incidents/{id}", ArgName: "id"},
		"update":  {Method: http.MethodPatch, Path: "/v1/incidents/{id}", ArgName: "id"},
		"changes": {Method: http.MethodGet, Path: "/v1/incidents/{id}/changes", ArgName: "id"},
		"cis":     {Method: http.MethodGet, Path: "/v1/incidents/{id}/cis", ArgName: "id"},
	}},
	"inventory-view": {Name: "inventory-view", Summary: "saved inventory list views", Ops: map[string]apiOp{
		"list":   {Method: http.MethodGet, Path: "/v1/inventory/views"},
		"create": {Method: http.MethodPost, Path: "/v1/inventory/views"},
		"get":    {Method: http.MethodGet, Path: "/v1/inventory/views/{id}", ArgName: "id"},
	}},
	"isolation": {Name: "isolation", Summary: "provider tenant isolation model operations", Ops: map[string]apiOp{
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
		"alerts":    {Method: http.MethodGet, Path: "/v1/alerts/active"},
		"ack":       {Method: http.MethodPost, Path: "/v1/alerts/active/ack"},
		"silence":   {Method: http.MethodPost, Path: "/v1/alerts/active/silence"},
		"incidents": {Method: http.MethodGet, Path: "/v1/incidents"},
		"changes":   {Method: http.MethodGet, Path: "/v1/changes"},
	}},
	"provider": {Name: "provider", Summary: "provider/MSP operator plane", Ops: map[string]apiOp{
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
		"breakglass":         {Method: http.MethodGet, Path: "/provider/v1/breakglass"},
		"request-breakglass": {Method: http.MethodPost, Path: "/provider/v1/breakglass"},
		"revoke-breakglass":  {Method: http.MethodPost, Path: "/provider/v1/breakglass/{id}/revoke", ArgName: "id"},
		"breakglass-results": {Method: http.MethodGet, Path: "/provider/v1/breakglass/{id}/results", ArgName: "id"},
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
	"result": {Name: "result", Summary: "latest synthetic results", Ops: map[string]apiOp{
		"latest": {Method: http.MethodGet, Path: "/v1/results/latest"},
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
	"threat": {Name: "threat", Summary: "threat detections", Ops: map[string]apiOp{
		"detections": {Method: http.MethodGet, Path: "/v1/threat/detections"},
	}},
	"tls": {Name: "tls", Summary: "TLS/certificate posture", Ops: map[string]apiOp{
		"posture": {Method: http.MethodGet, Path: "/v1/tls/posture"},
	}},
	"topology": {Name: "topology", Summary: "topology and what-if simulation", Ops: map[string]apiOp{
		"show":   {Method: http.MethodGet, Path: "/v1/topology"},
		"whatif": {Method: http.MethodPost, Path: "/v1/topology/whatif"},
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
		{Method: http.MethodGet, Path: "/v1/agents", Command: "probectl agent list"},
		{Method: http.MethodPost, Path: "/v1/agents/enroll-tokens", Command: "probectl agent enroll-token"},
		{Method: http.MethodGet, Path: "/v1/agents/{id}", Command: "probectl agent get <id>"},
		{Method: http.MethodPatch, Path: "/v1/agents/{id}", Command: "probectl agent patch <id>"},
		{Method: http.MethodDelete, Path: "/v1/agents/{id}", Command: "probectl agent delete <id>"},
		{Method: http.MethodGet, Path: "/v1/agents/{id}/ci", Command: "probectl agent ci <id>"},
		{Method: http.MethodPost, Path: "/v1/agents/{id}/revoke", Command: "probectl agent revoke <id>"},
	}
}
