// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"net/http"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type auditFacet string

const (
	auditFacetMutation      auditFacet = "mutation"
	auditFacetSensitiveRead auditFacet = "sensitive_read"
	auditFacetExport        auditFacet = "export"
	auditFacetOperational   auditFacet = "operational_action"
)

type auditMode string

const (
	auditModeExplicit auditMode = "explicit"
	auditModeWrapped  auditMode = "wrapped"
)

type auditRoutePolicy struct {
	Facet  auditFacet
	Mode   auditMode
	Action string
	Target string
}

func auditExplicit(facet auditFacet, action string) auditRoutePolicy {
	return auditRoutePolicy{Facet: facet, Mode: auditModeExplicit, Action: action}
}

func auditWrapped(facet auditFacet) auditRoutePolicy {
	return auditRoutePolicy{Facet: facet, Mode: auditModeWrapped}
}

func routeKey(method, pattern string) string { return method + " " + pattern }

func auditPolicyFor(method, pattern string) (auditRoutePolicy, bool) {
	p, ok := auditPolicyMatrix[routeKey(method, pattern)]
	if !ok {
		return auditRoutePolicy{}, false
	}
	return p.withDefaults(pattern), true
}

func (p auditRoutePolicy) withDefaults(pattern string) auditRoutePolicy {
	if p.Target == "" {
		p.Target = pattern
	}
	if p.Action == "" {
		p.Action = defaultAuditAction(p.Facet, pattern)
	}
	return p
}

func defaultAuditAction(facet auditFacet, pattern string) string {
	prefix := "access"
	switch facet {
	case auditFacetMutation:
		prefix = "access.mutate"
	case auditFacetSensitiveRead:
		prefix = "access.read"
	case auditFacetExport:
		prefix = "access.export"
	case auditFacetOperational:
		prefix = "access.operate"
	}
	base := strings.Trim(strings.TrimPrefix(pattern, "/v1/"), "/")
	base = strings.ReplaceAll(base, "{id}", "id")
	base = strings.NewReplacer("/", ".", "-", "_").Replace(base)
	if base == "" {
		base = "route"
	}
	return prefix + "." + base
}

func (p auditRoutePolicy) active() bool {
	return p.Mode == auditModeExplicit || p.Mode == auditModeWrapped
}

// auditRequiredFacet is the guardrail classifier used by the test suite: every
// tenant data-access route is either in this matrix or explicitly exempted.
func auditRequiredFacet(method, pattern string) (auditFacet, bool) {
	key := routeKey(method, pattern)
	if auditExemptRoutes[key] {
		return "", false
	}
	if auditExportRoutes[key] {
		return auditFacetExport, true
	}
	if auditSensitiveReadRoutes[key] {
		return auditFacetSensitiveRead, true
	}
	if auditOperationalRoutes[key] || strings.HasPrefix(pattern, "/v1/remediation") ||
		strings.HasPrefix(pattern, "/v1/rollouts") || strings.HasPrefix(pattern, "/v1/a2a/") {
		return auditFacetOperational, true
	}
	if method == http.MethodGet {
		return auditFacetSensitiveRead, true
	}
	return auditFacetMutation, true
}

// auditRoute records route-level audit events for policies whose handlers do
// not already append an explicit domain audit event. Pool-less unit servers
// cannot write the audit table, so they skip the wrapper while retaining the
// policy metadata that the coverage test verifies.
func (s *Server) auditRoute(rt apiRoute, p auditRoutePolicy, next apiHandler) apiHandler {
	p = p.withDefaults(rt.Pattern)
	return func(w http.ResponseWriter, r *http.Request) error {
		if s.pool != nil {
			data := map[string]any{
				"facet":  string(p.Facet),
				"method": rt.Method,
				"path":   rt.Pattern,
			}
			if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
				return s.recordAudit(ctx, sc, r, p.Action, p.Target, data)
			}); err != nil {
				return err
			}
		}
		return next(w, r)
	}
}

var auditExemptRoutes = map[string]bool{
	"GET /v1/audit":        true, // audit-console polling must not grow the chain it reads.
	"GET /v1/audit/verify": true,
	"GET /v1/me":           true,
}

var auditExportRoutes = map[string]bool{
	"GET /v1/tests/bundle":               true,
	"GET /v1/prometheus/federate":        true,
	"GET /v1/compliance/evidence":        true,
	"GET /v1/slos/openslo":               true,
	"GET /v1/lifecycle/export":           true,
	"POST /v1/lifecycle/subjects/export": true,
	"GET /v1/diagnostics/bundle":         true,
}

var auditSensitiveReadRoutes = map[string]bool{
	"POST /v1/grafana/api/v1/query":       true,
	"POST /v1/grafana/api/v1/query_range": true,
	"POST /v1/grafana/api/v1/series":      true,
	"POST /v1/grafana/api/v1/labels":      true,
	"POST /v1/alerts/maintenance/preview": true,
	"POST /v1/ai/ask":                     true,
	"POST /v1/ai/author":                  true,
}

var auditOperationalRoutes = map[string]bool{
	"POST /v1/tests/{id}/path":       true,
	"POST /v1/agents/enroll-tokens":  true,
	"POST /v1/collectors/register":   true,
	"POST /v1/agents/{id}/revoke":    true,
	"POST /v1/alerts/active/silence": true,
	"POST /v1/alerts/active/ack":     true,
	"POST /v1/security/keys/rotate":  true,
	"POST /v1/topology/whatif":       true,
	"POST /v1/ai/discover":           true,
}

var auditPolicyMatrix = map[string]auditRoutePolicy{
	"GET /v1/tests":                               auditWrapped(auditFacetSensitiveRead),
	"POST /v1/tests":                              auditExplicit(auditFacetMutation, "test.create"),
	"GET /v1/tests/{id}":                          auditWrapped(auditFacetSensitiveRead),
	"PUT /v1/tests/{id}":                          auditExplicit(auditFacetMutation, "test.update"),
	"DELETE /v1/tests/{id}":                       auditExplicit(auditFacetMutation, "test.delete"),
	"GET /v1/tests/bundle":                        auditWrapped(auditFacetExport),
	"GET /v1/tests/{id}/path":                     auditWrapped(auditFacetSensitiveRead),
	"POST /v1/tests/{id}/path":                    auditWrapped(auditFacetOperational),
	"GET /v1/agents":                              auditWrapped(auditFacetSensitiveRead),
	"POST /v1/agents/enroll-tokens":               auditExplicit(auditFacetOperational, "agent.enroll_token_minted"),
	"POST /v1/collectors/register":                auditExplicit(auditFacetOperational, "collector.registered"),
	"POST /v1/agents/{id}/revoke":                 auditExplicit(auditFacetOperational, "agent.revoked"),
	"GET /v1/agents/{id}":                         auditWrapped(auditFacetSensitiveRead),
	"PATCH /v1/agents/{id}":                       auditExplicit(auditFacetMutation, "agent.update"),
	"DELETE /v1/agents/{id}":                      auditExplicit(auditFacetMutation, "agent.delete"),
	"GET /v1/alerts":                              auditWrapped(auditFacetSensitiveRead),
	"POST /v1/alerts":                             auditExplicit(auditFacetMutation, "alert.create"),
	"GET /v1/alerts/active":                       auditWrapped(auditFacetSensitiveRead),
	"POST /v1/alerts/active/silence":              auditExplicit(auditFacetOperational, "alert.silence"),
	"POST /v1/alerts/active/ack":                  auditExplicit(auditFacetOperational, "alert.acknowledge"),
	"GET /v1/alerts/maintenance":                  auditWrapped(auditFacetSensitiveRead),
	"POST /v1/alerts/maintenance":                 auditExplicit(auditFacetMutation, "alert.maintenance_upsert"),
	"POST /v1/alerts/maintenance/preview":         auditWrapped(auditFacetSensitiveRead),
	"DELETE /v1/alerts/maintenance/{id}":          auditExplicit(auditFacetMutation, "alert.maintenance_delete"),
	"GET /v1/alerts/{id}":                         auditWrapped(auditFacetSensitiveRead),
	"PUT /v1/alerts/{id}":                         auditExplicit(auditFacetMutation, "alert.update"),
	"DELETE /v1/alerts/{id}":                      auditExplicit(auditFacetMutation, "alert.delete"),
	"GET /v1/incidents":                           auditWrapped(auditFacetSensitiveRead),
	"GET /v1/incidents/{id}":                      auditWrapped(auditFacetSensitiveRead),
	"GET /v1/incidents/{id}/changes":              auditWrapped(auditFacetSensitiveRead),
	"PATCH /v1/incidents/{id}":                    auditExplicit(auditFacetMutation, "incident.resolve"),
	"GET /v1/oncall/status":                       auditWrapped(auditFacetSensitiveRead),
	"GET /v1/changes":                             auditWrapped(auditFacetSensitiveRead),
	"GET /v1/bgp/events":                          auditWrapped(auditFacetSensitiveRead),
	"GET /v1/devices":                             auditWrapped(auditFacetSensitiveRead),
	"GET /v1/device/metrics":                      auditWrapped(auditFacetSensitiveRead),
	"GET /v1/ebpf/service-map":                    auditWrapped(auditFacetSensitiveRead),
	"GET /v1/flows/top":                           auditWrapped(auditFacetSensitiveRead),
	"GET /v1/flows/capacity":                      auditWrapped(auditFacetSensitiveRead),
	"GET /v1/flows/anomalies":                     auditWrapped(auditFacetSensitiveRead),
	"GET /v1/otlp/traces":                         auditWrapped(auditFacetSensitiveRead),
	"GET /v1/otlp/logs":                           auditWrapped(auditFacetSensitiveRead),
	"GET /v1/otlp-tokens":                         auditWrapped(auditFacetSensitiveRead),
	"POST /v1/otlp-tokens":                        auditExplicit(auditFacetMutation, "security.otlp_token_create"),
	"DELETE /v1/otlp-tokens/{id}":                 auditExplicit(auditFacetMutation, "security.otlp_token_revoke"),
	"GET /v1/grafana/api/v1/query":                auditWrapped(auditFacetSensitiveRead),
	"POST /v1/grafana/api/v1/query":               auditWrapped(auditFacetSensitiveRead),
	"GET /v1/grafana/api/v1/query_range":          auditWrapped(auditFacetSensitiveRead),
	"POST /v1/grafana/api/v1/query_range":         auditWrapped(auditFacetSensitiveRead),
	"GET /v1/grafana/api/v1/series":               auditWrapped(auditFacetSensitiveRead),
	"POST /v1/grafana/api/v1/series":              auditWrapped(auditFacetSensitiveRead),
	"GET /v1/grafana/api/v1/labels":               auditWrapped(auditFacetSensitiveRead),
	"POST /v1/grafana/api/v1/labels":              auditWrapped(auditFacetSensitiveRead),
	"GET /v1/grafana/api/v1/label/{name}/values":  auditWrapped(auditFacetSensitiveRead),
	"GET /v1/grafana/api/v1/status/buildinfo":     auditWrapped(auditFacetSensitiveRead),
	"GET /v1/grafana/api/v1/metadata":             auditWrapped(auditFacetSensitiveRead),
	"GET /v1/prometheus/federate":                 auditWrapped(auditFacetExport),
	"POST /v1/prometheus/write":                   auditWrapped(auditFacetMutation),
	"GET /v1/results/latest":                      auditWrapped(auditFacetSensitiveRead),
	"GET /v1/endpoints":                           auditWrapped(auditFacetSensitiveRead),
	"GET /v1/inventory/views":                     auditWrapped(auditFacetSensitiveRead),
	"POST /v1/inventory/views":                    auditExplicit(auditFacetMutation, "inventory.view.create"),
	"GET /v1/inventory/views/{id}":                auditWrapped(auditFacetSensitiveRead),
	"GET /v1/tls/posture":                         auditWrapped(auditFacetSensitiveRead),
	"GET /v1/siem/status":                         auditWrapped(auditFacetSensitiveRead),
	"GET /v1/threat/detections":                   auditWrapped(auditFacetSensitiveRead),
	"GET /v1/cmdb/lookup":                         auditWrapped(auditFacetSensitiveRead),
	"GET /v1/secrets/health":                      auditWrapped(auditFacetSensitiveRead),
	"GET /v1/topology":                            auditWrapped(auditFacetSensitiveRead),
	"GET /v1/cost/summary":                        auditWrapped(auditFacetSensitiveRead),
	"GET /v1/slos":                                auditWrapped(auditFacetSensitiveRead),
	"GET /v1/compliance":                          auditWrapped(auditFacetSensitiveRead),
	"GET /v1/compliance/evidence":                 auditWrapped(auditFacetExport),
	"GET /v1/slos/openslo":                        auditWrapped(auditFacetExport),
	"GET /v1/outages":                             auditWrapped(auditFacetSensitiveRead),
	"GET /v1/rum":                                 auditWrapped(auditFacetSensitiveRead),
	"GET /v1/carbon":                              auditWrapped(auditFacetSensitiveRead),
	"GET /v1/editions":                            auditWrapped(auditFacetSensitiveRead),
	"GET /v1/lifecycle/export":                    auditWrapped(auditFacetExport),
	"POST /v1/lifecycle/subjects/export":          auditWrapped(auditFacetExport),
	"POST /v1/lifecycle/subjects/erase":           auditWrapped(auditFacetMutation),
	"GET /v1/lifecycle/retention":                 auditWrapped(auditFacetSensitiveRead),
	"PUT /v1/lifecycle/retention":                 auditExplicit(auditFacetMutation, "lifecycle.retention_set"),
	"POST /v1/lifecycle/erase":                    auditWrapped(auditFacetMutation),
	"GET /v1/security/keys":                       auditWrapped(auditFacetSensitiveRead),
	"GET /v1/fairness":                            auditWrapped(auditFacetSensitiveRead),
	"GET /v1/diagnostics":                         auditWrapped(auditFacetSensitiveRead),
	"GET /v1/diagnostics/bundle":                  auditWrapped(auditFacetExport),
	"GET /v1/remediation/proposals":               auditWrapped(auditFacetOperational),
	"POST /v1/remediation/proposals":              auditWrapped(auditFacetOperational),
	"GET /v1/remediation/proposals/{id}":          auditWrapped(auditFacetOperational),
	"POST /v1/remediation/proposals/{id}/approve": auditWrapped(auditFacetOperational),
	"POST /v1/remediation/proposals/{id}/reject":  auditWrapped(auditFacetOperational),
	"POST /v1/security/keys/rotate":               auditExplicit(auditFacetOperational, "security.key_rotate"),
	"POST /v1/topology/whatif":                    auditWrapped(auditFacetOperational),
	"GET /v1/incidents/{id}/cis":                  auditWrapped(auditFacetSensitiveRead),
	"GET /v1/agents/{id}/ci":                      auditWrapped(auditFacetSensitiveRead),
	"POST /v1/ai/ask":                             auditExplicit(auditFacetSensitiveRead, "ai.ask"),
	"POST /v1/ai/feedback":                        auditExplicit(auditFacetMutation, "ai.feedback"),
	"POST /v1/ai/author":                          auditExplicit(auditFacetSensitiveRead, "ai.author"),
	"POST /v1/ai/discover":                        auditWrapped(auditFacetOperational),
	"GET /v1/abac/policies":                       auditWrapped(auditFacetSensitiveRead),
	"POST /v1/abac/policies":                      auditExplicit(auditFacetMutation, "abac.policy_create"),
	"DELETE /v1/abac/policies/{id}":               auditExplicit(auditFacetMutation, "abac.policy_delete"),
	"GET /v1/directory/scim-tokens":               auditWrapped(auditFacetSensitiveRead),
	"POST /v1/directory/scim-tokens":              auditExplicit(auditFacetMutation, "directory.scim_token_create"),
	"DELETE /v1/directory/scim-tokens/{id}":       auditExplicit(auditFacetMutation, "directory.scim_token_revoke"),
	"POST /v1/a2a/sessions":                       auditExplicit(auditFacetOperational, "a2a.session.start"),
	"POST /v1/a2a/mesh":                           auditExplicit(auditFacetOperational, "a2a.mesh.start"),
	"GET /v1/rollouts":                            auditWrapped(auditFacetOperational),
	"POST /v1/rollouts":                           auditExplicit(auditFacetOperational, "rollout.create"),
	"GET /v1/rollouts/{id}":                       auditWrapped(auditFacetOperational),
	"POST /v1/rollouts/{id}/advance":              auditExplicit(auditFacetOperational, "rollout.advance"),
	"POST /v1/rollouts/{id}/verify":               auditExplicit(auditFacetOperational, "rollout.verify"),
	"POST /v1/rollouts/{id}/halt":                 auditExplicit(auditFacetOperational, "rollout.halt"),
	"POST /v1/rollouts/{id}/resume":               auditExplicit(auditFacetOperational, "rollout.resume"),
}
