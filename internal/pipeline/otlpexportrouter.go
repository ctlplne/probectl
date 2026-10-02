// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

// Per-tenant OTLP re-export routing (RTP-06). A single shared export endpoint
// fans every tenant's telemetry to one collector — in a multi-tenant/regulated
// deployment that crosses tenants: tenant A's spans/logs/metrics reach tenant
// B's (or the provider's) collector. The deployment config refuses a shared
// endpoint under the production-like profiles and requires a PER-TENANT endpoint
// instead; this router carries that mapping into the export consumers so a
// tenant's telemetry can only ever reach that tenant's own collector, and a
// tenant with no configured endpoint is dropped closed (never forwarded to
// someone else's) — docs/guardrails.md G7-1.

// SignalExporter forwards any of the three OTLP signals to one collector
// endpoint. The real internal/otel/otlp.{GRPC,HTTP}Exporter satisfy it.
type SignalExporter interface {
	MetricsExporter
	TracesExporter
	LogsExporter
}

// TenantExportRouter maps each tenant to its OWN export client. It holds no
// shared/default fallback by construction: a tenant that is not in the map has
// no export destination, so its records are dropped rather than sent to another
// tenant's collector (fail closed).
type TenantExportRouter struct {
	byTenant map[string]SignalExporter
}

// NewTenantExportRouter builds an empty router.
func NewTenantExportRouter() *TenantExportRouter {
	return &TenantExportRouter{byTenant: map[string]SignalExporter{}}
}

// Add registers a tenant's export client. A nil exporter or empty tenant is
// ignored (that tenant then resolves to "no endpoint" and is dropped closed).
func (r *TenantExportRouter) Add(tenant string, exp SignalExporter) *TenantExportRouter {
	if r == nil || tenant == "" || exp == nil {
		return r
	}
	r.byTenant[tenant] = exp
	return r
}

// Len reports how many tenants have a configured export endpoint.
func (r *TenantExportRouter) Len() int {
	if r == nil {
		return 0
	}
	return len(r.byTenant)
}

// exporterFor returns the per-tenant export client, or (nil,false) when the
// tenant has no configured endpoint (drop closed).
func (r *TenantExportRouter) exporterFor(tenant string) (SignalExporter, bool) {
	if r == nil || tenant == "" {
		return nil, false
	}
	exp, ok := r.byTenant[tenant]
	return exp, ok
}
