// Package usage is the core metering seam (S-T3, F53): a zero-cost hook the
// tenant-tagged data paths call as they already flow (results, flow batches,
// AI calls) plus a quota gate the resource-creation paths consult.
//
// The seam follows the tenancy.SetRouter pattern: core ships no-op defaults
// (community deployments meter nothing and allow everything); the ee/billing
// implementation is installed at the main.go attach seam when the license
// grants the metering feature. Metering derives from the streams already
// flowing — never a parallel pipeline (the S-T3 contract).
package usage

import (
	"context"
	"sync"
)

// Meter names recorded by core call sites. ee/billing owns aggregation; the
// names are core vocabulary so call sites and exports agree.
const (
	MeterResultsIngested = "results_ingested" // canonical results consumed (count)
	MeterIngestBytes     = "ingest_bytes"     // result payload bytes consumed
	MeterFlowEvents      = "flow_events"      // flow records landed in the flow store
	MeterAICalls         = "ai_calls"         // AI assistant questions answered
	// Gauges collected by the ee snapshot collector (not recorded here, but
	// part of the same vocabulary): "agents", "tests".
	MeterAgents = "agents"
	MeterTests  = "tests"
)

// Recorder receives usage deltas. Implementations must be cheap and
// non-blocking (they sit on hot ingest paths) and tolerate concurrent use.
type Recorder interface {
	Record(tenantID, meter string, delta int64)
}

// QuotaChecker gates control-plane RESOURCE CREATION (tests, agents) against
// per-tenant quotas. Telemetry ingestion is NEVER quota-dropped here —
// fairness throttling of pooled ingest is S-T7's job, and observability
// must not silently lose data (the house doctrine).
type QuotaChecker interface {
	// AllowCreate returns nil when tenantID may create one more resource of
	// the given kind ("agents" | "tests"), or a descriptive error when the
	// tenant's quota is exhausted.
	AllowCreate(ctx context.Context, tenantID, resource string) error
}

type nopRecorder struct{}

func (nopRecorder) Record(string, string, int64) {}

type allowAll struct{}

func (allowAll) AllowCreate(context.Context, string, string) error { return nil }

var (
	mu      sync.RWMutex
	rec     Recorder     = nopRecorder{}
	quotas  QuotaChecker = allowAll{}
	enabled bool
)

// SetRecorder installs the metering recorder (the ee attach seam). nil
// restores the no-op.
func SetRecorder(r Recorder) {
	mu.Lock()
	defer mu.Unlock()
	if r == nil {
		rec, enabled = nopRecorder{}, false
		return
	}
	rec, enabled = r, true
}

// SetQuotaChecker installs the quota gate (the ee attach seam). nil restores
// allow-all.
func SetQuotaChecker(q QuotaChecker) {
	mu.Lock()
	defer mu.Unlock()
	if q == nil {
		quotas = allowAll{}
		return
	}
	quotas = q
}

// Record reports a usage delta for a tenant. A no-op unless a recorder is
// installed; empty tenants and non-positive deltas are ignored.
func Record(tenantID, meter string, delta int64) {
	if tenantID == "" || delta <= 0 {
		return
	}
	mu.RLock()
	r, on := rec, enabled
	mu.RUnlock()
	if !on {
		return
	}
	r.Record(tenantID, meter, delta)
}

// AllowCreate consults the installed quota gate (allow-all by default).
func AllowCreate(ctx context.Context, tenantID, resource string) error {
	mu.RLock()
	q := quotas
	mu.RUnlock()
	return q.AllowCreate(ctx, tenantID, resource)
}
