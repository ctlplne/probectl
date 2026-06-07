package tenancy

import (
	"context"
	"fmt"
	"regexp"
	"sync"
)

// Isolation models (F52, S-T2). Pooled is the default and stays core: shared
// stores, logical tenant_id scoping enforced at the storage+query layer.
// Siloed and hybrid are the stronger physical models (ee/, MSP bands):
//
//	pooled — shared Postgres (RLS), shared ClickHouse (tenant_id partition),
//	         shared bus topics (tenant-keyed), shared object store
//	         (tenant/<id>/ key prefix).
//	siloed — per-tenant Postgres SCHEMA (tenant-owned tables copied, RLS
//	         recreated — schema isolation on top of, not instead of, the GUC
//	         policies), per-tenant ClickHouse DATABASE (optionally on a
//	         residency-pinned data plane), per-tenant bus topic namespace,
//	         per-tenant object key namespace.
//	hybrid — shared control/config plane (pooled Postgres) with isolated DATA
//	         planes (ClickHouse database, bus namespace, object namespace).
//
// The MODEL is core vocabulary (config, migrations, the tenant record); the
// siloed/hybrid IMPLEMENTATION (provisioner + router) lives in ee/silo and is
// attached at the main.go seam when the license grants siloed_isolation.
type IsolationModel string

// The three isolation models.
const (
	IsolationPooled IsolationModel = "pooled"
	IsolationSiloed IsolationModel = "siloed"
	IsolationHybrid IsolationModel = "hybrid"
)

// ValidIsolationModel reports whether m names a known model ("" = pooled).
func ValidIsolationModel(m string) bool {
	switch IsolationModel(m) {
	case IsolationPooled, IsolationSiloed, IsolationHybrid, "":
		return true
	default:
		return false
	}
}

// Targets is where one tenant's data lives — the routing answer for every
// store. Zero values mean "the shared (pooled) target".
type Targets struct {
	Model IsolationModel
	// PGSchema is the tenant's Postgres schema ("" = public/pooled). Set only
	// for siloed tenants; hybrid keeps control state pooled.
	PGSchema string
	// CHDatabase is the tenant's ClickHouse database ("" = the shared one).
	CHDatabase string
	// CHBaseURL pins the tenant's ClickHouse data plane ("" = the deployment
	// default) — the S-T2 residency mechanism.
	CHBaseURL string
	// BusNamespace namespaces the tenant's bus topics ("" = shared topics).
	BusNamespace string
	// ObjectPrefix overrides the object-store key namespace ("" = the
	// standard tenant/<id>/ prefix).
	ObjectPrefix string
	// Residency is the operator-facing data-plane name ("" = default).
	Residency string
}

// Router resolves a tenant's isolation targets. Implementations MUST fail
// closed: a routing error must surface as an error, never silently degrade a
// siloed tenant to the pooled stores (the S-T2 watch-out — a pooled query
// must never touch a siloed tenant's data and vice versa).
type Router interface {
	// TargetsFor resolves where tenantID's data lives.
	TargetsFor(ctx context.Context, tenantID string) (Targets, error)
	// BusNamespaces lists every namespace with isolated bus topics (consumer
	// fan-out at startup).
	BusNamespaces(ctx context.Context) ([]string, error)
	// BusNamespaceTenants maps each isolated bus namespace to its tenant id —
	// the consumer side's AUTHORITATIVE tenant for records arriving on that
	// lane (TENANT-101: a namespaced lane is single-tenant by construction,
	// so the lane, not the payload, names the tenant).
	BusNamespaceTenants(ctx context.Context) (map[string]string, error)
}

// PooledRouter is the core default: every tenant routes to the shared stores.
type PooledRouter struct{}

// TargetsFor returns the pooled (zero) targets.
func (PooledRouter) TargetsFor(context.Context, string) (Targets, error) {
	return Targets{Model: IsolationPooled}, nil
}

// BusNamespaces returns none.
func (PooledRouter) BusNamespaces(context.Context) ([]string, error) { return nil, nil }

// BusNamespaceTenants: pooled deployments have no namespaced lanes.
func (PooledRouter) BusNamespaceTenants(context.Context) (map[string]string, error) {
	return nil, nil
}

var (
	routerMu sync.RWMutex
	router   Router = PooledRouter{}
)

// SetRouter installs the deployment's isolation router. Called once at the
// main.go attach seam when the silo feature is licensed; the core-only build
// never calls it and stays pooled.
func SetRouter(r Router) {
	if r == nil {
		r = PooledRouter{}
	}
	routerMu.Lock()
	router = r
	routerMu.Unlock()
}

// CurrentRouter returns the installed router (pooled by default).
func CurrentRouter() Router {
	routerMu.RLock()
	defer routerMu.RUnlock()
	return router
}

// identRe is the shape a routed Postgres schema name must have (defense in
// depth — schemas are derived from UUIDs by the provisioner, never from user
// input, but InTenant still refuses anything else).
var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// pgSchemaFor resolves the tenant's Postgres schema via the router, failing
// closed on routing errors or malformed schema names.
func pgSchemaFor(ctx context.Context, tenantID string) (string, error) {
	t, err := CurrentRouter().TargetsFor(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("tenancy: resolve isolation targets for %s: %w", tenantID, err)
	}
	if t.PGSchema == "" {
		return "", nil
	}
	if !identRe.MatchString(t.PGSchema) {
		return "", fmt.Errorf("tenancy: refusing malformed schema name %q", t.PGSchema)
	}
	return t.PGSchema, nil
}
