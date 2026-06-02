package ai

import "time"

// Domain identifies which store a query targets.
type Domain string

const (
	DomainMetrics  Domain = "metrics"  // Prometheus / VictoriaMetrics (S6 TSDB)
	DomainEvents   Domain = "events"   // ClickHouse (flows / threat / change / bgp)
	DomainEntities Domain = "entities" // Postgres (tests / agents / incidents)
	DomainTopology Domain = "topology" // the topology graph (S30)
)

// allDomains is the fixed fan-out order for a correlation.
var allDomains = []Domain{DomainMetrics, DomainEvents, DomainEntities, DomainTopology}

// TimeRange bounds a query. At is the topology snapshot instant (zero => latest).
type TimeRange struct {
	Start time.Time
	End   time.Time
	At    time.Time
}

// Query is a typed, store-agnostic query. There is deliberately NO tenant field:
// the tenant comes from the authenticated principal, so a query is incapable of
// crossing tenants by construction (the S23 security boundary).
type Query struct {
	Domain   Domain
	Selector map[string]string // domain filters (metric name, event type, node id, …)
	Range    TimeRange
	Limit    int

	// Topology (DomainTopology) traversal: From+To for a path, or NodeID for neighbors.
	From   string
	To     string
	NodeID string
}
