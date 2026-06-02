package ai

// Permission keys gating each query domain (RBAC — enforced AFTER the tenant
// boundary). A caller must hold the domain's permission or the query fails closed.
const (
	PermMetricsRead  = "metrics.read"
	PermEventsRead   = "events.read"
	PermEntitiesRead = "entities.read"
	PermTopologyRead = "topology.read"
)

func permissionFor(d Domain) string {
	switch d {
	case DomainMetrics:
		return PermMetricsRead
	case DomainEvents:
		return PermEventsRead
	case DomainEntities:
		return PermEntitiesRead
	case DomainTopology:
		return PermTopologyRead
	default:
		return ""
	}
}
