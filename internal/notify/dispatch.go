package notify

import (
	"context"
	"log/slog"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// Dispatcher fans an incident lifecycle transition out to a tenant's connectors,
// deduping via the LinkStore (idempotent) and skipping a transition's origin
// (loop-protected).
type Dispatcher struct {
	links    LinkStore
	byTenant map[string][]Connector
	log      *slog.Logger
}

// NewDispatcher builds a dispatcher over a link store.
func NewDispatcher(links LinkStore, log *slog.Logger) *Dispatcher {
	if log == nil {
		log = slog.Default()
	}
	return &Dispatcher{links: links, byTenant: map[string][]Connector{}, log: log}
}

// Register adds a connector for a tenant (per-tenant routing).
func (d *Dispatcher) Register(tenant string, c Connector) {
	d.byTenant[tenant] = append(d.byTenant[tenant], c)
}

// Connectors returns a tenant's connectors (inspection / tests).
func (d *Dispatcher) Connectors(tenant string) []Connector { return d.byTenant[tenant] }

// Enabled reports whether any connector is configured for the tenant.
func (d *Dispatcher) Enabled(tenant string) bool { return len(d.byTenant[tenant]) > 0 }

// Opened pages/posts/opens-a-ticket for a newly opened incident — once per
// connector. A connector that already has a link is skipped (idempotent across
// retries + restarts). A connector failure is logged, never fatal.
func (d *Dispatcher) Opened(ctx context.Context, inc incident.Incident) {
	for _, c := range d.byTenant[inc.TenantID] {
		existing, err := d.links.Get(ctx, inc.TenantID, inc.ID, c.Name())
		if err != nil {
			d.log.Warn("notify: link lookup failed", "connector", c.Name(), "incident", inc.ID, "error", err)
			continue
		}
		if existing != nil {
			continue // already opened on this connector — no double-page / dup ticket
		}
		del, err := c.Open(ctx, inc)
		if err != nil {
			d.log.Warn("notify: open failed", "connector", c.Name(), "incident", inc.ID, "error", err)
			continue
		}
		now := time.Now().UTC()
		if err := d.links.Upsert(ctx, Link{
			TenantID: inc.TenantID, IncidentID: inc.ID, Connector: c.Name(),
			ExternalRef: del.ExternalRef, Status: firstNonEmpty(del.Status, "open"),
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			d.log.Warn("notify: persist link failed", "connector", c.Name(), "incident", inc.ID, "error", err)
		}
	}
}

// Resolved syncs a resolution to a tenant's connectors. The transition's origin
// (source) is NOT called again — it already resolved the object on its side — but
// its link is still marked resolved so our mirror stays accurate; every other
// connector is resolved remotely. This is the loop protection: an inbound
// "resolved" from one system updates the others without ever echoing back to it.
// A connector with no link (nothing opened on it) or an already-resolved link is
// skipped (idempotent — a duplicate inbound webhook is a no-op).
func (d *Dispatcher) Resolved(ctx context.Context, inc incident.Incident, source string) {
	for _, c := range d.byTenant[inc.TenantID] {
		link, err := d.links.Get(ctx, inc.TenantID, inc.ID, c.Name())
		if err != nil {
			d.log.Warn("notify: link lookup failed", "connector", c.Name(), "incident", inc.ID, "error", err)
			continue
		}
		if link == nil || link.Status == "resolved" {
			continue
		}
		if c.Name() != source { // skip the origin (no echo), but still mark it resolved below
			if err := c.Resolve(ctx, inc, link.ExternalRef); err != nil {
				d.log.Warn("notify: resolve failed", "connector", c.Name(), "incident", inc.ID, "error", err)
				continue
			}
		}
		link.Status = "resolved"
		link.UpdatedAt = time.Now().UTC()
		if err := d.links.Upsert(ctx, *link); err != nil {
			d.log.Warn("notify: persist link failed", "connector", c.Name(), "incident", inc.ID, "error", err)
		}
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
