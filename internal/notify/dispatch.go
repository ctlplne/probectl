// SPDX-License-Identifier: LicenseRef-probectl-TBD

package notify

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

const (
	defaultDispatchQueueDepth = 64
	defaultConnectorTimeout   = 10 * time.Second
)

type dispatchKind int

const (
	dispatchOpened dispatchKind = iota + 1
	dispatchResolved
	dispatchBarrier
)

type dispatchJob struct {
	kind   dispatchKind
	ctx    context.Context
	inc    incident.Incident
	source string
	done   chan struct{}
}

// Dispatcher fans an incident lifecycle transition out to a tenant's connectors,
// deduping via the LinkStore (idempotent) and skipping a transition's origin
// (loop-protected).
type Dispatcher struct {
	links        LinkStore
	log          *slog.Logger
	queueDepth   int
	connectorTTL time.Duration

	mu       sync.RWMutex
	byTenant map[string][]Connector
	queues   map[string]chan dispatchJob
}

// NewDispatcher builds a dispatcher over a link store.
func NewDispatcher(links LinkStore, log *slog.Logger) *Dispatcher {
	if log == nil {
		log = slog.Default()
	}
	return &Dispatcher{
		links: links, log: log, queueDepth: defaultDispatchQueueDepth, connectorTTL: defaultConnectorTimeout,
		byTenant: map[string][]Connector{}, queues: map[string]chan dispatchJob{},
	}
}

// WithDispatchControls overrides the bounded per-tenant queue depth and the
// timeout applied to each connector/link-store operation. Call before first use.
func (d *Dispatcher) WithDispatchControls(queueDepth int, connectorTimeout time.Duration) *Dispatcher {
	d.mu.Lock()
	defer d.mu.Unlock()
	if queueDepth > 0 {
		d.queueDepth = queueDepth
	}
	if connectorTimeout > 0 {
		d.connectorTTL = connectorTimeout
	}
	return d
}

// Register adds a connector for a tenant (per-tenant routing).
func (d *Dispatcher) Register(tenant string, c Connector) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.byTenant[tenant] = append(d.byTenant[tenant], c)
}

// Connectors returns a tenant's connectors (inspection / tests).
func (d *Dispatcher) Connectors(tenant string) []Connector {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]Connector(nil), d.byTenant[tenant]...)
}

// Enabled reports whether any connector is configured for the tenant.
func (d *Dispatcher) Enabled(tenant string) bool { return len(d.Connectors(tenant)) > 0 }

// Opened pages/posts/opens-a-ticket for a newly opened incident — once per
// connector. A connector that already has a link is skipped (idempotent across
// retries + restarts). A connector failure is logged, never fatal.
func (d *Dispatcher) Opened(ctx context.Context, inc incident.Incident) {
	d.enqueue(ctx, inc.TenantID, dispatchJob{kind: dispatchOpened, inc: inc})
}

// Resolved syncs a resolution to a tenant's connectors. The transition's origin
// (source) is NOT called again — it already resolved the object on its side — but
// its link is still marked resolved so our mirror stays accurate; every other
// connector is resolved remotely. This is the loop protection: an inbound
// "resolved" from one system updates the others without ever echoing back to it.
// A connector with no link (nothing opened on it) or an already-resolved link is
// skipped (idempotent — a duplicate inbound webhook is a no-op).
func (d *Dispatcher) Resolved(ctx context.Context, inc incident.Incident, source string) {
	d.enqueue(ctx, inc.TenantID, dispatchJob{kind: dispatchResolved, inc: inc, source: source})
}

// Drain waits until all tenant dispatch jobs queued before Drain have completed.
// It is used by tests and controlled shutdown paths that need a clean barrier.
func (d *Dispatcher) Drain(ctx context.Context, tenant string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	job := dispatchJob{kind: dispatchBarrier, ctx: context.WithoutCancel(ctx), done: done}
	q := d.queueFor(tenant)
	select {
	case q <- job:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Dispatcher) enqueue(ctx context.Context, tenant string, job dispatchJob) {
	if ctx == nil {
		ctx = context.Background()
	}
	job.ctx = context.WithoutCancel(ctx)
	q := d.queueFor(tenant)
	select {
	case q <- job:
	case <-ctx.Done():
		d.log.Warn("notify: dispatch skipped because caller context ended", "tenant_id", tenant, "error", ctx.Err())
	default:
		d.log.Warn("notify: tenant dispatch queue full; dropping transition", "tenant_id", tenant)
	}
}

func (d *Dispatcher) queueFor(tenant string) chan dispatchJob {
	d.mu.Lock()
	defer d.mu.Unlock()
	if q := d.queues[tenant]; q != nil {
		return q
	}
	q := make(chan dispatchJob, d.queueDepth)
	d.queues[tenant] = q
	go d.runTenantQueue(tenant, q)
	return q
}

func (d *Dispatcher) runTenantQueue(tenant string, q <-chan dispatchJob) {
	for job := range q {
		switch job.kind {
		case dispatchOpened:
			d.openedSync(job.ctx, job.inc)
		case dispatchResolved:
			d.resolvedSync(job.ctx, job.inc, job.source)
		case dispatchBarrier:
			if job.done != nil {
				close(job.done)
			}
		default:
			d.log.Warn("notify: unknown dispatch job", "tenant_id", tenant)
		}
	}
}

func (d *Dispatcher) connectorContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if d.connectorTTL <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, d.connectorTTL)
}

func (d *Dispatcher) openedSync(ctx context.Context, inc incident.Incident) {
	for _, c := range d.Connectors(inc.TenantID) {
		opCtx, cancel := d.connectorContext(ctx)
		existing, err := d.links.Get(opCtx, inc.TenantID, inc.ID, c.Name())
		if err != nil {
			cancel()
			d.log.Warn("notify: link lookup failed", "connector", c.Name(), "incident", inc.ID, "error", err)
			continue
		}
		if existing != nil {
			cancel()
			continue // already opened on this connector — no double-page / dup ticket
		}
		del, err := c.Open(opCtx, inc)
		if err != nil {
			cancel()
			d.log.Warn("notify: open failed", "connector", c.Name(), "incident", inc.ID, "error", err)
			continue
		}
		now := time.Now().UTC()
		if err := d.links.Upsert(opCtx, Link{
			TenantID: inc.TenantID, IncidentID: inc.ID, Connector: c.Name(),
			ExternalRef: del.ExternalRef, Status: firstNonEmpty(del.Status, "open"),
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			cancel()
			d.log.Warn("notify: persist link failed", "connector", c.Name(), "incident", inc.ID, "error", err)
			continue
		}
		cancel()
	}
}

func (d *Dispatcher) resolvedSync(ctx context.Context, inc incident.Incident, source string) {
	for _, c := range d.Connectors(inc.TenantID) {
		opCtx, cancel := d.connectorContext(ctx)
		link, err := d.links.Get(opCtx, inc.TenantID, inc.ID, c.Name())
		if err != nil {
			cancel()
			d.log.Warn("notify: link lookup failed", "connector", c.Name(), "incident", inc.ID, "error", err)
			continue
		}
		if link == nil || link.Status == "resolved" {
			cancel()
			continue
		}
		if c.Name() != source { // skip the origin (no echo), but still mark it resolved below
			if err := c.Resolve(opCtx, inc, link.ExternalRef); err != nil {
				cancel()
				d.log.Warn("notify: resolve failed", "connector", c.Name(), "incident", inc.ID, "error", err)
				continue
			}
		}
		link.Status = "resolved"
		link.UpdatedAt = time.Now().UTC()
		if err := d.links.Upsert(opCtx, *link); err != nil {
			cancel()
			d.log.Warn("notify: persist link failed", "connector", c.Name(), "incident", inc.ID, "error", err)
			continue
		}
		cancel()
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
