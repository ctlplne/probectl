// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package notify

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/incident"
)

const (
	defaultDispatchQueueDepth = 64
	defaultConnectorTimeout   = 10 * time.Second
	defaultConnectorAttempts  = 3
	defaultRetryBackoff       = 50 * time.Millisecond
)

type dispatchKind int

const (
	dispatchOpened dispatchKind = iota + 1
	dispatchResolved
	dispatchUpdated
	dispatchReopened
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

// withDispatchControls overrides the bounded per-tenant queue depth and the
// timeout applied to each connector/link-store operation. Call before first use.
func (d *Dispatcher) withDispatchControls(queueDepth int, connectorTimeout time.Duration) *Dispatcher {
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

// Updated mirrors a newly correlated signal to lifecycle-aware ticket systems.
// Pager/chat connectors deliberately do nothing, preventing alert spam.
func (d *Dispatcher) Updated(ctx context.Context, inc incident.Incident) {
	d.enqueue(ctx, inc.TenantID, dispatchJob{kind: dispatchUpdated, inc: inc})
}

// Reopened reopens lifecycle-aware tickets after an explicit in-tenant incident
// reopen. Systems that implement only open+resolve remain unchanged.
func (d *Dispatcher) Reopened(ctx context.Context, inc incident.Incident) {
	d.enqueue(ctx, inc.TenantID, dispatchJob{kind: dispatchReopened, inc: inc})
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
	// Bounded queue + producer backpressure: once the incident transaction has
	// committed, a full queue slows this tenant's producer instead of dropping a
	// ticket transition. job.ctx is cancellation-detached, so an HTTP disconnect
	// cannot erase already-committed lifecycle work.
	q <- job
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
		case dispatchUpdated:
			d.updatedSync(job.ctx, job.inc)
		case dispatchReopened:
			d.reopenedSync(job.ctx, job.inc)
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
		cancel()
		del, err := d.openWithRetry(ctx, c, inc)
		if err != nil {
			d.log.Warn("notify: open failed", "connector", c.Name(), "incident", inc.ID, "error", err)
			continue
		}
		opCtx, cancel = d.connectorContext(ctx)
		now := time.Now().UTC()
		if err := d.links.Upsert(opCtx, Link{
			TenantID: inc.TenantID, IncidentID: inc.ID, Connector: c.Name(),
			ExternalRef: del.ExternalRef, Status: firstNonEmpty(del.Status, "open"),
			Revision:  inc.SignalCount,
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
			cancel()
			if err := d.runWithRetry(ctx, func(attemptCtx context.Context) error {
				return c.Resolve(attemptCtx, inc, link.ExternalRef)
			}); err != nil {
				d.log.Warn("notify: resolve failed", "connector", c.Name(), "incident", inc.ID, "error", err)
				continue
			}
			opCtx, cancel = d.connectorContext(ctx)
		}
		link.Status = "resolved"
		link.Revision = inc.SignalCount
		link.UpdatedAt = time.Now().UTC()
		if err := d.links.Upsert(opCtx, *link); err != nil {
			cancel()
			d.log.Warn("notify: persist link failed", "connector", c.Name(), "incident", inc.ID, "error", err)
			continue
		}
		cancel()
	}
}

func (d *Dispatcher) updatedSync(ctx context.Context, inc incident.Incident) {
	for _, base := range d.Connectors(inc.TenantID) {
		c, ok := base.(LifecycleConnector)
		if !ok {
			continue
		}
		opCtx, cancel := d.connectorContext(ctx)
		link, err := d.links.Get(opCtx, inc.TenantID, inc.ID, c.Name())
		cancel()
		if err != nil || link == nil || link.Status == "resolved" {
			if err != nil {
				d.log.Warn("notify: update link lookup failed", "connector", c.Name(), "incident", inc.ID, "error", err)
			}
			continue
		}
		if err := d.runWithRetry(ctx, func(attemptCtx context.Context) error {
			return c.Update(attemptCtx, inc, link.ExternalRef)
		}); err != nil {
			d.log.Warn("notify: update failed after retries", "connector", c.Name(), "incident", inc.ID, "error", err)
			continue
		}
		link.Revision = inc.SignalCount
		link.UpdatedAt = time.Now().UTC()
		opCtx, cancel = d.connectorContext(ctx)
		if err := d.links.Upsert(opCtx, *link); err != nil {
			d.log.Warn("notify: persist update revision failed", "connector", c.Name(), "incident", inc.ID, "error", err)
		}
		cancel()
	}
}

func (d *Dispatcher) reopenedSync(ctx context.Context, inc incident.Incident) {
	for _, base := range d.Connectors(inc.TenantID) {
		c, ok := base.(LifecycleConnector)
		if !ok {
			continue
		}
		opCtx, cancel := d.connectorContext(ctx)
		link, err := d.links.Get(opCtx, inc.TenantID, inc.ID, c.Name())
		cancel()
		if err != nil || link == nil || link.Status != "resolved" {
			if err != nil {
				d.log.Warn("notify: reopen link lookup failed", "connector", c.Name(), "incident", inc.ID, "error", err)
			}
			continue
		}
		if err := d.runWithRetry(ctx, func(attemptCtx context.Context) error {
			return c.Reopen(attemptCtx, inc, link.ExternalRef)
		}); err != nil {
			d.log.Warn("notify: reopen failed after retries", "connector", c.Name(), "incident", inc.ID, "error", err)
			continue
		}
		link.Status = "open"
		link.Revision = inc.SignalCount
		link.UpdatedAt = time.Now().UTC()
		opCtx, cancel = d.connectorContext(ctx)
		if err := d.links.Upsert(opCtx, *link); err != nil {
			d.log.Warn("notify: persist reopened link failed", "connector", c.Name(), "incident", inc.ID, "error", err)
		}
		cancel()
	}
}

// Reconcile recovers transitions lost to a process crash by comparing current
// tenant-scoped incident state with each persisted connector link. Receiver-side
// idempotency keys make ambiguous replays safe.
func (d *Dispatcher) Reconcile(ctx context.Context) {
	lister, ok := d.links.(IncidentLister)
	if !ok {
		return
	}
	d.mu.RLock()
	tenants := make([]string, 0, len(d.byTenant))
	for tenant := range d.byTenant {
		tenants = append(tenants, tenant)
	}
	d.mu.RUnlock()
	for _, tenant := range tenants {
		incidents, err := lister.ListIncidents(ctx, tenant)
		if err != nil {
			d.log.Warn("notify: reconciliation incident list failed", "tenant_id", tenant, "error", err)
			continue
		}
		for _, inc := range incidents {
			if inc.Status == incident.StatusResolved {
				d.resolvedSync(ctx, inc, "reconcile")
				continue
			}
			for _, c := range d.Connectors(tenant) {
				opCtx, cancel := d.connectorContext(ctx)
				link, linkErr := d.links.Get(opCtx, tenant, inc.ID, c.Name())
				cancel()
				if linkErr != nil {
					d.log.Warn("notify: reconciliation link lookup failed", "tenant_id", tenant, "connector", c.Name(), "incident", inc.ID, "error", linkErr)
					continue
				}
				if link == nil {
					d.openedSync(ctx, inc)
					break
				}
				if link.Status == "resolved" {
					d.reopenedSync(ctx, inc)
					break
				}
				if link.Revision < inc.SignalCount {
					d.updatedSync(ctx, inc)
					break
				}
			}
		}
	}
}

// RunReconciler runs immediately and periodically until shutdown.
func (d *Dispatcher) RunReconciler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	d.Reconcile(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.Reconcile(ctx)
		}
	}
}

func (d *Dispatcher) openWithRetry(ctx context.Context, c Connector, inc incident.Incident) (Delivery, error) {
	var out Delivery
	err := d.runWithRetry(ctx, func(attemptCtx context.Context) error {
		var err error
		out, err = c.Open(attemptCtx, inc)
		return err
	})
	return out, err
}

func (d *Dispatcher) runWithRetry(ctx context.Context, operation func(context.Context) error) error {
	var last error
	for attempt := 0; attempt < defaultConnectorAttempts; attempt++ {
		opCtx, cancel := d.connectorContext(ctx)
		last = operation(opCtx)
		cancel()
		if last == nil {
			return nil
		}
		if attempt+1 < defaultConnectorAttempts {
			time.Sleep(defaultRetryBackoff * time.Duration(attempt+1))
		}
	}
	return last
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
