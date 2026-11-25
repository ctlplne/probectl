// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package notify

import (
	"context"
	"slices"
)

// pollTicketStatuses reads one page per configured tenant and connector each
// reconciliation interval. The cursor rotates through owned open tickets so
// an older incident can still receive a resolution.
func (d *Dispatcher) pollTicketStatuses(ctx context.Context, tenant string, outputContext func() context.Context) {
	store, ok := d.links.(TicketStatusStore)
	if !ok {
		return
	}
	for _, connector := range d.Connectors(tenant) {
		c, ok := connector.(ticketStatusConnector)
		if !ok {
			continue
		}
		name := c.Name()
		cursorKey := tenant + "\x00" + name
		d.mu.RLock()
		after := d.statusCursors[cursorKey]
		d.mu.RUnlock()
		opCtx, cancel := d.connectorContext(ctx)
		limit := c.statusBatchSize()
		snapshots, err := store.OpenTicketStatuses(opCtx, tenant, name, after, limit)
		cancel()
		if err != nil {
			d.log.Warn("notify: ticket status snapshot failed", "tenant_id", tenant, "connector", name, "error", err)
			continue
		}
		if slices.ContainsFunc(snapshots, func(snapshot TicketStatusSnapshot) bool {
			return snapshot.TenantID != tenant || snapshot.Connector != name
		}) {
			d.log.Warn("notify: refused ticket status page outside its scope", "tenant_id", tenant, "connector", name)
			continue
		}
		next := ""
		if len(snapshots) == limit {
			next = snapshots[len(snapshots)-1].IncidentID
		}
		d.mu.Lock()
		d.statusCursors[cursorKey] = next
		d.mu.Unlock()
		if len(snapshots) == 0 {
			continue
		}
		opCtx, cancel = d.connectorContext(ctx)
		resolved, err := c.ResolvedTickets(opCtx, snapshots)
		cancel()
		if err != nil {
			d.log.Warn("notify: ticket status lookup failed", "tenant_id", tenant, "connector", name, "error", err)
			continue
		}
		for _, snapshot := range resolved {
			if !slices.Contains(snapshots, snapshot) {
				d.log.Warn("notify: refused ticket status outside the requested page", "tenant_id", tenant, "connector", name)
				continue
			}
			opCtx, cancel := d.connectorContext(ctx)
			inc, err := store.ResolveTicketStatus(opCtx, snapshot)
			cancel()
			if err != nil {
				d.log.Warn("notify: apply ticket status failed", "tenant_id", tenant, "connector", name, "error", err)
				continue
			}
			if inc != nil && inc.TenantID == tenant && inc.ID == snapshot.IncidentID {
				d.resolvedSync(outputContext(), *inc, name)
			}
		}
	}
}
