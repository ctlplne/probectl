// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package notify wires probectl incidents into operational tooling (S33, F27): it
// pages on-call (PagerDuty/Opsgenie), posts to chat (Slack/Teams), and opens +
// bidirectionally syncs tickets (ServiceNow/Jira/vendor-neutral PSA). probectl
// owns the incident; these systems mirror it.
//
// Three properties shape the design:
//   - Idempotent — a connector is opened at most once per incident (a LinkStore
//     records the external reference), so a retry or a control-plane restart never
//     double-pages or duplicates a ticket.
//   - Loop-protected — a transition that ARRIVED from one system (an inbound
//     ServiceNow "resolved") is synced to the OTHERS but never echoed back to its
//     origin (the dispatch source), so two systems cannot ping-pong forever.
//   - Recoverable — bounded retries degrade gracefully while periodic
//     tenant-scoped reconciliation converges a missed transition after restart.
//
// Connectors are tenant-scoped (per-tenant routing): the dispatcher only fans an
// incident out to its own tenant's connectors.
package notify

import (
	"context"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/branding"
	"github.com/ctlplne/probectl/internal/incident"
)

func attributedNotification(ctx context.Context, text string) string {
	brand := branding.Output(ctx)
	if attribution := brand.AttributionLine(); attribution != "" {
		return brand.DisplayName() + "\n" + attribution + "\n\n" + text
	}
	return text
}

// Doer is the subset of *http.Client a connector needs (injectable for tests).
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Capability is what a connector does with an incident.
type Capability string

const (
	CapabilityPager  Capability = "pager"  // pages on-call (PagerDuty/Opsgenie)
	CapabilityChat   Capability = "chat"   // posts a notification (Slack/Teams)
	CapabilityTicket Capability = "ticket" // opens + syncs a ticket (ServiceNow/Jira/PSA)
)

// Delivery is a connector's result for Open — the external handle to persist.
type Delivery struct {
	ExternalRef string // ticket id / page dedup key ("" for fire-and-forget chat)
	Status      string // external status if known ("triggered", "open", ...)
}

// Connector mirrors one incident into one external system for one tenant. Open is
// called once per incident (the dispatcher dedups); Resolve closes the external
// object identified by the ref Open returned.
type Connector interface {
	Name() string // provider id: pagerduty|opsgenie|slack|teams|servicenow|jira|psa
	Capability() Capability
	Open(ctx context.Context, inc incident.Incident) (Delivery, error)
	Resolve(ctx context.Context, inc incident.Incident, ref string) error
}

// LifecycleConnector is the optional full ticket lifecycle contract. Existing
// paging/chat/ITSM connectors remain open+resolve; the vendor-neutral PSA
// connector implements all four idempotent transitions.
type LifecycleConnector interface {
	Connector
	Update(ctx context.Context, inc incident.Incident, ref string) error
	Reopen(ctx context.Context, inc incident.Incident, ref string) error
}

// openRecoveryConnector resolves uncertain opens using the provider's stable
// lookup key. An empty reference means the provider has no visible ticket yet.
type openRecoveryConnector interface {
	Connector
	RecoverOpen(ctx context.Context, inc incident.Incident) (Delivery, error)
}

// LinkOpening marks a reserved create without a confirmed external reference.
const LinkOpening = "opening"

// Link is a persisted incident↔external mapping: idempotency for outbound, and
// the reverse lookup for inbound status sync.
type Link struct {
	TenantID    string
	IncidentID  string
	Connector   string
	ExternalRef string
	Status      string // connector status or LinkOpening while delivery is uncertain
	Revision    int    // newest incident signal_count confirmed by this mirror
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// IncidentLister is the optional durable recovery seam. Implementations list
// incidents inside one tenant's storage scope; the dispatcher never performs a
// cross-tenant telemetry query.
type IncidentLister interface {
	ListIncidents(ctx context.Context, tenant string) ([]incident.Incident, error)
}

// LinkStore persists incident↔external links. Implementations scope every
// operation to the tenant at the storage layer (RLS) — a link is never visible
// across tenants.
type LinkStore interface {
	// Get returns the link for (tenant, incident, connector), or (nil, nil) if none.
	Get(ctx context.Context, tenant, incidentID, connector string) (*Link, error)
	// Upsert records or updates a link (keyed by tenant+incident+connector).
	Upsert(ctx context.Context, l Link) error
	// FindByRef resolves a connector's external ref back to its link (inbound sync).
	FindByRef(ctx context.Context, tenant, connector, externalRef string) (*Link, error)
}

// OpenReservationStore prevents concurrent or uncertain ticket creates from
// being replayed before their outcome is known. All operations are tenant scoped.
type OpenReservationStore interface {
	ReserveOpen(ctx context.Context, tenant, incidentID, connector string) (bool, error)
	CompleteOpen(ctx context.Context, link Link) error
	ReleaseOpen(ctx context.Context, tenant, incidentID, connector string) error
}

// TicketStatusSnapshot binds a confirmed external ticket to the versions of
// its local link and incident. The store checks both versions before applying
// a status obtained outside the database transaction.
type TicketStatusSnapshot struct {
	TenantID        string
	Connector       string
	IncidentID      string
	ExternalRef     string
	IncidentVersion string
	LinkVersion     string
}

type ticketStatusConnector interface {
	Connector
	statusBatchSize() int
	ResolvedTickets(ctx context.Context, snapshots []TicketStatusSnapshot) ([]TicketStatusSnapshot, error)
}

// TicketStatusStore lists owned, open tickets and applies their confirmed state
// only while the same incident and connector link remain current.
type TicketStatusStore interface {
	OpenTicketStatuses(ctx context.Context, tenant, connector, after string, limit int) ([]TicketStatusSnapshot, error)
	ResolveTicketStatus(ctx context.Context, snapshot TicketStatusSnapshot) (*incident.Incident, error)
}

// dedupKey is the stable per-incident key a pager connector uses so even a
// duplicate trigger (e.g. an Open retried before its link persisted) coalesces
// server-side.
func dedupKey(incidentID string) string { return "probectl-" + incidentID }
