// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

	"github.com/ctlplne/probectl/internal/incident"
)

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

// Link is a persisted incident↔external mapping: idempotency for outbound, and
// the reverse lookup for inbound status sync.
type Link struct {
	TenantID    string
	IncidentID  string
	Connector   string
	ExternalRef string
	Status      string // "open" | "resolved"
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

// dedupKey is the stable per-incident key a pager connector uses so even a
// duplicate trigger (e.g. an Open retried before its link persisted) coalesces
// server-side.
func dedupKey(incidentID string) string { return "probectl-" + incidentID }
