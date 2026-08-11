// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package endpointstore persists endpoint/DEM observations. Numeric metrics
// still flow to the TSDB; this store owns the event-shaped attributes needed to
// reconstruct GET /v1/endpoints after a control-plane restart.
package endpointstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrNoTenant is returned before any unscoped storage or query operation.
var ErrNoTenant = errors.New("endpointstore: tenant_id is required")

// Event is one endpoint signal observation. SignalKey is empty for singleton
// signals (wifi/gateway/last-mile/attribution) and target for session signals.
// It is an internal storage key, not an API field.
type Event struct {
	TenantID   string             `json:"tenant_id"`
	AgentID    string             `json:"agent_id"`
	Type       string             `json:"type"`
	SignalKey  string             `json:"signal_key,omitempty"`
	Target     string             `json:"target,omitempty"`
	Success    bool               `json:"success"`
	Error      string             `json:"error,omitempty"`
	Metrics    map[string]float64 `json:"metrics,omitempty"`
	Attributes map[string]string  `json:"attributes,omitempty"`
	ObservedAt time.Time          `json:"observed_at"`
}

// Store is the durable endpoint event contract. Every method scopes by tenant
// at the store layer; implementations fail closed on an empty tenant.
type Store interface {
	Insert(ctx context.Context, events []Event) error
	Latest(ctx context.Context, tenantID string) ([]Event, error)
	PruneTenantBefore(ctx context.Context, tenantID string, cutoff time.Time) (deleted int, err error)
	DeleteTenant(ctx context.Context, tenantID string) (remaining int64, err error)
	ExportTenant(ctx context.Context, tenantID string, w io.Writer) (int64, error)
	Close() error
}

func validate(events []Event) error {
	for i := range events {
		if events[i].TenantID == "" {
			return fmt.Errorf("event %d: %w", i, ErrNoTenant)
		}
		if events[i].AgentID == "" || events[i].Type == "" || events[i].ObservedAt.IsZero() {
			return fmt.Errorf("endpointstore: event %d requires agent_id, type, and observed_at", i)
		}
	}
	return nil
}

// NewWithClient constructs the lightweight memory store or production
// ClickHouse store with an optional hardened ClickHouse HTTP client.
func NewWithClient(mode, rawURL string, retentionDays int, client *http.Client) (Store, error) {
	switch mode {
	case "", "memory":
		return NewMemory(), nil
	case "clickhouse":
		if rawURL == "" {
			return nil, errors.New("endpointstore: clickhouse mode requires PROBECTL_ENDPOINTSTORE_URL")
		}
		return NewClickHouseWithClient(rawURL, retentionDays, client)
	default:
		return nil, fmt.Errorf("endpointstore: unknown mode %q (want memory|clickhouse)", mode)
	}
}
