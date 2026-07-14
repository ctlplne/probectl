// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package outage

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/opendata"
)

// FeedHealth is one feed's runtime + provenance view (the API's feed block):
// status honesty plus the AUP the operator (or an MSP reseller) must know.
type FeedHealth struct {
	Name          string    `json:"name"`
	Status        string    `json:"status"` // "ok" | "failed" | "pending"
	LastSuccess   time.Time `json:"last_success,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	Events        int       `json:"events"`
	License       string    `json:"license"`
	Attribution   string    `json:"attribution,omitempty"`
	CommercialUse string    `json:"commercial_use"`
	URL           string    `json:"url"`
}

// Refresher periodically pulls every configured feed into the shared Store.
// A failing feed keeps its last-good events (the Store is only rewritten on
// success) and reports its error honestly — a down source never breaks the
// view (guardrail 10).
type Refresher struct {
	store     *Store
	feeds     []Feed
	interval  time.Duration
	retention time.Duration
	log       *slog.Logger

	mu     sync.Mutex
	health map[string]*FeedHealth
}

// NewRefresher builds a refresher over the configured feeds.
func NewRefresher(store *Store, feeds []Feed, interval, retention time.Duration, log *slog.Logger) *Refresher {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	if retention <= 0 {
		retention = DefaultRetention
	}
	if log == nil {
		log = slog.Default()
	}
	r := &Refresher{store: store, feeds: feeds, interval: interval, retention: retention, log: log, health: map[string]*FeedHealth{}}
	for _, f := range feeds {
		d := f.Descriptor()
		r.health[d.Name] = &FeedHealth{
			Name: d.Name, Status: "pending",
			License: d.AUP.License, Attribution: d.AUP.Attribution,
			CommercialUse: string(d.AUP.CommercialUse), URL: d.AUP.URL,
		}
	}
	return r
}

// Refresh fetches every feed once; failures keep last-good and are recorded.
func (r *Refresher) Refresh(ctx context.Context) {
	since := time.Now().Add(-r.retention)
	for _, f := range r.feeds {
		name := f.Descriptor().Name
		events, err := f.Fetch(ctx, since)
		r.mu.Lock()
		h := r.health[name]
		if err != nil {
			h.Status, h.LastError = "failed", err.Error()
			r.mu.Unlock()
			r.log.Warn("outage feed refresh failed (keeping last-good)", "feed", name, "error", err)
			continue
		}
		h.Status, h.LastError, h.LastSuccess, h.Events = "ok", "", time.Now(), len(events)
		r.mu.Unlock()
		r.store.SetEvents(name, events)
		r.log.Info("outage feed refreshed", "feed", name, "events", len(events))
	}
}

// Health snapshots every feed's status + AUP provenance.
func (r *Refresher) Health() []FeedHealth {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]FeedHealth, 0, len(r.health))
	for _, f := range r.feeds { // feed order, stable
		if h, ok := r.health[f.Descriptor().Name]; ok {
			out = append(out, *h)
		}
	}
	return out
}

// Run refreshes immediately, then on the interval until ctx is done.
func (r *Refresher) Run(ctx context.Context) error {
	r.Refresh(ctx)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			r.Refresh(ctx)
		}
	}
}

// Descriptors exposes the configured feeds' provenance (docs/UI use).
func (r *Refresher) Descriptors() []opendata.Descriptor {
	out := make([]opendata.Descriptor, 0, len(r.feeds))
	for _, f := range r.feeds {
		out = append(out, f.Descriptor())
	}
	return out
}
