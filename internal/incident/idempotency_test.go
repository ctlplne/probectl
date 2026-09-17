// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package incident

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// DPR-078: the same event delivered twice (at-least-once bus, analyzer re-run)
// is one signal on the timeline; an event that differs in when it occurred or
// in its evidence is another.
func TestIdenticalSignalsAreNotCountedTwice(t *testing.T) {
	store := NewMemoryStore()
	c := NewCorrelator(store, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	at := time.Date(2026, 9, 17, 11, 5, 27, 0, time.UTC)
	sig := Signal{TenantID: "t1", Plane: "bgp", Kind: "bgp.possible_hijack", Severity: SeverityCritical,
		Title: "sub-prefix 216.75.128.0/25 announced by unexpected AS65010", Target: "216.75.128.0/25", Prefix: "216.75.128.0/25",
		Attributes: map[string]string{"new_origin_asn": "65010", "collector": "rrc00"}, OccurredAt: at}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := c.Ingest(ctx, sig); err != nil {
			t.Fatal(err)
		}
	}
	open, err := store.OpenIncidents(ctx, "t1")
	if err != nil || len(open) != 1 {
		t.Fatalf("open incidents: %v %d", err, len(open))
	}
	if open[0].SignalCount != 1 || len(open[0].Signals) != 1 {
		t.Fatalf("three identical deliveries must be one signal: count=%d signals=%d", open[0].SignalCount, len(open[0].Signals))
	}
	later := sig
	later.OccurredAt = at.Add(time.Minute)
	if _, err := c.Ingest(ctx, later); err != nil {
		t.Fatal(err)
	}
	different := sig
	different.Attributes = map[string]string{"new_origin_asn": "65011", "collector": "rrc00"}
	if _, err := c.Ingest(ctx, different); err != nil {
		t.Fatal(err)
	}
	open, _ = store.OpenIncidents(ctx, "t1")
	if open[0].SignalCount != 3 {
		t.Fatalf("a later occurrence and different evidence are their own signals: count=%d", open[0].SignalCount)
	}
}

func TestSignalFingerprintIsStableAndSensitive(t *testing.T) {
	at := time.Date(2026, 9, 17, 11, 5, 27, 0, time.UTC)
	a := Signal{TenantID: "t1", Plane: "bgp", Kind: "bgp.rpki_invalid", Prefix: "1.1.1.0/24", OccurredAt: at,
		Attributes: map[string]string{"b": "2", "a": "1"}}
	b := a
	b.Attributes = map[string]string{"a": "1", "b": "2"} // same content, different insertion order
	if a.Fingerprint() != b.Fingerprint() || len(a.Fingerprint()) != 64 {
		t.Fatalf("fingerprint must be content-derived and stable: %s vs %s", a.Fingerprint(), b.Fingerprint())
	}
	for name, mutate := range map[string]func(*Signal){
		"tenant":     func(s *Signal) { s.TenantID = "t2" },
		"kind":       func(s *Signal) { s.Kind = "bgp.possible_leak" },
		"prefix":     func(s *Signal) { s.Prefix = "1.1.2.0/24" },
		"occurred":   func(s *Signal) { s.OccurredAt = at.Add(time.Second) },
		"attributes": func(s *Signal) { s.Attributes = map[string]string{"a": "1", "b": "3"} },
	} {
		c := a
		mutate(&c)
		if c.Fingerprint() == a.Fingerprint() {
			t.Errorf("%s change must alter the fingerprint", name)
		}
	}
}
