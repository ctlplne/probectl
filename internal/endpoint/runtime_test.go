// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type fakeEmitter struct{ got []Sample }

func (f *fakeEmitter) Emit(_ context.Context, s Sample) error {
	f.got = append(f.got, s)
	return nil
}

// TestRuntimeTickEmits runs one collection cycle: a pre-canceled context lets the
// immediate first tick fire, then the loop exits — so exactly one sample is
// collected, attributed, and emitted.
func TestRuntimeTickEmits(t *testing.T) {
	cfg := testConfig()
	col := NewCollector(cfg,
		fakeWiFi{w: WiFi{Present: true, Associated: true, RSSIDBm: -84, Have: WiFiHave{RSSI: true}}},
		fakeLastMile{lm: LastMile{Hops: []LastMileHop{{Index: 1, IP: "192.168.1.1", Private: true, RTTMs: 5}}}},
		fakeSession{s: Session{Success: true, TotalMs: 2200}},
	)
	em := &fakeEmitter{}
	rt := NewWith(cfg, col, em, quietLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the immediate tick still runs; then the loop sees Done and returns
	if err := rt.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(em.got) != 1 {
		t.Fatalf("want exactly one emitted sample, got %d", len(em.got))
	}
	if em.got[0].Attribution.Cause != CauseWiFi {
		t.Errorf("expected the WiFi verdict to flow through, got %q", em.got[0].Attribution.Cause)
	}
}

// TestNewBuildsRealCollectors confirms New wires the platform collectors without
// error (they degrade gracefully when the OS tools are absent, e.g. in CI).
func TestNewBuildsRealCollectors(t *testing.T) {
	cfg := testConfig()
	b := &captureBus{}
	rt, err := New(cfg, b, quietLogger())
	if err != nil || rt == nil {
		t.Fatalf("New: %v", err)
	}
}
