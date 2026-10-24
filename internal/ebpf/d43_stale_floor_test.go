// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/ebpf/l7"
)

// D-43 S2: a floor that can no longer be refreshed must not keep a looser mode
// indefinitely. After staleFloorGrace failed checks in a row the running mode
// falls back to metadata — including records already buffered — and a fresh
// floor restores the decided mode only once the control plane recorded it.
func TestD43StaleFloorFallsBackToMetadata(t *testing.T) {
	_ = recordLiveStarts(t)
	cfg := consentedConfig()
	cfg.L7CaptureRedaction = RedactHeaders
	cp := &fakeControlPlane{floor: "headers"}
	a := d43Agent(t, cfg, cp)
	if a.l7mode != RedactHeaders {
		t.Fatalf("headers opt-in did not start under headers: %q", a.l7mode)
	}
	// A call parsed and buffered under headers, before the outage.
	a.agg.ObserveL7(L7Record{TenantID: d43Tenant, Call: l7.Call{Protocol: "http1", Method: "GET", Resource: "/patients/48213", Status: "200"}})

	cp.mu.Lock()
	cp.floor, cp.err = "metadata", errors.New("control plane unreachable")
	cp.mu.Unlock()
	for i := 1; i < staleFloorGrace; i++ {
		a.refreshL7Floor(context.Background())
		if a.l7mode != RedactHeaders {
			t.Fatalf("fell back after %d failed checks, before the documented grace of %d", i, staleFloorGrace)
		}
	}
	for i := 0; i < 100; i++ { // the reviewer's probe: 100 failed refreshes
		a.refreshL7Floor(context.Background())
	}
	if a.l7mode != RedactMetadata || !a.L7CaptureActive() {
		t.Fatalf("after a stale floor: mode=%q active=%v, want metadata, still capturing", a.l7mode, a.L7CaptureActive())
	}
	if got := a.reminimize(a.agg.DrainL7()); len(got) != 1 || got[0].Call.Resource != "/patients/{id}" {
		t.Fatalf("buffered record left the agent as %+v, want it re-minimized to metadata", got)
	}

	// The fresh floor allows headers again: restored only when recorded.
	cp.mu.Lock()
	cp.floor, cp.err, cp.reportErr = "headers", nil, errors.New("cannot record")
	cp.mu.Unlock()
	a.refreshL7Floor(context.Background())
	if a.l7mode != RedactMetadata {
		t.Fatalf("restored %q without the control plane recording it", a.l7mode)
	}
	cp.mu.Lock()
	cp.reportErr = nil
	cp.mu.Unlock()
	a.refreshL7Floor(context.Background())
	if a.l7mode != RedactHeaders {
		t.Fatalf("fresh headers floor did not restore the decided mode: %q", a.l7mode)
	}
}

// A tightened floor applies to records already buffered, not only to new ones.
func TestD43TightenedFloorReminimizesBufferedRecords(t *testing.T) {
	_ = recordLiveStarts(t)
	cfg := consentedConfig()
	cfg.L7CaptureRedaction = RedactHeaders
	cp := &fakeControlPlane{floor: "headers"}
	a := d43Agent(t, cfg, cp)
	a.agg.ObserveL7(L7Record{TenantID: d43Tenant, Call: l7.Call{Protocol: "http1", Method: "GET", Resource: "/patients/48213", Status: "200"}})
	cp.floor = "length"
	if !a.refreshL7Floor(context.Background()) {
		t.Fatal("a length floor did not stop headers capture")
	}
	if got := a.reminimize(a.agg.DrainL7()); len(got) != 0 {
		t.Fatalf("buffered records left the agent under a length floor: %+v", got)
	}
}
