// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
)

type fakeLicenseSource struct {
	mu   sync.Mutex
	info license.Info
}

func (f *fakeLicenseSource) Info() license.Info {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.info
}

func (f *fakeLicenseSource) set(state license.State) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.info.State = state
}

// TestLicenseLifecycleIsAuditedInTheProviderStream (DPR-102): the loaded
// license is recorded once, every state transition once, with identity and
// lifecycle fields but no license contents, and a refused append is retried
// on the next tick instead of losing the transition.
func TestLicenseLifecycleIsAuditedInTheProviderStream(t *testing.T) {
	exp := time.Date(2026, 9, 15, 23, 59, 59, 0, time.UTC)
	ro := exp.Add(license.GracePeriod)
	src := &fakeLicenseSource{info: license.Info{Tier: license.TierMSP, State: license.StateActive, LicenseID: "lic_lab_msp", Customer: "Lab MSP GmbH", ExpiresAt: &exp, ReadOnlyAt: &ro, TrustAnchors: 1}}

	type ev struct {
		action string
		data   map[string]any
	}
	var mu sync.Mutex
	var events []ev
	fail := false
	appendEvent := func(_ context.Context, action, target string, data map[string]any) error {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return errors.New("provider audit refused")
		}
		if target != "license" {
			t.Errorf("target = %q", target)
		}
		events = append(events, ev{action, data})
		return nil
	}
	snapshot := func() []ev {
		mu.Lock()
		defer mu.Unlock()
		return append([]ev(nil), events...)
	}
	waitFor := func(n int) []ev {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if got := snapshot(); len(got) >= n {
				return got
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("expected %d audit events, got %v", n, snapshot())
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunLicenseAudit(ctx, src, appendEvent, 20*time.Millisecond, nil)

	got := waitFor(1)
	if got[0].action != licenseLoadedAuditAction || got[0].data["state"] != "active" || got[0].data["license_id"] != "lic_lab_msp" || got[0].data["expires_at"] != "2026-09-15T23:59:59Z" {
		t.Fatalf("loaded event mismatch: %+v", got[0])
	}
	for _, forbidden := range []string{"signature", "key", "claims"} {
		if _, ok := got[0].data[forbidden]; ok {
			t.Fatalf("license contents must never be audited: %v", got[0].data)
		}
	}

	// A refused append keeps the transition pending: grace is recorded once
	// the provider stream accepts writes again.
	mu.Lock()
	fail = true
	mu.Unlock()
	src.set(license.StateGrace)
	time.Sleep(80 * time.Millisecond)
	if len(snapshot()) != 1 {
		t.Fatalf("a refused append must not record: %v", snapshot())
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	got = waitFor(2)
	if got[1].action != licenseStateChangedAuditAction || got[1].data["from"] != "active" || got[1].data["state"] != "grace" {
		t.Fatalf("grace transition mismatch: %+v", got[1])
	}

	src.set(license.StateReadOnly)
	got = waitFor(3)
	if got[2].data["from"] != "grace" || got[2].data["state"] != "read_only" {
		t.Fatalf("read-only transition mismatch: %+v", got[2])
	}
	time.Sleep(80 * time.Millisecond)
	if len(snapshot()) != 3 {
		t.Fatalf("a steady state must not repeat events: %v", snapshot())
	}
}
