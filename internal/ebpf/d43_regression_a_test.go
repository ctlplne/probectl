// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/ctlplne/probectl/internal/bus"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

// fakeControlPlane is the agent's view of the control plane in these tests: it
// serves a floor (or fails) and records every posture report.
type fakeControlPlane struct {
	mu        sync.Mutex
	floor     string
	err       error
	reportErr error
	// dnsRegistered is the D-65 DNS rule the fake control plane delivers.
	dnsRegistered bool
	reports       []*agentv1.L7CapturePosture
	order         *[]string // shared with a liveRecorder: the order of reports and starts
}

func (f *fakeControlPlane) FetchFloor(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.floor, f.err
}

func (f *fakeControlPlane) ReportPosture(_ context.Context, p *agentv1.L7CapturePosture) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reportErr != nil {
		return f.reportErr
	}
	f.reports = append(f.reports, p)
	if f.order != nil {
		*f.order = append(*f.order, "report:"+p.GetState())
	}
	return nil
}

func (f *fakeControlPlane) Close() error { return nil }

func (f *fakeControlPlane) DNSRegisteredDomainOnly() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dnsRegistered
}

// liveRecorder replaces the live capture constructor: it records each start
// attempt and the redaction mode capture would run under.
type liveRecorder struct {
	starts []string
	order  []string
}

type nopL7 struct{}

func (nopL7) L7Events(ctx context.Context) (<-chan L7Event, error) {
	ch := make(chan L7Event)
	go func() { <-ctx.Done(); close(ch) }()
	return ch, nil
}
func (nopL7) Drops() uint64 { return 0 }
func (nopL7) Close() error  { return nil }

func recordLiveStarts(t *testing.T) *liveRecorder {
	t.Helper()
	rec := &liveRecorder{}
	prev := startLiveL7
	startLiveL7 = func(cfg *Config, _ *slog.Logger) (L7Source, error) {
		rec.starts = append(rec.starts, cfg.L7CaptureRedaction)
		rec.order = append(rec.order, "start")
		return nopL7{}, nil
	}
	t.Cleanup(func() { startLiveL7 = prev })
	return rec
}

const d43Tenant = "33333333-3333-4333-8333-333333333333"

func d43Agent(t *testing.T, cfg *Config, cp L7PolicyClient) *Agent {
	t.Helper()
	src, err := NewFixtureSource("testdata/flows.json")
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAgent(cfg, bus.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)), src, cp)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func consentedConfig() *Config {
	cfg := Default()
	cfg.TenantID = d43Tenant
	cfg.L7CaptureEnabled = true
	cfg.L7CaptureConsentTenant = d43Tenant
	cfg.L7CaptureScope = []string{"exe:/usr/sbin/nginx"}
	return cfg
}

// D-43 regression test (a), test-go half: capture refuses to start without
// consent, for each missing statement — the live capture constructor is never
// reached, nothing is attached, and the posture the agent reports says so. The
// fully consented case is the positive control that makes each refusal
// meaningful (the recorder does see a start when consent is complete).
func TestD43RegressionA_CaptureRefusesWithoutEachConsentStatement(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(c *Config)
		state string
	}{
		{"enable off", func(c *Config) { c.L7CaptureEnabled = false }, l7StateRefusedConsent},
		{"consent tenant absent", func(c *Config) { c.L7CaptureConsentTenant = "" }, l7StateRefusedConsent},
		{"consent tenant mismatched", func(c *Config) { c.L7CaptureConsentTenant = "44444444-4444-4444-8444-444444444444" }, l7StateRefusedConsent},
		{"scope empty", func(c *Config) { c.L7CaptureScope = nil }, l7StateRefusedConsent},
		{"nothing stated (the default)", func(c *Config) {
			c.L7CaptureEnabled, c.L7CaptureConsentTenant, c.L7CaptureScope = false, "", nil
		}, l7StateOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := recordLiveStarts(t)
			cfg := consentedConfig()
			tc.edit(cfg)
			cp := &fakeControlPlane{floor: "metadata"}
			a := d43Agent(t, cfg, cp)
			if len(rec.starts) != 0 {
				t.Fatalf("live capture was started without consent (%s): %v", tc.name, rec.starts)
			}
			if a.l7source != nil || a.L7CaptureActive() || a.L7CaptureRequested() {
				t.Fatalf("capture attached/requested without consent: source=%v active=%v requested=%v",
					a.l7source, a.L7CaptureActive(), a.L7CaptureRequested())
			}
			a.reportPosture(context.Background())
			if p := cp.reports[0]; p.GetState() != tc.state || p.GetActive() || p.GetEffectiveMode() != "" {
				t.Fatalf("reported posture %+v, want state %s, inactive, no effective mode", p, tc.state)
			}
		})
	}
	t.Run("positive control: all three statements", func(t *testing.T) {
		rec := recordLiveStarts(t)
		cp := &fakeControlPlane{floor: "metadata"}
		a := d43Agent(t, consentedConfig(), cp)
		if len(rec.starts) != 1 || rec.starts[0] != RedactMetadata {
			t.Fatalf("consented capture starts = %v, want one start under metadata", rec.starts)
		}
		if !a.L7CaptureActive() || !a.L7CaptureRequested() {
			t.Fatal("consented capture must be requested and active")
		}
	})
}

// Refinement 3: the agent refuses to start capture when its local redaction is
// looser than the tenant's floor, and applies metadata when no floor arrives.
func TestD43RedactionFloorAtTheSource(t *testing.T) {
	for _, tc := range []struct {
		name      string
		local     string
		floor     string
		floorErr  error
		wantStart string // "" = refused
		wantState string
	}{
		{"headers under a metadata floor is refused", RedactHeaders, "metadata", nil, "", l7StateRefusedFloor},
		{"full under a metadata floor is refused", RedactFull, "metadata", nil, "", l7StateRefusedFloor},
		{"full under a headers floor is refused", RedactFull, "headers", nil, "", l7StateRefusedFloor},
		{"metadata under a length floor is refused", RedactMetadata, "length", nil, "", l7StateRefusedFloor},
		{"metadata under a metadata floor starts", RedactMetadata, "metadata", nil, RedactMetadata, l7StateCapturing},
		{"headers under a headers opt-in starts", RedactHeaders, "headers", nil, RedactHeaders, l7StateCapturing},
		{"metadata under a headers opt-in stays metadata", RedactMetadata, "headers", nil, RedactMetadata, l7StateCapturing},
		{"no floor received: full is clamped to metadata", RedactFull, "", errors.New("unreachable"), RedactMetadata, l7StateCapturing},
		{"no floor received: length stays length", RedactLengthOnly, "", errors.New("unreachable"), RedactLengthOnly, l7StateCapturing},
		{"unknown floor is no floor", RedactHeaders, "bogus", nil, RedactMetadata, l7StateCapturing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := recordLiveStarts(t)
			cfg := consentedConfig()
			cfg.L7CaptureRedaction = tc.local
			cp := &fakeControlPlane{floor: tc.floor, err: tc.floorErr}
			a := d43Agent(t, cfg, cp)
			if tc.wantStart == "" {
				if len(rec.starts) != 0 || a.L7CaptureActive() || !a.L7CaptureRefusedByFloor() {
					t.Fatalf("looser-than-floor capture started: %v", rec.starts)
				}
			} else if len(rec.starts) != 1 || rec.starts[0] != tc.wantStart {
				t.Fatalf("starts = %v, want one under %s", rec.starts, tc.wantStart)
			}
			a.reportPosture(context.Background())
			if got := cp.reports[0]; got.GetState() != tc.wantState || got.GetRedactionMode() != tc.local {
				t.Fatalf("posture = %+v, want state %s with the local mode reported", got, tc.wantState)
			}
		})
	}
	t.Run("no control-plane channel at all refuses consented live capture (S1)", func(t *testing.T) {
		rec := recordLiveStarts(t)
		cfg := consentedConfig()
		_ = d43Agent(t, cfg, nil)
		if len(rec.starts) != 0 {
			t.Fatalf("starts = %v, want none without the control-plane channel", rec.starts)
		}
	})
}

// A floor that tightens while the agent runs stops capture at once.
func TestD43FloorTighteningStopsRunningCapture(t *testing.T) {
	_ = recordLiveStarts(t)
	cfg := consentedConfig()
	cfg.L7CaptureRedaction = RedactHeaders
	cp := &fakeControlPlane{floor: "headers"}
	a := d43Agent(t, cfg, cp)
	if !a.L7CaptureActive() {
		t.Fatal("headers opt-in did not start")
	}
	cp.floor = "metadata"
	if !a.refreshL7Floor(context.Background()) {
		t.Fatal("a tightened floor did not stop the running capture")
	}
	if a.L7CaptureActive() || !a.L7CaptureRefusedByFloor() {
		t.Fatal("capture still active after the floor tightened")
	}
	last := cp.reports[len(cp.reports)-1]
	if last.GetState() != l7StateRefusedFloor || last.GetRedactionFloor() != "metadata" {
		t.Fatalf("posture after tightening = %+v", last)
	}
	// A loosened floor never widens a running agent.
	cp.floor = "full"
	if a.refreshL7Floor(context.Background()) || a.L7CaptureActive() {
		t.Fatal("a loosened floor restarted capture without a restart")
	}
}

func TestControlPlaneConfigRequiresTheFullIdentity(t *testing.T) {
	cfg := Default()
	cfg.TenantID = d43Tenant
	cfg.ControlPlane.GRPCAddr = "control:9443"
	if err := cfg.validate(); err == nil {
		t.Fatal("grpc_addr without the mTLS identity must refuse")
	}
	cfg.ControlPlane.CertFile, cfg.ControlPlane.KeyFile, cfg.ControlPlane.CAFile = "/id/cert.pem", "/id/key.pem", "/id/server-ca.pem"
	if err := cfg.validate(); err == nil {
		t.Fatal("grpc_addr without the agent_id its certificate names must refuse")
	}
	cfg.AgentID = "55555555-5555-4555-8555-555555555555"
	if err := cfg.validate(); err != nil {
		t.Fatalf("full identity must validate: %v", err)
	}
}
