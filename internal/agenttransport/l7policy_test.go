// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
)

// fakeL7Policy records which tenant and agent every call was made for, so the
// tests prove both come from the client certificate and nowhere else.
type fakeL7Policy struct {
	mu       sync.Mutex
	floor    string
	tenants  []string
	agents   []string
	recorded []store.L7CapturePosture
}

func (f *fakeL7Policy) Floor(_ context.Context, tenant string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenants = append(f.tenants, tenant)
	return f.floor, nil
}

func (f *fakeL7Policy) RecordPosture(_ context.Context, tenant, agent string, p store.L7CapturePosture) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenants = append(f.tenants, tenant)
	f.agents = append(f.agents, agent)
	f.recorded = append(f.recorded, p)
	return true, nil
}

func TestFetchL7PolicyTenantFromCertificate(t *testing.T) {
	svc, ctx, tenant := testBundleService(t)
	if _, err := svc.FetchL7Policy(ctx, &agentv1.FetchL7PolicyRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unwired policy = %v, want FailedPrecondition (the agent then applies metadata)", err)
	}
	fake := &fakeL7Policy{floor: "metadata"}
	svc.l7policy = fake
	resp, err := svc.FetchL7Policy(ctx, &agentv1.FetchL7PolicyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetRedactionFloor() != "metadata" || len(fake.tenants) != 1 || fake.tenants[0] != tenant {
		t.Fatalf("floor %q read for tenants %v, want metadata for the certificate tenant %s", resp.GetRedactionFloor(), fake.tenants, tenant)
	}
	if _, err := svc.FetchL7Policy(context.Background(), &agentv1.FetchL7PolicyRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no client certificate = %v, want Unauthenticated", err)
	}
}

func TestReportL7PostureValidatesUntrustedFields(t *testing.T) {
	svc, ctx, tenant := testBundleService(t)
	fake := &fakeL7Policy{}
	svc.l7policy = fake
	good := &agentv1.L7CapturePosture{
		Enabled: true, ConsentTenant: tenant, Scope: []string{"exe:/usr/sbin/nginx", "cgroup:/kubepods/pod1"},
		RedactionMode: "metadata", EffectiveMode: "metadata", RedactionFloor: "metadata", Active: true, State: "capturing",
	}
	if _, err := svc.ReportL7Posture(ctx, &agentv1.ReportL7PostureRequest{Posture: good}); err != nil {
		t.Fatal(err)
	}
	got := fake.recorded[0]
	if got.ConsentTenant != tenant || got.ConsentMismatch || !got.Consented() || fake.agents[0] != "44444444-4444-4444-8444-444444444444" {
		t.Fatalf("recorded %+v for agent %v", got, fake.agents)
	}

	// A consent naming another tenant is never stored — only the mismatch.
	foreign := proto.Clone(good).(*agentv1.L7CapturePosture)
	foreign.ConsentTenant = "99999999-9999-4999-8999-999999999999"
	if _, err := svc.ReportL7Posture(ctx, &agentv1.ReportL7PostureRequest{Posture: foreign}); err != nil {
		t.Fatal(err)
	}
	if got := fake.recorded[1]; got.ConsentTenant != "" || !got.ConsentMismatch || got.Consented() {
		t.Fatalf("foreign consent stored as %+v", got)
	}

	for name, bad := range map[string]func(p *agentv1.L7CapturePosture){
		"unknown mode":        func(p *agentv1.L7CapturePosture) { p.RedactionMode = "everything" },
		"unknown state":       func(p *agentv1.L7CapturePosture) { p.State = "exfiltrating" },
		"host-wide scope":     func(p *agentv1.L7CapturePosture) { p.Scope = []string{"*"} },
		"control rune":        func(p *agentv1.L7CapturePosture) { p.Scope = []string{"exe:/bin/x\x1b[31m"} },
		"oversized scope set": func(p *agentv1.L7CapturePosture) { p.Scope = make([]string, maxPostureScope+1) },
	} {
		p := proto.Clone(good).(*agentv1.L7CapturePosture)
		bad(p)
		if _, err := svc.ReportL7Posture(ctx, &agentv1.ReportL7PostureRequest{Posture: p}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
	if _, err := svc.ReportL7Posture(ctx, &agentv1.ReportL7PostureRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing posture: %v, want InvalidArgument", err)
	}
	if len(fake.recorded) != 2 {
		t.Fatalf("an invalid posture reached the store: %d records", len(fake.recorded))
	}
}

// The audit rule: the first consented report and every later material change
// while consented are receipts; a never-consented agent re-reporting "off" is
// not.
func TestL7PostureMaterial(t *testing.T) {
	now := time.Now()
	off := store.L7CapturePosture{RedactionMode: "metadata", State: "off", Scope: []string{}, ReportedAt: now}
	on := store.L7CapturePosture{Enabled: true, ConsentTenant: "t", Scope: []string{"pid:1"}, RedactionMode: "metadata",
		EffectiveMode: "metadata", RedactionFloor: "metadata", Active: true, State: "capturing", ReportedAt: now}
	onLater := on
	onLater.ReportedAt = now.Add(time.Minute)
	onLater.Active = false // attach flapping alone is not a mode change
	headers := on
	headers.RedactionMode, headers.EffectiveMode, headers.RedactionFloor = "headers", "headers", "headers"
	refused := on
	refused.RedactionMode, refused.EffectiveMode, refused.State, refused.Active = "full", "", "refused_floor", false
	for _, tc := range []struct {
		name  string
		prior *store.L7CapturePosture
		next  store.L7CapturePosture
		want  bool
	}{
		{"first report, not consented", nil, off, false},
		{"first consented report", nil, on, true},
		{"off again", &off, off, false},
		{"consent granted", &off, on, true},
		{"same posture re-reported", &on, onLater, false},
		{"mode change", &on, headers, true},
		{"refused by the floor", &on, refused, true},
		{"consent withdrawn", &on, off, true},
	} {
		if got := l7PostureMaterial(tc.prior, tc.next); got != tc.want {
			t.Errorf("%s: material = %v, want %v", tc.name, got, tc.want)
		}
	}
}
