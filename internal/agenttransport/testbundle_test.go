// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

// fakeBundles records which tenant every call was made for, so the tests can
// prove the tenant comes from the client certificate and nowhere else.
type fakeBundles struct {
	mu       sync.Mutex
	version  uint64
	tenants  []string
	bundled  int
	failRead bool
}

func (f *fakeBundles) Version(_ context.Context, tenant string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenants = append(f.tenants, tenant)
	if f.failRead {
		return 0, errors.New("store down")
	}
	return f.version, nil
}

func (f *fakeBundles) Bundle(_ context.Context, tenant string) (uint64, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenants = append(f.tenants, tenant)
	f.bundled++
	return f.version, []byte(`{"bundle":{"tenant_id":"` + tenant + `"},"signature":""}`), nil
}

func testBundleService(t *testing.T) (*service, context.Context, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := crypto.GenerateCA("testbundle-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := ca.IssueServerCert("control", []string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(writeFile(t, dir, "srv.crt", srvCert), writeFile(t, dir, "srv.key", srvKey),
		writeFile(t, dir, "ca.crt", ca.CertPEM()), nil, nil, nil, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	srv.svc.hb = newHeartbeatBatcher(nil, discardLogger(), time.Minute)
	const tenant, agent = "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"
	certPEM, _, err := ca.IssueClientCert(agent, crypto.AgentSPIFFEID(tenant, agent), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return srv.svc, peerContextForLeaf(leafFromPEM(t, certPEM)), tenant
}

// G9: with no source wired, central test distribution is OFF and the RPC says
// so with FailedPrecondition (the agent keeps its local tests); the heartbeat
// never nudges and Register does not advertise the capability.
func TestFetchTestBundleOffWithoutSource(t *testing.T) {
	svc, ctx, _ := testBundleService(t)
	_, err := svc.FetchTestBundle(ctx, &agentv1.FetchTestBundleRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("FetchTestBundle without a source = %v, want FailedPrecondition", err)
	}
	hb, err := svc.Heartbeat(ctx, &agentv1.HeartbeatRequest{ConfigEpoch: 3})
	if err != nil || hb.GetConfigStale() {
		t.Fatalf("heartbeat without a source = %+v, %v; want not stale", hb, err)
	}
}

// G9 / G7-4: the source is always asked for the CERTIFICATE's tenant; there is
// no request field that could name another one. A known version equal to the
// current one is answered not_modified without building a bundle.
func TestFetchTestBundleUsesCertificateTenant(t *testing.T) {
	svc, ctx, tenant := testBundleService(t)
	f := &fakeBundles{version: 5}
	svc.testBundles = f

	resp, err := svc.FetchTestBundle(ctx, &agentv1.FetchTestBundleRequest{KnownVersion: 2})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetNotModified() || resp.GetVersion() != 5 || len(resp.GetSignedBundle()) == 0 {
		t.Fatalf("stale agent got %+v, want the version-5 bundle", resp)
	}
	resp, err = svc.FetchTestBundle(ctx, &agentv1.FetchTestBundleRequest{KnownVersion: 5})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetNotModified() || len(resp.GetSignedBundle()) != 0 {
		t.Fatalf("current agent got %+v, want not_modified with no bundle", resp)
	}
	if f.bundled != 1 {
		t.Fatalf("bundles built = %d, want 1 (not_modified must not sign)", f.bundled)
	}
	for _, got := range f.tenants {
		if got != tenant {
			t.Fatalf("source asked for tenant %q, want the certificate's %q", got, tenant)
		}
	}

	// Heartbeat nudge: behind → config_stale; current → not stale.
	hb, err := svc.Heartbeat(ctx, &agentv1.HeartbeatRequest{ConfigEpoch: 4})
	if err != nil || !hb.GetConfigStale() {
		t.Fatalf("behind agent heartbeat = %+v, %v; want config_stale", hb, err)
	}
	hb, err = svc.Heartbeat(ctx, &agentv1.HeartbeatRequest{ConfigEpoch: 5})
	if err != nil || hb.GetConfigStale() {
		t.Fatalf("current agent heartbeat = %+v, %v; want not stale", hb, err)
	}
	// The heartbeat recorded the reported version for the registry flush.
	svc.hb.mu.Lock()
	recorded := svc.hb.pending[tenant]
	svc.hb.mu.Unlock()
	if len(recorded) != 1 {
		t.Fatalf("pending heartbeats = %v, want the one agent", recorded)
	}
	for _, v := range recorded {
		if v != 5 {
			t.Fatalf("recorded applied version = %d, want 5", v)
		}
	}

	// A store failure is Unavailable for the pull, and never fails the heartbeat.
	f.failRead = true
	if _, err := svc.FetchTestBundle(ctx, &agentv1.FetchTestBundleRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("pull on store failure = %v, want Unavailable", err)
	}
	if hb, err := svc.Heartbeat(ctx, &agentv1.HeartbeatRequest{ConfigEpoch: 1}); err != nil || hb.GetConfigStale() {
		t.Fatalf("heartbeat on store failure = %+v, %v; want ok, not stale", hb, err)
	}
}

func TestFetchTestBundleCapabilityAdvertisedOnlyWhenConfigured(t *testing.T) {
	if slices.Contains(copyServerCapabilities(), fetchTestBundleCapability) {
		t.Fatal("the static capability list must not advertise test-bundle pull; Register adds it only when a source is wired")
	}
}
