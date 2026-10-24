// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
)

// channelPolicy is the control plane's L7Policy behind a real AgentService
// listener; it records the certificate-derived identity of every call.
type channelPolicy struct {
	mu        sync.Mutex
	floor     string
	regulated bool
	tenants   []string
	agents    []string
	posture   []store.L7CapturePosture
}

func (c *channelPolicy) DNSRegisteredDomainOnly() bool { return c.regulated }

func (c *channelPolicy) Floor(_ context.Context, tenant string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tenants = append(c.tenants, tenant)
	return c.floor, nil
}

func (c *channelPolicy) RecordPosture(_ context.Context, tenant, agent string, p store.L7CapturePosture) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tenants = append(c.tenants, tenant)
	c.agents = append(c.agents, agent)
	c.posture = append(c.posture, p)
	return true, nil
}

func writeChannelFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The floor travels over the EXISTING agent gRPC service and listener, over
// mTLS, and the tenant the control plane answers for is the one in the agent's
// certificate (refinement 3). The agent applies it: a local headers setting
// under the tenant's metadata floor is refused, and that posture is recorded
// against the certificate's agent id.
func TestL7FloorRidesTheExistingMTLSAgentChannel(t *testing.T) {
	dir := t.TempDir()
	ca, err := crypto.GenerateCA("d43-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sc, sk, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := writeChannelFile(t, dir, "ca.crt", ca.CertPEM())
	srv, err := agenttransport.New(writeChannelFile(t, dir, "srv.crt", sc), writeChannelFile(t, dir, "srv.key", sk), caFile,
		nil, bus.NewMemory(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	policy := &channelPolicy{floor: "metadata"}
	srv.WithL7Policy(policy)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.ServeListener(ctx, ln); close(done) }()
	t.Cleanup(func() { stop(); <-done })

	const agentID = "55555555-5555-4555-8555-555555555555"
	cert, key, err := ca.IssueClientCert(agentID, crypto.EBPFSPIFFEID(d43Tenant, agentID), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg := consentedConfig()
	cfg.L7CaptureRedaction = RedactHeaders // the misconfiguration the floor must catch
	cfg.ControlPlane = ControlPlaneConfig{
		GRPCAddr: ln.Addr().String(), ServerName: "localhost",
		CertFile: writeChannelFile(t, dir, "agent.crt", cert), KeyFile: writeChannelFile(t, dir, "agent.key", key), CAFile: caFile,
	}
	rec := recordLiveStarts(t)
	client, err := dialL7Policy(cfg.ControlPlane)
	if err != nil {
		t.Fatal(err)
	}
	a := d43Agent(t, cfg, client)
	if len(rec.starts) != 0 || !a.L7CaptureRefusedByFloor() {
		t.Fatalf("headers capture under the tenant's metadata floor was not refused (starts %v)", rec.starts)
	}
	a.reportPosture(context.Background())
	_ = client.Close()

	policy.mu.Lock()
	defer policy.mu.Unlock()
	for _, tn := range policy.tenants {
		if tn != d43Tenant {
			t.Fatalf("control plane answered for tenant %q, want the certificate tenant %q", tn, d43Tenant)
		}
	}
	if len(policy.posture) != 1 || policy.agents[0] != agentID {
		t.Fatalf("posture recorded %v for agents %v", policy.posture, policy.agents)
	}
	if p := policy.posture[0]; p.State != l7StateRefusedFloor || p.RedactionMode != RedactHeaders || p.RedactionFloor != "metadata" || p.Active {
		t.Fatalf("recorded posture = %+v", p)
	}
}

// D-43 S3: a channel whose certificate names another tenant (or another agent)
// is never used — the agent refuses consented capture rather than fetch that
// tenant's floor and record its posture there while publishing as itself.
func TestL7ChannelIdentityMustBeThisAgents(t *testing.T) {
	dir := t.TempDir()
	ca, err := crypto.GenerateCA("d43-s3", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const (
		otherTenant = "99999999-9999-4999-8999-999999999999"
		agentID     = "55555555-5555-4555-8555-555555555555"
	)
	for name, id := range map[string]string{
		"foreign tenant": crypto.EBPFSPIFFEID(otherTenant, agentID),
		"foreign agent":  crypto.EBPFSPIFFEID(d43Tenant, "66666666-6666-4666-8666-666666666666"),
		"agent plane":    crypto.AgentSPIFFEID(d43Tenant, agentID),
	} {
		t.Run(name, func(t *testing.T) {
			cert, key, err := ca.IssueClientCert(agentID, id, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			rec := recordLiveStarts(t)
			cfg := consentedConfig()
			cfg.AgentID = agentID
			cfg.FixturePath = "testdata/flows.json"
			cfg.ControlPlane = ControlPlaneConfig{GRPCAddr: "127.0.0.1:1", ServerName: "localhost",
				CertFile: writeChannelFile(t, dir, "c.pem", cert), KeyFile: writeChannelFile(t, dir, "c.key", key),
				CAFile: writeChannelFile(t, dir, "ca.pem", ca.CertPEM())}
			a, err := New(cfg, bus.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			if len(rec.starts) != 0 || a.policy != nil || !a.L7CaptureChannelRefused() {
				t.Fatalf("capture under another identity's channel: starts=%v policy=%v", rec.starts, a.policy)
			}
		})
	}
}
