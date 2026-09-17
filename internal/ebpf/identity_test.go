// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ebpf

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

// DPR-051: the agent used the host name as its bus agent_id, so a DaemonSet
// (pod names) could never carry the identity the tenant registered, and the
// control plane rejected every batch (TENANT-101). The registered collector id
// is now a first-class setting; host stays the observing node's name.
func TestRegisteredCollectorIdentityIsStampedAsAgentID(t *testing.T) {
	cfg := Default()
	cfg.TenantID = "tenant-a"
	cfg.Host = "node-a"
	cfg.AgentID = "e1b3987a-3dbf-4458-8726-9db9224c7af6"

	src := netip.MustParseAddr("2001:db8::10")
	dst := netip.MustParseAddr("2001:db8::20")
	e := l4eventC{Bytes: 1, Packets: 1, PID: 7, Sport: 40000, Dport: 443, Family: l4FamilyIPv6, NewState: l4TCPStateClose}
	copy(e.Comm[:], "curl")
	src16, dst16 := src.As16(), dst.As16()
	copy(e.Saddr[:], src16[:])
	copy(e.Daddr[:], dst16[:])

	f := e.toFlow(cfg)
	if f.AgentID != cfg.AgentID || f.Host != "node-a" || f.TenantID != "tenant-a" {
		t.Fatalf("live flow identity = agent %q host %q tenant %q, want the registered id and the node name", f.AgentID, f.Host, f.TenantID)
	}

	// Without a registered identity the host name remains the agent_id (the
	// single-node lightweight mode, where the pipeline has no registry binding).
	cfg.AgentID = ""
	if f := e.toFlow(cfg); f.AgentID != "node-a" {
		t.Fatalf("fallback agent_id = %q, want host node-a", f.AgentID)
	}
}

func TestConfigAgentIDFromYAMLAndEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ebpf.yaml")
	writeFile(t, path, "apiVersion: "+ConfigAPIVersion+"\ntenant_id: t-yaml\nagent_id: from-yaml\nbus:\n  mode: memory\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentID != "from-yaml" || cfg.identity() != "from-yaml" {
		t.Fatalf("agent_id from YAML = %q (identity %q)", cfg.AgentID, cfg.identity())
	}

	t.Setenv("PROBECTL_EBPF_AGENT_ID", "e1b3987a-3dbf-4458-8726-9db9224c7af6")
	if cfg, err = Load(path); err != nil {
		t.Fatal(err)
	}
	if cfg.AgentID != "e1b3987a-3dbf-4458-8726-9db9224c7af6" {
		t.Fatalf("env override lost: agent_id = %q", cfg.AgentID)
	}

	// A value that could not be a registry id (whitespace, control bytes)
	// refuses to start rather than publishing an unverifiable identity.
	t.Setenv("PROBECTL_EBPF_AGENT_ID", "not an id")
	if _, err := Load(path); err == nil {
		t.Fatal("agent_id with whitespace must be refused")
	}
}

// The runtime path: every flow the agent emits carries the registered
// identity, and the node name is preserved separately as host.
func TestAgentRunStampsRegisteredIdentity(t *testing.T) {
	src := &sliceSource{flows: []Flow{
		{Source: Endpoint{Address: "10.0.0.1", Workload: "api"}, Destination: Endpoint{Address: "10.0.0.2", Port: 443, Workload: "db"}, Transport: "tcp"},
	}}
	em := &captureEmitter{}
	cfg := &Config{TenantID: "t1", Host: "node-1", AgentID: "e1b3987a-3dbf-4458-8726-9db9224c7af6", FlushInterval: time.Hour}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), src, NopEnricher{}, em)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(em.flows) != 1 {
		t.Fatalf("emitted flows = %d, want 1", len(em.flows))
	}
	if f := em.flows[0]; f.AgentID != cfg.AgentID || f.Host != "node-1" || f.TenantID != "t1" {
		t.Fatalf("emitted identity = agent %q host %q tenant %q", f.AgentID, f.Host, f.TenantID)
	}
}
