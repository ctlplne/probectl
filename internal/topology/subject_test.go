// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package topology

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGraphSubjectExportAndDelete(t *testing.T) {
	g := NewGraph("tenant-a")
	at := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	g.UpsertNode(Node{ID: "device:alice-router", Kind: NodeDevice, Label: "Alice edge", Attributes: map[string]string{"owner": "alice@example.com"}}, at)
	g.UpsertNode(Node{ID: "hop:shared", Kind: NodeHop, Label: "shared"}, at)
	g.UpsertNode(Node{ID: "service:bob", Kind: NodeService, Label: "Bob service"}, at)
	g.UpsertEdge(Edge{From: "device:alice-router", To: "hop:shared", Kind: EdgeDevice, Label: "uplink"}, at)
	g.UpsertEdge(Edge{From: "hop:shared", To: "service:bob", Kind: EdgeFlow, Attributes: map[string]string{"ticket": "alice-change"}}, at)

	if nodes, edges, devices, err := g.ExportSubject(" ", &bytes.Buffer{}); err != nil || nodes != 0 || edges != 0 || devices != 0 {
		t.Fatalf("empty subject export = %d/%d/%d err=%v, want zero", nodes, edges, devices, err)
	}
	var out bytes.Buffer
	nodes, edges, devices, err := g.ExportSubject(" ALICE ", &out)
	if err != nil {
		t.Fatal(err)
	}
	if nodes != 1 || edges != 2 || devices != 1 {
		t.Fatalf("subject export = nodes=%d edges=%d devices=%d, want 1/2/1", nodes, edges, devices)
	}
	body := out.String()
	if !strings.Contains(body, "alice-router") || !strings.Contains(body, "alice-change") {
		t.Fatalf("subject export omitted matches: %s", body)
	}
	if nodes, edges, devices, err := g.ExportSubject("alice", topologyFailingWriter{}); !errors.Is(err, errTopologyWriter) || nodes != 0 || edges != 0 || devices != 0 {
		t.Fatalf("failed export = %d/%d/%d err=%v, want zero + writer error", nodes, edges, devices, err)
	}

	deleted, remaining, deviceDeleted, deviceRemaining := g.DeleteSubject("alice")
	if deleted != 3 || remaining != 0 || deviceDeleted != 1 || deviceRemaining != 0 {
		t.Fatalf("DeleteSubject = %d/%d devices=%d/%d, want 3/0 and 1/0", deleted, remaining, deviceDeleted, deviceRemaining)
	}
	latest := g.Latest()
	if len(latest.Nodes) != 2 || len(latest.Edges) != 0 {
		t.Fatalf("post-delete graph = %d nodes/%d edges, want 2/0", len(latest.Nodes), len(latest.Edges))
	}
	if deleted, remaining, deviceDeleted, deviceRemaining := g.DeleteSubject(" "); deleted != 0 || remaining != 0 || deviceDeleted != 0 || deviceRemaining != 0 {
		t.Fatalf("empty delete = %d/%d/%d/%d, want zero", deleted, remaining, deviceDeleted, deviceRemaining)
	}
}

func TestSubjectStoreWrappersStayTenantScoped(t *testing.T) {
	at := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	memoryStore := NewMemoryStore()
	indexedStore := NewIndexedStore()
	for _, tc := range []struct {
		name   string
		seed   func(tenant string)
		export func(tenant, subject string, w *bytes.Buffer) (int64, int64, int64, error)
		delete func(tenant, subject string) (int64, int64, int64, int64)
	}{
		{
			name: "memory",
			seed: func(tenant string) {
				memoryStore.observeDevice(tenant, DeviceInput{Address: "alice-switch", Name: "Alice switch", InterfaceIPs: []string{"192.0.2.10"}}, at)
			},
			export: func(tenant, subject string, w *bytes.Buffer) (int64, int64, int64, error) {
				return memoryStore.ExportSubject(tenant, subject, w)
			},
			delete: memoryStore.DeleteSubject,
		},
		{
			name: "indexed",
			seed: func(tenant string) {
				indexedStore.ObserveDevice(tenant, DeviceInput{Address: "alice-switch", Name: "Alice switch", InterfaceIPs: []string{"192.0.2.10"}}, at)
			},
			export: func(tenant, subject string, w *bytes.Buffer) (int64, int64, int64, error) {
				return indexedStore.ExportSubject(tenant, subject, w)
			},
			delete: indexedStore.DeleteSubject,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var empty bytes.Buffer
			if nodes, edges, devices, err := tc.export("never-seen", "alice", &empty); err != nil || nodes != 0 || edges != 0 || devices != 0 {
				t.Fatalf("empty wrapper export = %d/%d/%d err=%v", nodes, edges, devices, err)
			}
			tc.seed("tenant-a")
			tc.seed("tenant-b")
			var out bytes.Buffer
			nodes, _, devices, err := tc.export("tenant-a", "alice", &out)
			if err != nil || nodes != 1 || devices != 1 {
				t.Fatalf("tenant-a export = nodes=%d devices=%d err=%v body=%s", nodes, devices, err, out.String())
			}
			deleted, _, deviceDeleted, _ := tc.delete("tenant-a", "alice")
			if deleted == 0 || deviceDeleted != 1 {
				t.Fatalf("tenant-a delete = deleted=%d devices=%d", deleted, deviceDeleted)
			}
			var tenantB bytes.Buffer
			if nodes, _, devices, err := tc.export("tenant-b", "alice", &tenantB); err != nil || nodes != 1 || devices != 1 {
				t.Fatalf("tenant-b changed by tenant-a delete: nodes=%d devices=%d err=%v", nodes, devices, err)
			}
		})
	}
}

var errTopologyWriter = errors.New("topology writer failed")

type topologyFailingWriter struct{}

func (topologyFailingWriter) Write([]byte) (int, error) { return 0, errTopologyWriter }
