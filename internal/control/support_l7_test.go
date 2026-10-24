// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/ctlplne/probectl/internal/store"
)

// The bundle's L7 section is an allowlist projection: the scope SIZE travels,
// the scope entries, the consent tenant and the agent id never do.
func TestSupportL7CaptureProjectsAnAllowlist(t *testing.T) {
	p := store.L7CapturePosture{Enabled: true, ConsentTenant: "tenant-secret-id", Scope: []string{"exe:/opt/secret-workload"},
		RedactionMode: "headers", RedactionFloor: "metadata", State: "refused_floor", ReportedAt: time.Now()}
	raw, err := json.Marshal(l7SupportAgent(0, p))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"tenant-secret-id", "secret-workload"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("bundle projection carries %q: %s", leak, raw)
		}
	}
	if !strings.Contains(string(raw), `"agent_ref":"agent-0001"`) || !strings.Contains(string(raw), `"scope_entries":1`) {
		t.Fatalf("bundle projection = %s", raw)
	}
	// Without a database the section still renders, with the default floor.
	s := testServer(nil)
	sum := s.supportL7Capture(context.Background(), "", false)
	if sum.RedactionFloor != "metadata" || sum.Agents == nil || sum.IngestStrips == nil {
		t.Fatalf("db-less section = %+v", sum)
	}
}

// Review S11: a tenant's support bundle carries only that tenant's strip
// counts; the deployment-wide totals stay with the provider plane's bundle.
func TestSupportL7CaptureStripCountsAreTenantScoped(t *testing.T) {
	st := newL7IngestStrip(nil, false, nil).WithTenantBinding(stripBinding{})
	for i := 0; i < 3; i++ {
		st.Apply(context.Background(), &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{rawCall("tenant-b")}}, "", true)
	}
	st.Apply(context.Background(), &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{rawCall("tenant-a")}}, "", true)
	s := testServer(nil)
	s.WithL7IngestStrip(st)
	if got := s.supportL7Capture(context.Background(), "tenant-a", false).IngestStrips["query"]; got != 1 {
		t.Fatalf("tenant A's bundle query strips = %d, want its own 1 (not tenant B's)", got)
	}
	if got := s.supportL7Capture(context.Background(), "tenant-a", true).IngestStrips["query"]; got != 4 {
		t.Fatalf("provider bundle query strips = %d, want the deployment total 4", got)
	}
}
