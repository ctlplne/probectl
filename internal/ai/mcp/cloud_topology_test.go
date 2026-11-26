// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/topology"
)

func TestNativeCloudTopologyKeepsItsClockAndRequiresReaderGrants(t *testing.T) {
	const tenant = "tenant-a"
	const rawClock = "2026-11-26T08:30:00.123456789+01:00"
	want, err := time.Parse(time.RFC3339Nano, rawClock)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	read := func(_ context.Context, actor *auth.Principal, at time.Time) (topology.Viz, error) {
		calls++
		if actor.TenantID != tenant || !at.Equal(want) {
			t.Fatalf("read lost its authenticated tenant or requested clock: %s, %v", actor.TenantID, at)
		}
		return topology.ToViz(topology.Snapshot{Tenant: actor.TenantID, At: at}), nil
	}
	server := newTestServer(&fakeBackend{}, testGate(), WithCloudTopologyBackend(read, nil))
	grants := []string{ai.PermTopologyRead, permAIQuery}
	actor := principal(tenant, grants...)
	actor.UserID = "reader"
	input := map[string]any{"name": "topology_cloud", "arguments": map[string]string{"at": rawClock}}
	response := handle(t, server, actor, 1, "tools/call", input)
	body, _ := resultOf(t, response)["structuredContent"].(map[string]any)
	if calls != 1 || body["tenant"] != tenant || body["at"] != rawClock || body["cloud_latest_only"] != true {
		t.Fatalf("cloud topology lost its clock or latest-only marker: %+v", response)
	}
	for _, grant := range grants {
		delete(actor.Permissions, grant)
		denied := handle(t, server, actor, 2, "tools/call", input)
		if code, _ := errCode(denied); code != codeForbidden || calls != 1 {
			t.Fatalf("cloud topology admitted a caller without %s: %+v", grant, denied)
		}
		actor.Permissions[grant] = true
	}
	input["arguments"] = map[string]string{"at": "unparseable"}
	invalid := handle(t, server, actor, 3, "tools/call", input)
	if resultOf(t, invalid)["isError"] != true || calls != 1 {
		t.Fatalf("cloud topology admitted an invalid time: %+v", invalid)
	}
}
