// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	bgpv1 "github.com/ctlplne/probectl/internal/gen/probectl/bgp/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestAnalyzerBridgeKeepsCompleteOldAndNewPathsAndTenantBinding(t *testing.T) {
	const count = 65_538
	oldPath, newPath := make([]uint32, count), make([]uint32, count)
	for i := range oldPath {
		oldPath[i], newPath[i] = ^uint32(0), ^uint32(0)
	}
	oldPath[0], newPath[0] = 0, 23456
	oldPath[count-1], newPath[count-1] = 64496, 64500
	withTestRouter(t, testIsolationRouter{targets: map[string]tenancy.Targets{
		"red": {BusNamespace: "red"}, "blue": {BusNamespace: "blue"},
	}})
	for _, tenant := range []string{"red", "blue"} {
		event := Event{TenantID: tenant, EventType: "origin_change", Severity: "warning", Confidence: 0.7, Prefix: "192.0.2.0/24", NewASPath: newPath, OldASPath: oldPath, NewOriginASN: 64500, OldOriginASN: 64496, RPKIStatus: "unknown"}
		body, err := json.Marshal(event)
		if err != nil || len(body) <= 1<<20 {
			t.Fatal("complete analyzer fixture did not cross former line admission", len(body), err)
		}
		foreign := event
		foreign.TenantID = "other-tenant"
		foreignBody, err := json.Marshal(foreign)
		if err != nil {
			t.Fatal(err)
		}
		input := append(append(append(foreignBody, '\n'), body...), '\n')
		pub := &capturePublisher{}
		stats, err := NewBridge(pub, discardLogger()).WithExpectedTenant(tenant).Ingest(t.Context(), bytes.NewReader(input))
		if err != nil || stats.Published != 1 || stats.Skipped != 1 || len(pub.msgs) != 1 {
			t.Fatal("complete bound analyzer paths were refused or lost tenant admission", stats, err)
		}
		message := pub.msgs[0]
		var decoded bgpv1.BGPEvent
		if err := proto.Unmarshal(message.value, &decoded); err != nil {
			t.Fatal(err)
		}
		if tenantFromBGPKey(message.key) != tenant || message.topic != "probectl."+tenant+".bgp.events" || decoded.GetTenantId() != tenant || !slices.Equal(decoded.GetNewAsPath(), newPath) || !slices.Equal(decoded.GetOldAsPath(), oldPath) || decoded.GetNewOriginAsn() != 64500 || decoded.GetOldOriginAsn() != 64496 {
			t.Fatal("analyzer bridge lost complete old/new paths or crossed tenant")
		}
		t.Logf("simulation: tenant %s, %d JSON bytes, %d ASNs in each old/new path, exact decoded protobuf; bus publisher modeled", tenant, len(body), count)
	}
}

func TestAnalyzerBridgeRefusesUnadmittedWholeLineWithoutPublishingPrefix(t *testing.T) {
	pub := &capturePublisher{}
	stats, err := NewBridge(pub, discardLogger()).WithExpectedTenant("red").Ingest(t.Context(), strings.NewReader(strings.Repeat("x", maxEventLine+1)))
	if err == nil || stats.Published != 0 || len(pub.msgs) != 0 {
		t.Fatal("unadmitted analyzer record published a prefix", stats, err)
	}
}
