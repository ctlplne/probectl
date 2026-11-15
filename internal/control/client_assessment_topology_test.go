// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestAssessmentTopologyProjectionKeepsExactOriginalsAndEndpointPermissions(t *testing.T) {
	const contextID = "33333333-3333-4333-8333-333333333333"
	const fromID = "44444444-4444-4444-8444-444444444444"
	const toID = "55555555-5555-4555-8555-555555555555"
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		from, to, _, _ := clientReportTableFixture(tenant)
		item := store.ClientReportPhysicalLink{TenantID: tenant, ContextID: contextID, LinkID: contextID, FromEntityID: fromID, ToEntityID: toID,
			EvidenceID: fromID, ObservationID: toID, RemoteEvidenceID: toID, RemoteObservationID: fromID, Protocol: "lldp", LocalIfIndex: 4294967295,
			Source: entity.SourceKey{AgentID: "local-agent", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}, RemoteSource: entity.SourceKey{AgentID: "remote-agent", Kind: entity.DeviceTarget, SourceRef: "192.0.2.2"},
			LocalPort: "xe-0/0/7", RemotePort: "xe-0/0/8", Chassis: "00:11:22:33:44:55", ObservedAt: from, RemoteObservedAt: from.Add(-time.Second), CapturedAt: to.Add(time.Hour), OriginalsDigest: strings.Repeat("a", 64)}
		capture := &clientReportCapture{TenantID: tenant, From: from, To: to, PhysicalLinks: []store.ClientReportPhysicalLink{item}}
		table, err := projectAssessmentTopology(ctx, capture, 1<<20)
		if err != nil || table.ExpectedRows != 1 {
			t.Fatal("exact observed adjacency was lost", err)
		}
		capture.PhysicalLinks[0].RemotePort = "later mutable value"
		if err := table.WalkRows(ctx, func(row []string) error {
			if len(row) != 24 || row[0] != tenant || row[6] != "4294967295" || row[8] != item.RemotePort || row[12] != item.EvidenceID || row[17] != item.RemoteEvidenceID || row[22] != item.CapturedAt.Format(time.RFC3339Nano) || row[23] != item.OriginalsDigest {
				t.Fatal("topology substituted an endpoint, original clock or support receipt")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		foreign := tenancy.WithTenant(t.Context(), tenancy.ID("foreign"))
		called := false
		if err := table.WalkRows(foreign, func([]string) error { called = true; return nil }); !errors.Is(err, entity.ErrScopeMismatch) || called {
			t.Fatal("topology cursor disclosed sibling receipts", err)
		}
		refs := store.ClientReportPhysicalLinkRefs([]store.ClientReportPhysicalLink{item})
		var access []clientReportAccessRequirement
		for _, id := range []string{fromID, toID} {
			for _, permission := range []string{"entities.read", "metrics.read", "topology.read"} {
				access = append(access, clientReportAccessRequirement{Permission: permission, Resource: map[string]string{auth.ResourceTenantKey: tenant, "context_id": contextID, "entity_id": id}})
			}
		}
		if err := validateAssessmentTopologyRequirements(refs, access); err != nil {
			t.Fatal("complete current endpoint requirements refused", err)
		}
		if err := validateAssessmentTopologyRequirements(refs, access[:len(access)-1]); err == nil {
			t.Fatal("remote endpoint borrowed another endpoint's topology grant")
		}
		refs[0].RemoteEvidenceID = ""
		if err := validateAssessmentTopologyRequirements(refs, access); err == nil {
			t.Fatal("report omitted its exact independent support receipt")
		}
		capture.PhysicalLinks[0].TenantID = "foreign"
		if _, err := projectAssessmentTopology(ctx, capture, 1<<20); !errors.Is(err, entity.ErrScopeMismatch) {
			t.Fatal("mixed tenant topology entered report projection", err)
		}
	}
}
