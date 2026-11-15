// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestAssessmentTopologyRedactionKeepsPrivateMetadataWithinTenantPolicy(t *testing.T) {
	masked := map[string]string{}
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		from, to, _, _ := clientReportTableFixture(tenant)
		item := store.ClientReportPhysicalLink{TenantID: tenant, ContextID: tenant, LinkID: tenant,
			FromEntityID: tenant, ToEntityID: tenant, EvidenceID: tenant, RemoteEvidenceID: tenant, ObservationID: tenant, RemoteObservationID: tenant,
			Source: entity.SourceKey{AgentID: "local", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}, RemoteSource: entity.SourceKey{AgentID: "remote", Kind: entity.DeviceTarget, SourceRef: "192.0.2.2"},
			Protocol: "lldp", LocalIfIndex: 7, LocalPort: "password=local-private-value", RemotePort: "password=remote-private-value", DeviceName: "operator@example.net", Chassis: "00:11:22:33:44:55", ManagementAddress: "192.0.2.2",
			ObservedAt: from, RemoteObservedAt: from, CapturedAt: to, OriginalsDigest: strings.Repeat("a", 64)}
		table, err := projectAssessmentTopology(ctx, &clientReportCapture{TenantID: tenant, From: from, To: to, PhysicalLinks: []store.ClientReportPhysicalLink{item}}, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		policy := ai.RedactionPolicy{MaskIPs: true, MaskHostnames: true, MaskPII: true, TokenKey: bytes.Repeat([]byte{7}, 32)}
		output := redactMonthlyReportTables([]reporting.CSVTable{table}, policy, tenant)
		if err := output[0].WalkRows(ctx, func(row []string) error {
			for _, index := range []int{7, 8, 9, 10, 11, 15, 20} {
				if strings.Contains(row[index], "private-value") || strings.Contains(row[index], "operator@example.net") || strings.Contains(row[index], "192.0.2.") || strings.Contains(row[index], "00:11:22:33:44:55") {
					t.Fatal("assessment topology bypassed configured metadata redaction", index)
				}
			}
			if row[12] != tenant || row[13] != tenant || row[16] != from.Format(time.RFC3339Nano) || row[17] != tenant || row[23] != item.OriginalsDigest {
				t.Fatal("metadata redaction changed canonical original identity, clock or digest")
			}
			masked[tenant] = row[11]
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if masked["11111111-1111-4111-8111-111111111111"] == masked["22222222-2222-4222-8222-222222222222"] {
		t.Fatal("metadata masking reused a cross-tenant correlation token")
	}
}
