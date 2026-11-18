// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestComplianceFlowSourceSnapshotUsesCurrentTenantRolesAndOriginalOwners(t *testing.T) {
	f, _ := seedIncidentImpactFlowFixture(t)
	budget := flowstore.ExplorerQueryBudget(f.server.flowStore)
	members := []store.IncidentImpactEntity{{ContextID: f.contextID, EntityID: f.routerID}}
	actors := [2]*auth.Principal{}
	readByTenant := [2][]flowstore.RoutingCaptureRead{}
	windows := [2]complianceFlowWindow{}
	end := time.Now().UTC()
	private, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permAuditRead)
		})
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		current, err := loadCurrentUserAuthority(ctx, f.pool, tenant, f.users[tenant])
		if err != nil {
			t.Fatal(err)
		}
		actors[lane] = current.principal
		before, err := f.server.loadComplianceFlowSourceSnapshot(ctx, actors[lane], members, nil, budget)
		if err != nil || len(before.sources) != 1 || len(before.sources[0].Selections) != 1 || before.sourceDigest == "" {
			t.Fatal("scoped compliance source authority unavailable", err)
		}
		batch, err := flowstore.NewPlanBatch(ctx, f.server.flowStore, tenant, 1)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := batch.IncidentTrafficRows(flowstore.IncidentTrafficQuery{
			TenantID: tenant, From: end.Add(-time.Minute), To: end, Series: "raw", Sources: before.sources[0].Selections,
		})
		batch.Close()
		if err != nil || len(rows) != 1 {
			t.Fatal("original owned flow unavailable at the selected window", len(rows), err)
		}
		reads, err := flowstore.IncidentTrafficCaptureReferences(ctx, tenant, rows, budget.MemoryBytes/8)
		if err != nil || len(reads) != 1 {
			t.Fatal("selected retained row lost its original capture", len(reads), err)
		}
		readByTenant[lane] = reads
		after, err := f.server.loadComplianceFlowSourceSnapshot(ctx, actors[lane], members, reads, budget)
		if err != nil || after.sourceDigest != before.sourceDigest || after.captureDigest == "" || len(after.owners) != 1 ||
			!after.owners[0].Available || after.owners[0].Owner.Scope.TenantID != tenant ||
			!incidentImpactSourceCoverage(after.sources).covers(rows[0], after.owners[0]) {
			t.Fatal("original flow did not verify through the selected tenant source", err)
		}
		legacy := rows[0]
		legacy.RawFlowDigest, legacy.RoutingCaptureKey, legacy.RoutingCapturedUnixNanos = "", "", 0
		legacy.TS, legacy.StartTS = end.Add(-time.Nanosecond), end.Add(-time.Nanosecond)
		legacy.DstPort = 443
		if err := f.server.flowStore.Insert(ctx, []flowstore.Row{legacy}); err != nil {
			t.Fatal(err)
		}
		windows[lane], err = f.server.readComplianceFlowWindow(ctx, actors[lane], members, end.Add(-time.Minute), end, budget)
		if err != nil || windows[lane].observed != 2 || len(windows[lane].attested) != 1 ||
			windows[lane].attested[0].RoutingCaptureKey != rows[0].RoutingCaptureKey || windows[lane].attested[0].TenantID != tenant {
			t.Fatal("complete window did not distinguish attested and unavailable original flows", err)
		}
		if len(windows[lane].originals) != 1 || windows[lane].publicationDigest != after.captureDigest {
			t.Fatal("the frozen lineage included rows without original ownership")
		}
		verifyComplianceFlowControlWindow(t, tenant, windows[lane], private, lane)
	}
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		foreign, err := f.server.loadComplianceFlowSourceSnapshot(ctx, actors[lane], members, readByTenant[1-lane], budget)
		if err == nil && (len(foreign.owners) != 1 || foreign.owners[0].Available || foreign.owners[0].Owner.Scope.TenantID != "") {
			t.Fatal("foreign original captured flow obtained a current owner in this tenant")
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, tenant, f.roles[tenant], permAuditRead)
			return err
		})
		withdrawn, err := f.server.loadComplianceFlowSourceSnapshot(ctx, actors[lane], members, readByTenant[lane], budget)
		if err == nil || withdrawn.sourceDigest != "" || withdrawn.captureDigest != "" || len(withdrawn.owners) != 0 {
			t.Fatal("withdrawn current audit grant exposed retained flow source authority")
		}
		capture := &reportFlowCapture{TenantID: tenant, ComplianceControl: compliance.CMMCBoundaryControl,
			ComplianceFlow: &complianceFlowRequirements{Sources: []reporting.ComplianceFlowSource{{ContextID: f.contextID, EntityID: f.routerID}}, Originals: windows[lane].originals}}
		if err := f.server.revalidateReportFlowCapture(ctx, actors[lane], capture); err == nil {
			t.Fatal("captured window survived withdrawal of its current audit authority")
		}
	}
}

const complianceBoundaryFixturePolicy = `name: declared-boundary
zones:
  - name: external
    cidrs: ["203.0.113.1/32"]
  - name: protected
    cidrs: ["203.0.113.2/32"]
rules:
  - id: forbidden-443
    from: external
    to: protected
    ports: [443]
`

func verifyComplianceFlowControlWindow(t *testing.T, tenant string, window complianceFlowWindow, private []byte, lane int) {
	t.Helper()

	for _, ref := range []string{compliance.PCISegmentationControl, compliance.CMMCBoundaryControl, compliance.CMMCMonitoringControl} {
		section, err := projectComplianceFlowControl(t.Context(), tenant, ref, complianceBoundaryFixturePolicy, window)
		want := compliance.StatusObserved
		if lane == 0 && ref != compliance.CMMCMonitoringControl {
			want = compliance.StatusFailed
		}
		if err != nil || section.Status != want {
			t.Fatal("flow control lost its measured disposition", ref, section.Status, err)
		}
		coverage, ok := section.Content.(complianceFlowEvidence)
		if !ok || coverage.AttestedRows != 1 || coverage.RetainedRows != 2 || coverage.UnavailableOriginals != 1 || coverage.ObservationsDigest == "" {
			t.Fatal("signed coverage input lost retained-versus-verified populations", ref, coverage)
		}
		if coverage.Segmentation != nil && (coverage.Segmentation.Tenant != "" || len(coverage.Segmentation.Records) != 1 ||
			coverage.Segmentation.Records[0].Result.ObservedPairs != 1 || compliance.VerifyEvidence(*coverage.Segmentation) != nil) {
			t.Fatal("signed rule evidence lost its exact attested population", ref)
		}
		manifest, attachments, err := compliance.BuildControlEvidence(compliance.ControlEvidenceInput{
			TenantID: tenant, Reference: ref, CollectedAt: time.Now().UTC(), Evidence: section,
			Window: &compliance.ControlEvidenceWindow{From: window.from, To: window.to},
		})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := compliance.SignAuditorBundle(manifest, attachments, private)
		if err != nil {
			t.Fatal(err)
		}
		checked, err := compliance.VerifyEvidenceBundle(raw)
		if err != nil || checked.Control == nil || checked.Control.Reference != ref || checked.Control.Window == nil ||
			!checked.Control.Window.From.Equal(window.from) || !checked.Control.Window.To.Equal(window.to) || checked.Sections[0].Status != want {
			t.Fatal("signed retained control window did not verify", ref, err)
		}
	}
}
