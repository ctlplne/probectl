// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// The commercial compiler has a separate focused test. This HTTPS test uses
// the production archive and estimate readers with application-role RLS and
// observes exactly which tenant-owned evidence crosses the licensed seam.
func proveRoutingTransferDryRunArchiveScope(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, inputs []routingTransferRequest) {
	t.Helper()
	t.Run("original-evidence", func(t *testing.T) {
		proveRoutingTransferOriginalEvidence(t, entity.Scope{TenantID: f.tenants[0], ContextID: f.contextID}, inputs[0])
	})
	ops := device.NewPostgresOpsStore(f.pool)
	spy := &routingTransferDryRunCompilerProbe{}
	f.server.WithDeviceOps(ops).WithRemediation(spy)
	archives := make([]device.ConfigVersion, len(f.tenants))
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permRemediationPropose, "metrics.write"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		archives[lane] = recordRoutingTransferDryRunArchive(t, f, socket, tenant, lane)
	}
	const path = "/v1/remediation/routing-transfer-dry-run"
	for lane, tenant := range f.tenants {
		archive := archives[lane]
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			authorize := func(_ context.Context, binding device.ConfigArchiveBinding) error {
				if binding.ContextID != f.contextID || binding.DeviceEntityID != f.routerID {
					return entity.ErrScopeMismatch
				}
				return nil
			}
			if err := device.LockRoutingPolicyArchiveInScope(ctx, sc, archive, authorize); err != nil {
				return err
			}
			foreign := archives[1-lane]
			foreign.TenantID = tenant
			if err := device.LockRoutingPolicyArchiveInScope(ctx, sc, foreign, authorize); !errors.Is(err, device.ErrConfigBinding) {
				t.Fatal("review publication did not reject the foreign archived revision", err)
			}
			return nil
		})
		input := routingTransferDryRunInput{Estimate: inputs[lane], ArchiveID: archive.ID}
		body := routingTransferPOST(t, socket, f.tokens[tenant], path, input, http.StatusOK)
		var output remediation.RoutingTransferDryRun
		if err := json.Unmarshal(body, &output); err != nil || output.RouterID != f.routerID || output.ArchiveID != archive.ID ||
			output.ArchiveDigest != archive.ContentHash || output.ExactPrefix != input.Estimate.Destination ||
			output.CandidateASN != uint32(64496+lane) || strings.Contains(string(body), "candidate-config-marker-") {
			t.Fatalf("dry run lost its owned route or published archive content: %s %v", body, err)
		}
		evidence := spy.snapshot()
		if len(evidence) != lane+1 {
			t.Fatal("unexpected number of licensed compiler calls", len(evidence))
		}
		current := evidence[lane]
		if current.TenantID != tenant || current.RouterID != f.routerID || current.ArchiveDigest != archive.ContentHash ||
			len(current.EstimateDigest) != 64 || !current.SourceValidUntil.After(time.Now()) || !output.SourceValidUntil.Equal(current.SourceValidUntil) ||
			current.MovedPeakBPS != []string{"10000", "20000"}[lane] || current.CandidatePeakBPS != []string{"12000", "22000"}[lane] ||
			current.CandidatePeer.String() != "10.43.0.1" || !strings.Contains(current.ArchiveContent, "candidate-config-marker-"+strconv.Itoa(lane)) ||
			strings.Contains(current.ArchiveContent, "candidate-config-marker-"+strconv.Itoa(1-lane)) {
			t.Fatal("licensed compiler received a foreign archive or unmatched route")
		}
		if lane > 0 && current.EstimateDigest == evidence[lane-1].EstimateDigest {
			t.Fatal("the exact estimate evidence digest omitted the tenant scope")
		}
		foreign := input
		foreign.ArchiveID = archives[1-lane].ID
		routingTransferPOST(t, socket, f.tokens[tenant], path, foreign, http.StatusNotFound)
		newer := recordRoutingTransferDryRunArchive(t, f, socket, tenant, lane+2)
		if newer.Version != archive.Version+1 || newer.ID == archive.ID {
			t.Fatal("current router configuration archive did not advance")
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := device.LockRoutingPolicyArchiveInScope(ctx, sc, archive, func(context.Context, device.ConfigArchiveBinding) error { return nil }); !errors.Is(err, device.ErrConfigBinding) {
				t.Fatal("review publication still admitted the old archived revision", err)
			}
			return nil
		})
		routingTransferPOST(t, socket, f.tokens[tenant], path, input, http.StatusNotFound)
		if len(spy.snapshot()) != lane+1 {
			t.Fatal("a foreign or superseded configuration reached the licensed compiler")
		}
	}
}

func proveRoutingTransferOriginalEvidence(t *testing.T, scope entity.Scope, selection routingTransferRequest) {
	t.Helper()
	ctx := t.Context()
	stamp := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	budget := flowstore.DefaultExplorerBudget()
	route := routingTransferRoute{selectedView: store.BGPRoutingViewRef{ID: "loc", Generation: "one"},
		candidateView: store.BGPRoutingViewRef{ID: "alternate", Generation: "one"}}
	counters := []flowstore.CounterRow{{CaptureKey: [32]byte{1}, CapturedAt: stamp, Value: 17},
		{CaptureKey: [32]byte{2}, CapturedAt: stamp.Add(time.Second), Value: 2017}}
	read := flowstore.RoutingCaptureRead{Ref: entity.FlowCaptureReference{Key: [32]byte{3}, CapturedAt: stamp}}
	digest := func(route routingTransferRoute, counters []flowstore.CounterRow, read flowstore.RoutingCaptureRead, validUntil time.Time) string {
		t.Helper()
		response := routingTransferResponse{ContextID: scope.ContextID, ValidUntil: validUntil,
			proofDigest: func(ctx context.Context) ([32]byte, error) {
				return routingTransferEvidenceIdentity(ctx, scope, route, routingTransferBillPlans{}, counters,
					routingTransferFlowEvidence{all: []flowstore.RoutingCaptureRead{read}}, budget)
			}}
		got, err := routingTransferDryRunEstimateDigest(ctx, scope, selection, response)
		if err != nil || len(got) != 64 {
			t.Fatalf("could not bind the original estimate evidence: %v", err)
		}
		return got
	}
	before := digest(route, counters, read, stamp)
	if got := digest(route, []flowstore.CounterRow{counters[1], counters[0]}, read, stamp.Add(time.Minute)); got != before {
		t.Fatal("a renewed expiry or reordered original rows changed the review evidence")
	}
	nextRoute := route
	nextRoute.candidateView.Generation = "two"
	nextCounters := append([]flowstore.CounterRow(nil), counters...)
	nextCounters[0].CaptureKey = [32]byte{4}
	nextRead := read
	nextRead.Ref.CapturedAt = stamp.Add(time.Nanosecond)
	for _, got := range []string{
		digest(nextRoute, counters, read, stamp),
		digest(route, nextCounters, read, stamp),
		digest(route, counters, nextRead, stamp),
	} {
		if got == before {
			t.Fatal("a different original source kept the review evidence despite identical displayed values")
		}
	}
}

func recordRoutingTransferDryRunArchive(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, tenant string, marker int) device.ConfigVersion {
	t.Helper()
	body := routingTransferPOST(t, socket, f.tokens[tenant], "/v1/device/configs", sdk.DeviceConfigArchiveRequest{
		Device: "Shared router identity", Source: "operator-submitted",
		Content: "frr version 10.7.1\n! candidate-config-marker-" + strconv.Itoa(marker) + "\n",
		Binding: &sdk.DeviceConfigBindingInput{ContextId: f.contextID, DeviceEntityId: f.routerID, AgentId: "role-snmp", SourceRef: "192.0.2.1"},
	}, http.StatusCreated)
	var out device.ConfigVersion
	if err := json.Unmarshal(body, &out); err != nil || out.TenantID != tenant || out.ID == "" || out.ContentHash == "" || out.Binding == nil {
		t.Fatalf("fixture did not record the tenant's authorized archive: %s %v", body, err)
	}
	return out
}

type routingTransferDryRunCompilerProbe struct {
	remediation.Service
	mu   sync.Mutex
	seen []remediation.RoutingTransferDryRunEvidence
}

func (p *routingTransferDryRunCompilerProbe) PreviewRoutingTransfer(ctx context.Context, tenant string, evidence remediation.RoutingTransferDryRunEvidence) (remediation.RoutingTransferDryRun, error) {
	principal := auth.PrincipalFrom(ctx)
	bound, ok := tenancy.FromContext(ctx)
	if !ok || principal == nil || principal.TenantID != tenant || tenant != bound.String() || tenant != evidence.TenantID {
		return remediation.RoutingTransferDryRun{}, entity.ErrScopeMismatch
	}
	p.mu.Lock()
	p.seen = append(p.seen, evidence)
	p.mu.Unlock()
	return remediation.RoutingTransferDryRun{RouterID: evidence.RouterID, ArchiveID: evidence.ArchiveID, ArchiveDigest: evidence.ArchiveDigest,
		CandidateASN: evidence.CandidateASN, ExactPrefix: evidence.ExactPrefix.String(),
		SourceValidUntil: evidence.SourceValidUntil}, nil
}

func (p *routingTransferDryRunCompilerProbe) snapshot() []remediation.RoutingTransferDryRunEvidence {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]remediation.RoutingTransferDryRunEvidence(nil), p.seen...)
}
