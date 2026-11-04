// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestReportContextCaptureKeepsOnlyAuthorizedOwnedRequirements(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		t.Run(tenant, func(t *testing.T) {
			sink := &reportContextCapture{tenant: tenant, remaining: 32 << 10}
			ctx := context.WithValue(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), reportContextCaptureKey{}, sink)
			principal := &auth.Principal{TenantID: tenant}
			records := []entity.ContextRecord{
				{TenantID: tenant, ContextID: "same-context", SiteID: tenant + "-site", VRFID: tenant + "-vrf", SiteLabel: tenant + " 東京", VRFLabel: "private"},
				{TenantID: tenant, ContextID: "hidden"},
				{TenantID: tenant, ContextID: "plain"},
			}
			allowed := map[string]bool{"same-context": true, "plain": true}
			related := map[string]map[string]bool{"device": {"same-context": true}, "agent": {"same-context": true}, "prefix": {"hidden": true}}
			if err := captureReportContextRequirements(ctx, principal, records, allowed, related, []string{"interface", "agent", "prefix"}); err != nil {
				t.Fatal(err)
			}
			if !sink.captured || len(sink.contexts) != 2 || sink.remaining >= 32<<10 {
				t.Fatal("capture did not retain the complete charged authorized scope")
			}
			got := sink.contexts[0]
			if got.ContextID != "same-context" || got.Resource[auth.ResourceTenantKey] != tenant || got.Resource["context_id"] != "same-context" || got.Resource["site_id"] != tenant+"-site" || got.Resource["vrf_id"] != tenant+"-vrf" || got.Resource["site_label"] != tenant+" 東京" {
				t.Fatal("captured context requirements lost exact tenant/resource identity", got)
			}
			if !slices.Equal(got.Permissions, []string{"agent.read", permFlowRead, "metrics.read", permTagsRead}) || !slices.Equal(sink.contexts[1].Permissions, []string{permFlowRead, permTagsRead}) {
				t.Fatal("capture borrowed an unselected or unauthorized related context grant", sink.contexts)
			}
			records[0].SiteID, records[0].SiteLabel = "changed", "changed"
			allowed["hidden"], related["prefix"]["same-context"] = true, true
			if got.Resource["site_id"] != tenant+"-site" || got.Resource["site_label"] != tenant+" 東京" || slices.Contains(got.Permissions, "entities.read") {
				t.Fatal("frozen requirements changed after source/policy input mutation")
			}
			before := sink.remaining
			if err := captureReportContextRequirements(ctx, principal, records, allowed, related, nil); err == nil || sink.remaining != before || len(sink.contexts) != 2 {
				t.Fatal("capture could be replaced or broadened within one source batch")
			}
		})
	}
}

func TestReportContextCaptureRefusesScopeCostAndCancellationAtomically(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*reportContextCapture, *auth.Principal, *[]entity.ContextRecord)
	}{
		{"principal", func(_ *reportContextCapture, p *auth.Principal, _ *[]entity.ContextRecord) { p.TenantID = "blue" }},
		{"sink", func(s *reportContextCapture, _ *auth.Principal, _ *[]entity.ContextRecord) { s.tenant = "blue" }},
		{"foreign_after_own", func(_ *reportContextCapture, _ *auth.Principal, r *[]entity.ContextRecord) {
			*r = append(*r, entity.ContextRecord{TenantID: "blue", ContextID: "same"})
		}},
		{"missing_context", func(_ *reportContextCapture, _ *auth.Principal, r *[]entity.ContextRecord) { (*r)[0].ContextID = "" }},
		{"exhausted", func(s *reportContextCapture, _ *auth.Principal, _ *[]entity.ContextRecord) { s.remaining = 1 }},
		{"large_resource", func(_ *reportContextCapture, _ *auth.Principal, r *[]entity.ContextRecord) {
			(*r)[0].SiteLabel = strings.Repeat("x", 20000)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &reportContextCapture{tenant: "red", remaining: 8 << 10}
			p := &auth.Principal{TenantID: "red"}
			records := []entity.ContextRecord{{TenantID: "red", ContextID: "same"}}
			tc.edit(sink, p, &records)
			before := *sink
			ctx := context.WithValue(tenancy.WithTenant(t.Context(), "red"), reportContextCaptureKey{}, sink)
			if err := captureReportContextRequirements(ctx, p, records, map[string]bool{"same": true}, nil, nil); err == nil || !reflect.DeepEqual(before, *sink) {
				t.Fatal("failed capture left partial requirements or consumed its budget", err, sink)
			}
		})
	}
	sink := &reportContextCapture{tenant: "red", remaining: 8 << 10}
	ctx := context.WithValue(tenancy.WithTenant(t.Context(), "red"), reportContextCaptureKey{}, sink)
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := captureReportContextRequirements(ctx, &auth.Principal{TenantID: "red"}, nil, nil, nil, nil); !errors.Is(err, context.Canceled) || sink.captured || sink.remaining != 8<<10 {
		t.Fatal("empty canceled source metadata capture succeeded", err)
	}
	missing := context.WithValue(t.Context(), reportContextCaptureKey{}, sink)
	if err := captureReportContextRequirements(missing, &auth.Principal{TenantID: "red"}, nil, nil, nil, nil); err == nil || sink.captured {
		t.Fatal("unbound source metadata capture succeeded")
	}
}
