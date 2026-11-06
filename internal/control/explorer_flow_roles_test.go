// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFlowRoleSnapshotRequiresCurrentTenantUserBeforeStorage(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	s := &Server{}
	for _, actor := range []*auth.Principal{nil, {TenantID: tenant}, {TenantID: tenant, UserID: "u"}} {
		if out, err := s.loadFlowRoleSnapshot(t.Context(), actor, flowstore.DefaultExplorerBudget()); err == nil || out.data != nil {
			t.Fatal("unbound role query reached source storage", out, err)
		}
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	if out, err := s.loadFlowRoleSnapshot(ctx, &auth.Principal{TenantID: tenant, UserID: "u"}, flowstore.DefaultExplorerBudget()); err == nil || out.data != nil {
		t.Fatal("role query invented a metadata store", out, err)
	}
	actor := &auth.Principal{TenantID: tenant, UserID: "u"}
	bound, err := bindFlowRoleContext(t.Context(), actor)
	if err != nil {
		t.Fatal("authenticated role service could not establish its tenant scope", err)
	}
	if id, present := tenancy.FromContext(bound); !present || id.String() != tenant || auth.PrincipalFrom(bound).UserID != "u" {
		t.Fatal("authenticated role service lost its actual credential scope")
	}
	foreign := tenancy.WithTenant(t.Context(), tenancy.ID("33333333-3333-4333-8333-333333333333"))
	if _, err := bindFlowRoleContext(foreign, actor); err == nil {
		t.Fatal("role service overwrote an existing foreign tenant scope")
	}
}

func TestRoleSnapshotReceiptRefusesMissingOrForeignAuthority(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	source := &flowSnapshotSource{server: &Server{}, now: time.Now}
	scope := flowsnapshot.Scope{TenantID: tenant, Owner: "owner"}
	roleInput := flowstore.SnapshotInputs{Fields: []string{"in_if_role"}}
	for _, proof := range []flowSnapshotValidity{
		{Inputs: []flowstore.SnapshotInputs{roleInput}},
		{Inputs: []flowstore.SnapshotInputs{{Fields: []string{"protocol"}}}, RoleDigest: strings.Repeat("a", 64)},
		{Inputs: []flowstore.SnapshotInputs{roleInput}, RoleDigest: strings.Repeat("a", 64)},
	} {
		if err := source.validateRoleAuthorization(t.Context(), scope, proof); err == nil {
			t.Fatal("frozen role result invented current authority", proof)
		}
	}
	if err := source.validateRoleAuthorization(t.Context(), scope, flowSnapshotValidity{Inputs: []flowstore.SnapshotInputs{{Fields: []string{"protocol"}}}}); err != nil {
		t.Fatal("ordinary result acquired an unrelated role prerequisite", err)
	}
}

func TestReportRoleContextCapturePreservesTagsAndCurrentSourceRequirements(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	record := entity.ContextRecord{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222", SiteLabel: "owned", VRFLabel: "private"}
	principal := &auth.Principal{TenantID: tenant, UserID: "owner"}
	sink := &reportContextCapture{tenant: tenant, remaining: 1 << 20, captured: true,
		contexts: []reportContextRequirement{{record.ContextID, entityContextResource(record), []string{"agent.read", "flow.read", "tags.read"}}}}
	ctx := context.WithValue(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), reportContextCaptureKey{}, sink)
	allowed := map[string]bool{record.ContextID: true}
	if err := captureReportRoleContextRequirements(ctx, principal, []entity.ContextRecord{record}, allowed); err != nil {
		t.Fatal(err)
	}
	want := []string{"agent.read", "entities.read", "events.read", "flow.read", "metrics.read", "tags.read"}
	if len(sink.contexts) != 1 || !slices.Equal(sink.contexts[0].Permissions, want) {
		t.Fatal("role capture dropped another metadata source requirement", sink.contexts)
	}
	remaining := sink.remaining
	if err := captureReportRoleContextRequirements(ctx, principal, []entity.ContextRecord{record}, allowed); err != nil || sink.remaining != remaining || len(sink.contexts) != 1 {
		t.Fatal("authority revalidation duplicated retained metadata or charged it again", sink, err)
	}
	changed := record
	changed.SiteLabel = "rebound"
	if err := captureReportRoleContextRequirements(ctx, principal, []entity.ContextRecord{changed}, allowed); err == nil {
		t.Fatal("report role capture accepted a context change")
	}
	foreign := record
	foreign.TenantID = "33333333-3333-4333-8333-333333333333"
	if err := captureReportRoleContextRequirements(ctx, principal, []entity.ContextRecord{foreign}, allowed); err == nil {
		t.Fatal("report role capture accepted foreign tenant metadata")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := captureReportRoleContextRequirements(cancelled, principal, []entity.ContextRecord{record}, allowed); !errors.Is(err, context.Canceled) {
		t.Fatal("report role capture ignored cancellation", err)
	}
}
