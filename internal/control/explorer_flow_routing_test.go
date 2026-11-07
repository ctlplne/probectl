// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFlowRoutingSnapshotRequiresCurrentTenantUserBeforeReferenceReads(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	server := &Server{}
	reads := 0
	selector := func(context.Context) ([]flowstore.RoutingCaptureRead, error) {
		reads++
		return nil, nil
	}
	for _, actor := range []*auth.Principal{nil, {TenantID: tenant}, {TenantID: tenant, UserID: "owner"}} {
		for _, ctx := range []context.Context{t.Context(), tenancy.WithTenant(t.Context(), tenancy.ID("22222222-2222-4222-8222-222222222222"))} {
			if result, err := server.loadFlowRoutingSnapshotFrom(ctx, actor, flowstore.DefaultExplorerBudget(), selector); err == nil || result.data != nil || reads != 0 {
				t.Fatal("routing source reads preceded current tenant user authority", err, reads)
			}
		}
	}
	actor := &auth.Principal{TenantID: tenant, UserID: "owner"}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	if result, err := server.loadFlowRoutingSnapshotFrom(ctx, actor, flowstore.DefaultExplorerBudget(), selector); err == nil || result.data != nil || reads != 0 {
		t.Fatal("routing query invented a current metadata store", err, reads)
	}
	foreignUser := auth.WithPrincipal(ctx, &auth.Principal{TenantID: tenant, UserID: "another-owner"})
	if result, err := server.loadFlowRoutingSnapshotFrom(foreignUser, actor, flowstore.DefaultExplorerBudget(), selector); err == nil || result.data != nil || reads != 0 {
		t.Fatal("routing query replaced the actual credential user", err, reads)
	}
	var public *apierror.Error
	if err := flowRoutingQueryError(errors.New("private routing SQL detail")); !errors.As(err, &public) || public.Code != string(apierror.CodeUnavailable) || strings.Contains(public.Message, "private") {
		t.Fatal("routing query disclosed private storage failure", err)
	}
	if err := flowRoutingQueryError(store.ErrBGPRoutingBudget); !errors.As(err, &public) || public.Code != string(apierror.CodeFlowQueryBudget) {
		t.Fatal("routing query lost observable resource admission", err)
	}
	denied := apierror.Forbidden("current routing source denied")
	if flowRoutingQueryError(denied) != denied {
		t.Fatal("routing query changed an actual authorization denial")
	}
}
