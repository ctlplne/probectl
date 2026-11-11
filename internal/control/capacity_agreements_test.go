// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestCapacityAgreementAPIRejectsContradictoryTenantBeforeStorage(t *testing.T) {
	server := &Server{}
	for _, actor := range []*auth.Principal{nil, {TenantID: "red", UserID: "reader"}} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID("blue"))
		if actor != nil {
			ctx = auth.WithPrincipal(ctx, actor)
		}
		r := httptest.NewRequest("GET", "/v1/flows/capacity/agreements", nil).WithContext(ctx)
		if op, err := server.beginCapacityAgreement(r); err == nil || op.store != nil || op.request != nil {
			t.Fatal("missing or contradictory tenant actor reached financial storage", err)
		}
	}
}

func TestCapacityAgreementAPIPageAdmissionAndErrorsPreserveExactInputs(t *testing.T) {
	for _, text := range []string{"0", "-1", "1.5", "01", "9223372036854775808"} {
		r := httptest.NewRequest("GET", "/?limit="+text, nil)
		if _, err := capacityAgreementPageInput(r); err == nil {
			t.Fatal("invalid exact page count was accepted", text)
		}
	}
	r := httptest.NewRequest("GET", "/?limit=1001&after=original-cursor", nil)
	if page, err := capacityAgreementPageInput(r); err != nil || page.Limit != 1001 || page.After != "original-cursor" {
		t.Fatal("valid complete-page request was clamped or lost continuation", page, err)
	}
	for _, err := range []error{flow.ErrCapacityAgreementInvalid, flow.ErrCapacityAgreementNotFound, flow.ErrCapacityAgreementConflict, flow.ErrCapacityAgreementBudget, errors.New("private SQL, tenant and unit price")} {
		if mapped := capacityAgreementAPIError(err); mapped == nil || strings.Contains(mapped.Error(), "private") {
			t.Fatal("financial API lost domain rejection or exposed backend details", err)
		}
	}
}
