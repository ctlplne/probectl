// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type monthlyQueueProbe struct {
	calls                  int
	actor, tenant, request string
}

func (q *monthlyQueueProbe) QueueMonthlyReports(ctx context.Context, tenant, actor, request string) (reporting.MonthlyReportQueueResult, error) {
	q.calls++
	if bound, ok := tenancy.FromContext(ctx); !ok || bound.String() != tenant {
		panic("provider dispatch lost explicit tenant scope")
	}
	q.actor, q.tenant, q.request = actor, tenant, request
	return reporting.MonthlyReportQueueResult{TenantID: tenant, Eligible: 1, Queued: 1, Pending: 1}, nil
}
func (q *monthlyQueueProbe) MonthlyReportProgress(ctx context.Context, tenant, actor, request string) (reporting.MonthlyReportQueueResult, error) {
	if bound, ok := tenancy.FromContext(ctx); !ok || bound.String() != tenant {
		panic("provider dispatch lost explicit tenant scope")
	}
	q.actor, q.tenant, q.request = actor, tenant, request
	return reporting.MonthlyReportQueueResult{TenantID: tenant, Eligible: 1, Queued: 1, Delivered: 1, Replay: true}, nil
}
func TestProviderMonthlyReportsUseOperatorAuthorityAndCountsOnly(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	token := f.bootstrapAndLoginFast(t)
	probe := &monthlyQueueProbe{}
	f.h.WithMonthlyReports(probe)
	tenant := "11111111-1111-4111-8111-111111111111"
	request := "22222222-2222-4222-8222-222222222222"
	path := "/provider/v1/tenants/" + tenant + "/monthly-reports"
	if response := doReq(f.h, newReq(http.MethodPost, path, map[string]string{"request_id": request})); response.Code != http.StatusUnauthorized {
		t.Fatal("anonymous provider queue admitted", response.Code)
	}
	if response := f.doAuthed(t, "tenant-admin-A", http.MethodPost, path, map[string]string{"request_id": request}); response.Code != http.StatusUnauthorized {
		t.Fatal("tenant credential became provider authority", response.Code)
	}
	if probe.calls != 0 {
		t.Fatal("unauthorized request reached trusted queue")
	}
	response := f.doAuthed(t, token, http.MethodPost, path, map[string]string{"request_id": request})
	if response.Code != http.StatusAccepted || probe.calls != 1 || probe.actor == "" || probe.tenant != tenant || probe.request != request {
		t.Fatal("operator metadata dispatch failed", response.Code)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 7 {
		t.Fatal("provider response gained report payload fields")
	}
	response = f.doAuthed(t, token, http.MethodGet, path+"/"+request, nil)
	if response.Code != http.StatusOK || probe.calls != 1 {
		t.Fatal("progress read queued work", response.Code)
	}
	f.h.WithMonthlyReports(nil)
	if response := f.doAuthed(t, token, http.MethodPost, path, map[string]string{"request_id": request}); response.Code != http.StatusNotFound {
		t.Fatal("unattached queue exposed a capability", response.Code)
	}
}
