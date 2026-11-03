// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestNetBoxImportQueryBudgetUsesRateLimitedDomain(t *testing.T) {
	for _, policy := range []fairness.Policy{{QueryConcurrency: 1, QueriesPerMin: 600}, {QueryConcurrency: 2, QueriesPerMin: 1}} {
		gate := fairness.NewGate(policy, nil)
		ctx := tenancy.WithTenant(t.Context(), "00000000-0000-4000-8000-000000000001")
		_, _, release, err := beginNetBoxImport(ctx, nil, gate)
		if err != nil {
			t.Fatal(err)
		}
		if policy.QueriesPerMin == 1 {
			release()
		} else {
			defer release()
		}
		_, _, done, err := beginNetBoxImport(ctx, nil, gate)
		if err == nil || done != nil {
			if done != nil {
				done()
			}
			t.Fatal("query guard admitted a saturated tenant")
		}
		rec := httptest.NewRecorder()
		writeError(rec, httptest.NewRequest(http.MethodPost, "/v1/entity-contexts/context/tag-imports/netbox/preview", nil), err)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("query-budget refusal became HTTP%d instead of429", rec.Code)
		}
		_, _, otherDone, err := beginNetBoxImport(tenancy.WithTenant(t.Context(), "00000000-0000-4000-8000-000000000002"), nil, gate)
		if err != nil {
			t.Fatal("one tenant's query debt blocked another tenant")
		}
		otherDone()
	}
}
