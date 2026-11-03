// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http/httptest"
	"testing"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestTagQueryThrottlesRetainRetryHintAndNativeMCPBudgetWiring(t *testing.T) {
	for _, cause := range []error{fairness.ErrQueryConcurrency, fairness.ErrQueryBudget} {
		err := tagQueryAdmissionError(cause)
		rec := httptest.NewRecorder()
		if tagQueryResponseError(rec, err) != err || rec.Header().Get("Retry-After") != "1" {
			t.Fatal("rate refusal lost its retry hint or domain error")
		}
	}
	budget := flowstore.DefaultExplorerBudget()
	budget.ResponseBytes = 1
	if domain, ok := apierror.As(netBoxImportResponseBudget(map[string]string{"value": "too large"}, budget)); !ok || domain.Kind != apierror.KindValidation {
		t.Fatal("bounded preview did not report a validation refusal")
	}
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	native, other := flowstore.NewMemory(), flowstore.NewMemory()
	backend := tagReadBackend(nil, nil, AISources{NativeFlow: &Server{flowStore: native}, Flow: other}, gate)
	if backend.flowStore != native || backend.fairnessGate != gate {
		t.Fatal("native NetBox/tag MCP reads lost the configured operation budgets")
	}
}
