// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"errors"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
)

func TestMCPListTestsHonorsTenantQueryConcurrency(t *testing.T) {
	gate := fairness.NewGate(fairness.Policy{QueryConcurrency: 1}, nil)
	release, err := gate.BeginQuery(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	backend := mcpBackend{gate: gate}
	_, err = backend.ListTests(t.Context(), &auth.Principal{TenantID: "tenant-a"})
	if !errors.Is(err, fairness.ErrQueryConcurrency) {
		t.Fatalf("ListTests error = %v, want %v", err, fairness.ErrQueryConcurrency)
	}
	snapshot := gate.SnapshotTenant(t.Context(), "tenant-a")
	if snapshot.Queries.RejectedConcurrency != 1 {
		t.Fatalf("tenant query rejection accounting = %+v, want one concurrency rejection", snapshot.Queries)
	}
}
