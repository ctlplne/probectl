// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tsdb

import (
	"context"
	"errors"
	"testing"
)

func TestTenantSnapshotScopesBeforeCopyAndRefusesPartialJoin(t *testing.T) {
	memory := NewMemory()
	rows := []Series{
		{Metric: "probectl_device_if_in_octets", Labels: map[string]string{TenantLabel: "red", "if_name": "inside"}, TimeMillis: 1},
		{Metric: "probectl_device_if_out_octets", Labels: map[string]string{TenantLabel: "red", "if_name": "outside"}, TimeMillis: 1},
		{Metric: "probectl_device_if_in_octets", Labels: map[string]string{TenantLabel: "blue", "if_name": "secret-blue"}, TimeMillis: 1},
	}
	if err := memory.Write(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	got, err := memory.TenantSnapshot(t.Context(), "red", "probectl_device_", 2)
	if err != nil || len(got) != 2 {
		t.Fatalf("tenant read=%+v %v", got, err)
	}
	for _, row := range got {
		if row.Labels[TenantLabel] != "red" {
			t.Fatalf("foreign sample copied: %+v", row)
		}
	}
	got[0].Labels["if_name"] = "mutated"
	again, err := memory.TenantSnapshot(t.Context(), "red", "probectl_device_", 2)
	if err != nil || again[0].Labels["if_name"] != "inside" {
		t.Fatalf("snapshot mutated stored labels: %+v %v", again, err)
	}
	if partial, err := memory.TenantSnapshot(t.Context(), "red", "probectl_device_", 1); err == nil || partial != nil {
		t.Fatalf("incomplete metadata join returned: %+v %v", partial, err)
	}
	if _, err := memory.TenantSnapshot(t.Context(), "", "probectl_device_", 2); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("empty tenant did not fail closed: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := memory.TenantSnapshot(ctx, "red", "probectl_device_", 2); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled join read continued: %v", err)
	}
}
