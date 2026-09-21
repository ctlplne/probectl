// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/bus"
	bgpv1 "github.com/ctlplne/probectl/internal/gen/probectl/bgp/v1"
)

func TestBindBGPEventAuthenticatedTenantAcceptsBucketedKeys(t *testing.T) {
	for _, tc := range []struct {
		name       string
		laneTenant string
	}{
		{name: "pooled"},
		{name: "silo lane", laneTenant: "tenant-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := &bgpv1.BGPEvent{TenantId: "tenant-a"}
			got, err := bindBGPEventAuthenticatedTenant(ev, bus.Message{
				Key: bus.TenantKey("tenant-a", "rrc00"),
			}, tc.laneTenant)
			if err != nil || got != "tenant-a" || ev.GetTenantId() != "tenant-a" {
				t.Fatalf("binding = %q event=%q error=%v", got, ev.GetTenantId(), err)
			}
		})
	}
}

func TestBindBGPEventAuthenticatedTenantRejectsBucketedCrossTenantPayload(t *testing.T) {
	ev := &bgpv1.BGPEvent{TenantId: "tenant-b"}
	_, err := bindBGPEventAuthenticatedTenant(ev, bus.Message{
		Key: bus.TenantKey("tenant-a", "rrc00"),
	}, "")
	if !errors.Is(err, errBGPTenantEnvelopeMismatch) {
		t.Fatalf("error = %v, want tenant envelope mismatch", err)
	}
}
