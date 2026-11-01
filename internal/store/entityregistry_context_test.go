// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
)

func TestNamedContextIDTenantAndKindBoundary(t *testing.T) {
	first, err := namedContextID("tenant-a", "site", "West DC")
	if err != nil {
		t.Fatal(err)
	}
	again, err := namedContextID("tenant-a", "site", "West DC")
	if err != nil || again != first {
		t.Fatalf("site identity was not repeatable: %q %q %v", first, again, err)
	}
	for _, other := range []struct{ tenant, kind, label string }{
		{"tenant-b", "site", "West DC"},
		{"tenant-a", "vrf", "West DC"},
		{"tenant-a", "site", "East DC"},
	} {
		id, err := namedContextID(other.tenant, other.kind, other.label)
		if err != nil || id == first {
			t.Fatalf("tenant/kind/label identity crossed boundary: %q %v", id, err)
		}
	}
	if _, err := uuid.Parse(first); err != nil {
		t.Fatalf("named identity is not a UUID: %v", err)
	}
}

func TestValidContextLabelRefusesAmbiguousNames(t *testing.T) {
	for _, input := range []string{"", "  ", "West\nDC", strings.Repeat("x", 129)} {
		if _, err := validContextLabel(input); !errors.Is(err, entity.ErrInvalidClaim) {
			t.Fatalf("accepted invalid context label %q: %v", input, err)
		}
	}
	if got, err := validContextLabel("  West DC  "); err != nil || got != "West DC" {
		t.Fatalf("context label trim = %q, %v", got, err)
	}
}

func TestEntityContextAttributesNormalizeBeforePolicyCheck(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000101"
	got, err := EntityContextAttributes(tenant, "  West DC  ", "  Private VRF  ")
	if err != nil {
		t.Fatal(err)
	}
	if got.SiteLabel != "West DC" || got.VRFLabel != "Private VRF" ||
		got.SiteID == "" || got.VRFID == "" || got.ContextID != "" {
		t.Fatalf("policy attributes were not canonical: %+v", got)
	}
	again, err := EntityContextAttributes(tenant, "West DC", "Private VRF")
	if err != nil || got.SiteID != again.SiteID || got.VRFID != again.VRFID {
		t.Fatalf("padded labels bypassed stable policy IDs: %+v %+v %v", got, again, err)
	}
}
