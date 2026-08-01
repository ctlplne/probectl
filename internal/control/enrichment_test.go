// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/opendata"
)

// rirFixture is a minimal RIR delegated-extended stats file covering
// 192.0.2.0/24 (TEST-NET-1) and 2001:db8::/32.
const rirFixture = `arin|US|ipv4|192.0.2.0|256|20100714|assigned|opaque
ripencc|NL|ipv6|2001:db8::|32|20080512|allocated|opaque
`

func writeRIRDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "delegated-test-extended-latest"), []byte(rirFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBuildEnrichmentNothingConfigured(t *testing.T) {
	en, ok := BuildEnrichment(&config.Config{}, statusQuietLog())
	if ok || en != nil {
		t.Fatalf("BuildEnrichment with no sources = (%v, %v), want (nil, false)", en, ok)
	}
}

func TestBuildEnrichmentRegistersConfiguredSources(t *testing.T) {
	cfg := &config.Config{
		FlowEnrichASN:      true,
		FlowEnrichIXP:      true,
		FlowEnrichRIRDir:   writeRIRDir(t),
		FlowEnrichCacheMax: 16,
	}
	en, ok := BuildEnrichment(cfg, statusQuietLog())
	if !ok {
		t.Fatal("BuildEnrichment = false with three sources configured")
	}
	var names []string
	for _, st := range en.Status() {
		names = append(names, st.Descriptor.Name)
		if !st.Health.Enabled || st.Health.Status != "ok" {
			t.Fatalf("source %s registered %+v, want enabled/ok", st.Descriptor.Name, st.Health)
		}
	}
	// Registration order is precedence: local files, then Cymru, then the
	// ASN-keyed PeeringDB source last.
	want := []string{"rir-stats", "team-cymru", "peeringdb"}
	if len(names) != len(want) {
		t.Fatalf("registered sources = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("registered sources = %v, want %v", names, want)
		}
	}
	// The loaded RIR index actually serves: TEST-NET-1 resolves.
	e, err := en.Enrich(context.Background(), "192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	if e.RIR != "arin" || e.AllocationStatus != "assigned" || e.CountryCode != "US" {
		t.Fatalf("rir enrichment = %+v", e)
	}
}

func TestBuildEnrichmentAbsentDataDegradesHonestly(t *testing.T) {
	cfg := &config.Config{
		FlowEnrichGeoDB:    filepath.Join(t.TempDir(), "missing.mmdb"),
		FlowEnrichRIRDir:   t.TempDir(), // exists but holds no stats files
		FlowEnrichCacheMax: 16,
	}
	en, ok := BuildEnrichment(cfg, statusQuietLog())
	if !ok {
		t.Fatal("BuildEnrichment = false; configured-but-broken sources must still register for visibility")
	}
	sts := en.Status()
	if len(sts) != 2 {
		t.Fatalf("Status() = %+v, want geo + rir entries", sts)
	}
	for _, st := range sts {
		if st.Health.Enabled || st.Health.Status != "unavailable" || st.Health.LastError == "" {
			t.Fatalf("source %s health = %+v, want disabled/unavailable with the load error", st.Descriptor.Name, st.Health)
		}
	}
	// Enrichment still serves (degraded to empty), never errors on a valid IP.
	if _, err := en.Enrich(context.Background(), "192.0.2.7"); err != nil {
		t.Fatalf("degraded enrichment errored: %v", err)
	}
}

// fullContextSource fills every advertised enrichment field so the route test
// proves the whole breadth is served, not just ASN + country.
type fullContextSource struct{}

func (fullContextSource) Descriptor() opendata.Descriptor {
	return opendata.Descriptor{
		Name:    "test-full",
		Kind:    opendata.KindGeo,
		Cadence: time.Hour,
		AUP:     opendata.AUP{License: "test", Attribution: "Test Data"},
	}
}

func (fullContextSource) Enrich(_ context.Context, _ netip.Addr, e *opendata.Enrichment) error {
	e.ASN = 64500
	e.ASName = "EXAMPLE-NET"
	e.Prefix = "192.0.2.0/24"
	e.CountryCode = "US"
	e.City = "Example City"
	e.Latitude = 37.75
	e.Longitude = -97.82
	e.RIR = "arin"
	e.AllocationStatus = "assigned"
	e.AllocationDate = "20100714"
	e.IXPs = []opendata.IXP{{Name: "Example-IX", IXID: 42, SpeedM: 10000}}
	return nil
}

func TestOpenDataEnrichmentRoute(t *testing.T) {
	en := opendata.NewEnricher(statusQuietLog())
	en.Register(fullContextSource{})
	srv := testServer(fakePinger{}).WithOpenDataStatus(en, nil, nil)

	rec := do(srv, http.MethodGet, "/v1/opendata/enrichment?ip=192.0.2.7")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var e opendata.Enrichment
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.IP != "192.0.2.7" || e.ASN != 64500 || e.ASName != "EXAMPLE-NET" ||
		e.CountryCode != "US" || e.City != "Example City" ||
		e.Latitude == 0 || e.Longitude == 0 ||
		e.RIR != "arin" || e.AllocationStatus != "assigned" || e.AllocationDate != "20100714" ||
		len(e.IXPs) != 1 || e.IXPs[0].Name != "Example-IX" {
		t.Fatalf("served enrichment lost fields: %+v", e)
	}

	if rec := do(srv, http.MethodGet, "/v1/opendata/enrichment?ip=not-an-ip"); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid ip status = %d, want 400", rec.Code)
	}
	if rec := do(srv, http.MethodGet, "/v1/opendata/enrichment"); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing ip status = %d, want 400", rec.Code)
	}
	if rec := do(testServer(fakePinger{}), http.MethodGet, "/v1/opendata/enrichment?ip=192.0.2.7"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured enrichment status = %d, want 503", rec.Code)
	}
}
