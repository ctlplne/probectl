// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ixPrefixFile(t *testing.T, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ixpfx.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
func ixPrefixFixture(at time.Time) ixPrefixManifest {
	return ixPrefixManifest{Version: 1, Object: "ixpfx", ObservedAt: at, Complete: true, RecordCount: 2,
		Data: []ixPrefixRecord{{ID: 7, LANID: 11, Protocol: "IPv4", Prefix: "198.51.100.0/24", Status: "ok"}, {ID: 8, LANID: 12, Protocol: "IPv6", Prefix: "2001:db8::/64", Status: "ok"}}}
}

// Synthetic dataset; this does not claim a permitted PeeringDB download.
func TestPeeringDBIXPrefixesKeepCompletePopulationClockAndOwnedMatches(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	manifest := ixPrefixFixture(at)
	for i := range 20000 {
		manifest.Data = append(manifest.Data, ixPrefixRecord{ID: int64(i) + 100, LANID: int64(i) + 100, Protocol: "IPv6", Prefix: fmt.Sprintf("2001:db8:%x::/64", i+1), Status: "ok"})
	}
	manifest.RecordCount = int64(len(manifest.Data))
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= 1<<20 {
		t.Fatal("complete IX prefix workload lost its original population")
	}
	path := ixPrefixFile(t, body)
	source, err := LoadPeeringDBIXPrefixes(t.Context(), path, time.Hour, 128<<20, time.Now())
	if err != nil {
		t.Fatal("complete IX prefix cache was refused", err)
	}
	en := NewEnricher(nil)
	en.Register(source)
	before := en.IXPrefixes(time.Now())
	if len(before.entries) != 20002 || !before.Current || !before.ObservedAt.Equal(at) || !before.ValidUntil.Equal(at.Add(time.Hour)) {
		t.Fatal("partial IX prefix cache or renewed source clock", before)
	}
	addresses := []netip.Addr{netip.MustParseAddr("198.51.100.4"), netip.MustParseAddr("2001:db8::4"), netip.MustParseAddr("2001:db8:4e20::1")}
	matches, err := before.Match(t.Context(), addresses, 1<<20, 100000)
	if err != nil || len(matches) != 3 || !strings.Contains(matches[2].SourceID, "/snapshot/"+before.Version) {
		t.Fatal("complete IX v4/v6 source tail or version lost", matches, err)
	}
	matches[0].SourceID = "changed-by-caller"
	again, err := before.Match(t.Context(), addresses, 1<<20, 100000)
	if err != nil || again[0].SourceID == "changed-by-caller" {
		t.Fatal("IX cache borrowed mutable output", err)
	}
	// Changing the file never silently refreshes an already admitted generation.
	if err := os.WriteFile(path, []byte(`{"complete":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !before.SameGeneration(en.IXPrefixes(time.Now())) {
		t.Fatal("local file write silently changed an admitted generation")
	}
	expired := en.IXPrefixes(at.Add(time.Hour))
	expiredMatches, err := expired.Match(t.Context(), addresses, 1<<20, 100000)
	if err != nil || expired.Current || len(expiredMatches) != 0 || expired.SameGeneration(before) {
		t.Fatal("stale IX cache retained current evidence", expiredMatches, err)
	}
	en.setEnabled(source.Descriptor().Name, false)
	if en.IXPrefixes(time.Now()).Current {
		t.Fatal("disabled IX cache retained current evidence")
	}
	if _, err := before.Match(t.Context(), addresses, 1, 100000); !errors.Is(err, ErrIXPrefixBudget) {
		t.Fatal("IX matches escaped complete memory admission", err)
	}
	if _, err := before.Match(t.Context(), addresses, 1<<20, 1); !errors.Is(err, ErrIXPrefixBudget) {
		t.Fatal("IX matches escaped complete work admission", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := before.Match(canceled, addresses, 1<<20, 100000); !errors.Is(err, context.Canceled) {
		t.Fatal("IX match ignored cancellation", err)
	}
}

func TestPeeringDBIXPrefixesRefusePartialAmbiguousOrMalformedSnapshot(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	for _, name := range []string{"partial", "count", "missing-data", "future", "protocol", "host-prefix", "duplicate-id", "duplicate-prefix", "unknown-status", "missing-lan", "object-clock", "unknown-field", "duplicate-field", "case-field", "missing-count", "null-count", "duplicate-row-field", "trailing", "budget", "cancel"} {
		t.Run(name, func(t *testing.T) {
			manifest := ixPrefixFixture(at)
			switch name {
			case "partial":
				manifest.Complete = false
			case "count":
				manifest.RecordCount++
			case "missing-data":
				manifest.Data = nil
				manifest.RecordCount = 0
			case "future":
				manifest.ObservedAt = time.Now().Add(time.Hour)
			case "protocol":
				manifest.Data[0].Protocol = "IPv6"
			case "host-prefix":
				manifest.Data[0].Prefix = "198.51.100.1/24"
			case "duplicate-id":
				manifest.Data[1].ID = manifest.Data[0].ID
			case "duplicate-prefix":
				manifest.Data[1].Prefix = manifest.Data[0].Prefix
				manifest.Data[1].Protocol = "IPv4"
			case "unknown-status":
				manifest.Data[1].Status = "unknown"
			case "missing-lan":
				manifest.Data[1].LANID = 0
			case "object-clock":
				clock := at.Add(time.Hour)
				manifest.Data[1].Updated = &clock
			}
			body, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "unknown-field":
				body = []byte(strings.Replace(string(body), `"object":`, `"extra":true,"object":`, 1))
			case "duplicate-field":
				body = []byte(strings.Replace(string(body), `"complete":true`, `"complete":false,"complete":true`, 1))
			case "case-field":
				body = []byte(strings.Replace(string(body), `"complete":true`, `"complete":false,"Complete":true`, 1))
			case "missing-count":
				body = []byte(strings.Replace(string(body), `"record_count":2,`, ``, 1))
			case "null-count":
				body = []byte(strings.Replace(string(body), `"record_count":2`, `"record_count":null`, 1))
			case "duplicate-row-field":
				body = []byte(strings.Replace(string(body), `"status":"ok"`, `"status":"deleted","status":"ok"`, 1))
			case "trailing":
				body = append(body, []byte(` {}`)...)
			}
			ctx, memory := t.Context(), int64(1<<20)
			if name == "budget" {
				memory = 4096
			}
			if name == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, err := LoadPeeringDBIXPrefixes(ctx, ixPrefixFile(t, body), time.Hour, memory, time.Now())
			if err == nil || got != nil {
				t.Fatal("partial IX snapshot was published", got, err)
			}
		})
	}
}

func TestPeeringDBIXPrefixesKeepInactiveAndExpiredSourcesVisibleWithoutMemberships(t *testing.T) {
	at := time.Now().UTC().Add(-2 * time.Hour)
	manifest := ixPrefixFixture(at)
	manifest.Data[1].Status = "deleted"
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	source, err := LoadPeeringDBIXPrefixes(t.Context(), ixPrefixFile(t, body), time.Hour, 1<<20, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	en := NewEnricher(nil)
	en.Register(source)
	status := en.Status()
	if len(status) != 1 || status[0].Health.Status != "unavailable" || status[0].Health.LastError == "" || status[0].Descriptor.AUP.CommercialUse != CommercialRestricted {
		t.Fatal("expired IX source or restricted provenance was hidden", status)
	}
	if snapshot := en.IXPrefixes(at.Add(time.Minute)); len(snapshot.entries) != 1 || !snapshot.Current {
		t.Fatal("deleted prefix contributed to IX evidence", snapshot)
	}
	enriched, err := en.Enrich(t.Context(), "198.51.100.1")
	if err != nil || len(enriched.IXPs) != 0 {
		t.Fatal("IX prefix invented an ASN membership", enriched, err)
	}
	// A complete empty dataset explicitly withdraws every prefix.
	manifest.ObservedAt = time.Now().UTC().Add(-time.Minute)
	manifest.Data = []ixPrefixRecord{}
	manifest.RecordCount = 0
	body, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	clear, err := LoadPeeringDBIXPrefixes(t.Context(), ixPrefixFile(t, body), time.Hour, 1<<20, time.Now())
	if err != nil || len(clear.snapshot.entries) != 0 || clear.snapshot.Version == source.snapshot.Version {
		t.Fatal("complete IX clear was not a distinct generation", err)
	}
}
