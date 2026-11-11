// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rpkiSourceForTest(t testing.TB, raw string, now time.Time) (*RPKIVRPs, error) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "validator.json")
	if err := os.WriteFile(file, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadRPKIVRPs(t.Context(), file, time.Hour, 2<<30, 8<<30, now)
}

func TestRPKICompleteValidatorSourceKeepsFullFamiliesASNsAndOriginalFreshness(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	raw := fmt.Sprintf(`{"metadata":{"generated":%d,"generatedTime":%q},"roas":[{"prefix":"192.0.2.1/24","asn":"AS4294967295","maxLength":25},{"prefix":"192.0.2.0/24","asn":0,"maxLength":32},{"prefix":"2001:db8::/32","asn":64496,"maxLength":128}]}`, now.Unix(), now.Format(time.RFC3339))
	loaded, err := rpkiSourceForTest(t, raw, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := loaded.snapshotAt(now)
	if !snapshot.Current || snapshot.Records != 3 || !snapshot.ObservedAt.Equal(now) || !snapshot.ValidUntil.Equal(now.Add(time.Hour)) || len(snapshot.Version) != 64 {
		t.Fatal("RPKI source lost complete population or original generation", snapshot)
	}
	for _, tc := range []struct {
		prefix string
		asn    uint32
		status string
		count  int
	}{
		{"192.0.2.0/24", ^uint32(0), "valid", 2}, {"192.0.2.0/26", ^uint32(0), "invalid", 2}, {"192.0.2.0/24", 64496, "invalid", 2},
		{"2001:db8::/64", 64496, "valid", 1}, {"203.0.113.0/24", 64496, "not_found", 0},
	} {
		verdict, proof, err := snapshot.Validate(t.Context(), netip.MustParsePrefix(tc.prefix), &tc.asn, 128<<20, 128<<20)
		if err != nil || verdict != tc.status || len(proof) != tc.count {
			t.Fatal("RPKI classification lost complete independent VRP evidence", tc, verdict, proof, err)
		}
	}
	if verdict, _, err := snapshot.Validate(t.Context(), netip.MustParsePrefix("192.0.2.0/24"), nil, 1<<20, 1<<20); err != nil || verdict != "unknown" {
		t.Fatal("ambiguous origin became a validation verdict", verdict, err)
	}
	stale, err := rpkiSourceForTest(t, raw, now.Add(2*time.Hour))
	if err != nil || stale.snapshotAt(now.Add(2*time.Hour)).Current || !stale.snapshot.ObservedAt.Equal(now) {
		t.Fatal("copying stale validator bytes renewed their generation", err)
	}
	array, err := rpkiSourceForTest(t, `[{"prefix":"0.0.0.0/0","asn":0,"maxLength":32}]`, now)
	if err != nil || array.snapshot.Records != 1 || array.snapshotAt(now).Current {
		t.Fatal("generation-free export invented freshness or lost AS0 denial", err)
	}
	if verdict, _, err := array.snapshotAt(now).Validate(t.Context(), netip.MustParsePrefix("192.0.2.0/24"), new(uint32), 1<<20, 1<<20); err != nil || verdict != "unknown" {
		t.Fatal("unknown source became an empty authoritative set", verdict, err)
	}
}

func TestRPKICompleteValidatorSourceRefusesMalformedLateOrUnadmittedData(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid := fmt.Sprintf(`{"metadata":{"generated":%d},"roas":[{"prefix":"192.0.2.0/24","asn":64496,"maxLength":24}]}`, now.Unix())
	for _, raw := range []string{
		valid[:len(valid)-1], valid + ` null`, valid + string([]byte{255}), strings.Replace(valid, `"asn":64496`, `"asn":64496,"asn":65000`, 1),
		strings.Replace(valid, `"maxLength":24`, `"maxLength":23`, 1), strings.Replace(valid, `"asn":64496`, `"asn":4294967296`, 1),
		strings.Replace(valid, `"asn":64496`, `"asn":true`, 1), strings.Replace(valid, `"asn":64496`, `"asn":1.5`, 1),
		valid[:len(valid)-1] + `,"roas":[]}`, strings.Replace(valid, `"maxLength":24`, `"maxLength":null`, 1),
		strings.Replace(valid, `"roas":[`, `"roas":[null,`, 1), valid[:len(valid)-1] + `,"tail":{"x":1,"x":2}}`,
	} {
		if source, err := rpkiSourceForTest(t, raw, now); err == nil || source != nil {
			t.Fatal("partial or malformed validator export became authoritative", raw, err)
		}
	}
	file := filepath.Join(t.TempDir(), "validator.json")
	if err := os.WriteFile(file, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, limits := range [][2]int64{{1, 1 << 30}, {1 << 30, 1}} {
		if source, err := LoadRPKIVRPs(t.Context(), file, time.Hour, limits[0], limits[1], now); err == nil || source != nil {
			t.Fatal("unadmitted validator source returned partial authoritative data", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if source, err := LoadRPKIVRPs(ctx, file, time.Hour, 1<<30, 1<<30, now); err == nil || source != nil {
		t.Fatal("canceled RPKI load published data", err)
	}
}

func TestRPKIValidatorSourceKeepsCompleteIntendedPopulationBeyondMonitoringPrefixes(t *testing.T) {
	const count = 600001
	now := time.Now().UTC().Truncate(time.Second)
	var raw strings.Builder
	fmt.Fprintf(&raw, `{"metadata":{"generated":%d},"roas":[`, now.Unix())
	for i := range count {
		if i != 0 {
			raw.WriteByte(',')
		}
		asn := uint32(i + 1)
		if i == count-1 {
			asn = ^uint32(0)
		}
		address := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		fmt.Fprintf(&raw, `{"prefix":%q,"asn":%d,"maxLength":32}`, address.String()+"/32", asn)
	}
	raw.WriteString(`]}`)
	loaded, err := rpkiSourceForTest(t, raw.String(), now)
	if err != nil || loaded.snapshot.Records != count {
		t.Fatal("complete validator population was filtered or capped", err)
	}
	last := netip.AddrFrom4([4]byte{10, byte((count - 1) >> 16), byte(((count - 1) >> 8) & 255), byte((count - 1) & 255)})
	origin := ^uint32(0)
	verdict, proof, err := loaded.snapshotAt(now).Validate(t.Context(), netip.PrefixFrom(last, 32), &origin, 1<<20, 1<<20)
	if err != nil || verdict != "valid" || len(proof) != 1 || proof[0].ASN != origin {
		t.Fatal("later unmonitored full-ASN validator entry was lost", verdict, proof, err)
	}
}

func TestRPKISnapshotKeepsLargeMetadataAndOriginalSubsecondGeneration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload := map[string]any{"metadata": map[string]any{"generated": now.Unix(), "generatedTime": now.Add(123456789 * time.Nanosecond).Format(time.RFC3339Nano), "note": strings.Repeat("界", 2<<20)}, "roas": []any{map[string]any{"prefix": "::/0", "asn": "AS0", "maxLength": 128}}}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := rpkiSourceForTest(t, string(raw), now.Add(time.Second))
	if err != nil || loaded.snapshot.ObservedAt.UnixNano() != now.Add(123456789*time.Nanosecond).UnixNano() || loaded.snapshot.Records != 1 {
		t.Fatal("RPKI source narrowed complete metadata or original nanoseconds", err)
	}
}

func TestRPKISnapshotRefusesDisabledAmbiguousAndExpiredSourcesBeyondIPCache(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	raw := fmt.Sprintf(`{"metadata":{"generated":%d},"roas":[{"prefix":"0.0.0.0/0","asn":64496,"maxLength":32}]}`, now.Unix())
	loaded, err := rpkiSourceForTest(t, raw, now)
	if err != nil {
		t.Fatal(err)
	}
	en := NewEnricher(nil)
	en.Register(loaded)
	if _, err := en.Enrich(t.Context(), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	origin := uint32(64496)
	current := en.RPKI(now)
	for _, limit := range [][2]int64{{1, 1 << 20}, {1 << 20, 1}} {
		if verdict, proof, err := current.Validate(t.Context(), netip.MustParsePrefix("192.0.2.0/24"), &origin, limit[0], limit[1]); err == nil || verdict != "unknown" || proof != nil {
			t.Fatal("unadmitted validation published partial source evidence", verdict, proof, err)
		}
	}
	en.setEnabled(loaded.Descriptor().Name, false)
	disabled := en.RPKI(now)
	if disabled.Enabled || disabled.Current || sameRPKITestGeneration(current, disabled) {
		t.Fatal("disabled RPKI source survived address cache", disabled)
	}
	en.setEnabled(loaded.Descriptor().Name, true)
	stale := en.RPKI(now.Add(2 * time.Hour))
	if stale.Current || sameRPKITestGeneration(current, stale) {
		t.Fatal("expired validator source survived snapshot identity", stale)
	}
	en.Register(loaded)
	ambiguous := en.RPKI(now)
	if ambiguous.Current || ambiguous.Enabled || ambiguous.Version != "ambiguous" {
		t.Fatal("duplicate validator source silently won precedence", ambiguous)
	}
	for _, snapshot := range []RPKISnapshot{disabled, stale, ambiguous, {Version: current.Version, Enabled: true, Current: true}} {
		if verdict, proof, err := snapshot.Validate(t.Context(), netip.MustParsePrefix("192.0.2.0/24"), &origin, 1<<20, 1<<20); err != nil || verdict != "unknown" || proof != nil {
			t.Fatal("unavailable or incomplete validator became authoritative", verdict, proof, err)
		}
	}
}

// Generation equality is a test oracle; shipping capture validation uses the
// original source's UsableAt and complete retained proof, not this convenience.
func sameRPKITestGeneration(s, other RPKISnapshot) bool {
	return s.Version == other.Version && s.ObservedAt.Equal(other.ObservedAt) && s.ValidUntil.Equal(other.ValidUntil) && s.Enabled == other.Enabled && s.Current == other.Current && s.Records == other.Records && s.complete == other.complete
}
