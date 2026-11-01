// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPRTGTreePagesPreserveParentIDsWithoutGuessingSite(t *testing.T) {
	devices := `[
		{"id":"101","parentid":"20","name":"Edge R1","basic":{"host":"10.0.0.1","credentials":"secret-prtg-123"}},
		{"id":"102","parentid":"20","name":"Probe host","basic":{"host":"edge.example.invalid"}}
	]`
	got, err := parsePRTGDevices(strings.NewReader(devices))
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != PRTG || len(got.Rows) != 2 || got.Rows[0].ExternalID != "101" ||
		got.Rows[0].ParentID != "20" || got.Rows[0].Address != "10.0.0.1" ||
		got.Rows[1].Hostname != "edge.example.invalid" ||
		!contains(got.Rows[0].UnmappedCodes, "parent_unresolved") ||
		!contains(got.Rows[1].UnmappedCodes, "dns_host_unmapped") ||
		!contains(got.Rows[0].UnmappedCodes, "site_unmapped") {
		t.Fatalf("PRTG page lost source identity or guessed a mapping: %+v", got.Rows)
	}
	groups, err := parsePRTGGroups(strings.NewReader(`[{"id":"20","parentid":"3","name":"WAN","basic":{"password":"secret-prtg-456"}}]`))
	if err != nil || len(groups.Rows) != 1 || groups.Rows[0].ExternalID != "20" ||
		groups.Rows[0].ParentID != "3" || groups.Rows[0].Kind != "group" {
		t.Fatalf("PRTG group ancestry missing: %+v, %v", groups, err)
	}
	probes, err := parsePRTGProbes(strings.NewReader(`[{"id":"3","parentid":"0","name":"East probe"}]`))
	if err != nil || len(probes.Rows) != 1 || probes.Rows[0].ExternalID != "3" ||
		probes.Rows[0].Kind != "probe" {
		t.Fatalf("PRTG probe root missing: %+v, %v", probes, err)
	}
	for _, snapshot := range []Snapshot{got, groups, probes} {
		wire, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"secret-prtg-123", "secret-prtg-456"} {
			if strings.Contains(string(wire), secret) {
				t.Fatalf("PRTG credential %q escaped into preview", secret)
			}
		}
	}
}

func TestPRTGTreePagesRejectAmbiguousIDsAndHostURLs(t *testing.T) {
	for _, raw := range []string{
		`[{"id":101},{"id":"0101"}]`,
		`[{"id":0,"name":"root"}]`,
		`{"items":[{"id":"101"}]}`,
	} {
		_, err := parsePRTGDevices(strings.NewReader(raw))
		if !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("invalid PRTG page accepted: %v", err)
		}
	}
	got, err := parsePRTGDevices(strings.NewReader(`[{"id":"103","parentid":"20","name":"bad host","basic":{"host":"https://secret.invalid/?token=abc"}}]`))
	if err != nil || len(got.Rows) != 1 || got.Rows[0].Hostname != "" ||
		!contains(got.Rows[0].UnmappedCodes, "host_unmapped") {
		t.Fatalf("PRTG host URL accepted: %+v, %v", got, err)
	}
}
