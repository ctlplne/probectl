// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

const frrRPKINotFound = "2001:db8:6000::/48"

type frrRPKICase struct {
	prefix, status, reason string
	origin                 uint32
	registryStatus         string
}

type frrRPKITarget struct {
	frrRPKICase
	path string
}

type frrRPKIPosture struct {
	Prefix   string `json:"prefix"`
	Coverage string `json:"coverage"`
	Paths    []struct {
		RouterID string                `json:"router_id"`
		Vantage  string                `json:"vantage"`
		Origin   uint32                `json:"origin_asn"`
		RPKI     opendata.RPKIPosture  `json:"rpki"`
		IRR      []opendata.IRRPosture `json:"irr"`
	} `json:"paths"`
	Trend []struct {
		Vantage string `json:"vantage"`
		store.BGPRPKIHistoryObservation
	} `json:"trend"`
}

func prepareFRRRPKICases(t *testing.T, lab *routingLab, advertised6, link6 string) ([]frrRPKICase, map[string]string) {
	t.Helper()
	lab.docker(t, "exec", lab.container("edge"), "ip", "-6", "addr", "add", "2001:db8:6000::1/48", "dev", "lo")
	lab.docker(t, "exec", lab.container("edge"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(edgeASN),
		"-c", "address-family ipv6 unicast", "-c", "network "+frrRPKINotFound+" route-map FX5-V6-ORIGIN", "-c", "end")
	link := netip.MustParsePrefix(link6)
	parent := netip.PrefixFrom(link.Addr(), link.Bits()-1).Masked()
	body := fmt.Sprintf(`{"metadata":{"generated":%d},"roas":[{"prefix":%q,"asn":%d,"maxLength":24},`+
		`{"prefix":%q,"asn":%d,"maxLength":48},{"prefix":%q,"asn":%d,"maxLength":%d}]}`,
		time.Now().UTC().Add(-time.Minute).Unix(), prefixA, originA, advertised6, originB, parent.String(), edgeASN, parent.Bits())
	file := filepath.Join(t.TempDir(), "isolated-rpki-validator.json")
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	registry := seedFRRRegistrySnapshot(t, advertised6, link6)
	return []frrRPKICase{
		{prefixA, "valid", "matching_prefix_and_origin", originA, "match"},
		{advertised6, "invalid", "origin_mismatch", originA, "origin_mismatch"},
		{link6, "invalid", "prefix_length_exceeds_origin_authorization", edgeASN, "match"},
		{frrRPKINotFound, "not_found", "no_covering_assertion", originA, "not_found"},
	}, map[string]string{"PROBECTL_FLOW_ENRICH_RPKI_FILE": file, "PROBECTL_FLOW_ENRICH_IRR_MANIFEST": registry}
}

func seedFRRRegistrySnapshot(t *testing.T, advertised6, link6 string) string {
	t.Helper()
	dir := t.TempDir()
	stamp := time.Now().UTC().Add(-time.Minute)
	content := []byte(fmt.Sprintf("route: %s\norigin: AS%d\nlast-modified: %s\nsource: LAB\n\n"+
		"route6: %s\norigin: AS%d\nsource: LAB\n\nroute6: %s\norigin: AS%d\nsource: LAB\n\n"+
		"route6: 2001:db8::/32\norigin: AS%d\nsource: LAB\n", prefixA, originA, stamp.AddDate(-2, 0, 0).Format(time.RFC3339),
		advertised6, originB, link6, edgeASN, originA))
	if err := os.WriteFile(filepath.Join(dir, "lab.rpsl"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := hex.EncodeToString(crypto.Hash(content))
	manifest, err := json.Marshal(map[string]any{"version": 1, "sources": []map[string]any{
		{"source": "LAB", "file": "lab.rpsl", "generated_at": stamp, "sha256": digest, "terms": "https://registry.example/terms", "rpki_filtered": false},
		{"source": "UNAVAILABLE", "file": "unavailable.rpsl", "generated_at": stamp, "sha256": digest, "terms": "https://registry.example/terms", "rpki_filtered": false},
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func addFRRRPKIMonitors(t *testing.T, st *shipped.Stack, lanes []edgeFlowRegistration, cases []frrRPKICase) [][]frrRPKITarget {
	t.Helper()
	out := make([][]frrRPKITarget, len(lanes))
	for i, lane := range lanes {
		for _, item := range cases {
			code, raw := st.Do(t, lane.cookie, http.MethodPost, "/v1/entities", map[string]any{
				"context_id": lane.contextID, "kind": "prefix", "network_prefix": item.prefix, "label": "Owned FRR validation prefix",
			})
			var prefix entity.Record
			if code != http.StatusCreated || json.Unmarshal(raw, &prefix) != nil || prefix.ID == "" || prefix.Scope.TenantID != lane.tenantID {
				t.Fatalf("could not inventory the owned validation prefix: HTTP %d", code)
			}
			code, raw = st.Do(t, lane.cookie, http.MethodPut, "/v1/bgp/visibility", map[string]any{"prefix": item.prefix, "minimum_visible_basis_points": 9500})
			var monitor store.BGPVisibilityMonitor
			if code != http.StatusOK || json.Unmarshal(raw, &monitor) != nil || monitor.Prefix.String() != item.prefix {
				t.Fatalf("could not monitor the exact FRR validation prefix: HTTP %d", code)
			}
			q := url.Values{"context_id": {lane.contextID}, "prefix_id": {prefix.ID}, "intended_asn": {strconv.FormatUint(uint64(item.origin), 10)}}
			out[i] = append(out[i], frrRPKITarget{frrRPKICase: item, path: "/v1/bgp/visibility/" + monitor.ID + "/rpki-posture?" + q.Encode()})
		}
	}
	return out
}

func proveFRRRPKI(t *testing.T, st *shipped.Stack, lanes []edgeFlowRegistration, targets [][]frrRPKITarget) {
	t.Helper()
	for i, lane := range lanes {
		for item, target := range targets[i] {
			var result frrRPKIPosture
			ready := false
			t.Cleanup(func() {
				if !ready {
					t.Logf("lane %d prefix %s last RPKI coverage %q with %d paths and %d history points", i, target.prefix,
						result.Coverage, len(result.Paths), len(result.Trend))
				}
			})
			shipped.Await(t, "complete owned current and original validation for "+target.prefix, 25*time.Second, func() bool {
				code, raw := st.Do(t, lane.cookie, http.MethodGet, target.path, nil)
				result = frrRPKIPosture{}
				return code == http.StatusOK && json.Unmarshal(raw, &result) == nil && result.Coverage == "observed_source_population" &&
					len(result.Paths) > 0 && len(result.Trend) > 0
			})
			ready = true
			assertFRRRPKIPosture(t, lane, target, result)
			if code, _ := st.Do(t, lane.cookie, http.MethodGet, targets[1-i][item].path, nil); code != http.StatusNotFound {
				t.Fatal("foreign RPKI posture scope returned HTTP", code)
			}
		}
	}
	t.Log("real-integration: pinned FRR announced all four validation cases through both issued BMP identities and tenant-scoped storage; original validator generations and exact ROA suggestions passed")
}

func assertFRRRPKIPosture(t *testing.T, lane edgeFlowRegistration, target frrRPKITarget, result frrRPKIPosture) {
	t.Helper()
	if result.Prefix != target.prefix {
		t.Fatalf("returned prefix %s, expected the owned FRR prefix %s", result.Prefix, target.prefix)
	}
	history := make(map[string]store.BGPRPKIHistoryObservation)
	for _, point := range result.Trend {
		if point.Vantage == "" || point.Origin == nil || *point.Origin != target.origin ||
			point.Posture.Status != target.status || point.Posture.Suggestion != nil {
			t.Fatalf("invalid retained RPKI observation for %s: %+v", target.prefix, point)
		}
		if _, found := history[point.Vantage]; !found {
			history[point.Vantage] = point.BGPRPKIHistoryObservation
		}
	}
	seen := make(map[string]bool)
	for _, current := range result.Paths {
		original, found := history[current.Vantage]
		if !found || seen[current.Vantage] || current.RouterID != lane.deviceID || current.Origin != target.origin ||
			current.RPKI.Status != target.status || current.RPKI.Reason != target.reason ||
			current.RPKI.ValidatorVersion == "" || original.Posture.ValidatorVersion != current.RPKI.ValidatorVersion {
			t.Fatalf("current RPKI view lacks its own retained proof for %s: %+v", target.prefix, current)
		}
		seen[current.Vantage] = true
		if len(current.IRR) != 2 || current.IRR[0].Source != "LAB" || current.IRR[0].Status != target.registryStatus ||
			len(current.IRR[0].SHA256) != 64 || current.IRR[0].ObservedAt == nil || current.IRR[1].Status != "unavailable" {
			t.Fatal("the exact prefix and original registry coverage were lost", target, current.IRR)
		}
		if target.prefix == prefixA && (len(current.IRR[0].Objects) != 1 || current.IRR[0].Objects[0].Review != "past_review_age") {
			t.Fatal("the old matching object lost its review state", current.IRR[0])
		}
		exact := current.RPKI.Suggestion
		if (exact != nil) != (target.status != "valid") || exact != nil && (exact.Prefix.String() != target.prefix || exact.OriginASN != target.origin) {
			t.Fatal("ROA suggestion exceeded the exact observed and intended route", target, exact)
		}
	}
}
