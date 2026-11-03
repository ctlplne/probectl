// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetBoxSubjectImportUsesCompleteFactsExactSelectionAndFreshRelations(t *testing.T) {
	var foreign, down atomic.Bool
	var roleID atomic.Int64
	roleID.Store(51)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		source := r.URL.Query().Get("tenant_id")
		if source != "7" && source != "8" {
			t.Error("source request omitted mapped tenant")
			w.WriteHeader(400)
			return
		}
		if r.URL.Path == "/api/ipam/ip-addresses/" {
			id := r.URL.Query().Get("id")
			key := r.URL.Query().Get("address")
			if id == "" {
				id = map[string]string{"192.0.2.10": "10", "2001:db8::10": "11", "192.0.2.12": "12"}[key]
			}
			address := map[string]string{"10": "192.0.2.10/32", "11": "2001:db8::10/128", "12": "192.0.2.12/32"}[id]
			if address == "" {
				fmt.Fprint(w, `{"count":0,"results":[]}`)
				return
			}
			owner := 42
			if id == "12" {
				owner = 43
			}
			fmt.Fprintf(w, `{"count":1,"results":[{"id":%s,"tenant":{"id":%s},"address":%q,"dns_name":"test.example","assigned_object":{"device":{"id":%d}}}]}`, id, source, address, owner)
			return
		}
		if r.URL.Path == "/api/virtualization/virtual-machines/" {
			fmt.Fprint(w, `{"count":0,"results":[]}`)
			return
		}
		if r.URL.Path != "/api/dcim/devices/" {
			t.Error("unexpected source endpoint")
			w.WriteHeader(400)
			return
		}
		id, name := r.URL.Query().Get("id"), "router"
		if id == "" {
			id, name = "44", "test.example"
		}
		if id == "44" {
			name = "test.example"
		}
		if foreign.Load() {
			source = "9"
		}
		fmt.Fprintf(w, `{"count":1,"results":[{"id":%s,"tenant":{"id":%s},"name":%q,"role":{"id":%d,"name":"edge"},"site":{"id":61,"name":"iad"}}]}`, id, source, name, roleID.Load())
	}))
	defer server.Close()
	provider := NewNetBox(server.URL, "test-token", map[string]string{netBoxTenantA: "7", netBoxTenantB: "8"})
	provider.client = server.Client()
	resolver := NewResolver(provider, time.Hour)
	facts := NetBoxTagFacts{Addresses: []netip.Addr{netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("192.0.2.10")}}
	for _, tenant := range []string{netBoxTenantA, netBoxTenantB} {
		ctx := netBoxContext(tenant)
		selected, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "role", "")
		if err != nil || selected.Candidate().LookupCIID != "netbox:ipam.ip_address:10" || selected.Candidate().Value != "edge" || !selected.Matches(facts) {
			t.Fatalf("complete dual-stack facts did not select deterministic same-owner witness: %v", err)
		}
		expected := selected.Candidate()
		foreignReview := expected
		foreignReview.NetBoxTenantID = "999"
		if _, err := resolver.RecheckNetBoxSubjectTag(ctx, facts, foreignReview); !errors.Is(err, ErrTagReviewChanged) || !errors.Is(err, ErrTenantBinding) {
			t.Fatalf("reviewed tenant transplant lost its conflict and binding classifications: %v", err)
		}
		if data, _ := json.Marshal(map[string]any{"selection": selected}); string(data) != `{"selection":{}}` {
			t.Fatal("selection disclosed private correspondence")
		}
		if data, _ := json.Marshal(facts); string(data) != "{}" {
			t.Fatal("facts gained a transport projection")
		}
		if selected.Matches(NetBoxTagFacts{Addresses: []netip.Addr{netip.MustParseAddr("2001:db8::10")}}) {
			t.Fatal("removed selected address retained authority")
		}
		extra := NetBoxTagFacts{Addresses: append(append([]netip.Addr{}, facts.Addresses...), netip.MustParseAddr("192.0.2.99"))}
		if !selected.Matches(extra) {
			t.Fatal("unrelated address invalidated unchanged selected relationship")
		}
		ambiguous := NetBoxTagFacts{Addresses: append(append([]netip.Addr{}, facts.Addresses...), netip.MustParseAddr("192.0.2.12"))}
		if _, err := resolver.PreviewNetBoxSubjectTag(ctx, ambiguous, "role", ""); !errors.Is(err, ErrNoTagCandidate) {
			t.Fatal("matching values on different owners silently selected a CI")
		}
		if _, err := resolver.PreviewNetBoxSubjectTag(ctx, ambiguous, "role", "12"); err != nil {
			t.Fatal("explicit current IP CI did not disambiguate")
		}
		if _, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "role", "12"); !errors.Is(err, ErrNoTagCandidate) {
			t.Fatal("explicit ID without a current local correspondence was admitted")
		}
		if _, err := resolver.RecheckNetBoxSubjectTag(ctx, extra, expected); err != nil {
			t.Fatal("exact selected relationship was not freshly re-attested")
		}
		roleID.Store(52)
		changed, err := resolver.RecheckNetBoxSubjectTag(ctx, facts, expected)
		if err != nil || changed.Candidate() == expected {
			t.Fatal("same-name role identity change did not alter reviewed provenance")
		}
		roleID.Store(51)
	}
	ctx := netBoxContext(netBoxTenantA)
	dns := NetBoxTagFacts{Hostname: "test.example"}
	for _, id := range []string{"", "10"} {
		selected, err := resolver.PreviewNetBoxSubjectTag(ctx, dns, "site", id)
		if err != nil || !selected.Matches(dns) {
			t.Fatal("owned configured DNS host could not match its current CI without DNS resolution")
		}
		if _, err := resolver.RecheckNetBoxSubjectTag(ctx, dns, selected.Candidate()); err != nil {
			t.Fatal("exact DNS witness could not be re-attested")
		}
	}
	foreign.Store(true)
	if _, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "role", "10"); !errors.Is(err, ErrTenantBinding) {
		t.Fatal("owned IP authorized foreign related metadata")
	}
	foreign.Store(false)
	down.Store(true)
	if _, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "role", ""); err == nil {
		t.Fatal("outage used enrichment cache as import authority")
	}
	for _, id := range []string{"0", "01", "-1", "9223372036854775808", "https://foreign.example/1"} {
		if _, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "role", id); !errors.Is(err, ErrNoTagCandidate) {
			t.Fatal("noncanonical source selection was accepted")
		}
	}
}

func TestNetBoxPrefixImportAttestsExactRangeScopeVRFAndOwnRole(t *testing.T) {
	var phase atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ipam/prefixes/" || r.URL.Query().Get("tenant_id") != "7" || r.URL.Query().Get("prefix") != "2001:db8::/32" {
			t.Error("prefix lookup inferred a host or omitted its tenant/exact range")
		}
		id := r.URL.Query().Get("id")
		if phase.Load() == 1 && id == "" {
			fmt.Fprint(w, `{"count":2,"results":[]}`)
			return
		}
		tenant, prefix, kind, scopeID, scopeObject, vrf, role := "7", "2001:db8::/32", "dcim.site", 71, 71, 9, 51
		switch phase.Load() {
		case 2:
			tenant = "8"
		case 3:
			prefix = "2001:db8:1::/48"
		case 4:
			scopeObject = 72
		case 5:
			kind = "dcim.region"
		case 6:
			vrf = 10
		case 7:
			role = 52
		}
		fmt.Fprintf(w, `{"count":1,"results":[{"id":101,"tenant":{"id":%s},"prefix":%q,"vrf":{"id":%d},"role":{"id":%d,"name":"ipam-edge"},"scope_type":%q,"scope_id":%d,"scope":{"id":%d,"name":"iad"}}]}`, tenant, prefix, vrf, role, kind, scopeID, scopeObject)
	}))
	defer server.Close()
	provider := NewNetBox(server.URL, "test-token", map[string]string{netBoxTenantA: "7"})
	provider.client = server.Client()
	resolver := NewResolver(provider, time.Hour)
	facts := NetBoxTagFacts{Prefix: netip.MustParsePrefix("2001:db8::/32")}
	ctx := netBoxContext(netBoxTenantA)
	selected, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "site", "")
	if err != nil || selected.Candidate().CIID != "netbox:ipam.prefix:101" || selected.Candidate().Value != "iad" || !selected.Matches(facts) {
		t.Fatalf("typed prefix/site preview: %v", err)
	}
	initial := selected.Candidate()
	for _, current := range []int64{1, 2, 3, 4, 5, 6, 7} {
		phase.Store(current)
		got, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "site", "")
		if current <= 5 && err == nil {
			t.Fatalf("invalid/ambiguous prefix state %d was admitted", current)
		}
		if current >= 6 && (err != nil || got.Candidate() == initial) {
			t.Fatal("same-value scope/VRF/role move preserved reviewed provenance")
		}
		if current == 1 {
			if _, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "site", "101"); err != nil {
				t.Fatal("exact prefix ID did not disambiguate an overlapping VRF")
			}
		}
		if current == 5 {
			if role, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "role", "101"); err != nil || role.Candidate().Value != "ipam-edge" {
				t.Fatal("non-site scope incorrectly replaced or disabled the prefix's own role")
			}
		}
	}
	phase.Store(0)
	if _, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "site", "102"); !errors.Is(err, ErrTenantBinding) {
		t.Fatal("source ignored exact selected prefix ID")
	}
	if selected.Matches(NetBoxTagFacts{Prefix: netip.MustParsePrefix("2001:db8:1::/48")}) {
		t.Fatal("narrower current range retained old prefix correspondence")
	}
	if !strings.Contains(initial.SourceRef, ":v9:s71:r51:") || len(initial.SourceRef) > 128 {
		t.Fatal("provenance omitted typed source relations or exceeded stored bound")
	}
}
