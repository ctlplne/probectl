// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

const rpkiTestNetwork = "198.19.0.0/24"

func seedBGPRPKIPosture(t *testing.T) (*roleExplanationAPIFixture, *httptest.Server, [2]string, [2]map[string]any) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	now := time.Now().UTC()
	vrps := filepath.Join(t.TempDir(), "owned-rpki-vrps.json")
	source := fmt.Sprintf(`{"metadata":{"generated":%d},"roas":[{"prefix":"%s","asn":64497,"maxLength":24}]}`, now.Add(-time.Minute).Unix(), rpkiTestNetwork)
	if err := os.WriteFile(vrps, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	en, ok := BuildEnrichment(&config.Config{FlowEnrichRPKIFile: vrps, FlowEnrichRPKIMaxAge: time.Hour,
		FlowEnrichRPKIMemoryBytes: 1 << 20, FlowEnrichRPKIWorkUnits: 1 << 20, FlowEnrichCacheMax: 16}, statusQuietLog())
	if !ok {
		t.Fatal("the local validator was unavailable")
	}
	f.server.WithOpenDataStatus(en, nil, nil)
	var paths [2]string
	var commands [2]map[string]any
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permAlertWrite, permAIQuery} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		created := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/entities",
			map[string]string{"context_id": f.contextID, "kind": "prefix", "label": "Owned RPKI check", "network_prefix": rpkiTestNetwork}, http.StatusCreated)
		var prefix entity.Record
		if err := json.Unmarshal(created, &prefix); err != nil || prefix.ID == "" {
			t.Fatal("the tenant did not receive its inventoried prefix", err)
		}
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPut, "/v1/bgp/visibility",
			map[string]any{"prefix": rpkiTestNetwork, "minimum_visible_basis_points": 9500}, http.StatusOK)
		var monitor store.BGPVisibilityMonitor
		if err := json.Unmarshal(raw, &monitor); err != nil || monitor.ID == "" {
			t.Fatal("the tenant did not receive its monitor", err)
		}
		asn := uint32(64497 + lane)
		seedInternetRoutingViewWithStore(t, f, tenant, asn, (store.BGPRouting{}).WithRPKIHistory(en))
		commands[lane] = map[string]any{"id": monitor.ID, "context_id": f.contextID, "prefix_id": prefix.ID, "intended_asn": asn}
		paths[lane] = "/v1/bgp/visibility/" + monitor.ID + "/rpki-posture?context_id=" + f.contextID +
			"&prefix_id=" + prefix.ID + "&intended_asn=" + strconv.FormatUint(uint64(asn), 10)
	}
	return f, socket, paths, commands
}

func TestBGPRPKIPostureUsesEachTenantsCurrentOwnedOrigin(t *testing.T) {
	f, socket, paths, commands := seedBGPRPKIPosture(t)
	var hijacks [2]string
	for lane, tenant := range f.tenants {
		clock := f.observedAt(tenant)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permIncidentRead); err != nil {
				return err
			}
			incidents := store.Incidents{}
			item, err := incidents.Create(ctx, sc, incident.Incident{TenantID: tenant, Title: "Owned potential origin change",
				Severity: incident.SeverityCritical, Prefix: rpkiTestNetwork, StartedAt: clock, LastSeenAt: clock,
				IdentityContextID: f.contextID, IdentityLookupAttempted: true})
			if err != nil {
				return err
			}
			hijacks[lane] = item.ID
			_, err = incidents.AppendSignal(ctx, sc, item.ID, incident.Signal{TenantID: tenant, Plane: "bgp", Kind: "bgp.possible_hijack",
				Severity: incident.SeverityCritical, Prefix: rpkiTestNetwork, OccurredAt: clock, Attributes: map[string]string{"new_origin_asn": "64498"}})
			return err
		})
	}
	var validatorVersions [2]string
	for lane, tenant := range f.tenants {
		out := readBGPRPKITestView(t, socket, f.tokens[tenant], paths[lane])
		want := [2]string{"valid", "invalid"}[lane]
		if len(out.Paths) != 1 || out.Coverage != "observed_source_population" || out.Paths[0].Origin == nil ||
			*out.Paths[0].Origin != uint32(64497+lane) || out.Paths[0].RPKI.Status != want ||
			len(out.Paths[0].RPKI.Covering) != 1 || out.Paths[0].RPKI.ValidatorObservedAt == nil {
			t.Fatalf("the current view lost its exact owned origin or validator evidence, got %+v", out)
		}
		if len(out.Trend) != 1 || out.Trend[0].Origin == nil || *out.Trend[0].Origin != uint32(64497+lane) ||
			out.Trend[0].Posture.Status != want || out.Trend[0].Posture.ValidatorVersion != out.Paths[0].RPKI.ValidatorVersion ||
			out.Trend[0].Posture.Suggestion != nil {
			t.Fatal("the history did not keep its original validator and owned origin", out.Trend)
		}
		validatorVersions[lane] = out.Trend[0].Posture.ValidatorVersion
		suggestion := out.Paths[0].RPKI.Suggestion
		if (suggestion != nil) != (lane == 1) || suggestion != nil &&
			(suggestion.Prefix.String() != rpkiTestNetwork || suggestion.OriginASN != 64498) {
			t.Fatal("the exact suggestion escaped its observed prefix or approved intended origin", suggestion)
		}
		links := out.Paths[0].RelatedHijacks
		if len(links) != lane || lane == 1 && links[0].IncidentID != hijacks[lane] {
			t.Fatal("posture did not restrict related hijacks to the exact invalid origin and tenant", links)
		}
		callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, paths[1-lane], nil, http.StatusNotFound)
	}
	seedInterfaceRoleMCPConsent(f)
	for _, wire := range []string{"2025-11-25", "2026-07-28"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for lane, tenant := range f.tenants {
			var native struct {
				Prefix string `json:"prefix"`
				Trend  []struct {
					Origin  uint32 `json:"origin_asn"`
					Posture struct {
						ValidatorVersion string `json:"validator_version"`
					} `json:"posture"`
				} `json:"trend"`
			}
			call(tenant, "bgp_rpki_posture", commands[lane], &native, true)
			if len(native.Trend) != 1 || native.Trend[0].Origin != uint32(64497+lane) ||
				native.Trend[0].Posture.ValidatorVersion != validatorVersions[lane] || native.Prefix == "" || strings.Contains(native.Prefix, "198.19.0.0") {
				t.Fatal("native posture changed the tenant's original evidence or disclosed its prefix", wire, native)
			}
			call(tenant, "bgp_rpki_posture", commands[1-lane], nil, false)
		}
	}
	owner := f.tenants[1]
	f.in(owner, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, owner, f.roles[owner], permIncidentRead)
		return err
	})
	revoked := readBGPRPKITestView(t, socket, f.tokens[owner], paths[1])
	if len(revoked.Paths) != 1 || len(revoked.Paths[0].RelatedHijacks) != 0 {
		t.Fatal("revoked incident permission still exposed an RPKI incident link", revoked.Paths)
	}
	f.server.WithOpenDataStatus(nil, nil, nil)
	unknown := readBGPRPKITestView(t, socket, f.tokens[f.tenants[1]], paths[1])
	if len(unknown.Paths) != 1 || unknown.Paths[0].RPKI.Status != "unknown" || unknown.Paths[0].RPKI.Suggestion != nil ||
		len(unknown.Trend) != 1 || unknown.Trend[0].Posture.Status != "invalid" || unknown.Trend[0].Posture.ValidatorVersion == "" {
		t.Fatal("validator unavailability became a posture claim", unknown)
	}
}

func TestBGPRPKIPostureBrowserShowsOwnedCurrentAndRetainedResults(t *testing.T) {
	f, socket, _, _ := seedBGPRPKIPosture(t)
	ca := filepath.Join(t.TempDir(), "rpki-posture-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		cookie := seasonalFlowBrowserCookie(t, f, tenant)
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("tenant-%d-%s", lane, theme), func(t *testing.T) {
				own, foreign := strconv.Itoa(64497+lane), strconv.Itoa(64498-lane)
				verdict := [2]string{"Valid", "Invalid"}[lane]
				currentTable := "table:has(caption:text-is('Current RPKI posture for " + rpkiTestNetwork + "'))"
				current := []string{"AS" + own, verdict}
				if lane == 1 {
					current = append(current, rpkiTestNetwork+" from AS"+own)
				}
				testsupport.RenderUI(t, testsupport.RenderSpec{URL: socket.URL + "/ui/planes/bgp",
					Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}}, TrustCertFiles: []string{ca},
					CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
					Steps: []testsupport.RenderStep{
						{Click: "Open prefix visibility"}, {Click: "Open RPKI posture"},
						{Select: "select:has(option[value='" + f.contextID + "'])", Value: f.contextID},
						{Fill: "input[name='origin']", Value: own},
						{Click: "Check RPKI posture", Expect: current,
							ExpectWithin: currentTable},
						{Click: "Validator evidence", Summary: true, Within: currentTable, Expect: []string{"AS" + own, verdict}, Absent: []string{"AS" + foreign},
							ExpectWithin: "table:has(caption:text-is('RPKI trend for retained route observations'))"},
					}})
			})
		}
	}
}

func readBGPRPKITestView(t *testing.T, socket *httptest.Server, token, path string) bgpRPKICurrentPosture {
	t.Helper()
	raw := callSeasonalAPI(t, socket, token, http.MethodGet, path, nil, http.StatusOK)
	var view bgpRPKICurrentPosture
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal("invalid RPKI posture response", err)
	}
	return view
}
