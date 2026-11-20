// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestBGPVisibilitySignalsAndHistoryStayTenantScoped(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	seedInterfaceRoleMCPConsent(f)
	monitors, histories := publishBGPVisibilityFixture(t, f, socket)
	ca := filepath.Join(t.TempDir(), "bgp-visibility-cli-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		var stdout, stderr bytes.Buffer
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		if code := cli.RunWithStdin([]string{"--json", "bgp", "visibility", monitors[lane].ID}, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
			t.Fatal("shipped CLI could not read the authorized history", code, stderr.String())
		}
		var cliHistory bgpVisibilityHistory
		if err := json.Unmarshal(stdout.Bytes(), &cliHistory); err != nil || cliHistory.Monitor.ID != monitors[lane].ID || len(cliHistory.Items) != len(histories[lane].Items) {
			t.Fatal("CLI changed the authorized monitor or its exact history", err)
		}
	}
	for _, wire := range []string{"2025-11-25", "2026-07-28"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for lane, tenant := range f.tenants {
			var native struct {
				Items []store.BGPVisibilityObservation `json:"items"`
			}
			call(tenant, "bgp_visibility_history", map[string]any{"id": monitors[lane].ID}, &native, true)
			if len(native.Items) != len(histories[lane].Items) || native.Items[0].Availability != histories[lane].Items[0].Availability {
				t.Fatal("native read changed the owned measurement or absence", wire)
			}
			call(tenant, "bgp_visibility_history", map[string]any{"id": monitors[1-lane].ID}, &native, false)
		}
	}
}

func publishBGPVisibilityFixture(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server) ([2]store.BGPVisibilityMonitor, [2]bgpVisibilityHistory) {
	t.Helper()
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	var monitors [2]store.BGPVisibilityMonitor
	var histories [2]bgpVisibilityHistory
	observed := map[string]int{}
	observer := func(_ context.Context, item *incident.Incident, _ bool) { observed[item.TenantID]++ }
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{ai.PermEventsRead, permAlertWrite, permAIQuery} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		created := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPut, "/v1/bgp/visibility",
			map[string]any{"prefix": prefix, "minimum_visible_basis_points": 9500, "alert_on_partial": true, "alert_on_loss": true}, http.StatusOK)
		if err := json.Unmarshal(created, &monitors[lane]); err != nil || monitors[lane].Prefix != prefix {
			t.Fatal("shipped route did not capture a tenant prefix monitor", err)
		}
		at := monitors[lane].CreatedAt.UTC().Add(time.Microsecond)
		clock := at.Truncate(2 * time.Hour)
		counts := []int{4, 2, 0, 0}
		if lane == 1 {
			counts = []int{4, 4, 4, 4}
		}
		for index, seen := range counts {
			point := store.BGPVisibilityObservation{Source: "routeviews", Collector: "route-views.eqix", ObservedAt: at.Add(time.Duration(index) * time.Microsecond),
				BaselineClock: clock, ArchiveClock: clock, BaselineSHA256: strings.Repeat("ab", 32),
				ArchiveSHA256: strings.Repeat(fmt.Sprintf("%02x", index+16), 32), PolicyVersion: "qa-1", MinimumPeerRoutes: 1,
				Availability: "available", Counts: &store.BGPVisibilityCounts{EligiblePeers: 4, VisiblePeers: seen}}
			if seen > 0 {
				point.Counts.Origins = []bgp.PublicVisibilityOrigin{{ASN: uint32(64496 + lane), Peers: seen}}
			}
			if lane == 0 && index == 3 {
				point.Availability, point.Counts = "archive_gap", nil
			}
			for range 2 {
				if err := f.server.publishBGPVisibility(t.Context(), tenancy.ID(tenant), monitors[lane].ID, prefix, point, true, time.Hour, observer); err != nil {
					t.Fatal("tenant observation or immutable replay failed", err)
				}
			}
		}
	}
	if observed[f.tenants[0]] != 2 || observed[f.tenants[1]] != 0 {
		t.Fatal("a gap or sibling emitted a signal, or a repeat changed the transition count", observed)
	}
	for lane, tenant := range f.tenants {
		path := "/v1/bgp/visibility/" + monitors[lane].ID
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, path, nil, http.StatusOK)
		if err := json.Unmarshal(raw, &histories[lane]); err != nil || len(histories[lane].Items) != 4 || histories[lane].Monitor.ID != monitors[lane].ID {
			t.Fatal("shipped HTTPS history did not retain four scoped points", err)
		}
		callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, "/v1/bgp/visibility/"+monitors[1-lane].ID, nil, http.StatusNotFound)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			rows, err := listBGPEventItems(ctx, sc, prefix.String(), "", 20)
			if err != nil || lane == 0 && (len(rows) != 2 || rows[0].Kind != "bgp.visibility_lost" || rows[1].Kind != "bgp.visibility_partial" ||
				rows[0].Attributes["probectl.bgp.visibility.visible_peers"] != "0") || lane == 1 && len(rows) != 0 {
				t.Fatal("incidents did not retain exact, scoped threshold crossings", rows, err)
			}
			return nil
		})
	}
	return monitors, histories
}

func TestBGPVisibilityHistoryServedInBothThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	publishBGPVisibilityFixture(t, f, socket)
	ca := filepath.Join(t.TempDir(), "bgp-visibility-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		cookie := seasonalFlowBrowserCookie(t, f, tenant)
		for _, theme := range []string{"light", "dark"} {
			want := []string{"route-views.eqix", "4 of 4 eligible peers", fmt.Sprintf("AS%d (4)", 64496+lane)}
			if lane == 0 {
				want = append(want, "2 of 4 eligible peers", "0 of 4 eligible peers", "Archive gap")
			}
			t.Run(fmt.Sprintf("tenant-%d-%s", lane, theme), func(t *testing.T) {
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: socket.URL + "/ui/planes/bgp", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
					Steps: []testsupport.RenderStep{{Click: "Open prefix visibility", Expect: want,
						ExpectWithin: "table:has(caption:text-is('Collector coverage for 192.0.2.0/24'))",
						Absent:       []string{fmt.Sprintf("AS%d (4)", 64497-lane)}}},
				})
			})
		}
	}
}
