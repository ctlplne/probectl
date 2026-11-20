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

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func seedBGPASPathHistoryAPI(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server) ([2]store.BGPVisibilityMonitor, [2]string) {
	t.Helper()
	var monitors [2]store.BGPVisibilityMonitor
	var incidentIDs [2]string
	prefix := netip.MustParsePrefix("198.19.0.0/24")
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	clock := at.Truncate(2 * time.Hour)
	public := store.BGPASPathPublicSource{Source: "routeviews", Collector: "route-views.eqix", BaselineClock: clock, ArchiveClock: clock,
		BaselineSHA256: strings.Repeat("ab", 32), ArchiveSHA256: strings.Repeat("ab", 32),
		PeerAddress: netip.MustParseAddr("198.51.100.2"), PeerASN: 64496, ArchiveRecord: 2, ObservedUnixNanos: at.UnixNano()}
	peerIndex, sequence, originated := uint16(0), uint32(11), public.ObservedUnixNanos
	public.RIBPeerIndex, public.RIBSequence, public.RIBOriginatedAt = &peerIndex, &sequence, &originated
	replacement := public
	replacement.ArchiveSHA256, replacement.ArchiveRecord = strings.Repeat("cd", 32), 1
	replacement.RIBPeerIndex, replacement.RIBSequence, replacement.RIBOriginatedAt = nil, nil, nil
	route := bgp.RoutePrefix{Prefix: prefix, HasPathID: true}
	previous := &store.BGPASPathPublicSnapshot{Source: public, AS4Action: "absent",
		Segments: []bgp.ASPathSegment{{Kind: bgp.ASPathSequence, Values: []uint32{64496, 64500}}}}
	current := &store.BGPASPathPublicSnapshot{Source: replacement, AS4Action: "absent",
		Segments: []bgp.ASPathSegment{{Kind: bgp.ASPathSequence, Values: []uint32{64499, 64500, 64500}}}}
	events := []store.BGPASPathPublicEvent{{Route: route, Kind: "baseline", Original: public, Current: previous},
		{Route: route, Kind: "path_change", Original: replacement, Previous: previous, Current: current}}
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permAIQuery, permAlertWrite, permChangeRead, permIncidentRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPut, "/v1/bgp/visibility",
			map[string]any{"prefix": prefix, "minimum_visible_basis_points": 9500}, http.StatusOK)
		if err := json.Unmarshal(raw, &monitors[lane]); err != nil || monitors[lane].Prefix != prefix {
			t.Fatal("paired monitor was not created through HTTPS", err)
		}
		seedInternetRoutingView(t, f, tenant, uint32(64497+lane))
		for range 2 {
			if err := f.server.publishPublicASPaths(t.Context(), tenancy.ID(tenant), monitors[lane].ID, events); err != nil {
				t.Fatal("public history publication or exact replay failed", err)
			}
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			inc, err := (store.Incidents{}).Create(ctx, sc, incident.Incident{Status: incident.StatusOpen,
				Severity: incident.SeverityWarning, Title: "Owned visibility incident", Target: prefix.String(), Prefix: prefix.String(),
				StartedAt: at, LastSeenAt: at})
			if err != nil {
				return err
			}
			incidentIDs[lane] = inc.ID
			signal := bgpVisibilityAlertSignal(tenancy.ID(tenant), monitors[lane], store.BGPVisibilityObservation{
				ObservedAt: at, Source: replacement.Source, Collector: replacement.Collector, BaselineSHA256: replacement.BaselineSHA256,
				ArchiveSHA256: replacement.ArchiveSHA256, Counts: &store.BGPVisibilityCounts{EligiblePeers: 4, VisiblePeers: 2},
			}, "bgp.visibility_partial")
			_, err = (store.Incidents{}).AppendSignal(ctx, sc, inc.ID, signal)
			return err
		})
	}
	return monitors, incidentIDs
}

func TestBGPASPathHistoryServesScopedPrivateAndPublicSources(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	monitors, incidentIDs := seedBGPASPathHistoryAPI(t, f, socket)
	seedInterfaceRoleMCPConsent(f)
	ca := filepath.Join(t.TempDir(), "as-path-api-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		path := "/v1/bgp/visibility/" + monitors[lane].ID + "/paths"
		var first, second, owned bgpASPathHistoryPage
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, path+"?source=public_mrt&limit=1", nil, http.StatusOK)
		if err := json.Unmarshal(raw, &first); err != nil || first.NextCursor == "" || len(first.Items) != 1 || first.Items[0].Kind != "path_change" ||
			first.Items[0].Changes == nil || !first.Items[0].Changes.UpstreamChanged || !first.Items[0].Changes.LengthChanged ||
			len(first.Items[0].Incidents) != 1 || first.Items[0].Incidents[0].ID != incidentIDs[lane] {
			t.Fatal("HTTPS lost same-archive incident context, upstream change or continuation", err)
		}
		raw = callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, path+"?cursor="+first.NextCursor, nil, http.StatusOK)
		if err := json.Unmarshal(raw, &second); err != nil || len(second.Items) != 1 || second.Items[0].Kind != "baseline" ||
			!second.Items[0].ObservedAt.Equal(first.Items[0].ObservedAt) {
			t.Fatal("continuation lost the exact same-clock baseline", err)
		}
		raw = callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, path+"?source=router_bmp", nil, http.StatusOK)
		if err := json.Unmarshal(raw, &owned); err != nil || len(owned.Items) != 1 || owned.Items[0].RouterView != "loc_rib" ||
			owned.Items[0].Current == nil || len(owned.Items[0].Current.Facts.PossibleOrigins) != 1 ||
			owned.Items[0].Current.Facts.PossibleOrigins[0] != uint32(64497+lane) {
			t.Fatal("HTTPS lost the owned original routing source", err)
		}
		foreignPath := "/v1/bgp/visibility/" + monitors[1-lane].ID + "/paths"
		callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, foreignPath, nil, http.StatusNotFound)
		var out, stderr bytes.Buffer
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		if status := cli.RunWithStdin([]string{"--json", "bgp", "path-history", monitors[lane].ID, "--query", "source=public_mrt",
			"--query", "limit=1"}, getenv, bytes.NewReader(nil), &out, &stderr); status != 0 {
			t.Fatal("CLI could not read the same scoped AS path", status, stderr.String())
		}
		var cliPage bgpASPathHistoryPage
		if err := json.Unmarshal(out.Bytes(), &cliPage); err != nil || len(cliPage.Items) != 1 || cliPage.Items[0].ID != first.Items[0].ID {
			t.Fatal("CLI changed the original selected path", err)
		}
	}
	for _, wire := range []string{"2025-11-25", "2026-07-28"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for lane, tenant := range f.tenants {
			var first struct {
				NextCursor string `json:"next_cursor"`
				Monitor    struct {
					ID     string `json:"id"`
					Prefix string `json:"prefix"`
				} `json:"monitor"`
				Items []struct {
					Kind         string `json:"kind"`
					PublicSource struct {
						ArchiveSHA256 string `json:"archive_sha256"`
						PeerAddress   string `json:"peer_address"`
					} `json:"public_source"`
				} `json:"items"`
			}
			call(tenant, "bgp_as_path_history", map[string]any{"id": monitors[lane].ID, "source": "public_mrt", "limit": 1}, &first, true)
			if len(first.Items) != 1 || first.Items[0].Kind != "path_change" || first.NextCursor == "" ||
				first.Monitor.ID != monitors[lane].ID || first.Monitor.Prefix == "" || strings.Contains(first.Monitor.Prefix, monitors[lane].Prefix.Addr().String()) ||
				first.Items[0].PublicSource.ArchiveSHA256 != strings.Repeat("cd", 32) || strings.Contains(first.Items[0].PublicSource.PeerAddress, "198.51.100.2") {
				t.Fatal("MCP changed the owned event, exact cursor, digest or address redaction", wire)
			}
			cursor := first.NextCursor
			call(tenant, "bgp_as_path_history", map[string]any{"id": monitors[lane].ID, "cursor": cursor}, &first, true)
			if len(first.Items) != 1 || first.Items[0].Kind != "baseline" {
				t.Fatal("MCP could not continue the same clock and vantage", wire)
			}
			call(tenant, "bgp_as_path_history", map[string]any{"id": monitors[1-lane].ID, "source": "router_bmp"}, nil, false)
		}
	}
	revoked := f.tenants[0]
	if _, _, err := store.NewAgentIdentities(f.pool).RevokeAgent(t.Context(), revoked, "role-router", f.users[revoked]); err != nil {
		t.Fatal(err)
	}
	callSeasonalAPI(t, socket, f.tokens[revoked], http.MethodGet, "/v1/bgp/visibility/"+monitors[0].ID+"/paths?source=router_bmp", nil, http.StatusNotFound)
	callSeasonalAPI(t, socket, f.tokens[f.tenants[1]], http.MethodGet, "/v1/bgp/visibility/"+monitors[1].ID+"/paths?source=router_bmp", nil, http.StatusOK)
}

func TestBGPASPathHistoryBrowserUsesBothScopedSources(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	seedBGPASPathHistoryAPI(t, f, socket)
	ca := filepath.Join(t.TempDir(), "as-path-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		cookie := seasonalFlowBrowserCookie(t, f, tenant)
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("tenant-%d-%s", lane, theme), func(t *testing.T) {
				testsupport.RenderUI(t, testsupport.RenderSpec{URL: socket.URL + "/ui/planes/bgp",
					Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}}, TrustCertFiles: []string{ca},
					CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
					Steps: []testsupport.RenderStep{
						{Click: "Open prefix visibility"},
						{Click: "Open AS-path history", Expect: []string{"route-views.eqix", "loc rib", "Upstream changed", "Path length changed"},
							ExpectWithin: "table:has(caption:text-is('AS-path timeline for 198.19.0.0/24'))"},
						{Click: "Path change", Expect: []string{"AS64496", "AS64499", "AS64500 → AS64500", "Archive SHA-256", "Visibility incident"},
							ExpectWithin: "[role='dialog']"},
						{Click: "Close details", Within: "[role='dialog']"},
						{Select: "select:has(option[value='router_bmp'])", Value: "router_bmp"},
						{Click: "Baseline", Expect: []string{fmt.Sprintf("AS%d", 64497+lane)},
							Absent: []string{fmt.Sprintf("AS%d", 64498-lane)}, ExpectWithin: "[role='dialog']"},
					}})
			})
		}
	}
}
