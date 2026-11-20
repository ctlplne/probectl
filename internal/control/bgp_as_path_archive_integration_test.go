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
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

const runSealedRouteViewsASPaths = "PROBECTL_TEST_RUN_ROUTEVIEWS_AS_PATH_ARCHIVES"

func TestBGPASPathHistoryReplaysSealedRouteViewsOriginals(t *testing.T) {
	if os.Getenv(runSealedRouteViewsASPaths) != "1" {
		testsupport.SkipOptIn(t, runSealedRouteViewsASPaths, "requires the three publicly available EQIX archive originals")
	}
	cache, err := opendata.NewPublicMRTCache(os.Getenv("PROBECTL_TEST_BGP_PUBLIC_MRT_CACHE"), 512<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	ref := opendata.PublicMRTArchiveRef{Source: "routeviews", Collector: "route-views.eqix", Kind: opendata.PublicMRTBaseline,
		At: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	prefixes := []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24"), netip.MustParsePrefix("8.8.8.0/24"), netip.MustParsePrefix("2001:4860::/32")}
	series, err := bgp.ReadPublicVisibilityCollector(t.Context(), cache, ref, bgpVisibilityArchiveBudget, bgpVisibilityBaselinePolicy, prefixes)
	if err != nil {
		t.Fatal(err)
	}
	point := series.Point()
	if point.Baseline.SHA256 != "0536405604a0b64d2f869b240c845f104ea38500a18f7fe1f91f6d4b47c161a5" {
		t.Fatal("baseline is not the independently identified public original", point.Baseline.SHA256)
	}
	projection := publicASPathProjection{}
	paths := projection.advance(point)
	origins := map[netip.Prefix]uint32{prefixes[0]: 13335, prefixes[1]: 15169, prefixes[2]: 15169}
	counts := map[netip.Prefix]int{}
	for _, event := range paths {
		original := event.Original
		origin, selected := origins[event.Route.Prefix]
		if !selected || event.Kind != "baseline" || original.RIBSequence == nil || original.RIBPeerIndex == nil || original.ArchiveRecord < 2 || event.Current == nil {
			t.Fatal("local baseline lost its exact prefix, original entry or path")
		}
		if slices.Contains(bgp.SummarizeASPath(event.Current.Segments).PossibleOrigins, origin) {
			counts[event.Route.Prefix]++
		}
	}
	if counts[prefixes[0]] < 22 || counts[prefixes[1]] < 22 || counts[prefixes[2]] < 21 {
		t.Fatal("independently expected public origin paths missing", counts)
	}
	t.Logf("verified %d original RIB entries with expected origin coverage %v", len(paths), counts)
	for _, expected := range []string{"7d917cd55a455bb934b6d6ba4d19a6d0ee075062194899d11e4fb03b4ba26ac8", "3a3c36f24364c54d8b0a94b91fee9d946a074e5525c111feeb43b6522ff82b69"} {
		next, ok := series.NextArchive()
		if !ok {
			t.Fatal("missing original update interval")
		}
		if err := series.Advance(t.Context(), cache, next, bgpVisibilityArchiveBudget); err != nil {
			t.Fatal(err)
		}
		point = series.Point()
		if point.Latest.SHA256 != expected || point.Paths == nil {
			t.Fatal("public interval lost its original identity or continuity", next.At, point.Latest.SHA256)
		}
		changes := projection.advance(point)
		for _, change := range changes {
			if !slices.Contains(prefixes, change.Route.Prefix) || change.Original.ArchiveSHA256 != expected || change.Original.ArchiveRecord < 1 ||
				change.Previous == nil && change.Current == nil {
				t.Fatal("update changed original scope, archive, ordinal or stage")
			}
		}
		t.Logf("verified archive %s through %s with %d selected operations and %d path changes", next.At, point.Through, len(point.Paths.Updates), len(changes))
	}
}

func TestBGPASPathHistoryPublishesOriginalsAfterLateMonitorEnrollment(t *testing.T) {
	if os.Getenv(runSealedRouteViewsASPaths) != "1" {
		testsupport.SkipOptIn(t, runSealedRouteViewsASPaths, "requires the three EQIX originals and a disposable TLS PostgreSQL database")
	}
	f := newRoleExplanationAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permAlertWrite)
		})
	}
	collector, err := NewBGPVisibilitySupervisor(f.server, os.Getenv("PROBECTL_TEST_BGP_PUBLIC_MRT_CACHE"), []string{"route-views.eqix"}, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	load := func(tenant string, monitor store.BGPVisibilityMonitor) bgpASPathHistoryPage {
		t.Helper()
		path := "/v1/bgp/visibility/" + monitor.ID + "/paths?source=public_mrt&from=2026-10-01T00:00:00Z&limit=1000"
		body := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, path, nil, http.StatusOK)
		var page bgpASPathHistoryPage
		if err := json.Unmarshal(body, &page); err != nil || page.Monitor.ID != monitor.ID || len(page.Items) < 22 || page.NextCursor != "" {
			t.Fatal("whole original source was not served for the expected monitor", len(page.Items), err)
		}
		return page
	}
	states := map[string]*bgpVisibilityCollectorState{}
	var monitors [2]store.BGPVisibilityMonitor
	var pages [2]bgpASPathHistoryPage
	clock := time.Date(2026, 10, 1, 0, 35, 30, 0, time.UTC)
	for lane, tenant := range f.tenants {
		body := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPut, "/v1/bgp/visibility",
			map[string]any{"prefix": "8.8.8.0/24", "minimum_visible_basis_points": 9500}, http.StatusOK)
		if err := json.Unmarshal(body, &monitors[lane]); err != nil {
			t.Fatal(err)
		}
		if err := collector.sync(t.Context(), states, clock); err != nil {
			t.Fatal("local collector replay rejected a complete archive", err)
		}
		pages[lane] = load(tenant, monitors[lane])
	}
	firstAgain := load(f.tenants[0], monitors[0])
	if len(firstAgain.Items) != len(pages[0].Items) || firstAgain.Items[0].ID != pages[0].Items[0].ID || len(pages[0].Items) != len(pages[1].Items) {
		t.Fatal("late enrollment changed or duplicated the first tenant's original history")
	}
	for index, original := range pages[0].Items {
		sibling := pages[1].Items[index]
		if original.PublicSource == nil || sibling.PublicSource == nil || original.ID == sibling.ID || original.Vantage != sibling.Vantage ||
			original.PublicSource.ArchiveSHA256 != sibling.PublicSource.ArchiveSHA256 || original.Sequence != sibling.Sequence || original.Operation != sibling.Operation {
			t.Fatal("late enrollment failed to replay the same public evidence into a distinct tenant row")
		}
	}
	foreign := "/v1/bgp/visibility/" + monitors[1].ID + "/paths?source=public_mrt"
	callSeasonalAPI(t, socket, f.tokens[f.tenants[0]], http.MethodGet, foreign, nil, http.StatusNotFound)
	t.Logf("both tenant monitors retained %d original public path events after late enrollment", len(pages[0].Items))
}
