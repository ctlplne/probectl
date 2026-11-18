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
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Modeled optic readings cross the actual remote-write and query transports,
// current PostgreSQL-backed sessions, and the served production device page.
// The hardware collection leg has separate transport coverage.
func TestOpticalFleetServesOriginalTimesAndTenantRows(t *testing.T) {
	promURL := os.Getenv("PROBECTL_PROM_URL")
	if promURL == "" {
		testsupport.SkipOrFatal(t, "set PROBECTL_PROM_URL to the integration remote-write and deletion receiver")
	}
	f := newRoleExplanationAPIFixture(t)
	writer := tsdb.NewPrometheus(promURL)
	if caFile := os.Getenv("PROBECTL_TEST_PROM_CA_FILE"); caFile != "" {
		client, err := crypto.HardenedHTTPClientWithCAFile(30*time.Second, caFile)
		if err != nil {
			t.Fatal(err)
		}
		writer = tsdb.NewPrometheusWithClient(promURL, client)
	}
	f.server.WithTSDB(writer)
	labels := []string{"Alpha optical tenant", "Beta optical tenant"}
	observedAt := make([]time.Time, len(f.tenants))
	cookies := make([]string, len(f.tenants))
	write := func(lane, count int) {
		t.Helper()
		observedAt[lane] = time.Now().UTC().Truncate(time.Millisecond).Add(-time.Duration(lane+1) * 15 * time.Second)
		samples := opticalFleetSamples(f.tenants[lane], lane)[:count]
		for i := range samples {
			samples[i].Labels["device_name"] = labels[lane]
			samples[i].TimeMillis = observedAt[lane].UnixMilli()
		}
		if err := writer.Write(t.Context(), samples); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range f.tenants {
		write(lane, 5632)
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := writer.DeleteTenant(ctx, tenant); err != nil {
				t.Error(err)
			}
		})
		var grants []auth.PermissionGrant
		f.in(tenant, func(ctx context.Context, scope tenancy.Scope) error {
			var err error
			grants, err = (store.Permissions{}).ForSubject(ctx, scope, "user", f.users[tenant])
			return err
		})
		cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant], Email: "optics@local.invalid", DisplayName: "Device operator", AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
		if err != nil {
			t.Fatal(err)
		}
		cookies[lane] = cookie
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "served-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	read := func(lane int, want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+"/v1/device/metrics?limit=50000", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.tokens[f.tenants[lane]])
		response, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result struct {
			Items  []deviceMetricSummary `json:"items"`
			Source string                `json:"source"`
		}
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil || response.StatusCode != http.StatusOK || result.Source != "tsdb" || len(result.Items) != want {
			t.Fatalf("complete owned optical series: status=%d rows=%d source=%q decode=%v", response.StatusCode, len(result.Items), result.Source, err)
		}
		seen := make(map[string]struct{}, want)
		for _, sample := range result.Items {
			offset, knownChannel := map[string]float64{"": 0, "0": 1, "1": 2}[sample.PhysicalChannel]
			_, duplicate := seen[sample.ID]
			if sample.DeviceName != labels[lane] || !sample.LastSeen.Equal(observedAt[lane]) || sample.Value != -3.25-float64(lane*1000)-offset ||
				!knownChannel || sample.Component == "" || sample.IfName != "" || sample.IfIndex != "" || duplicate {
				t.Fatal("served optical reading changed its tenant, component/channel, value or stored observation time")
			}
			seen[sample.ID] = struct{}{}
		}
	}
	render := func(t *testing.T, lane, components int, accessibility bool) {
		t.Helper()
		for _, theme := range []string{"light", "dark"} {
			t.Run(strconv.Itoa(lane)+"/"+theme, func(t *testing.T) {
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: socket.URL + "/ui/planes/device", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookies[lane]}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: accessibility, TimeoutMs: 90000,
					Expect: []string{labels[lane], "Component level", fmt.Sprintf("optic-%04d", components-1)}, Absent: []string{labels[1-lane]},
					Controls: []testsupport.RenderControl{
						{Role: "table", Name: "Component sensors"},
						{Role: "row", Within: `table:has(caption:text-is("Component sensors")) > tbody`, Count: components * 3},
					},
				})
			})
		}
	}
	for lane := range f.tenants {
		read(lane, 5632)
		render(t, lane, 512, false)
	}
	if _, err := writer.DeleteTenant(t.Context(), f.tenants[0]); err != nil {
		t.Fatal(err)
	}
	read(0, 0)
	read(1, 5632)
	// Audit the shared table with a component and both channels, including empty
	// channel fields. Scanning 1,536 identical row templates made Chromium's
	// axe run time out. Both full populations are checked above in both themes.
	write(0, 11)
	read(0, 11)
	t.Run("accessibility", func(t *testing.T) { render(t, 0, 1, true) })
}
