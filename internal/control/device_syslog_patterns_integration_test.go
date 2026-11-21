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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestDeviceSyslogPatternsServeExactScopedCounts(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	ops := device.NewPostgresOpsStore(f.pool)
	f.server.WithDeviceOps(ops)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "syslog-patterns-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	left := time.Now().UTC().Add(-40 * time.Second).Truncate(time.Second)
	right := left.Add(20 * time.Second)
	from, to := left.Format(time.RFC3339), right.Format(time.RFC3339)
	router := "edge-overlap"
	input := url.Values{"from": {from}, "to": {to}, "device": {router}}
	const route = "/v1/device/syslog/patterns"
	messages := [2]string{
		"%LINK-3-UPDOWN: Interface Ethernet7/2, changed state to down",
		"%PLATFORM-2-PS_FAIL: Power supply 4 failed or shut down (Serial number sample-supply-17)",
	}
	families := [2]string{"cisco_ios", "cisco_nxos"}
	kinds := [2]device.SyslogPatternKind{device.SyslogPatternLinkDown, device.SyslogPatternSupplyFault}
	captions := [2]string{"Interface down", "Power supply fault"}
	var cookies [2]string
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		for n := range lane + 1 {
			_, err := ops.RecordSyslogForPatternSource(ctx, device.SyslogEvent{TenantID: tenant, Device: router,
				ObservedAt: left.Add(time.Duration(n+1) * time.Second), Message: messages[lane]}, device.SyslogPatternSource{Family: families[lane]})
			if err != nil {
				t.Fatal(err)
			}
		}
		cookies[lane] = issueDeviceOperatorSession(t, f, tenant)
	}
	seedInterfaceRoleMCPConsent(f)
	assert := func(lane int, page deviceSyslogPatternPage) {
		t.Helper()
		if !page.From.Equal(left) || !page.To.Equal(right) || page.IndexedRows != int64(lane+1) || page.UnindexedRows != 0 ||
			page.TotalPatterns != 1 || len(page.Patterns) != 1 {
			t.Fatalf("pattern result lost the complete tenant interval: %+v", page)
		}
		pattern := page.Patterns[0]
		if pattern.Kind != kinds[lane] || pattern.ID == "" || pattern.Count != int64(lane+1) ||
			!pattern.FirstAt.Equal(left.Add(time.Second)) || !pattern.LastAt.Equal(left.Add(time.Duration(lane+1)*time.Second)) {
			t.Fatalf("operator surface changed the original scoped pattern count: %+v", pattern)
		}
	}
	assertJSON := func(lane int, body []byte) {
		t.Helper()
		var page deviceSyslogPatternPage
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatal(err)
		}
		assert(lane, page)
	}
	for lane, tenant := range f.tenants {
		assertJSON(lane, callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, route+"?"+input.Encode(), nil, http.StatusOK))
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		sdkPage, err := client.ListDeviceSyslogPatterns(t.Context(), sdk.ListDeviceSyslogPatternsRequest{From: &from, To: &to, Device: &router})
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(sdkPage)
		if err != nil {
			t.Fatal(err)
		}
		assertJSON(lane, body)
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		var stdout, stderr bytes.Buffer
		args := []string{"--json", "device", "syslog-patterns", "--query", "from=" + from, "--query", "to=" + to, "--query", "device=" + router}
		if code := cli.RunWithStdin(args, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
			t.Fatal("CLI device pattern read failed", code, stderr.String())
		}
		assertJSON(lane, stdout.Bytes())
		for _, theme := range []string{"light", "dark"} {
			t.Run(tenant+"/"+theme, func(t *testing.T) {
				testsupport.RenderUI(t, testsupport.RenderSpec{URL: socket.URL + "/ui/planes/device",
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookies[lane]}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 45000,
					Absent: []string{captions[1-lane]},
					Controls: []testsupport.RenderControl{
						{Role: "table", Name: "Syslog patterns"},
						{Role: "cell", Name: captions[lane], Within: `table:has(caption:text-is("Syslog patterns"))`},
					},
				})
			})
		}
	}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for lane, tenant := range f.tenants {
			var page deviceSyslogPatternPage
			args := map[string]any{"from": from, "to": to, "device": router}
			call(tenant, "device_syslog_patterns", args, &page, true)
			assert(lane, page)
			args["tenant_id"] = f.tenants[1-lane]
			call(tenant, "device_syslog_patterns", args, nil, false)
		}
	}
}

func TestDeviceSyslogPatternsServeWeeklyFrequency(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	ops := device.NewPostgresOpsStore(f.pool)
	f.server.WithDeviceOps(ops)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "syslog-frequency-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	const route = "/v1/device/syslog/patterns"
	edge := "edge-overlap"
	now := time.Now().UTC()
	right := now.Truncate(time.Hour)
	left := right.Add(-time.Hour)
	from, to, weekly := left.Format(time.RFC3339), right.Format(time.RFC3339), "weekly"
	var ids, cookies [2]string
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		event := device.SyslogEvent{TenantID: tenant, Device: edge,
			Message: "%LINK-3-UPDOWN: Interface Ethernet7/2, changed state to down"}
		cookies[lane] = issueDeviceOperatorSession(t, f, tenant)
		write := func(at time.Time) {
			t.Helper()
			event.ObservedAt = at
			stored, err := ops.RecordSyslogForPatternSource(ctx, event, device.SyslogPatternSource{Family: "cisco_ios"})
			if err != nil || (ids[lane] != "" && ids[lane] != stored.PatternID) {
				t.Fatal("did not preserve this tenant's original pattern", err)
			}
			ids[lane] = stored.PatternID
		}
		for _, start := range []time.Time{left, right} {
			for week := range 5 {
				count := 3
				if lane == 0 && week == 0 {
					count = 20
				}
				window := start.AddDate(0, 0, -7*week)
				for n := range count {
					write(window.Add(time.Duration(n+30) * time.Second))
				}
				if lane == 1 && week >= 3 {
					f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
						_, err := sc.Q.Exec(ctx, "INSERT INTO device_syslog(tenant_id,device,observed_at,message) VALUES ($1,$2,$3,$4)",
							tenant, edge, window.Add(time.Minute), "legacy row for coverage")
						return err
					})
				}
			}
		}
		write(now)
	}
	if ids[0] == "" || ids[0] == ids[1] {
		t.Fatal("identical original messages received shared tenant pattern keys")
	}
	seedInterfaceRoleMCPConsent(f)
	assert := func(lane int, page deviceSyslogPatternPage) {
		t.Helper()
		frequency := page.Frequency
		if frequency == nil || frequency.RequiredWeeks != 3 || len(page.Patterns) != 1 || page.Patterns[0].ID != ids[lane] ||
			!page.From.Equal(left) || !page.To.Equal(right) {
			t.Fatalf("comparison lost original tenant pattern or clocks: %+v", page)
		}
		if lane == 1 {
			if frequency.State != anomaly.SeasonalWarming || frequency.ComparableWeeks != 2 || frequency.Band != nil {
				t.Fatalf("legacy and empty weeks became observed counts: %+v", frequency)
			}
			return
		}
		if frequency.State != anomaly.SeasonalUp || frequency.ComparableWeeks != 4 || frequency.Band == nil ||
			frequency.Band.Current != "20" || frequency.Band.Median != "3" || len(frequency.Citations) < 2 {
			t.Fatalf("original healthy band and event surge changed: %+v", frequency)
		}
		for _, citation := range frequency.Citations {
			ref, err := url.Parse(citation.Ref)
			if err != nil || ref.Path != route || ref.Query().Get("pattern_id") != ids[lane] ||
				ref.Query().Get("device") != edge || ref.Query().Get("from") == "" || ref.Query().Get("to") == "" {
				t.Fatalf("comparison lost an original scoped clock citation: %+v", citation)
			}
		}
	}
	want := [2]string{"Frequency is above the expected range.", "More comparable weeks are needed."}
	for lane, tenant := range f.tenants {
		input := url.Values{"from": {from}, "to": {to}, "device": {edge}, "pattern_id": {ids[lane]}, "frequency": {weekly}}
		decode := func(body []byte) (page deviceSyslogPatternPage) {
			t.Helper()
			if err := json.Unmarshal(body, &page); err != nil {
				t.Fatal(err)
			}
			return page
		}
		path := route + "?" + input.Encode()
		assert(lane, decode(callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, path, nil, http.StatusOK)))
		foreign := decode(callSeasonalAPI(t, socket, f.tokens[f.tenants[1-lane]], http.MethodGet, path, nil, http.StatusOK))
		if foreign.Frequency == nil || foreign.Frequency.State != anomaly.SeasonalUnavailable || len(foreign.Patterns) != 0 {
			t.Fatal("foreign pattern selected an observation")
		}
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		sdkPage, err := client.ListDeviceSyslogPatterns(t.Context(), sdk.ListDeviceSyslogPatternsRequest{
			From: &from, To: &to, Device: &edge, PatternId: &ids[lane], Frequency: &weekly,
		})
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(sdkPage)
		if err != nil {
			t.Fatal(err)
		}
		assert(lane, decode(body))
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		var stdout, stderr bytes.Buffer
		args := []string{"--json", "device", "syslog-patterns", "--query", "from=" + from, "--query", "to=" + to,
			"--query", "device=" + edge, "--query", "pattern_id=" + ids[lane], "--query", "frequency=" + weekly}
		if code := cli.RunWithStdin(args, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
			t.Fatal("CLI device pattern frequency read failed", code, stderr.String())
		}
		assert(lane, decode(stdout.Bytes()))
		for _, theme := range []string{"light", "dark"} {
			t.Run(tenant+"/"+theme, func(t *testing.T) {
				testsupport.RenderUI(t, testsupport.RenderSpec{URL: socket.URL + "/ui/planes/device",
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookies[lane]}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 45000,
					Absent: []string{want[1-lane]}, RetrySafe: true,
					Steps: []testsupport.RenderStep{{Click: "Compare", Within: `table:has(caption:text-is("Syslog patterns"))`,
						Expect: []string{want[lane]}}},
				})
			})
		}
	}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for lane, tenant := range f.tenants {
			var page deviceSyslogPatternPage
			call(tenant, "device_syslog_patterns", map[string]any{
				"from": from, "to": to, "device": edge, "pattern_id": ids[lane], "frequency": weekly,
			}, &page, true)
			assert(lane, page)
		}
	}
	missingPattern := url.Values{"from": {from}, "to": {to}, "frequency": {weekly}}
	callSeasonalAPI(t, socket, f.tokens[f.tenants[0]], http.MethodGet, route+"?"+missingPattern.Encode(), nil, http.StatusUnprocessableEntity)
}
