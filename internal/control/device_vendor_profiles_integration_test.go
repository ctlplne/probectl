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
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/crypto"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestVendorProfileMetricsUseOriginalTenantReadings(t *testing.T) {
	promURL := os.Getenv("PROBECTL_PROM_URL")
	if promURL == "" {
		testsupport.SkipOrFatal(t, "set PROBECTL_PROM_URL to the integration remote-write receiver")
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
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "vendor-profile-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	address := "192.0.2.50"
	at := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Second)
	provenance := &devicev1.DeviceSNMPMetricSource{ProfileId: "hpe-aruba-5406r", SystemObjectId: ".1.3.6.1.4.1.11.2.3.7.11.160",
		MibObject: "FAN-MIB::hpicfFanState", Oid: ".1.3.6.1.4.1.11.2.14.11.5.1.54.2.1.1.4"}
	names, values := [2]string{"Alpha vendor chassis", "Beta vendor chassis"}, [2]float64{0, 5}
	var cookies [2]string
	for lane, tenant := range f.tenants {
		sample := pipeline.DeviceMetricToSeries(&devicev1.DeviceMetric{TenantId: tenant, AgentId: "profile-sender", DeviceAddress: address,
			DeviceName: names[lane], Source: "snmp", Component: "4", Name: "probectl.device.fan.state", Value: values[lane],
			Unit: "1", TimeUnixNano: at.UnixNano(), SnmpMetricSource: provenance})
		if err := writer.Write(t.Context(), []tsdb.Series{sample}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := writer.DeleteTenant(ctx, tenant); err != nil {
				t.Error(err)
			}
		})
		cookies[lane] = issueDeviceOperatorSession(t, f, tenant)
	}
	seedInterfaceRoleMCPConsent(f)
	check := func(lane int, result nativeDeviceMetrics, exactNumericOIDs bool) {
		t.Helper()
		if len(result.Items) != 1 || !result.MetricsRunning {
			t.Fatal("read did not return exactly the tenant's admitted metric", result)
		}
		got := result.Items[0]
		if got.Value != values[lane] || got.Component != "4" || !got.LastSeen.Equal(at) ||
			got.SNMPProfile != provenance.ProfileId || got.SNMPMIBObject != provenance.MibObject ||
			got.SNMPSystemOID == "" || got.SNMPOID == "" || got.SNMPUnit != "1" {
			t.Fatal("profile provenance, exact value or instance did not survive the authorized read", got)
		}
		if exactNumericOIDs && (got.SNMPSystemOID != provenance.SystemObjectId || got.SNMPOID != provenance.Oid) {
			t.Fatal("an exact device reader altered the stored numeric OID", got)
		}
	}
	for lane, tenant := range f.tenants {
		body := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, "/v1/device/metrics?device="+address, nil, http.StatusOK)
		var result nativeDeviceMetrics
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		check(lane, result, true)
		check(lane, readVendorProfileCLI(t, f, socket, tenant, ca, address), true)
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		sdkResult, err := client.ListDeviceMetricSummaries(t.Context(), sdk.ListDeviceMetricSummariesRequest{Device: &address})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(sdkResult)
		if err != nil {
			t.Fatal(err)
		}
		result = nativeDeviceMetrics{}
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		check(lane, result, true)
		for _, theme := range []string{"light", "dark"} {
			t.Run(tenant+"/"+theme, func(t *testing.T) {
				testsupport.RenderUI(t, testsupport.RenderSpec{URL: socket.URL + "/ui/planes/device",
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookies[lane]}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 45000,
					Expect: []string{names[lane], provenance.ProfileId, provenance.SystemObjectId, provenance.MibObject, provenance.Oid},
					Absent: []string{names[1-lane]}, Controls: []testsupport.RenderControl{
						{Role: "table", Name: "Vendor profile readings"},
						{Role: "cell", Name: strconv.FormatFloat(values[lane], 'f', -1, 64), Within: `table:has(caption:text-is("Vendor profile readings"))`},
					},
				})
			})
		}
	}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for lane, tenant := range f.tenants {
			var result nativeDeviceMetrics
			call(tenant, "device_metrics", map[string]any{}, &result, true)
			// The AI adapter inherits full egress redaction for sender strings,
			// including dot-separated values that match address patterns.
			check(lane, result, false)
			call(tenant, "device_metrics", map[string]any{"tenant_id": f.tenants[1-lane]}, nil, false)
		}
	}
}

func issueDeviceOperatorSession(t *testing.T, f *roleExplanationAPIFixture, tenant string) string {
	t.Helper()
	var grants []auth.PermissionGrant
	f.in(tenant, func(ctx context.Context, scope tenancy.Scope) error {
		if err := (store.Roles{}).AddPermission(ctx, scope, f.roles[tenant], "ai.query"); err != nil {
			return err
		}
		var err error
		grants, err = (store.Permissions{}).ForSubject(ctx, scope, "user", f.users[tenant])
		return err
	})
	cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant],
		Email: "device-operator@local.invalid", DisplayName: "Device operator", AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
	if err != nil {
		t.Fatal(err)
	}
	return cookie
}

func readVendorProfileCLI(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, tenant, ca, address string) nativeDeviceMetrics {
	t.Helper()
	getenv := func(key string) string {
		return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
	}
	var stdout, stderr bytes.Buffer
	if code := cli.RunWithStdin([]string{"--json", "device", "metrics", "--query", "device=" + address}, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
		t.Fatal("CLI device metric read failed", code, stderr.String())
	}
	var result nativeDeviceMetrics
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
