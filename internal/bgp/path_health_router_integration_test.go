// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	pathstore "github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/pkg/sdk"
)

type routerPathHealth struct {
	ContextID string `json:"context_id"`
	Items     []struct {
		IP         string                   `json:"ip"`
		Resolution entity.Resolution        `json:"resolution"`
		Health     *sdk.PathInterfaceHealth `json:"health"`
	} `json:"items"`
}

// Reuse the existing issued-sender/four-store FRR lab. Routes, trace replies,
// interface identities, polls and transport are real. Only the error counter
// is deliberately planted in Net-SNMP's existing override facility; this does
// not claim a physical CRC fault. Configs are explicitly operator-submitted.
// Served both-theme and shipped-process/native lifecycle evidence stays separate.
func proveRouterPathHealth(t *testing.T, st *shipped.Stack, lab *routingLab, first, second edgeFlowRegistration, agents []string, target, primary, community string) {
	t.Helper()
	from := time.Now().UTC().Add(-time.Second)
	// Own one exact host route through the router, rather than the Docker
	// bridge's direct connected route to the destination. Preserve other routes.
	route := target + "/32"
	if out, err := exec.Command("ip", "route", "show", "exact", route).Output(); err != nil || len(strings.TrimSpace(string(out))) != 0 {
		t.Fatal("owned path destination already has a host route", err)
	}
	pathLabPrivileged(t, "ip", "route", "add", route, "via", primary)
	t.Cleanup(func() { pathLabPrivileged(t, "ip", "route", "del", route, "via", primary) })
	pathLabPrivileged(t, "setcap", "cap_net_raw+ep", st.Control)
	st.RestartControl(t, "path-router-raw", nil)

	registrations := []edgeFlowRegistration{first, second}
	tests := make([]string, len(registrations))
	responder := ""
	for lane, reg := range registrations {
		tests[lane], responder = discoverRouterHealthPath(t, st, reg, target, primary)
	}
	for lane, reg := range registrations {
		code, _ := st.Do(t, reg.cookie, http.MethodGet, "/v1/tests/"+tests[1-lane]+"/path/entities?include_health=true", nil)
		if code != http.StatusNotFound {
			t.Fatal("foreign tenant selected the other physical path binding", code)
		}
	}
	sidecar := lab.name + "-rtr-a-snmp"
	index := queryEdgeSNMP(t, sidecar, community, ".1.3.6.1.2.1.4.20.1.2."+responder)
	if value, err := strconv.ParseUint(index, 10, 32); err != nil || value == 0 {
		t.Fatal("observed trace responder has no actual SNMP interface index", err)
	}
	config := lab.docker(t, "exec", sidecar, "cat", "/etc/snmp/snmpd.conf")
	t.Cleanup(func() { setRouterPathError(t, lab, sidecar, config, index, "") })
	archiveRouterPathConfigs(t, st, lab, registrations, agents, primary)
	frozenWindows := make([]time.Time, len(registrations))
	originals := make([]*sdk.PathInterfaceHealth, len(registrations))
	for lane, reg := range registrations {
		label := "primary"
		if lane == 1 {
			label = "paired"
		}
		t.Run(label, func(t *testing.T) {
			setRouterPathError(t, lab, sidecar, config, index, "100")
			read := func(to time.Time) (*sdk.PathInterfaceHealth, bool) {
				query := url.Values{"include_health": {"true"}, "health_from": {from.Format(time.RFC3339Nano)}, "health_to": {to.Format(time.RFC3339Nano)}}
				code, body := st.Do(t, reg.cookie, http.MethodGet, "/v1/tests/"+tests[lane]+"/path/entities?"+query.Encode(), nil)
				var result routerPathHealth
				if code != http.StatusOK || json.Unmarshal(body, &result) != nil || result.ContextID != reg.contextID {
					return nil, false
				}
				for _, item := range result.Items {
					if item.IP == responder && item.Resolution.Scope.TenantID == reg.tenantID && item.Resolution.EntityID == reg.deviceID && item.Health != nil {
						return item.Health, true
					}
				}
				return nil, false
			}
			shipped.Await(t, "two original baseline SNMP counter polls", time.Minute, func() bool {
				health, ok := read(time.Now().UTC())
				if !ok {
					return false
				}
				for _, counter := range health.Counters {
					if counter.Metric == "probectl.device.if.in.errors" && counter.Value == "100" && counter.PreviousValue == "100" && counter.CaptureKey != "" && counter.PreviousCaptureKey != "" {
						return true
					}
				}
				return false
			})
			setRouterPathError(t, lab, sidecar, config, index, "230")
			var frozen time.Time
			shipped.Await(t, "original planted SNMP error climb on the actual trace responder", time.Minute, func() bool {
				health, ok := read(time.Now().UTC())
				if !ok {
					return false
				}
				for _, counter := range health.Counters {
					if counter.Metric == "probectl.device.if.in.errors" && counter.Value == "230" && counter.PreviousValue == "100" && counter.MinimumDelta == "130" && counter.RateNumerator != "" && counter.RateDenominator != "" {
						var err error
						frozen, err = time.Parse(time.RFC3339Nano, counter.PollCompletedAt)
						return err == nil && counter.CaptureKey != counter.PreviousCaptureKey
					}
				}
				return false
			})
			health, ok := read(frozen)
			if !ok || health.Status != "observed_originals" || health.AgentId != agents[lane] || health.DeviceId != reg.deviceID || health.SourceRef != primary || len(health.ConfigChanges) != 2 || health.ConfigChanges[1].PreviousId != health.ConfigChanges[0].Id {
				t.Fatal("real path health lost its original tenant source or operator archives")
			}
			frozenWindows[lane], originals[lane] = frozen, health
			code, body := st.Do(t, reg.cookie, http.MethodPost, "/v1/ai/ask", map[string]any{"question": "Explain the original path interface error observations and operator archive changes without assuming causation.", "subject": map[string]string{"path_test_id": tests[lane]}, "range": map[string]string{"start": from.Format(time.RFC3339Nano), "end": frozen.Format(time.RFC3339Nano)}})
			var answer ai.Answer
			if code != http.StatusOK || json.Unmarshal(body, &answer) != nil || len(answer.Evidence) != 1 || !answer.RootCauseGrounded || len(answer.RootCauseCitations) == 0 || answer.RootCauseCitations[0].EvidenceID != answer.Evidence[0].ID {
				t.Fatal("real routed SNMP path RCA did not cite its original evidence", code)
			}
			encoded, err := json.Marshal(answer.Evidence[0].Fields["path_health"])
			var cited routerPathHealth
			if err != nil || json.Unmarshal(encoded, &cited) != nil || cited.ContextID != reg.contextID {
				t.Fatal("RCA changed the physical path evidence context", err)
			}
			matched := false
			for _, item := range cited.Items {
				if item.Health == nil || item.Health.InterfaceId != health.InterfaceId || item.Health.DeviceId != reg.deviceID {
					continue
				}
				if len(item.Health.ConfigChanges) != 2 || item.Health.ConfigChanges[1].Id != health.ConfigChanges[1].Id {
					t.Fatal("cited path lost original operator config identity")
				}
				for _, counter := range item.Health.Counters {
					if counter.Metric == "probectl.device.if.in.errors" && counter.Value == "230" && counter.PreviousValue == "100" && counter.MinimumDelta == "130" && counter.CaptureKey != "" && counter.PreviousCaptureKey != "" {
						matched = true
					}
				}
			}
			if !matched {
				t.Fatal("cited path omitted the original planted error climb")
			}
			for _, wire := range []string{"2026-07-28", "2025-11-25"} {
				t.Run("stdio/"+wire, func(t *testing.T) {
					proveRouterPathStdio(t, st, reg, tests[lane], tests[1-lane], from, frozen, health, wire)
				})
			}
			other := registrations[1-lane]
			for _, theme := range []string{"light", "dark"} {
				t.Run(theme, func(t *testing.T) {
					renderRouterPathHealth(t, st, reg, other, tests[lane], from, frozen, health, theme)
				})
			}
		})
	}
	if t.Failed() {
		return
	}
	t.Run("restart", func(t *testing.T) {
		st.RestartControl(t, "path-router-originals-restart", nil)
		for lane, reg := range registrations {
			query := url.Values{"include_health": {"true"}, "health_from": {from.Format(time.RFC3339Nano)}, "health_to": {frozenWindows[lane].Format(time.RFC3339Nano)}}
			code, body := st.Do(t, reg.cookie, http.MethodGet, "/v1/tests/"+tests[lane]+"/path/entities?"+query.Encode(), nil)
			if code != http.StatusOK {
				t.Fatal("original routed path did not survive the control restart", code)
			}
			verifyRouterPathOriginals(t, body, reg, originals[lane])
		}
	})
}

func pathLabPrivileged(t *testing.T, program string, args ...string) {
	t.Helper()
	if os.Geteuid() != 0 {
		args = append([]string{"-n", program}, args...)
		program = "sudo"
	}
	if out, err := exec.Command(program, args...).CombinedOutput(); err != nil {
		t.Fatalf("owned path fixture command %s: %v %.300s", program, err, out)
	}
}

func discoverRouterHealthPath(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, target, primary string) (string, string) {
	t.Helper()
	code, body := st.Do(t, reg.cookie, http.MethodPost, "/v1/tests", map[string]any{"name": "Routed interface health", "type": "icmp", "target": target, "interval_seconds": 60, "timeout_seconds": 3, "enabled": true, "params": map[string]string{"allow_private_targets": "true"}})
	var test struct{ ID string }
	if code != http.StatusCreated || json.Unmarshal(body, &test) != nil || test.ID == "" {
		t.Fatal("create owned routed path test", code)
	}
	code, _ = st.Do(t, reg.cookie, http.MethodPut, "/v1/tests/"+test.ID+"/entity-context", map[string]string{"context_id": reg.contextID})
	if code != http.StatusOK {
		t.Fatal("bind routed path to its original tenant context", code)
	}
	time.Sleep(5 * time.Millisecond) // distinct from ClickHouse's binding-clock millisecond
	code, body = st.Do(t, reg.cookie, http.MethodPost, "/v1/tests/"+test.ID+"/path", nil)
	var trace pathstore.Path
	if code != http.StatusOK || json.Unmarshal(body, &trace) != nil || !trace.DestinationReached || trace.MeasurementFidelity == nil || trace.MeasurementFidelity.AcquisitionMode != "raw_icmp" || trace.MeasurementFidelity.HopVisibility != "full" {
		t.Fatal("routed path did not execute a complete raw ICMP traceroute", code)
	}
	for _, hop := range trace.Hops {
		for _, node := range hop.Nodes {
			if node.IP == primary && node.IP != target {
				return test.ID, node.IP
			}
		}
	}
	t.Fatal("actual trace did not pass through the monitored FRR router")
	return "", ""
}

func setRouterPathError(t *testing.T, lab *routingLab, sidecar, original, index, value string) {
	t.Helper()
	config := original
	if value != "" {
		// Net-SNMP documents Counter32 overrides and HUP reloads at
		// https://www.net-snmp.org/docs/man/snmpd.conf.html .
		config += "\noverride .1.3.6.1.2.1.2.2.1.14." + index + " counter " + value + "\n"
	}
	file := filepath.Join(t.TempDir(), "snmpd.conf")
	if err := os.WriteFile(file, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	lab.docker(t, "cp", file, sidecar+":/etc/snmp/snmpd.conf")
	lab.docker(t, "kill", "--signal", "HUP", sidecar)
}

func archiveRouterPathConfigs(t *testing.T, st *shipped.Stack, lab *routingLab, registrations []edgeFlowRegistration, agents []string, primary string) {
	t.Helper()
	for version := range 2 {
		description := "probectl-path-health-baseline"
		if version == 1 {
			description = "probectl-path-health-changed"
		}
		// A CLI hostname command did not establish changed running content.
		// Require a daemon-visible interface line before archiving either state.
		lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "configure terminal", "-c", "interface lo", "-c", "description "+description, "-c", "end")
		content := lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "show running-config")
		if !strings.Contains(content, "description "+description) {
			t.Fatal("FRR did not expose the requested owned interface description in its running config")
		}
		for lane, reg := range registrations {
			code, body := st.Do(t, reg.cookie, http.MethodPost, "/v1/device/configs", map[string]any{"device": "same-router", "source": "operator-submitted", "content": content, "binding": map[string]string{"context_id": reg.contextID, "device_entity_id": reg.deviceID, "agent_id": agents[lane], "source_ref": primary}})
			var archive sdk.DeviceConfigVersion
			decodeErr := json.Unmarshal(body, &archive)
			if code != http.StatusCreated || decodeErr != nil || archive.Version != version+1 || archive.Binding == nil || archive.Binding.DeviceEntityId != reg.deviceID || version == 1 && (archive.Drifted == nil || !*archive.Drifted) {
				matching := archive.Binding != nil && archive.Binding.DeviceEntityId == reg.deviceID
				t.Fatalf("operator FRR archive lost its exact device/source stream: status=%d decoded=%t expected_version=%d actual_version=%d bound=%t matching_device=%t drift_present=%t drifted=%t", code, decodeErr == nil, version+1, archive.Version, archive.Binding != nil, matching, archive.Drifted != nil, archive.Drifted != nil && *archive.Drifted)
			}
		}
	}
}

func renderRouterPathHealth(t *testing.T, st *shipped.Stack, reg, other edgeFlowRegistration, test string, from, to time.Time, health *sdk.PathInterfaceHealth, theme string) {
	t.Helper()
	var climb sdk.PathHealthCounter
	for _, counter := range health.Counters {
		if counter.Metric == "probectl.device.if.in.errors" {
			climb = counter
		}
	}
	if climb.CaptureKey == "" || climb.PreviousCaptureKey == "" {
		t.Fatal("served path has no original error-climb receipts")
	}
	query := url.Values{"ctx_v": {"1"}, "ctx_expires": {time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)}, "ctx_filter": {"path_test:" + test}, "ctx_from": {from.Format(time.RFC3339Nano)}, "ctx_to": {to.Format(time.RFC3339Nano)}}
	errorRow := `table:has(> caption:text-is("Original directional interface counters")) tbody tr:has-text("in errors")`
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL: st.BaseURL + "/ui/path?" + query.Encode(), Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: reg.cookie}},
		CAFile: st.CAFile, TrustCertFiles: st.TrustCerts(), Theme: theme, Accessibility: true,
		Expect: []string{"Selected interval interface health"}, Absent: []string{other.deviceID, other.contextID},
		Steps: []testsupport.RenderStep{
			{Click: "Polled interface health preview · observed originals", Summary: true, Expect: []string{health.InterfaceId, health.DeviceId, health.ConfigChanges[1].Id}},
			{Click: "Counter words and receipts", Summary: true, Within: errorRow, ExpectWithin: errorRow, Expect: []string{"Previous 100 · latest 230 · width 32", climb.CaptureKey, climb.PreviousCaptureKey}},
			{Click: "Explain this view", Expect: []string{"Original path observations"}},
			{Click: "Original path observations", Summary: true, ExpectWithin: `[aria-label="Complete original path evidence"]`, Expect: []string{health.InterfaceId, health.ConfigChanges[1].Id, climb.CaptureKey, climb.PreviousCaptureKey}},
		},
	})
}
