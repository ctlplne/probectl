// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/pkg/sdk"
)

type routerChangeProbe struct {
	agent, test, serial string
}

// The shipped synthetic agent collects real routed echo replies. Its ordinary
// SVID, separate evidence SVID and signed current test bundle are all real;
// direct SQL below only reads resulting receipts through application-role RLS.
func startRouterChangeProbe(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, target, label string) routerChangeProbe {
	t.Helper()
	probe := routerChangeProbe{agent: gouuid.NewString()}
	name := "change-rtt-" + label
	ordinary := st.EnrollAgent(t, reg.tenantID, probe.agent, name)
	csr, key, err := crypto.CreateCSR(name + "-evidence")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	code, body := st.Do(t, reg.cookie, http.MethodPost, "/v1/agents/enroll-tokens", map[string]any{"name": name + "-evidence", "agent_id": probe.agent, "ttl_seconds": 600})
	var token struct{ Token string }
	if code != http.StatusCreated || json.Unmarshal(body, &token) != nil || token.Token == "" {
		t.Fatal("mint actual probe evidence identity", code)
	}
	code, body = st.Do(t, reg.cookie, http.MethodPost, "/v1/collectors/register", map[string]string{"token": token.Token, "plane": "entity", "hostname": name, "csr_pem": string(csr)})
	var registration struct {
		TenantID string           `json:"tenant_id"`
		AgentID  string           `json:"agent_id"`
		SVID     *enroll.Identity `json:"svid"`
	}
	if code != http.StatusCreated || json.Unmarshal(body, &registration) != nil || registration.SVID == nil || registration.TenantID != reg.tenantID || registration.AgentID != probe.agent || registration.SVID.SPIFFEID != crypto.EntitySPIFFEID(reg.tenantID, probe.agent) {
		t.Fatal("restricted probe evidence identity changed tenant or sender", code)
	}
	probe.serial = registration.SVID.Serial
	cert, private, ca := writeRouterEvidenceFiles(t, st, name+"-evidence", registration.SVID.CertPEM, key)
	code, body = st.Do(t, reg.cookie, http.MethodPost, "/v1/tests", map[string]any{"name": name, "type": "icmp", "target": target, "interval_seconds": 10, "timeout_seconds": 2, "enabled": true, "params": map[string]string{"allow_private_targets": "true", "count": "3"}})
	var test struct{ ID string }
	if code != http.StatusCreated || json.Unmarshal(body, &test) != nil || test.ID == "" {
		t.Fatal("create actual routed RTT test", code)
	}
	probe.test = test.ID
	if code, _ = st.Do(t, reg.cookie, http.MethodPut, "/v1/tests/"+probe.test+"/entity-context", map[string]string{"context_id": reg.contextID}); code != http.StatusOK {
		t.Fatal("assign actual RTT test context", code)
	}
	requireRoleSourceBinding(t, st, reg, map[string]string{"agent_id": probe.agent, "source_kind": "path_agent", "source_ref": probe.test, "context_id": reg.contextID, "anchor_entity_id": reg.deviceID})
	configuration := fmt.Sprintf(`apiVersion: probectl.io/agent/v1
control_plane:
  grpc_addr: %q
tls:
  cert_file: %q
  key_file: %q
  ca_file: %q
  server_name: localhost
identity:
  server: %q
agent:
  hostname: %q
  capabilities: [icmp]
  labels: {site: %q}
  heartbeat_interval: 1s
buffer:
  dir: %q
  max_records: 100
  drain_pace: 100ms
test_sync:
  enabled: true
  interval: 2s
  allowed_types: [icmp]
  allow_private_targets: true
evidence:
  control_addr: %q
  cert_file: %q
  key_file: %q
  ca_file: %q
  server_name: localhost
`, st.AgentAddr, filepath.Join(ordinary, "cert.pem"), filepath.Join(ordinary, "key.pem"), st.CAFile, st.BaseURL, name, name, filepath.Join(st.Dir, name+"-buffer"), st.AgentAddr, cert, private, ca)
	file := filepath.Join(st.Dir, name+".yaml")
	if err := os.WriteFile(file, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	st.StartProcess(t, name, st.Agent, []string{"-config", file}, []string{"PROBECTL_AGENT_METRICS_ADDR=127.0.0.1:0"})
	return probe
}

func awaitRouterChangeProbe(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, probe routerChangeProbe, after time.Time) time.Time {
	t.Helper()
	pool, err := pgxpool.New(t.Context(), st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var completed time.Time
	shipped.Await(t, "actual sender-bound routed RTT receipt", time.Minute, func() bool {
		err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(reg.tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
				return err
			}
			var raw []byte
			if err := sc.Q.QueryRow(ctx, `SELECT icmp_measurement FROM entity_evidence WHERE tenant_id=$1 AND context_id=$2 AND entity_id=$3 AND agent_id=$4 AND configured_ref=$5 AND sender_serial=$6 AND source_ref='icmp:configured-test' ORDER BY observed_at DESC,id LIMIT 1`, reg.tenantID, reg.contextID, reg.deviceID, probe.agent, probe.test, probe.serial).Scan(&raw); err != nil {
				return err
			}
			var original entity.ICMPMeasurement
			if err := json.Unmarshal(raw, &original); err != nil {
				return err
			}
			if original.Version == 3 && original.RoundTrips != nil && original.Replies > 0 && len(original.RoundTrips.Nanos) == int(original.Replies) && original.ReadComplete && !original.Canceled && !original.IOFailed && !original.StartedAt.Before(after) && original.CompletedAt.After(after) {
				completed = original.CompletedAt
			}
			return nil
		})
		return err == nil && !completed.IsZero()
	})
	return completed
}

func proveRouterOriginalChangeEffects(t *testing.T, st *shipped.Stack, registrations []edgeFlowRegistration, probes []routerChangeProbe, archives [][]sdk.DeviceConfigVersion, from, changed time.Time) {
	t.Helper()
	ids := make([]string, len(registrations))
	for lane := range registrations {
		ids[lane] = "device-config:" + archives[lane][1].Id
	}
	proveRouterOriginalEffects(t, st, registrations, probes, ids, from, changed)
}

func proveRouterOriginalEffects(t *testing.T, st *shipped.Stack, registrations []edgeFlowRegistration, probes []routerChangeProbe, ids []string, from, changed time.Time) {
	t.Helper()
	for lane, reg := range registrations {
		label := []string{"primary", "paired"}[lane]
		t.Run(label, func(t *testing.T) {
			to := awaitRouterChangeProbe(t, st, reg, probes[lane], changed).Add(time.Microsecond)
			id := ids[lane]
			query := url.Values{"from": {from.Format(time.RFC3339Nano)}, "to": {to.Format(time.RFC3339Nano)}}
			var result sdk.ChangeEffectsResponse
			shipped.Await(t, "actual RTT/change/flow originals in one comparison", time.Minute, func() bool {
				code, body := st.Do(t, reg.cookie, http.MethodGet, "/v1/changes/"+id+"/effects?"+query.Encode(), nil)
				if code != http.StatusOK || json.Unmarshal(body, &result) != nil || result.Original.Id != id || len(result.Tests) != 1 {
					return false
				}
				test := result.Tests[0]
				if test.TestId != probes[lane].test || test.AgentId != probes[lane].agent || test.Before.Latency == nil || test.After.Latency == nil || len(test.Before.Observations) == 0 || len(test.After.Observations) == 0 {
					return false
				}
				return lane != 0 || result.Before.ObservedTotals.ScaledBytes != "" && result.After.ObservedTotals.ScaledBytes != "" && len(result.Before.Captures) > 0 && len(result.After.Captures) > 0
			})
			if lane == 1 && (result.Before.ObservedTotals.ScaledBytes != "" || result.After.ObservedTotals.ScaledBytes != "") {
				t.Fatal("paired reader borrowed the primary physical flow source")
			}
			verifyRouterOriginalTestPeriod(t, st, reg, probes[lane], result.Tests[0].Before)
			verifyRouterOriginalTestPeriod(t, st, reg, probes[lane], result.Tests[0].After)
			other := 1 - lane
			if code, _ := st.Do(t, registrations[other].cookie, http.MethodGet, "/v1/changes/"+id+"/effects?"+query.Encode(), nil); code == http.StatusOK {
				t.Fatal("foreign reader selected another tenant's original change effect")
			}
			proveRouterChangeClients(t, st, reg, probes[lane], id, ids[other], result)
			params := url.Values{"view": {"changes"}, "changes_from": {from.Format(time.RFC3339Nano)}, "changes_to": {to.Format(time.RFC3339Nano)}, "change_id": {id}}
			for _, theme := range []string{"light", "dark"} {
				t.Run(theme, func(t *testing.T) {
					steps := []testsupport.RenderStep{{Click: "Compare original measurements", Expect: []string{probes[lane].test, result.Tests[0].Before.Latency.MeanNanos, result.Tests[0].After.Latency.MeanNanos}}}
					if strings.HasPrefix(id, "device-config:") {
						steps = append(steps, testsupport.RenderStep{Click: "Open exact redacted configuration diff", Role: "link", Expect: []string{"same-router: version 1 → 2", "probectl-path-health-baseline", "probectl-path-health-changed", "Complete comparison"}})
					}
					rendered := testsupport.RenderUI(t, testsupport.RenderSpec{URL: st.BaseURL + "/ui/incidents?" + params.Encode(), Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: reg.cookie}}, TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile, Theme: theme, Accessibility: true,
						Expect: []string{"Change timeline", "Original before and after"},
						Steps:  steps})
					if rendered.Accessibility == nil {
						t.Fatal("served change-effects accessibility proof was missing or unexecuted")
					}
				})
			}
		})
	}
}

func verifyRouterOriginalTestPeriod(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, probe routerChangeProbe, period sdk.ChangeEffectTestPeriod) {
	t.Helper()
	from, err := time.Parse(time.RFC3339Nano, period.From)
	if err != nil {
		t.Fatal(err)
	}
	to, err := time.Parse(time.RFC3339Nano, period.To)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(t.Context(), st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var sum, samples, sent, replied big.Int
	one := big.NewInt(1)
	err = tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(reg.tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
			return err
		}
		for _, observation := range period.Observations {
			var raw []byte
			if err := sc.Q.QueryRow(ctx, `SELECT icmp_measurement FROM entity_evidence WHERE tenant_id=$1 AND id=$2 AND context_id=$3 AND entity_id=$4 AND agent_id=$5 AND configured_ref=$6 AND sender_serial=$7`, reg.tenantID, observation.EvidenceId, reg.contextID, reg.deviceID, probe.agent, probe.test, probe.serial).Scan(&raw); err != nil {
				return err
			}
			var original entity.ICMPMeasurement
			if err := json.Unmarshal(raw, &original); err != nil {
				return err
			}
			if !observation.Available || original.Version != 3 || original.RoundTrips == nil || observation.RoundTrips == nil || len(original.RoundTrips.Nanos) != len(observation.RoundTrips.Nanos) || observation.RoundTrips.ExecutionNanos != strconv.FormatUint(original.RoundTrips.ExecutionNanos, 10) {
				t.Fatal("served comparison lost its actual source-bound original RTT document")
			}
			inside := !original.StartedAt.Before(from) && !original.CompletedAt.After(to)
			for i, sample := range original.RoundTrips.Nanos {
				if observation.RoundTrips.Nanos[i] != strconv.FormatUint(sample, 10) {
					t.Fatal("served comparison changed an actual RTT sample")
				}
				if inside {
					var value big.Int
					value.SetUint64(sample)
					sum.Add(&sum, &value)
					samples.Add(&samples, one)
				}
			}
			if inside && original.ReadComplete && !original.IOFailed && !original.Canceled && original.Attempted == original.Requested && original.Transmitted == original.Requested && original.SendErrors == 0 {
				var count big.Int
				count.SetUint64(uint64(original.Transmitted))
				sent.Add(&sent, &count)
				count.SetUint64(uint64(original.Replies))
				replied.Add(&replied, &count)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if samples.Sign() == 0 || sent.Sign() == 0 || period.Latency == nil || period.Packets == nil || period.LossRatio == nil {
		t.Fatal("actual complete original execution population was not available")
	}
	lost := new(big.Int).Sub(&sent, &replied)
	if period.Latency.Samples != samples.String() || period.Latency.SumNanos != sum.String() || period.Latency.MeanNanos != new(big.Rat).SetFrac(&sum, &samples).RatString() || period.Packets.Transmitted != sent.String() || period.Packets.Replies != replied.String() || period.Packets.Lost != lost.String() || *period.LossRatio != new(big.Rat).SetFrac(lost, &sent).RatString() {
		t.Fatal("before/after RTT or loss differs from actual retained originals")
	}
}

// Change the real FRR selected AS path. Both authenticated collector streams
// must publish their own original update and compare the real probe population.
// Neither route metadata nor measurement bodies are inserted by this proof.
func proveRouterOriginalRouteEffects(t *testing.T, st *shipped.Stack, lab *routingLab, registrations []edgeFlowRegistration, probes []routerChangeProbe, replay func(*testing.T, time.Time)) {
	t.Helper()
	from := time.Now().UTC()
	for lane, reg := range registrations {
		awaitRouterChangeProbe(t, st, reg, probes[lane], from)
	}
	replay(t, from)
	changed := time.Now().UTC()
	lab.docker(t, "exec", lab.container("edge"), "vtysh", "-c", "configure terminal", "-c", "route-map ORIGIN-A permit 10", "-c", "no set as-path prepend", "-c", "set as-path prepend "+strconv.Itoa(hijackerA), "-c", "exit", "-c", "router bgp "+strconv.Itoa(edgeASN), "-c", "address-family ipv4 unicast", "-c", "network "+prefixA+" route-map ORIGIN-A", "-c", "end")
	lab.awaitRoutes(t, "rtr-a", map[string]string{prefixA: path(edgeASN, hijackerA)})
	ids := make([]string, len(registrations))
	for lane, reg := range registrations {
		original := awaitRouterTimelineRoute(t, st, reg, changed, "selected_route_update")
		if original.Routing == nil || !original.Routing.PriorPresent || !original.Routing.PathChanged {
			t.Fatal("actual FRR path replacement lost its prior selected-path identity")
		}
		ids[lane] = original.ID
	}
	replay(t, changed)
	proveRouterOriginalEffects(t, st, registrations, probes, ids, from, changed)

	withdrawn := time.Now().UTC()
	lab.docker(t, "exec", lab.container("edge"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(edgeASN), "-c", "address-family ipv4 unicast", "-c", "no network "+prefixA+" route-map ORIGIN-A", "-c", "end")
	for _, reg := range registrations {
		awaitRouterTimelineRoute(t, st, reg, withdrawn, "withdrawal")
	}
	announced := time.Now().UTC()
	lab.docker(t, "exec", lab.container("edge"), "vtysh", "-c", "configure terminal", "-c", "route-map ORIGIN-A permit 10", "-c", "no set as-path prepend", "-c", "set as-path prepend "+strconv.Itoa(originA), "-c", "exit", "-c", "router bgp "+strconv.Itoa(edgeASN), "-c", "address-family ipv4 unicast", "-c", "network "+prefixA+" route-map ORIGIN-A", "-c", "end")
	lab.awaitRoutes(t, "rtr-a", map[string]string{prefixA: path(edgeASN, originA)})
	for _, reg := range registrations {
		awaitRouterTimelineRoute(t, st, reg, announced, "announcement")
	}
}

func awaitRouterTimelineRoute(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, from time.Time, action string) change.Event {
	t.Helper()
	var found change.Event
	shipped.Await(t, "actual FRR "+action+" in its tenant timeline", time.Minute, func() bool {
		query := url.Values{"from": {from.Format(time.RFC3339Nano)}, "to": {time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)}, "limit": {"100"}}
		seen := map[string]bool{}
		for {
			code, body := st.Do(t, reg.cookie, http.MethodGet, "/v1/changes?"+query.Encode(), nil)
			var page struct {
				Items []change.Event `json:"items"`
				Next  string         `json:"next_cursor"`
			}
			if code != http.StatusOK || json.Unmarshal(body, &page) != nil {
				return false
			}
			for _, item := range page.Items {
				if item.Routing == nil || item.Kind != change.KindRoute || item.Prefix != prefixA || item.Routing.Action != action || item.Routing.View != "loc_rib" {
					continue
				}
				if item.TenantID != reg.tenantID || item.Routing.Validate() != nil || item.Routing.ContextID != reg.contextID || item.Routing.RouterID != reg.deviceID || item.Target != reg.deviceID || item.Routing.ObservedAt.Before(from) {
					t.Fatal("actual routing timeline changed its tenant, canonical source or original clock")
				}
				found = item
				return true
			}
			if page.Next == "" {
				return false
			}
			if seen[page.Next] {
				t.Fatal("routing timeline repeated a continuation")
			}
			seen[page.Next] = true
			query.Set("cursor", page.Next)
		}
	})
	t.Logf("real-integration: FRR %s reached tenant timeline in %s (60s observation window)", action, time.Since(from))
	return found
}
