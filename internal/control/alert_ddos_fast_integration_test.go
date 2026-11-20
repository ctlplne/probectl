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
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func TestFastDDoSSchedulerSeparatesIdenticalFlowCrowdsByTenantApplication(t *testing.T) {
	f := newRoleExplanationAPIFixture(t, slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelWarn})))
	rows := seasonalFlowFixtureStore(t, f, true)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	traces, metrics := fastDDoSApplicationFixtureStore(t, f.tenants), tsdb.NewMemory()
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithTSDB(metrics).WithFlowStore(rows).WithFlowQueryViews(views).WithFairness(gate).WithOTelStore(traces)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	var ruleIDs [2]string
	var inputs [2]flow.DDoSAssessmentInput
	var viewIDs [2]string
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := fieldComparisonViewDefinition("Five-second traffic")
		definition.Time.LookbackSeconds = 60
		definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "exporter", Op: flow.QueryEqual, Values: []string{"203.0.113.15"}},
		}}
		view, err := views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		viewIDs[lane] = view.ID
		inputs[lane] = flow.DDoSAssessmentInput{Version: view.Version, Prefix: "192.0.2.1/32", Direction: "ingress",
			PeriodSeconds: 5, BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
			VectorShareBasisPoints: 6000, MinObservedRecords: 1, MinObservedAddresses: 2,
			Application: &flow.DDoSApplicationBinding{Service: "synthetic-public-site", Port: 443}}
	}

	center := time.Now().UTC().Truncate(5 * time.Second)
	for lane, tenant := range f.tenants {
		seedFastDDoSPairedEvidence(t, rows, traces, tenant, center, lane == 0)
		source := alert.QuerySourceInput{ViewID: viewIDs[lane], ViewVersion: inputs[lane].Version,
			Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &inputs[lane]}}
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/alerts",
			map[string]any{"name": fmt.Sprintf("Protected synthetic host %d", lane), "query_source": source}, http.StatusCreated)
		var rule alert.Rule
		if err := json.Unmarshal(raw, &rule); err != nil || rule.ID == "" {
			t.Fatal("could not configure the five-second scoped detector", err)
		}
		ruleIDs[lane] = rule.ID
	}

	callSeasonalAPI(t, socket, f.tokens[f.tenants[0]], http.MethodPost, "/v1/alerts", map[string]any{
		"name": "Slow ordinary metric", "metric": "probectl_fixture_slow_metric", "type": "threshold", "comparison": "gt", "threshold": 1,
	}, http.StatusCreated)
	stalled := &blockedDDoSFixtureMetric{ready: make(chan struct{})}
	sup, ok := BuildAlertEvaluatorSupervisor(f.pool, stalled, alert.ChannelDeps{}, 250*time.Millisecond, nil, f.server.log, nil, nil,
		AlertTagDependencies{Gate: gate, Queries: f.server, IncidentWindow: time.Minute})
	if !ok {
		t.Fatal("short-window detector activation failed")
	}
	sup.listTenants = func(context.Context) ([]store.Tenant, error) {
		return []store.Tenant{{ID: f.tenants[0], Status: "active"}, {ID: f.tenants[1], Status: "active"}}, nil
	}
	run, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		sup.Run(run)
	}()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-stalled.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the ordinary evaluation did not reach its blocked telemetry read")
	}
	var fingerprint string
	started := time.Now()
	shipped.Await(t, "both short-window scopes evaluated by the fast lane", 12*time.Second, func() bool {
		ready := true
		for lane, tenant := range f.tenants {
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				var evaluated bool
				if err := sc.Q.QueryRow(ctx, `SELECT query_next_eval_at IS NOT NULL FROM alert_rules WHERE tenant_id=$1 AND id=$2`,
					tenant, ruleIDs[lane]).Scan(&evaluated); err != nil {
					return err
				}
				ready = ready && evaluated
				return nil
			})
		}
		return ready
	})
	t.Logf("real-integration: five-second stored observations reached the active fast scheduler in %s while ordinary alert evaluation waited on telemetry", time.Since(started))
	for lane, tenant := range f.tenants {
		items := getSeasonalFlowReceipts(t, socket, f.tokens[tenant], ruleIDs[lane]).Items
		for _, item := range items {
			if item.Reason == "Sustained flow traffic pressure" {
				if lane != 0 || fingerprint != "" {
					t.Fatal("healthy crowd alarm or duplicate execution crossed the scope")
				}
				fingerprint = item.Fingerprint
			}
		}
	}
	if !alert.ValidFieldDigest(fingerprint) {
		t.Fatal("short-window episode had no original receipt")
	}
	path := "/v1/alerts/rules/" + ruleIDs[0] + "/ddos-receipt?fingerprint=" + fingerprint
	body := callSeasonalAPI(t, socket, f.tokens[f.tenants[0]], http.MethodGet, path, nil, http.StatusOK)
	var proof alert.DDoSEvaluationEvidence
	if err := json.Unmarshal(body, &proof); err != nil || proof.Previous.Application == nil || proof.Current.Application == nil ||
		proof.Current.Application.State != anomaly.DDoSApplicationDegraded ||
		proof.Current.Application.Current.Requests != 1440 || proof.Current.Application.Current.Successes != 960 ||
		proof.Current.Application.Current.FlowBytes != "360000" || proof.Current.Application.Current.FlowPackets != "3600" ||
		proof.Current.After.To.Sub(proof.Previous.After.From) != 10*time.Second {
		t.Fatal("round-tripped receipt lost exact observed evidence or duration", err)
	}
	callSeasonalAPI(t, socket, f.tokens[f.tenants[1]], http.MethodGet, path, nil, http.StatusNotFound)
	cancel()
	<-done
	owner := f.tenants[0]
	f.in(owner, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`,
			owner, f.roles[owner], permMetricsRead)
		return err
	})
	callSeasonalAPI(t, socket, f.tokens[owner], http.MethodGet, path, nil, http.StatusForbidden)
}

type blockedDDoSFixtureMetric struct {
	ready chan struct{}
	once  sync.Once
}

func (m *blockedDDoSFixtureMetric) InstantVector(ctx context.Context, _ string) ([]tsdb.LabeledSample, error) {
	m.once.Do(func() { close(m.ready) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func fastDDoSApplicationFixtureStore(t *testing.T, tenants []string) otelstore.Store {
	t.Helper()
	endpoint := os.Getenv("PROBECTL_FLOWSTORE_URL")
	traces, err := otelstore.NewClickHouseWithClient(endpoint, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = traces.Close() })
	readerUser, reader := chtest.ProvisionReader(t, endpoint, "ddos_application")
	traces.WithTenantScoping(true).WithReader(reader)
	if err := traces.EnsureReaderRowPolicy(t.Context(), readerUser); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, tenant := range tenants {
			if _, _, err := traces.EraseTenant(ctx, tenant); err != nil {
				t.Error("owned application observations cleanup", err)
			}
		}
	})
	return traces
}

func seedFastDDoSPairedEvidence(t *testing.T, flows flowstore.Store, traces otelstore.Store, tenant string, center time.Time, degraded bool) {
	t.Helper()
	var rows []flowstore.Row
	var spans []otelstore.Span
	for offset := -8; offset <= 10; offset++ {
		end := center.Add(time.Duration(offset) * 5 * time.Second)
		windows, err := anomaly.DDoSCompletedWindows(end, 5)
		if err != nil {
			t.Fatal(err)
		}
		for i, window := range []anomaly.TrainingWindow{windows.Before, windows.After} {
			at := window.Start.Add(2 * time.Second)
			row := flowstore.Row{TenantID: tenant, AgentID: "passive-assessment-source", Exporter: "203.0.113.15", Protocol: "ipfix",
				TS: at, StartTS: at.Add(-time.Second), SrcAddr: "198.51.100.42", DstAddr: "192.0.2.1", SrcPort: 42001, DstPort: 443,
				Transport: "tcp", TCPFlags: 16, Sampling: 1, Bytes: 90000, BytesScaled: 90000, Packets: 900, PacketsScaled: 900}
			sample := benchmarkDDoSApplication{Requests: 360, LatencyMS: 18}
			if i == 1 {
				row.Bytes, row.BytesScaled, row.Packets, row.PacketsScaled = 360000, 360000, 3600, 3600
				sample.Requests = 1440
				if degraded {
					sample.Failures, sample.LatencyMS = 480, 80
				}
			}
			rows = append(rows, row)
			for n, span := range benchmarkDDoSAppSpans(sample, window.Start) {
				span.TenantID = tenant
				span.TraceID = fmt.Sprintf("%016x%016x", window.Start.UnixNano(), n+1)
				spans = append(spans, span)
			}
			if i == 1 && offset >= -4 {
				for n := range 1001 {
					spans = append(spans, otelstore.Span{TenantID: tenant, TraceID: fmt.Sprintf("%016x%016x", window.Start.UnixNano(), n+10000),
						SpanID: "0000000000000001", Kind: "server", Service: "synthetic-public-site",
						Start: window.Start.Add(time.Second + time.Duration(n)*time.Millisecond), Duration: 20 * time.Millisecond,
						Attrs: map[string]string{"server.address": "192.0.2.1", "server.port": "8443", "http.response.status_code": "200"}})
				}
			}
		}
	}
	if err := flows.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	if err := traces.WriteSpans(t.Context(), spans); err != nil {
		t.Fatal(err)
	}
}
