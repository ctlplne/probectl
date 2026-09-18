// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-150: flow-analytics, otlp and device-telemetry reported "engine is running
// and waiting for tenant data" no matter what the tenant had delivered, because
// each passed a literal false where a measurement belonged. The old code passes
// every other onboarding test, so this one exists to fail against it: it gives
// each plane one row of its OWN ledger and requires the verdict to change.
func TestOnboardingEngineReadinessReadsPlaneLedgers(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-a"
	now := time.Now().UTC()

	quality := flow.NewMemoryQualityStore()
	decoded := now.Add(-time.Minute)
	valid := flow.QualityReceipt{
		TenantID: tenant, AgentID: "agent-1",
		// RFC 5737 documentation address: a real exporter address is required,
		// and a documentation one keeps the fixture publishable.
		ExporterAddress: "198.51.100.10",
		Protocol:        flow.ProtoNetFlow9,
		TemplateState:   flow.QualityTemplateReady,
		SamplingState:   flow.QualitySamplingUnsampled,
		WindowStartedAt: now.Add(-5 * time.Minute), WindowEndedAt: now, LastPacketAt: now.Add(-time.Minute),
		PacketsReceived: 10, RecordsDecoded: 10, LastValidRecordAt: &decoded,
	}
	// The store requires state/reason/next_action to be exactly what the plane's
	// own evaluator derives from the counters, so derive them rather than
	// asserting a state the fixture has not earned.
	valid = flow.EvaluateQualityState(valid, valid.WindowEndedAt)
	if err := quality.UpsertQualityReceipt(ctx, tenant, valid); err != nil {
		t.Fatalf("seed flow quality receipt: %v", err)
	}

	otel := otelstore.NewMemory()
	if err := otel.WriteSpans(ctx, []otelstore.Span{{
		TenantID: tenant, TraceID: "0af7651916cd43dd8448eb211c80319c", SpanID: "b7ad6b7169203331",
		Name: "GET /checkout", Kind: "server", Service: "checkout-api",
		Start: now.Add(-time.Minute), Duration: 12 * time.Millisecond, StatusCode: "ok",
	}}); err != nil {
		t.Fatalf("seed span: %v", err)
	}

	outcomes := device.NewMemoryCollectionOutcomeStore()
	attempt := now.Add(-time.Minute)
	if err := outcomes.UpsertCollectionOutcome(ctx, tenant, device.CollectionOutcome{
		TenantID: tenant, AgentID: "agent-1", ConfiguredTarget: "edge-1", Protocol: "lldp",
		LastAttemptAt: &attempt, LastSuccessAt: &attempt,
		State: device.CollectionStateOKWithRows, RowCount: 3,
		Reason: device.CollectionReasonRowsObserved, NextAction: device.CollectionActionReviewEvidence,
	}); err != nil {
		t.Fatalf("seed collection outcome: %v", err)
	}

	server := &Server{
		cfg:         &config.Config{},
		flowStore:   flowstore.NewMemory(),
		flowQuality: quality,
		otelStore:   otel,
		deviceOps:   device.NewMemoryOpsStore(),
		// The plane ledgers the verdict must actually read.
		deviceOutcomes: outcomes,
	}
	items, err := server.onboardingEngineReadiness(
		ctx, tenancy.Scope{Tenant: tenant}, nil, func(string) bool { return true },
	)
	if err != nil {
		t.Fatalf("engine readiness: %v", err)
	}
	got := make(map[string]onboardingReadiness, len(items))
	for _, item := range items {
		got[item.ID] = item
	}
	for _, id := range []string{"flow-analytics", "otlp", "device-telemetry"} {
		if got[id].State != onboardingReady {
			t.Errorf("%s reported %q (%s) for a tenant whose own plane ledger holds data — the verdict is not reading the ledger",
				id, got[id].State, got[id].Detail)
		}
	}
}

// DPR-150, second pass: the device plane has two ledgers and a tenant may
// populate either. The lab populates only the TSDB — three device metrics, one
// device in inventory, zero LLDP/CDP collection outcomes — and the first fix
// asked only the collection-outcome ledger, so it still answered "waiting for
// tenant data". Same constant-shaped wrongness, one ledger along.
func TestOnboardingDeviceReadinessAcceptsEitherDeviceLedger(t *testing.T) {
	server := &Server{
		cfg:            &config.Config{},
		deviceOps:      device.NewMemoryOpsStore(),
		deviceOutcomes: device.NewMemoryCollectionOutcomeStore(), // deliberately empty
		tsdbWriter:     deviceMetricsOnly{},
	}
	items, err := server.onboardingEngineReadiness(
		context.Background(), tenancy.Scope{Tenant: "tenant-c"}, nil, func(string) bool { return true },
	)
	if err != nil {
		t.Fatalf("engine readiness: %v", err)
	}
	for _, item := range items {
		if item.ID != "device-telemetry" {
			continue
		}
		if item.State != onboardingReady {
			t.Errorf("device-telemetry reported %q (%s) for a tenant with device metrics but no neighbor discovery", item.State, item.Detail)
		}
		return
	}
	t.Fatal("device-telemetry engine missing")
}

// deviceMetricsOnly answers the device-metric instant vector with one sample
// and nothing else, which is the shape of a tenant polled by SNMP.
type deviceMetricsOnly struct{}

func (deviceMetricsOnly) Write(context.Context, []tsdb.Series) error { return nil }
func (deviceMetricsOnly) Close() error                               { return nil }

func (deviceMetricsOnly) InstantVector(context.Context, string) ([]tsdb.LabeledSample, error) {
	return []tsdb.LabeledSample{{
		Labels: map[string]string{"__name__": deviceMetricPrefix + "if_in_octets", "device": "edge-1"},
		Value:  42,
	}}, nil
}

// The other half of the contract: with the engines wired but the tenant's
// ledgers empty, the same three must say quiet — never ready. A verdict that
// cannot say "nothing yet" is as useless as one that cannot say "ready".
func TestOnboardingEngineReadinessStaysQuietWithoutTenantData(t *testing.T) {
	server := &Server{
		cfg:            &config.Config{},
		flowStore:      flowstore.NewMemory(),
		flowQuality:    flow.NewMemoryQualityStore(),
		otelStore:      otelstore.NewMemory(),
		deviceOps:      device.NewMemoryOpsStore(),
		deviceOutcomes: device.NewMemoryCollectionOutcomeStore(),
	}
	items, err := server.onboardingEngineReadiness(
		context.Background(), tenancy.Scope{Tenant: "tenant-b"}, nil, func(string) bool { return true },
	)
	if err != nil {
		t.Fatalf("engine readiness: %v", err)
	}
	for _, item := range items {
		switch item.ID {
		case "flow-analytics", "otlp", "device-telemetry":
			if item.State != onboardingQuiet {
				t.Errorf("%s reported %q with an empty tenant ledger", item.ID, item.State)
			}
		}
	}
}
