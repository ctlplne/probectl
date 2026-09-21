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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/carbon"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// The real-service execution receipt for carbon/power (F48). The gap was that the
// engine had "unit and handler coverage but no dedicated real-service execution
// proof" — nothing drove the SHIPPING consumer over a real bus and read the answer
// back through the operator's surfaces.
//
// This runs the production CarbonConsumer against a real Kafka, publishes flow
// batches for two tenants with deliberately DIFFERENT byte volumes, and then reads
// the per-tenant summary through GET /v1/carbon and `probectl carbon summary`.
// Different volumes matter for the same reason they do everywhere else here: with
// equal inputs, a summary served from the wrong tenant's accumulator is
// indistinguishable from a correct one.
//
// It also pins the one property a unit test of an accumulator cannot reach — that
// an unscoped record is DROPPED rather than attributed to someone. A flow with no
// tenant id must not land anywhere, which is docs/guardrails.md G7-1 at the
// ingestion edge.
func TestCarbonLiveConsumerAttributesBytesPerTenant(t *testing.T) {
	brokers := testsupport.KafkaBrokers()
	if len(brokers) == 0 {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_KAFKA not set — the carbon real-service receipt needs a real bus")
	}
	ctx := context.Background()

	b, err := bus.NewKafka(brokers, 0, kgo.AllowAutoTopicCreation())
	if err != nil {
		t.Fatalf("kafka: %v", err)
	}
	defer b.Close()

	engine := carbon.NewEngine(nil, carbon.Coefficients{})
	srv, db := setupAPIServerWithLatest(t, nil)
	h := srv.WithCarbon(engine).Handler()

	tenantA := freshTenant(t, db, "carbonA")
	tenantB := freshTenant(t, db, "carbonB")
	tenantC := freshTenant(t, db, "carbonC") // ingests nothing

	// A per-run consumer group. Two reasons, both about determinism rather than
	// convenience: a BRAND-NEW group starts at the earliest offset, so a batch
	// published before the member finishes joining is still read (sharing the
	// persistent group made this test depend on winning a 3-second race, and it
	// lost); and replayed history from earlier runs belongs to earlier tenants,
	// whose UUIDs are not these, so it cannot move these totals.
	SetInstanceGroupSuffix(fmt.Sprintf("carbon-receipt-%d", time.Now().UnixNano()))
	t.Cleanup(func() { SetInstanceGroupSuffix("") })

	// Produce BEFORE the consumer subscribes. Producing is what creates the topic
	// on a fresh broker, and a consumer that subscribes to a not-yet-existing
	// topic has to wait for a metadata refresh — the one ordering that can lose a
	// run on a clean CI broker. A brand-new group reads from the earliest offset,
	// so nothing published first is missed.
	const bytesA, bytesB = 5_000, 11_000
	now := time.Now().UTC()
	publishFlowBatch(ctx, t, b, tenantA, flowRecord(tenantA, "10.30.0.1", bytesA, now))
	publishFlowBatch(ctx, t, b, tenantB, flowRecord(tenantB, "10.40.0.1", bytesB, now))
	// An unscoped record: the consumer must drop it, not attribute it.
	publishFlowBatch(ctx, t, b, tenantA, flowRecord("", "10.50.0.1", 999_000, now))

	// The SHIPPING consumer, not a test double.
	consumer := NewCarbonConsumer(b, engine, quietLog())
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Keep the consumer's error: "it never consumed" and "it could not subscribe"
	// are different failures, and discarding this made them look identical.
	runErr := make(chan error, 1)
	go func() { runErr <- consumer.Run(runCtx) }()

	// Poll rather than sleep-and-hope: the assertion is what arrived, and a
	// timeout says the consumer never consumed instead of silently passing.
	sumA := awaitCarbonBytes(t, h, tenantA, bytesA, runErr)
	sumB := awaitCarbonBytes(t, h, tenantB, bytesB, runErr)

	if sumA.TotalBytes == sumB.TotalBytes {
		t.Fatalf("both tenants report %d bytes — with equal totals this receipt cannot detect a cross-tenant mix-up", sumA.TotalBytes)
	}
	if sumA.TotalGCO2e <= 0 || sumB.TotalGCO2e <= 0 {
		t.Errorf("the engine ran but produced no emissions estimate: A=%v B=%v", sumA.TotalGCO2e, sumB.TotalGCO2e)
	}
	// More traffic must mean more emissions; a constant would satisfy "> 0".
	if sumB.TotalGCO2e <= sumA.TotalGCO2e {
		t.Errorf("tenant B moved %d bytes to A's %d but reports %v gCO2e against %v — the estimate does not follow the input",
			bytesB, bytesA, sumB.TotalGCO2e, sumA.TotalGCO2e)
	}
	// The unscoped 999,000-byte record must be nowhere.
	for _, tc := range []struct {
		name string
		sum  carbon.Summary
	}{{"tenant A", sumA}, {"tenant B", sumB}} {
		if tc.sum.TotalBytes >= 999_000 {
			t.Errorf("%s absorbed the unscoped record: %d bytes", tc.name, tc.sum.TotalBytes)
		}
	}
	if got := carbonSummary(t, h, tenantC); got.TotalBytes != 0 {
		t.Errorf("a tenant that ingested nothing reports %d bytes", got.TotalBytes)
	}

	// The operator's own path.
	live := httptest.NewServer(h)
	defer live.Close()
	out, code := runCLI(t, live.URL, tenantB, "carbon", "summary")
	if code != 0 {
		t.Fatalf("`probectl carbon summary` exited %d: %s", code, out)
	}
	if !strings.Contains(out, fmt.Sprint(bytesB)) {
		t.Errorf("CLI does not report tenant B's %d bytes: %s", bytesB, out)
	}
	if strings.Contains(out, fmt.Sprint(bytesA)) {
		t.Errorf("CLI reports tenant A's %d bytes to tenant B: %s", bytesA, out)
	}
}

func flowRecord(tenant, src string, bytes uint64, at time.Time) *flowv1.FlowRecord {
	return &flowv1.FlowRecord{
		TenantId:           tenant,
		SourceAddress:      src,
		DestinationAddress: "10.99.0.1",
		Bytes:              bytes,
		BytesScaled:        bytes,
		SamplingRate:       1,
		EndUnixNano:        at.UnixNano(),
	}
}

func publishFlowBatch(ctx context.Context, t *testing.T, b bus.Bus, tenant string, records ...*flowv1.FlowRecord) {
	t.Helper()
	publishProto(ctx, t, b, bus.FlowEventsTopic, tenant, &flowv1.FlowBatch{Flows: records})
}

func carbonSummary(t *testing.T, h http.Handler, tenant string) carbon.Summary {
	t.Helper()
	rec := apiReq(t, h, http.MethodGet, "/v1/carbon", tenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/carbon as %s: %d %s", tenant, rec.Code, rec.Body)
	}
	var body struct {
		Running bool           `json:"carbon_running"`
		Summary carbon.Summary `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode carbon: %v", err)
	}
	if !body.Running {
		t.Fatal("the API reports the carbon engine is not running, so the summary below means nothing")
	}
	return body.Summary
}

// awaitCarbonBytes waits for the consumer to attribute exactly want bytes to the
// tenant. A timeout fails loudly: "the consumer never consumed" and "the totals
// are wrong" are different bugs and must not look alike.
func awaitCarbonBytes(t *testing.T, h http.Handler, tenant string, want uint64, runErr <-chan error) carbon.Summary {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	var last carbon.Summary
	for time.Now().Before(deadline) {
		select {
		case err := <-runErr:
			t.Fatalf("the carbon consumer stopped before attributing anything: %v", err)
		default:
		}
		last = carbonSummary(t, h, tenant)
		if last.TotalBytes == want {
			return last
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("tenant %s reports %d bytes after 45s, want %d — the shipping consumer did not attribute the published flow batch", tenant, last.TotalBytes, want)
	return last
}
