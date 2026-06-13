// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/carbon"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/cost"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func TestBuildCarbonGatingAndFailClosed(t *testing.T) {
	if _, on, err := BuildCarbon(&config.Config{CarbonEnabled: false}, intelTestLog()); on || err != nil {
		t.Fatalf("disabled: on=%v err=%v", on, err)
	}
	if _, on, err := BuildCarbon(&config.Config{CarbonEnabled: true, CarbonGridGCO2E: 400}, intelTestLog()); !on || err != nil {
		t.Fatalf("enabled default: on=%v err=%v", on, err)
	}
	// Malformed attribution config fails startup (fail closed).
	if _, _, err := BuildCarbon(&config.Config{
		CarbonEnabled: true, CostZones: "not-a-cidr=zone",
	}, intelTestLog()); err == nil {
		t.Fatal("malformed zones must fail startup")
	}
}

func TestCarbonEndpointNotWired(t *testing.T) {
	srv := testServer(fakePinger{})
	rec := do(srv, http.MethodGet, "/v1/carbon")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Running bool `json:"carbon_running"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Running {
		t.Fatal("unwired endpoint must report carbon_running=false")
	}
}

// Flow batch → consumer → engine → /v1/carbon with the methodology block —
// tenant-scoped, with leak canaries in both directions.
func TestCarbonConsumerAndEndpointIsolation(t *testing.T) {
	eng, on, err := BuildCarbon(&config.Config{CarbonEnabled: true, CarbonGridGCO2E: 400}, intelTestLog())
	if err != nil || !on {
		t.Fatal(err)
	}
	cc := NewCarbonConsumer(nil, eng, intelTestLog())
	tid := tenancy.DefaultTenantID.String()

	batch := &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{
		{TenantId: tid, SourceAddress: "10.1.0.5", DestinationAddress: "203.0.113.9",
			Bytes: 1 << 30, EndUnixNano: time.Now().UnixNano()},
		{TenantId: "other-tenant", SourceAddress: "10.2.0.5", DestinationAddress: "203.0.113.10",
			Bytes: 1 << 30, EndUnixNano: time.Now().UnixNano()},
		{SourceAddress: "10.3.0.5", DestinationAddress: "203.0.113.11", Bytes: 1 << 30}, // unscoped → dropped
	}}
	raw, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := cc.handleLane(context.Background(), bus.Message{Value: raw}, ""); err != nil {
		t.Fatal(err)
	}
	// Malformed payloads skip, never fail.
	if err := cc.handleLane(context.Background(), bus.Message{Value: []byte("junk")}, ""); err != nil {
		t.Fatal(err)
	}

	srv := testServer(fakePinger{}).WithCarbon(eng)
	rec := do(srv, http.MethodGet, "/v1/carbon")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Running bool           `json:"carbon_running"`
		Summary carbon.Summary `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Running || resp.Summary.TotalBytes != 1<<30 {
		t.Fatalf("caller must see exactly its own 1 GiB, got %+v", resp.Summary)
	}
	if resp.Summary.Methodology.Measured {
		t.Fatal("methodology must say estimated, structurally")
	}
	if resp.Summary.Methodology.GridGCO2ePerKWh != 400 || resp.Summary.Methodology.Note == "" {
		t.Fatalf("methodology block incomplete: %+v", resp.Summary.Methodology)
	}
	// The other tenant's bytes are not reachable from this caller.
	if resp.Summary.TotalBytes >= 2<<30 {
		t.Fatal("cross-tenant carbon leak")
	}
	if other := eng.Summary("other-tenant"); other.TotalBytes != 1<<30 {
		t.Fatalf("other tenant's own view wrong: %d", other.TotalBytes)
	}
	// Without zone config the class is unknown — tracked, conservatively.
	if _, ok := resp.Summary.ByClass[cost.ClassUnknown]; !ok {
		t.Fatalf("unmapped zones must land in unknown, got %+v", resp.Summary.ByClass)
	}
}
