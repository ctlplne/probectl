// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type serviceFlowBinding struct{}

func (serviceFlowBinding) Verify(_ context.Context, tenant, agent string) error {
	if (tenant == "red" || tenant == "blue") && agent == "agent-"+tenant {
		return nil
	}
	return ErrTenantNotBound
}

type serviceFlowStore struct {
	*flowstore.Memory
	batches []int
}

func (store *serviceFlowStore) Insert(ctx context.Context, rows []flowstore.Row) error {
	store.batches = append(store.batches, len(rows))
	return store.Memory.Insert(ctx, rows)
}

func localFlowServiceSource(t *testing.T, at time.Time) *opendata.Enricher {
	t.Helper()
	document := fmt.Sprintf(`{"version":1,"sources":[{"publisher":"aws","fetched_at":%q,"complete":true,"data":{"syncToken":"qa-source","createDate":%q,"prefixes":[{"ip_prefix":"192.0.2.0/24","service":"AMAZON","region":"GLOBAL"},{"ip_prefix":"192.0.2.0/25","service":"EC2","region":"us-east-1"},{"ip_prefix":"192.0.2.0/25","service":"S3","region":"us-east-1"}],"ipv6_prefixes":[]}},{"publisher":"cloudflare","fetched_at":%q,"complete":true,"data":{"success":true,"result":{"etag":"qa-cf","ipv4_cidrs":[],"ipv6_cidrs":["2001:db8::/32"]}}}]}`, at.Add(-time.Minute).Format(time.RFC3339Nano), at.Add(-time.Hour).Format("2006-01-02-15-04-05"), at.Add(-time.Minute).Format(time.RFC3339Nano))
	path := filepath.Join(t.TempDir(), "sources.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := opendata.LoadServiceRanges(t.Context(), path, 24*time.Hour, 16<<20, at)
	if err != nil {
		t.Fatal(err)
	}
	en := opendata.NewEnricher(nil)
	en.Register(source)
	return en
}

// Modeled authenticated lanes and memory backend; complete real signed sender,
// ClickHouse and served/native proofs remain separate integration requirements.
func TestFlowServiceAttributionKeepsTwoTenantVolumesCompleteCandidatesAndRetryIdentity(t *testing.T) {
	at := time.Now().UTC()
	sources := localFlowServiceSource(t, at)
	store := &serviceFlowStore{Memory: flowstore.NewMemory()}
	consumer := NewFlowConsumer(bus.NewMemory(), store, nil, nil).WithTenantBinding(serviceFlowBinding{}).WithServiceRanges(sources, 4096)
	messages := map[string]bus.Message{}
	for lane, tenant := range []string{"red", "blue"} {
		var records []*flowv1.FlowRecord
		for i := range 17 {
			records = append(records, &flowv1.FlowRecord{TenantId: tenant, AgentId: "agent-" + tenant, ExporterAddress: "203.0.113.1", FlowProtocol: "ipfix", SourceAddress: "192.0.2.7", DestinationAddress: "2001:db8::7", SourcePort: uint32(1000 + i), DestinationPort: 443, EndUnixNano: at.UnixNano(), SourceAsn: 64500, SourceCountry: "US", DestinationAsn: 64501, DestinationCountry: "GB", BytesScaled: uint64(100 * (lane + 1)), PacketsScaled: uint64(lane + 1)})
		}
		raw, err := proto.Marshal(&flowv1.FlowBatch{Flows: records})
		if err != nil {
			t.Fatal(err)
		}
		message := bus.Message{Value: raw}
		messages[tenant] = message
		if err := consumer.handleLane(t.Context(), message, bus.FlowEventsTopic, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.batches) <= 2 || store.Len() != 34 {
		t.Fatal("attribution admission truncated the workload or did not flush complete chunks", store.batches, store.Len())
	}
	for lane, tenant := range []string{"red", "blue"} {
		plan := flow.QueryPlan{From: at.Add(-time.Second), To: at.Add(time.Second), GroupBy: []string{"src_service", "src_service_region", "src_service_provider", "dst_service", "dst_service_region"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, View: "table"}
		result, err := store.ExplorePlan(t.Context(), flowstore.PlanQuery{TenantID: tenant, Plan: plan})
		if err != nil || len(result.Rows) != 1 {
			t.Fatal("service query did not retain one tenant group", result, err)
		}
		group := result.Rows[0].Group
		if group["src_service"] != "S3" || group["src_service_region"] != "us-east-1" || group["src_service_provider"] != "aws" || group["dst_service"] != "Cloudflare" || group["dst_service_region"] != "" {
			t.Fatal("range mapping lost known labels or invented anycast region", group)
		}
		want := fmt.Sprint(1700 * (lane + 1))
		if result.Totals["bytes:total"] != want {
			t.Fatal("overlapping labels multiplied traffic or foreign rows leaked", tenant, result.Totals, want)
		}
		var export bytes.Buffer
		count, err := store.ExportTenant(t.Context(), tenant, &export)
		if err != nil || count != 17 {
			t.Fatal("tenant export lost rows", count, err)
		}
		decoder := json.NewDecoder(&export)
		for decoder.More() {
			var row flowstore.Row
			if err := decoder.Decode(&row); err != nil {
				t.Fatal(err)
			}
			var evidence flowServiceEvidence
			if err := json.Unmarshal([]byte(row.ServiceEvidence), &evidence); err != nil || evidence.Version != 1 || len(evidence.Source.Sources) != 2 || len(evidence.Source.Sources[0].Matches) != 3 || row.ServiceClassifiedAt == "" {
				t.Fatal("captured complete source candidates or clock were lost", row, err)
			}
			if row.TenantID != tenant {
				t.Fatal("export crossed tenant boundary")
			}
		}
	}
	// A retried original remains one observation even when public classification
	// is unavailable later. Derived labels never change the original dedup key.
	consumer.WithServiceRanges(nil, 4096)
	for tenant, message := range messages {
		if err := consumer.handleLane(t.Context(), message, bus.FlowEventsTopic, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if store.Len() != 34 {
		t.Fatal("changed classification duplicated original traffic", store.Len())
	}
	before := store.Len()
	forged, err := proto.Marshal(&flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{TenantId: "red", AgentId: "agent-blue", BytesScaled: 999999}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.handleLane(t.Context(), bus.Message{Value: forged}, bus.FlowEventsTopic, "red"); err != nil {
		t.Fatal(err)
	}
	if store.Len() != before || consumer.rejected.Load() == 0 {
		t.Fatal("foreign sender entered the service projection")
	}
}
