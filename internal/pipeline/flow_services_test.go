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
	"slices"
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

func TestOfflinePublishedRangeFormatsClassifyBothTenantFlows(t *testing.T) {
	fetched := time.Now().UTC().Add(-time.Minute)
	// These are synthetic addresses in original publisher formats. Fresh
	// and expired runs import identical bytes and keep the original clock.
	cases := []struct {
		publisher, address, service, provider, region, body string
	}{
		{"aws", "192.0.2.11", "S3", "aws", "us-east-1", `{"syncToken":"1","createDate":"2026-11-14-09-00-00","prefixes":[{"ip_prefix":"192.0.2.11/32","region":"us-east-1","service":"S3"}],"ipv6_prefixes":[]}`},
		{"google", "192.0.2.12", "Google", "google", "global", `{"syncToken":"1","creationTime":"2026-11-14T09:00:00Z","prefixes":[{"ipv4Prefix":"192.0.2.12/32"}]}`},
		{"google_cloud", "192.0.2.13", "Google Cloud", "google_cloud", "us-west1", `{"syncToken":"1","creationTime":"2026-11-14T09:00:00Z","prefixes":[{"ipv4Prefix":"192.0.2.13/32","service":"Google Cloud","scope":"us-west1"}]}`},
		{"cloudflare", "192.0.2.14", "Cloudflare", "cloudflare", "", `{"success":true,"result":{"etag":"fixture","ipv4_cidrs":["192.0.2.14/32"],"ipv6_cidrs":[]}}`},
		{"salesforce", "192.0.2.15", "Salesforce", "salesforce", "us-east-1", `{"syncToken":"fixture","createDate":"2026-11-14-09-00-00","prefixes":[{"region":"us-east-1","provider":"aws","ip_prefix":["192.0.2.15/32"]}],"ipv6_prefixes":[]}`},
		{"azure_public", "192.0.2.16", "AzureStorage", "azure", "eastus", `{"changeNumber":1,"cloud":"Public","values":[{"name":"Storage.EastUS","properties":{"region":"eastus","systemService":"AzureStorage","addressPrefixes":["192.0.2.16/32"]}}]}`},
		{"m365_worldwide", "192.0.2.17", "Microsoft 365 Exchange", "microsoft_365", "", `[{"id":1,"serviceArea":"Exchange","ips":["192.0.2.17/32"],"category":"Allow","required":true}]`},
		{"zoom_meetings_ipv4", "192.0.2.18", "Zoom Meetings", "zoom", "", "192.0.2.18/32\n"},
		{"slack_huddles", "192.0.2.19", "", "", "", `<!doctype html><html><body><article><h1>Slack Huddles network configuration</h1><h3><strong>Huddles network paths</strong></h3><ul><li>Approve <strong>*.chime.aws</strong> or IP range <strong>192.0.2.19/32</strong></li></ul></article></body></html>`},
	}
	type original struct {
		Publisher string    `json:"publisher"`
		FetchedAt time.Time `json:"fetched_at"`
		Complete  bool      `json:"complete"`
		Data      string    `json:"data"`
	}
	sources := make([]original, 0, len(cases))
	for _, item := range cases {
		sources = append(sources, original{item.publisher, fetched, true, item.body})
	}
	raw, err := json.Marshal(map[string]any{"version": 2, "sources": sources})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "recorded-publishers.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name string
		age  time.Duration
	}{{"fresh", time.Hour}, {"expired", time.Second}} {
		t.Run(scenario.name, func(t *testing.T) {
			now := time.Now().UTC()
			ranges, err := opendata.LoadServiceRanges(t.Context(), path, scenario.age, 16<<20, now)
			if err != nil {
				t.Fatal(err)
			}
			enricher := opendata.NewEnricher(nil)
			enricher.Register(ranges)
			flows := flowstore.NewMemory()
			consumer := NewFlowConsumer(bus.NewMemory(), flows, nil, nil).WithTenantBinding(serviceFlowBinding{}).WithServiceRanges(enricher, 16<<20)
			for lane, tenant := range []string{"red", "blue"} {
				var batch flowv1.FlowBatch
				for i, item := range cases {
					octets := uint64(100 * (i + 1) * (lane + 1))
					batch.Flows = append(batch.Flows, &flowv1.FlowRecord{TenantId: tenant, AgentId: "agent-" + tenant,
						ExporterAddress: "203.0.113.1", FlowProtocol: "ipfix", SourceAddress: "198.51.100.1",
						DestinationAddress: item.address, DestinationPort: 443, EndUnixNano: now.UnixNano(),
						Bytes: octets, BytesScaled: octets, Packets: 1, PacketsScaled: 1, SamplingRate: 1})
				}
				wire, err := proto.Marshal(&batch)
				if err != nil {
					t.Fatal(err)
				}
				if err := consumer.handleLane(t.Context(), bus.Message{Value: wire}, bus.FlowEventsTopic, tenant); err != nil {
					t.Fatal(err)
				}
			}
			for lane, tenant := range []string{"red", "blue"} {
				var output bytes.Buffer
				if _, err := flows.ExportTenant(t.Context(), tenant, &output); err != nil {
					t.Fatal(err)
				}
				read := json.NewDecoder(&output)
				found := map[string]flowstore.Row{}
				for read.More() {
					var row flowstore.Row
					if err := read.Decode(&row); err != nil {
						t.Fatal(err)
					}
					if _, duplicate := found[row.DstAddr]; duplicate || row.TenantID != tenant {
						t.Fatalf("tenant %s received a duplicate or foreign flow for %s", tenant, row.DstAddr)
					}
					found[row.DstAddr] = row
				}
				if len(found) != len(cases) {
					t.Fatalf("tenant %s retained %d of %d golden flows", tenant, len(found), len(cases))
				}
				for i, item := range cases {
					row := found[item.address]
					service, provider, region, status := item.service, item.provider, item.region, "known"
					if scenario.name == "expired" || service == "" {
						service, provider, region, status = "", "", "", "unknown"
					}
					if row.DstService != service || row.DstServiceProvider != provider || row.DstServiceRegion != region ||
						row.DstServiceStatus != status || row.Bytes != uint64(100*(i+1)*(lane+1)) {
						t.Errorf("tenant %s publisher %s got service=%q provider=%q region=%q status=%q bytes=%d",
							tenant, item.publisher, row.DstService, row.DstServiceProvider, row.DstServiceRegion, row.DstServiceStatus, row.Bytes)
					}
					if scenario.name == "expired" {
						var evidence flowServiceEvidence
						if err := json.Unmarshal([]byte(row.ServiceEvidence), &evidence); err != nil {
							t.Fatal(err)
						}
						if !slices.ContainsFunc(evidence.Destination.Sources, func(source opendata.ServiceRangeStatus) bool {
							return source.Publisher == item.publisher && source.Status == "stale" && source.FetchedAt.Equal(fetched)
						}) {
							t.Errorf("tenant %s publisher %s lost the stale source clock", tenant, item.publisher)
						}
					}
				}
			}
		})
	}
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
