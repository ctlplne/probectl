// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cloudmetrics

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/promapi"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

func TestParseCloudMetricExportsForceTenantAndNormalizeProviders(t *testing.T) {
	raw := strings.Join([]string{
		`{"namespace":"AWS/EC2","metric_name":"NetworkIn","dimensions":[{"Name":"InstanceId","Value":"i-123"},{"Name":"tenant_id","Value":"evil"}],"timestamp":"2026-06-30T12:00:00Z","value":1024,"unit":"Bytes","account_id":"123456789012","region":"us-east-1"}`,
		`{"namespace":"Microsoft.Network/loadBalancers","name":"ByteCount","resource_id":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb1","timeStamp":"2026-06-30T12:01:00Z","total":2048,"unit":"Bytes","labels":{"frontend":"public","tenant_id":"evil"}}`,
		`{"metric":{"type":"compute.googleapis.com/instance/network/received_bytes_count","labels":{"instance_name":"web-1"}},"resource":{"type":"gce_instance","labels":{"project_id":"p1","zone":"us-central1-a","tenant_id":"evil"}},"unit":"By","points":[{"interval":{"endTime":"2026-06-30T12:02:00Z"},"value":{"doubleValue":4096}}]}`,
	}, "\n")

	series, err := Parse(context.Background(), ProviderAWSCloudWatch, "tenant-a", strings.NewReader(strings.Split(raw, "\n")[0]))
	if err != nil {
		t.Fatal(err)
	}
	more, err := Parse(context.Background(), ProviderAzureMonitor, "tenant-a", strings.NewReader(strings.Split(raw, "\n")[1]))
	if err != nil {
		t.Fatal(err)
	}
	series = append(series, more...)
	more, err = Parse(context.Background(), ProviderGCPCloudMonitor, "tenant-a", strings.NewReader(strings.Split(raw, "\n")[2]))
	if err != nil {
		t.Fatal(err)
	}
	series = append(series, more...)

	if len(series) != 3 {
		t.Fatalf("series = %+v, want 3", series)
	}
	for _, s := range series {
		if s.Labels[tsdb.TenantLabel] != "tenant-a" {
			t.Fatalf("tenant was not forced: %+v", s)
		}
		if strings.Contains(s.Metric, ".") || strings.Contains(s.Metric, "/") {
			t.Fatalf("metric name was not prometheus-safe: %q", s.Metric)
		}
	}
	if series[0].Metric != "probectl_cloud_aws_networkin" || series[0].Labels["aws_dimension_instanceid"] != "i-123" {
		t.Fatalf("aws series = %+v", series[0])
	}
	if series[1].Labels["cloud_provider"] != "azure" || series[1].Labels["aggregation"] != "total" {
		t.Fatalf("azure series = %+v", series[1])
	}
	if series[2].Labels["gcp_resource_project_id"] != "p1" || series[2].Value != 4096 {
		t.Fatalf("gcp series = %+v", series[2])
	}
}

func TestLoadWritesTenantScopedTSDBSeries(t *testing.T) {
	mem := tsdb.NewMemory()
	raw := `{"namespace":"AWS/ApplicationELB","metric_name":"TargetResponseTime","dimensions":{"LoadBalancer":"app/api/123"},"timestamp":"2026-06-30T12:00:00Z","value":"0.123","unit":"Seconds"}`
	n, err := load(context.Background(), ProviderAWSCloudWatch, "tenant-a", strings.NewReader(raw), mem)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("wrote %d, want 1", n)
	}
	got := mem.Query("probectl_cloud_aws_targetresponsetime", map[string]string{tsdb.TenantLabel: "tenant-a"})
	if len(got) != 1 || got[0].Labels["aws_dimension_loadbalancer"] != "app/api/123" {
		t.Fatalf("tenant-a query = %+v", got)
	}
	if leaked := mem.Query("probectl_cloud_aws_targetresponsetime", map[string]string{tsdb.TenantLabel: "tenant-b"}); len(leaked) != 0 {
		t.Fatalf("cross-tenant leak = %+v", leaked)
	}
}

func TestEncodeRemoteWriteRoundTripsThroughServedDecoder(t *testing.T) {
	series := []tsdb.Series{{
		Metric:     "probectl_cloud_aws_networkin",
		Labels:     map[string]string{tsdb.TenantLabel: "evil", "cloud_provider": "aws"},
		Value:      42,
		TimeMillis: time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC).UnixMilli(),
	}}
	body, err := EncodeRemoteWrite(series)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := promapi.DecodeRemoteWrite(body, "tenant-a", promapi.WriteLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Labels[tsdb.TenantLabel] != "tenant-a" || decoded[0].Value != 42 {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestCloudMetricsFailClosed(t *testing.T) {
	if _, err := Parse(context.Background(), ProviderAWSCloudWatch, "", strings.NewReader("{}")); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("missing tenant = %v", err)
	}
	if _, err := Parse(context.Background(), Provider("aws"), "tenant-a", strings.NewReader("{}")); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("unknown provider = %v", err)
	}
	if _, err := Parse(context.Background(), ProviderAWSCloudWatch, "tenant-a", bytes.NewReader([]byte(`{"metric_name":"x","timestamp":"2026-06-30T12:00:00Z"}`))); err == nil {
		t.Fatal("missing value should fail closed")
	}
}
