// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package promapi

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/proto"

	prompb "github.com/ctlplne/probectl/internal/gen/prometheus/v1"
)

func TestOfflineInteropPrometheusRemoteWriteFixtureForcesTenant(t *testing.T) {
	raw, err := os.ReadFile("../../test/interop/fixtures/prometheus-remote-write.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		TenantUnderTest string `json:"tenant_under_test"`
		Series          []struct {
			Metric  string              `json:"metric"`
			Labels  map[string]string   `json:"labels"`
			Samples []remoteWriteSample `json:"samples"`
		} `json:"series"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if fx.TenantUnderTest == "" || len(fx.Series) != 1 {
		t.Fatalf("fixture shape = %+v", fx)
	}

	wr := &prompb.WriteRequest{}
	for _, s := range fx.Series {
		ts := &prompb.TimeSeries{Labels: []*prompb.Label{{Name: "__name__", Value: s.Metric}}}
		for name, value := range s.Labels {
			ts.Labels = append(ts.Labels, &prompb.Label{Name: name, Value: value})
		}
		for _, sm := range s.Samples {
			ts.Samples = append(ts.Samples, &prompb.Sample{Value: sm.Value, Timestamp: sm.TimestampMS})
		}
		wr.Timeseries = append(wr.Timeseries, ts)
	}
	pb, err := proto.Marshal(wr)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeRemoteWrite(snappy.Encode(nil, pb), fx.TenantUnderTest, WriteLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded series = %d, want 1", len(decoded))
	}
	got := decoded[0]
	if got.Metric != "external_metric" || got.Labels["job"] != "node" {
		t.Fatalf("decoded metric = %+v", got)
	}
	if got.Labels[TenantLabel] != fx.TenantUnderTest {
		t.Fatalf("remote-write tenant not forced: %+v", got.Labels)
	}
}

type remoteWriteSample struct {
	Value       float64 `json:"value"`
	TimestampMS int64   `json:"timestamp_ms"`
}
