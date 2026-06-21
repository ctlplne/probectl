// SPDX-License-Identifier: LicenseRef-probectl-TBD

package promapi

import (
	"testing"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/proto"

	prompb "github.com/imfeelingtheagi/probectl/internal/gen/prometheus/v1"
)

func FuzzDecodeRemoteWrite(f *testing.F) {
	for _, seed := range remoteWriteSeeds() {
		f.Add(seed)
	}

	limits := WriteLimits{
		MaxDecodedBytes: 4096,
		MaxSeries:       4,
		MaxSamples:      8,
		MaxLabels:       8,
		MaxLabelBytes:   32,
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		series, err := DecodeRemoteWrite(body, "tenant-a", limits)
		if err != nil {
			return
		}
		if len(series) > limits.MaxSamples {
			t.Fatalf("accepted %d samples, limit %d", len(series), limits.MaxSamples)
		}
		for _, s := range series {
			if s.Metric == "" {
				t.Fatal("accepted series without metric name")
			}
			if got := s.Labels[TenantLabel]; got != "tenant-a" {
				t.Fatalf("accepted series tenant_id=%q, want tenant-a", got)
			}
			if len(s.Labels) > limits.MaxLabels {
				t.Fatalf("accepted %d labels, limit %d", len(s.Labels), limits.MaxLabels)
			}
			for name, value := range s.Labels {
				if len(name) > limits.MaxLabelBytes || len(value) > limits.MaxLabelBytes {
					t.Fatalf("accepted oversized label %q=%q", name, value)
				}
			}
		}
	})
}

func remoteWriteSeeds() [][]byte {
	return [][]byte{
		{},
		[]byte("not snappy"),
		snappy.Encode(nil, nil),
		snappy.Encode(nil, []byte{0x82, 0x06, 0x00}), // unknown field 100, length-delimited, empty
		mustRemoteWriteSeed(&prompb.WriteRequest{Timeseries: []*prompb.TimeSeries{{
			Labels: []*prompb.Label{
				{Name: "__name__", Value: "external_metric"},
				{Name: "job", Value: "node"},
				{Name: TenantLabel, Value: "evil-tenant"},
			},
			Samples: []*prompb.Sample{{Value: 7, Timestamp: 1700000000000}},
		}}}),
		mustRemoteWriteSeed(&prompb.WriteRequest{Timeseries: []*prompb.TimeSeries{{
			Labels:  []*prompb.Label{{Name: "job", Value: "missing-name"}},
			Samples: []*prompb.Sample{{Value: 1, Timestamp: 1}},
		}}}),
		mustRemoteWriteSeed(&prompb.WriteRequest{Timeseries: []*prompb.TimeSeries{{
			Labels: []*prompb.Label{
				{Name: "__name__", Value: "too_many_samples"},
			},
			Samples: []*prompb.Sample{
				{Value: 1, Timestamp: 1},
				{Value: 2, Timestamp: 2},
				{Value: 3, Timestamp: 3},
				{Value: 4, Timestamp: 4},
				{Value: 5, Timestamp: 5},
				{Value: 6, Timestamp: 6},
				{Value: 7, Timestamp: 7},
				{Value: 8, Timestamp: 8},
				{Value: 9, Timestamp: 9},
			},
		}}}),
		mustRemoteWriteSeed(&prompb.WriteRequest{Timeseries: []*prompb.TimeSeries{{
			Labels: []*prompb.Label{
				{Name: "__name__", Value: "too_many_labels"},
				{Name: "l1", Value: "1"},
				{Name: "l2", Value: "2"},
				{Name: "l3", Value: "3"},
				{Name: "l4", Value: "4"},
				{Name: "l5", Value: "5"},
				{Name: "l6", Value: "6"},
				{Name: "l7", Value: "7"},
				{Name: "l8", Value: "8"},
			},
			Samples: []*prompb.Sample{{Value: 1, Timestamp: 1}},
		}}}),
		mustRemoteWriteSeed(&prompb.WriteRequest{Timeseries: []*prompb.TimeSeries{{
			Labels: []*prompb.Label{
				{Name: "__name__", Value: "oversized_label"},
				{Name: "label_with_a_name_that_is_far_too_long_for_the_fuzz_limit", Value: "x"},
			},
			Samples: []*prompb.Sample{{Value: 1, Timestamp: 1}},
		}}}),
	}
}

func mustRemoteWriteSeed(wr *prompb.WriteRequest) []byte {
	raw, err := proto.Marshal(wr)
	if err != nil {
		panic(err)
	}
	return snappy.Encode(nil, raw)
}
