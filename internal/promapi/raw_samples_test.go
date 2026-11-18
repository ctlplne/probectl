// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package promapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRawSampleHistoryPinsTenantAndPreservesObservedTimes(t *testing.T) {
	after := time.UnixMilli(1780000000000).UTC()
	through := after.Add(time.Minute)
	const owned = "owned-fixture"
	const other = "sibling-fixture"
	var calls atomic.Int64
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		if err := req.ParseForm(); err != nil || req.Method != http.MethodPost || req.URL.Path != "/api/v1/query" {
			t.Error("raw sample history did not use the pinned instant-query path", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		query := req.Form.Get("query")
		if !strings.Contains(query, TenantLabel+`="`+owned+`"`) || strings.Contains(query, other) || !strings.HasSuffix(query, "[60000ms]") ||
			req.Form.Get("time") != through.UTC().Format(time.RFC3339Nano) {
			t.Error("raw sample history query lost its tenant or time pin")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"probe_rate","tenant_id":%q,"node":"first"},"values":[[1780000000.021,"17"],[1780000031.432,"22"]]}]}}`, owned)
	}))
	t.Cleanup(up.Close)
	client := NewUpstreamWithClient(up.URL, up.Client())
	selector := Selector{Metric: "probe_rate", Matchers: []Matcher{{Name: "node", Op: "=", Value: "first"}}}
	if series, err := client.ReadRawSamples(t.Context(), selector, after, through, 2048); !errors.Is(err, ErrUnscopedUpstreamQuery) || len(series) != 0 || calls.Load() != 0 {
		t.Fatal("read crossed an unscoped storage boundary", err)
	}
	selector = ForceTenant(ForceTenant(selector, other), owned)
	series, err := client.ReadRawSamples(t.Context(), selector, after, through, 2048)
	if err != nil || len(series) != 1 || len(series[0].Points) != 2 || series[0].Labels[TenantLabel] != owned ||
		series[0].Points[0] != (Point{TimeMillis: after.UnixMilli() + 21, Value: 17}) ||
		series[0].Points[1] != (Point{TimeMillis: after.UnixMilli() + 31432, Value: 22}) {
		t.Fatalf("matrix changed the authored values or exact TSDB sample times: %+v (%v)", series, err)
	}
	if prefix, err := client.ReadRawSamples(t.Context(), selector, after, through, 100); err == nil || len(prefix) != 0 {
		t.Fatalf("over-budget matrix became partial history: %+v (%v)", prefix, err)
	}
}

func TestRawSampleHistoryRefusesMixedOrPartialMatrices(t *testing.T) {
	const first = `{"metric":{"__name__":"probe_rate","tenant_id":"owned"},"values":[[1780000000.021,"17"]]}`
	const sibling = `{"metric":{"__name__":"probe_rate","tenant_id":"sibling"},"values":[[1780000000.018,"297"]]}`
	selector := ForceTenant(Selector{Metric: "probe_rate"}, "owned")
	for _, tc := range []struct{ name, rows, warning string }{
		{"foreign tenant", first + "," + sibling, ""},
		{"duplicate identity", first + "," + first, ""},
		{"partial warning", first, `,"warnings":["partial response"]`},
		{"out of window", strings.Replace(first, "1780000000.021", "1780001031.021", 1), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"status":"success","data":{"resultType":"matrix","result":[` + tc.rows + `]}` + tc.warning + `}`)
			if got, err := readRawSampleMatrix(t.Context(), body, selector, 1780000000000, 1780000060000); err == nil || len(got) != 0 {
				t.Fatalf("invalid response yielded a usable subset: %+v (%v)", got, err)
			}
		})
	}
}
