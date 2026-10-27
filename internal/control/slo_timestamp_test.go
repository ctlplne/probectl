// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/slo"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSLOEvaluationStartOmitsUnknownTime(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		definitions, own, foreign bool
	}{
		{name: "no definitions"},
		{name: "cold definition", definitions: true},
		{name: "other tenant observed", definitions: true, foreign: true},
		{name: "own tenant observed", definitions: true, own: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := slo.NewEngine(nil)
			if tc.definitions {
				engine = sloTestEngine(t)
			}
			at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
			engine.WithClock(func() time.Time { return at })
			if tc.foreign {
				engine.WithClock(func() time.Time { return at.Add(-time.Hour) })
				engine.ObserveResult("other-tenant", "http", "web.acme.example", "", true, at.Add(-time.Hour))
				engine.WithClock(func() time.Time { return at })
			}
			if tc.own {
				engine.ObserveResult(tenancy.DefaultTenantID.String(), "http", "web.acme.example", "", true, at)
			}
			rec := do(testServer(fakePinger{}).WithSLO(engine), http.MethodGet, "/v1/slos")
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			check := func(label string, value map[string]any) {
				t.Helper()
				since, exists := value["data_since"]
				if !tc.definitions && exists {
					t.Errorf("%s unknown evaluation start must be absent, got %v", label, since)
				}
				if tc.definitions && since != at.Format(time.RFC3339) {
					t.Errorf("%s known evaluation start changed: %v", label, since)
				}
			}
			check("response", body)
			for _, raw := range body["items"].([]any) {
				check("status", raw.(map[string]any))
			}
		})
	}
}
