// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func counterTextDocument(t *testing.T, row CounterRow) map[string]any {
	t.Helper()
	body, err := json.Marshal(counterDocument(row))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	// The actual SELECT projects numeric columns through toString. Preserve
	// their original decimal tokens here without ever passing through float64.
	for name, value := range document {
		if number, ok := value.(json.Number); ok {
			document[name] = number.String()
		}
	}
	return document
}

func TestCounterHistoryCodecPreservesFullWordsClockPresenceAndNanoseconds(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	for _, row := range counterHistoryRows(t, tenant) {
		document := counterDocument(row)
		body, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if row.Value == ^uint64(0) && !bytes.Contains(body, []byte(`"counter_value":18446744073709551615`)) {
			t.Fatal("the original maximum uint64 was rounded before ClickHouse insertion")
		}
		if !bytes.Contains(body, []byte(`"poll_started_unix_nanos":1794000000123456789`)) || !bytes.Contains(body, []byte(`"uptime_known":1`)) || !bytes.Contains(body, []byte(`"uptime_ticks":0`)) {
			t.Fatal("original nanosecond clock or observed zero presence was lost")
		}
		got, err := counterHistoryRow(counterTextDocument(t, row))
		if err != nil || got.Value != row.Value || got.Width != row.Width || got.Population != row.Population || got.CaptureKey != row.CaptureKey || got.RawDigest != row.RawDigest || !sameCounterSource(got.CounterSource, row.CounterSource) ||
			!got.PollStartedAt.Equal(row.PollStartedAt) || !got.PollCompletedAt.Equal(row.PollCompletedAt) || !got.CapturedAt.Equal(row.CapturedAt) || got.UptimeKnown != row.UptimeKnown || got.DiscontinuityKnown != row.DiscontinuityKnown {
			t.Fatal("stored counter projection changed original values or source provenance", err)
		}
	}
}

func TestCounterHistorySQLBindsWholeCurrentSourceAndRefusesAlteredRows(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	row := counterHistoryRows(t, tenant)[0]
	query := CounterQuery{TenantID: tenant, From: row.PollStartedAt.Add(-time.Minute), To: row.PollCompletedAt.Add(time.Minute), Budget: counterHistoryBudget(),
		Sources: []CounterSelector{{CounterSource: row.CounterSource, IfIndexes: []uint32{7, 4294967295}}}}
	query.Sources[0].SourceRef = "opaque-source' OR 1=1--"
	predicate, params, err := counterSourcePredicate(query)
	if err != nil || strings.Contains(predicate, query.Sources[0].SourceRef) || params["counter_source_0_ref"] != query.Sources[0].SourceRef || params["counter_source_0_indexes"] != "[7,4294967295]" || params["counter_source_0_source_at"] != "1793996400123456789" {
		t.Fatal("counter source identity entered SQL syntax, lost its full interface set or rounded its incarnation", err)
	}
	for _, required := range []string{"tenant_id={tenant:String}", "context_id={counter_source_0_context:String}", "device_id={counter_source_0_device:String}", "agent_id={counter_source_0_agent:String}", "source_assigned_unix_nanos={counter_source_0_source_at:Int64}", "agent_assigned_unix_nanos={counter_source_0_agent_at:Int64}"} {
		if !strings.Contains(predicate, required) {
			t.Fatal("counter read omitted its current storage scope", required)
		}
	}
	for _, change := range []func(map[string]any){
		func(m map[string]any) { m["counter_value"] = 1.0 },
		func(m map[string]any) { m["counter_value"] = "18446744073709551616" },
		func(m map[string]any) { m["counter_value"] = "01" },
		func(m map[string]any) { m["uptime_known"] = "2" },
		func(m map[string]any) { m["row_id"] = strings.Repeat("0", 64) },
		func(m map[string]any) { m["poll_completed_unix_nanos"] = "1" },
		func(m map[string]any) { m["future_scope"] = "unverified" },
	} {
		document := counterTextDocument(t, row)
		change(document)
		if got, err := counterHistoryRow(document); err == nil || !reflect.DeepEqual(got, CounterRow{}) {
			t.Fatal("an altered or rounded counter response yielded a partial original row")
		}
	}
	if _, err := counterHistoryTableFor(Target{Database: "bad;database"}); err == nil {
		t.Fatal("counter routing accepted SQL syntax in the physical database name")
	}
}
