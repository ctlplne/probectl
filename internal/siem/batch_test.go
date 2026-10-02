// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package siem

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// batchCapSender captures each POST payload (concurrency-safe) and can fail its
// first N calls to exercise whole-batch retry.
type batchCapSender struct {
	mu        sync.Mutex
	payloads  [][]byte
	calls     int
	failFirst int
}

func (s *batchCapSender) Send(_ context.Context, p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls <= s.failFirst {
		return errors.New("siem unavailable")
	}
	s.payloads = append(s.payloads, append([]byte(nil), p...))
	return nil
}

func (s *batchCapSender) snapshot() (calls int, payloads [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.payloads))
	copy(out, s.payloads)
	return s.calls, out
}

func batchEvents(tenant string, n int) []Event {
	out := make([]Event, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Event{
			Time:       time.Unix(int64(1700000000+i), 0).UTC(),
			TenantID:   tenant,
			Category:   CategoryAudit,
			Action:     "alert.create",
			Severity:   SeverityInfo,
			Actor:      "alice",
			Target:     "rule-1",
			Outcome:    "success",
			Attributes: map[string]string{"audit.seq": strconv.Itoa(i + 1)},
		})
	}
	return out
}

// batchRecordCount returns how many individual SIEM records a batched payload
// carries for a given format: newline-delimited records for syslog/CEF/ECS, or
// the summed logRecords across resourceLogs for OTLP.
func batchRecordCount(t *testing.T, format string, payload []byte) int {
	t.Helper()
	if format == "otlp" {
		var doc struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []json.RawMessage `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		if err := json.Unmarshal(payload, &doc); err != nil {
			t.Fatalf("otlp batch not valid json: %v", err)
		}
		n := 0
		for _, rl := range doc.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				n += len(sl.LogRecords)
			}
		}
		return n
	}
	lines := strings.Split(strings.TrimSpace(string(payload)), "\n")
	n := 0
	for _, ln := range lines {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return n
}

// Every shipped format frames a whole batch into one payload carrying every
// record — no silent collapse to a single event.
func TestFormatBatchFramesEveryRecord(t *testing.T) {
	for _, name := range []string{"syslog", "cef", "ecs", "otlp"} {
		t.Run(name, func(t *testing.T) {
			f, ok := NewFormatter(name)
			if !ok {
				t.Fatalf("formatter %s missing", name)
			}
			events := batchEvents("tenant-A", 3)
			payload := f.FormatBatch(events)
			if got := batchRecordCount(t, name, payload); got != 3 {
				t.Fatalf("%s batch carried %d records, want 3", name, got)
			}
			// The batch is genuinely multi-record, not one event's output.
			if single := f.Format(events[0]); len(payload) <= len(single) {
				t.Fatalf("%s batch payload (%d bytes) is not larger than a single record (%d bytes)", name, len(payload), len(single))
			}
		})
	}
}

// OTLP groups records by resource/tenant: a batch that ever mixed tenants keeps
// each tenant's records under its own resource (never one record attributed to
// another tenant, G7-N).
func TestFormatBatchOTLPGroupsRecordsByTenant(t *testing.T) {
	events := append(batchEvents("tenant-A", 2), batchEvents("tenant-B", 1)...)
	payload := otlpFormatter{}.FormatBatch(events)

	var doc struct {
		ResourceLogs []struct {
			Resource struct {
				Attributes []struct {
					Key   string `json:"key"`
					Value struct {
						StringValue string `json:"stringValue"`
					} `json:"value"`
				} `json:"attributes"`
			} `json:"resource"`
			ScopeLogs []struct {
				LogRecords []json.RawMessage `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("otlp batch not json: %v", err)
	}
	if len(doc.ResourceLogs) != 2 {
		t.Fatalf("want 2 resourceLogs (one per tenant), got %d", len(doc.ResourceLogs))
	}
	perTenant := map[string]int{}
	for _, rl := range doc.ResourceLogs {
		tenant := ""
		for _, a := range rl.Resource.Attributes {
			if a.Key == "probectl.tenant_id" {
				tenant = a.Value.StringValue
			}
		}
		if tenant == "" {
			t.Fatalf("resource missing tenant attribute: %s", payload)
		}
		for _, sl := range rl.ScopeLogs {
			perTenant[tenant] += len(sl.LogRecords)
		}
	}
	if perTenant["tenant-A"] != 2 || perTenant["tenant-B"] != 1 {
		t.Fatalf("records not grouped per tenant: %v", perTenant)
	}
}

// The structural heart of AUD-16: a batch of N events is delivered in exactly
// ONE POST (not one request per event), and all N are marked delivered. This
// assertion is RED against the old serial one-event-per-POST forwarder.
func TestDeliverBatchIsOnePOSTForManyEvents(t *testing.T) {
	snk := &batchCapSender{}
	f, _ := NewFormatter("ecs")
	fw := NewForwarder(f, snk, Config{RetryBackoff: time.Millisecond, MaxBackoff: time.Millisecond}, nil)

	const n = 5
	if err := fw.DeliverBatch(context.Background(), batchEvents("tenant-A", n)); err != nil {
		t.Fatalf("deliver batch: %v", err)
	}
	calls, payloads := snk.snapshot()
	if calls != 1 || len(payloads) != 1 {
		t.Fatalf("want exactly 1 POST for %d events, got %d calls / %d payloads", n, calls, len(payloads))
	}
	if got := batchRecordCount(t, "ecs", payloads[0]); got != n {
		t.Fatalf("single POST carried %d records, want %d", got, n)
	}
	if d := fw.Stats().Delivered; d != n {
		t.Fatalf("delivered %d events, want %d", d, n)
	}
}

// A failed batch is retried AS A WHOLE until it lands — one successful payload
// carrying every event, nothing dropped.
func TestDeliverBatchRetriesWholeBatch(t *testing.T) {
	snk := &batchCapSender{failFirst: 2}
	f, _ := NewFormatter("cef")
	fw := NewForwarder(f, snk, Config{RetryBackoff: time.Millisecond, MaxBackoff: time.Millisecond}, nil)

	const n = 4
	if err := fw.DeliverBatch(context.Background(), batchEvents("tenant-A", n)); err != nil {
		t.Fatalf("deliver batch: %v", err)
	}
	calls, payloads := snk.snapshot()
	if len(payloads) != 1 {
		t.Fatalf("want 1 successful payload, got %d (calls=%d)", len(payloads), calls)
	}
	if got := batchRecordCount(t, "cef", payloads[0]); got != n {
		t.Fatalf("retried payload carried %d records, want %d", got, n)
	}
	if st := fw.Stats(); st.Delivered != n || st.Retried < 2 {
		t.Fatalf("stats after retry = %+v, want delivered=%d retried>=2", st, n)
	}
}

func TestDeliverBatchEmptyIsNoop(t *testing.T) {
	snk := &batchCapSender{}
	f, _ := NewFormatter("ecs")
	fw := NewForwarder(f, snk, Config{}, nil)
	if err := fw.DeliverBatch(context.Background(), nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
	if calls, _ := snk.snapshot(); calls != 0 {
		t.Fatalf("empty batch should not POST, got %d calls", calls)
	}
}
