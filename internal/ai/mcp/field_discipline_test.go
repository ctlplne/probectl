// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
)

// TestMCPEventRowsPassTheSharedFieldAllowList is the row half of the field
// discipline: event rows are the one legitimately map-shaped payload an MCP tool
// returns, and they must be reduced by the SAME per-domain allow-list the RCA
// evidence path applies. Engine.Query returns RAW store rows — only Correlate
// reduced them — so before this, a column added to the events store reached an
// external AI client with no code change anywhere near this package.
func TestMCPEventRowsPassTheSharedFieldAllowList(t *testing.T) {
	raw := ai.Row{
		// Allow-listed for DomainEvents: these are the published contract.
		"id":     "ev-1",
		"kind":   "bgp.withdraw",
		"prefix": "203.0.113.0/24",
		// NOT allow-listed: stands in for the next column somebody adds to the
		// events table without thinking about this boundary.
		"internal_customer_note": "renewal at risk, see acct notes",
		"raw_pdu_hex":            "ffffffffffffffff",
	}

	got := SanitizeEventRows([]ai.Row{raw})
	if len(got) != 1 {
		t.Fatalf("SanitizeEventRows returned %d rows, want 1", len(got))
	}
	for _, keep := range []string{"id", "kind", "prefix"} {
		if _, ok := got[0][keep]; !ok {
			t.Errorf("allow-listed key %q was dropped; the tool returns nothing useful: %v", keep, got[0])
		}
	}
	for _, drop := range []string{"internal_customer_note", "raw_pdu_hex"} {
		if v, ok := got[0][drop]; ok {
			t.Errorf("unlisted key %q reached the MCP client with value %v — a new store column "+
				"must be dropped at this boundary by default", drop, v)
		}
	}
}

// TestMCPResultTypesDoNotCarryUncheckedMaps is the struct half. The typed
// results (results.go) exist so a new field on a store object cannot cross by
// accident. A map[string]any or map[string]string field inside one of them would
// re-open exactly that hole — data would decide the wire schema again — so the
// contract is stated as a property over the types themselves rather than as a
// list of fields somebody has to keep current.
func TestMCPResultTypesDoNotCarryUncheckedMaps(t *testing.T) {
	// Every declared MCP result type. A new one added to the Backend belongs
	// here; the Backend-coverage test below is what makes that non-optional.
	types := []any{
		TestsResult{}, TestSummary{},
		PathResult{}, PathHop{}, PathNode{},
		IncidentResult{}, IncidentSignal{},
		CorrelationResult{}, PlaneSignals{},
		ProposalResult{},
	}
	for _, v := range types {
		rt := reflect.TypeOf(v)
		t.Run(rt.Name(), func(t *testing.T) {
			for i := range rt.NumField() {
				f := rt.Field(i)
				if f.Type.Kind() == reflect.Map {
					t.Errorf("%s.%s is a %s: a free-form map lets the DATA decide which keys "+
						"cross to an external AI client, which is the hole these types close. "+
						"Project it into named fields, or reduce it with ai.SanitizeRow like "+
						"EventsResult.Events does", rt.Name(), f.Name, f.Type)
				}
				if f.Type.Kind() == reflect.Interface {
					t.Errorf("%s.%s is %s: an untyped field is the `any` return this change "+
						"removed, one level down", rt.Name(), f.Name, f.Type)
				}
			}
		})
	}
}

// TestBackendReturnsDeclaredTypes states the discipline at the seam: no Backend
// method may return `any`. This is the rule the finding is about — a gate that
// listed today's eight methods would be a denylist and would pass the moment a
// ninth arrived.
func TestBackendReturnsDeclaredTypes(t *testing.T) {
	bt := reflect.TypeOf((*Backend)(nil)).Elem()
	anyType := reflect.TypeOf((*any)(nil)).Elem()
	for i := range bt.NumMethod() {
		m := bt.Method(i)
		ft := m.Type
		for r := range ft.NumOut() {
			out := ft.Out(r)
			if out == anyType {
				t.Errorf("Backend.%s returns `any`: the MCP surface would again publish whatever "+
					"struct the control plane had at hand, bounded only by a byte cap. Declare a "+
					"result type in results.go and project into it", m.Name)
			}
		}
	}
}

// recordingEgressSink captures what the gate durably recorded.
type recordingEgressSink struct{ events []ai.EgressEvent }

func (r *recordingEgressSink) audit(_ context.Context, ev ai.EgressEvent) error {
	r.events = append(r.events, ev)
	return nil
}

// TestMCPConsentDenialIsDurablyRecorded is the audit half of the finding: a
// refused MCP tool call is a refused EGRESS ATTEMPT, and used to appear only in
// the call-audit stream — so an operator asking "what did we refuse to send
// out" saw the RCA and author surfaces but not this one.
func TestMCPConsentDenialIsDurablyRecorded(t *testing.T) {
	sink := &recordingEgressSink{}
	gate := ai.NewEgressGate(
		func(context.Context, string) (bool, error) { return false, nil }, // no consent
		sink.audit,
		ai.DefaultRedaction,
	)
	s := newTestServer(&fakeBackend{}, gate)
	p := &auth.Principal{TenantID: "t1", Permissions: map[string]bool{"test.read": true}}

	res := callRPC(t, s, p, "list_tests")
	if isErr, _ := res["isError"].(bool); !isErr {
		t.Fatalf("a consent denial must surface as an error tool result: %v", res)
	}

	if len(sink.events) != 1 {
		t.Fatalf("consent denial emitted %d durable egress events, want exactly 1: %+v", len(sink.events), sink.events)
	}
	ev := sink.events[0]
	if !ev.Denied {
		t.Errorf("durable egress event must be marked Denied: %+v", ev)
	}
	if ev.TenantID != "t1" {
		t.Errorf("durable egress event tenant = %q, want t1", ev.TenantID)
	}
	if ev.Surface != "mcp" {
		t.Errorf("durable egress event surface = %q, want mcp — the stream must say WHICH surface refused", ev.Surface)
	}
	if strings.TrimSpace(ev.DenialReason) == "" {
		t.Errorf("durable egress event must carry a denial reason: %+v", ev)
	}
}

// A denial must not also emit an ALLOWED egress receipt: the stream would then
// show the tool call as having egressed.
func TestMCPConsentDenialEmitsNoAllowedReceipt(t *testing.T) {
	sink := &recordingEgressSink{}
	gate := ai.NewEgressGate(func(context.Context, string) (bool, error) { return false, nil }, sink.audit, ai.DefaultRedaction)
	s := newTestServer(&fakeBackend{}, gate)
	p := &auth.Principal{TenantID: "t1", Permissions: map[string]bool{"test.read": true}}
	callRPC(t, s, p, "list_tests")

	for _, ev := range sink.events {
		if !ev.Denied {
			b, _ := json.Marshal(ev)
			t.Fatalf("a refused tool call emitted an ALLOWED egress receipt: %s", b)
		}
	}
}
