// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func reportRoutingRequirementsFixture(t *testing.T, tenant string, count int) *reportFlowCapture {
	t.Helper()
	capture := reportRequirementsFixture(tenant)
	capture.ContextSources = true
	capture.Permissions = []string{permAIQuery, permFlowRead, "entities.read"}
	capture.Contexts[0].Permissions = []string{permFlowRead, "entities.read"}
	capture.Inputs[0].TagAsOf, capture.Inputs[0].TagRevision = time.Time{}, ""
	capture.Inputs = append(capture.Inputs, capture.Inputs[0])
	capture.Inputs[1].Period = "previous"
	capture.Inputs[1].From = capture.Inputs[0].From.Add(-time.Hour)
	capture.Inputs[1].To = capture.Inputs[0].From
	input := entity.FlowCaptureInput{Exporter: netip.MustParseAddr("192.0.2.1"), Source: netip.MustParseAddr("203.0.113.1"), Destination: netip.MustParseAddr("2001:db8::1"), Protocol: "ipfix", Domain: ^uint32(0)}
	for period := range capture.Inputs {
		reads := make([]flowstore.RoutingCaptureRead, count)
		for i := range reads {
			read := flowstore.RoutingCaptureRead{Sender: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Witness: entity.FlowCaptureWitness{Input: input}}
			ordinal := int64(period*count + i + 1)
			binary.BigEndian.PutUint64(read.Witness.RawDigest[:8], uint64(ordinal))
			key, err := entity.FlowCaptureKey(tenant, read.Sender, read.Witness.RawDigest, input)
			if err != nil {
				t.Fatal(err)
			}
			read.Ref = entity.FlowCaptureReference{Key: key, CapturedAt: time.Unix(1700000000, 123456789+ordinal).UTC()}
			reads[i] = read
		}
		proof, err := encodeFlowRoutingValidity(&flowstore.RoutingQueryProof{Digest: strings.Repeat("a", 64), InputDigest: strings.Repeat("b", 64), Captures: reads})
		if err != nil {
			t.Fatal(err)
		}
		capture.Inputs[period].RoutingSource, capture.Inputs[period].Routing = true, proof
	}
	return capture
}

func TestReportRoutingRequirementsKeepWholeOriginalPeriodsAndAdmission(t *testing.T) {
	const count = 50_000
	tenants := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}
	memory := flowstore.DefaultExplorerBudget().MemoryBytes / 4
	for lane, tenant := range tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		capture := reportRoutingRequirementsFixture(t, tenant, count)
		raw, err := marshalReportSourceRequirements(ctx, capture, memory)
		if err != nil || len(raw) <= 1<<20 {
			t.Fatal("report refused complete original routing selectors above former source envelope", len(raw), err)
		}
		parsed, err := parseReportSourceRequirements(ctx, raw, memory)
		if err != nil || !reflect.DeepEqual(parsed.Inputs, capture.Inputs) || len(parsed.Inputs[0].Routing.Captures) != count || len(parsed.Inputs[1].Routing.Captures) != count {
			t.Fatal("report changed or truncated an original routing period", err)
		}
		if partial, err := parseReportSourceRequirements(tenancy.WithTenant(t.Context(), tenancy.ID(tenants[1-lane])), raw, memory); err == nil || partial != nil {
			t.Fatal("report routing receipt crossed tenant boundary", err)
		}
		if partial, err := parseReportSourceRequirements(ctx, raw, 4096); err == nil || partial != nil {
			t.Fatal("report source decode ignored current workspace admission", err)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if partial, err := parseReportSourceRequirements(cancelled, raw, memory); err == nil || partial != nil {
			t.Fatal("cancelled report returned source requirements", err)
		}
		t.Logf("simulation: tenant lane %d, two complete periods of %d original selectors, %d encoded bytes; no current-source or physical-sender grant", lane, count, len(raw))
	}
}

func TestReportRoutingRequirementsRefuseOmittedAndMalformedSourceLineage(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	for _, change := range []func(*reportFlowCapture){
		func(c *reportFlowCapture) { c.Inputs[1].Routing = nil },
		func(c *reportFlowCapture) { c.Inputs[1].RoutingSource = false },
		func(c *reportFlowCapture) { c.ContextSources = false },
		func(c *reportFlowCapture) { c.ContextsCaptured = false },
		func(c *reportFlowCapture) { c.Inputs[1].Routing.Captures[2].Raw = strings.Repeat("f", 64) },
		func(c *reportFlowCapture) { c.Inputs[1].Routing.Captures[2].Clock = 0 },
		func(c *reportFlowCapture) { c.Inputs[1].Routing.InputDigest = "" },
	} {
		value := reportRoutingRequirementsFixture(t, tenant, 3)
		change(value)
		if raw, err := marshalReportSourceRequirements(ctx, value); err == nil || raw != nil {
			t.Fatal("report accepted omitted or malformed original routing lineage", err)
		}
		version := 2
		requirements := reportSourceRequirements{Version: version, TenantID: tenant, Inputs: value.Inputs, Permissions: value.Permissions, Contexts: value.Contexts, ContextsCaptured: value.ContextsCaptured, ContextSources: value.ContextSources}
		raw, err := json.Marshal(requirements)
		if err != nil {
			t.Fatal(err)
		}
		if partial, err := parseReportSourceRequirements(ctx, raw); err == nil || partial != nil {
			t.Fatal("stored report invented missing original routing authority", err)
		}
	}
}

func TestReportRoutingReaderRequiresCurrentScopedAuthorityBeyondReceipt(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	actor := &auth.Principal{TenantID: tenant, UserID: "reader"}
	capture := reportRoutingRequirementsFixture(t, tenant, 3)
	server := &Server{}
	if err := server.revalidateReportRoutingScope(ctx, tenancy.Scope{Tenant: tenancy.ID(tenant)}, actor, capture); err == nil {
		t.Fatal("report routing receipt replaced unavailable current source authority")
	}
	capture.Inputs[0].RoutingSource = false
	if err := server.revalidateReportRoutingScope(ctx, tenancy.Scope{Tenant: tenancy.ID(tenant)}, actor, capture); err == nil {
		t.Fatal("report routing reader borrowed an unbound stored receipt")
	}
}
