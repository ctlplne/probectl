// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestNativeFieldProjectionRefusesUnregisteredDimensionsAndMetrics(t *testing.T) {
	const tenant = "25ebf92b-c387-451d-9e67-0b323c402a58"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	actor := &auth.Principal{TenantID: tenant, UserID: "verified-field-reader"}
	source := flow.FieldComparison{TopKeys: 2, Measure: "bytes:total", Changes: []flow.FieldChange{
		{Kind: "entered_top_set", Group: map[string]string{"protocol": "ipfix", "dst_port": "443"},
			After: &flow.FieldObservation{Rank: 1, Value: "9007199254740993", Secondary: map[string]string{"packets:total": "5"}}},
	}}
	server := &Server{}
	result, err := server.projectNativeFlowFieldComparison(ctx, actor, source)
	if err != nil || len(result.Changes) != 1 {
		t.Fatal("native projection lost the declared change", err)
	}
	change := result.Changes[0]
	if len(change.Group) != 2 || change.Group[0].Field != "dst_port" || change.Group[0].Value != "443" ||
		change.Group[1].Field != "protocol" || change.Before != nil || change.After == nil ||
		change.After.Value != "9007199254740993" || len(change.After.Secondary) != 1 ||
		change.After.Secondary[0].Metric != "packets:total" || !change.After.Secondary[0].Defined {
		t.Fatal("native projection changed exact field values or their declared order")
	}
	const private = "undeclared_fixture_field"
	source.Changes[0].Group[private] = "discarded"
	if result, err := server.projectNativeFlowFieldComparison(ctx, actor, source); err == nil || len(result.Changes) != 0 {
		t.Fatal("an undeclared dimension reached the native result")
	}
	delete(source.Changes[0].Group, private)
	source.Changes[0].After.Secondary[private+":total"] = "7"
	if result, err := server.projectNativeFlowFieldComparison(ctx, actor, source); err == nil || len(result.Changes) != 0 {
		t.Fatal("an undeclared secondary metric reached the native result")
	}
	foreign := tenancy.WithTenant(t.Context(), tenancy.ID("aada3cf5-de40-4ac5-ae6d-c7bea50fd2dd"))
	if result, err := server.projectNativeFlowFieldComparison(foreign, actor, source); !errors.Is(err, tenancy.ErrNoTenant) || len(result.Changes) != 0 {
		t.Fatal("another tenant projected owned field evidence", err)
	}
}
