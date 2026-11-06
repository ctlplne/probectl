// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestInterfaceRoleQuerySelectorsRequireAllSourcePlanesAndCompleteInputs(t *testing.T) {
	plan := QueryPlan{GroupBy: []string{"in_if_role"}, Filter: &QueryFilterGroup{Groups: []QueryFilterGroup{{Conditions: []QueryPredicate{{Field: "out_if_role", Op: QueryEqual, Values: []string{"customer"}}}}}}}
	permissions := QueryPlanPermissions(plan)
	slices.Sort(permissions)
	if !slices.Equal(permissions, []string{"entities.read", "events.read", "metrics.read"}) {
		t.Fatal("role query omitted a source-plane disclosure grant", permissions)
	}
	for _, name := range []string{"in_if_role", "out_if_role"} {
		field, ok := LookupQueryField(name)
		if !ok || field.LegacyHourly || !field.Raw || !field.Rollup || field.Type != QueryText {
			t.Fatal("role query narrowed complete input support or claimed legacy reconstruction", name, field)
		}
	}
}

func TestQueryRegistryRejectsTenantAndStatementSelectors(t *testing.T) {
	for _, field := range []string{"tenant", "tenant_id", "tenant.id", "tenant-id", "src_addr; SELECT 1", "*", "(SELECT tenant_id)", "unknown"} {
		if _, ok := LookupQueryField(field); ok {
			t.Fatalf("untrusted selector %q entered the flow registry", field)
		}
	}
	field, ok := LookupQueryField(" SRC_ADDR ")
	if !ok || field.Name != "src_addr" || field.Type != QueryAddress {
		t.Fatalf("canonical address field = %+v, %v", field, ok)
	}
}

func TestQueryRegistryCopiesCannotChangeAnotherRequest(t *testing.T) {
	fields := QueryFields()
	fields[0].Name = "tenant_id"
	fields[0].Operators[0] = "raw_sql"
	fresh := QueryFields()
	if fresh[0].Name != "agent_id" || fresh[0].Operators[0] != QueryEqual {
		t.Fatal("schema consumer mutated the process-wide registry")
	}
	field, _ := LookupQueryField("src_addr")
	field.Operators[0] = "raw_sql"
	freshField, _ := LookupQueryField("src_addr")
	if freshField.Operators[0] != QueryEqual {
		t.Fatal("field consumer mutated another request's operators")
	}
}

func TestQueryRegistrySchemaKeepsStorageDetailsPrivate(t *testing.T) {
	fields := QueryFields()
	seen := map[string]bool{}
	for _, field := range fields {
		if seen[field.Name] || field.Name == "" || field.Column == "" || len(field.Operators) == 0 {
			t.Fatalf("invalid or duplicate field %+v", field)
		}
		seen[field.Name] = true
		body, err := json.Marshal(field)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"Column", "column", "Derived", "derived", "MaxValue", "max_value"} {
			if _, exists := wire[key]; exists {
				t.Fatalf("schema leaked storage-only property %q", key)
			}
		}
	}
	for _, rawOnly := range []string{"src_port", "dst_port", "in_if_name", "src_asn", "tcp_flags", "ts"} {
		field, ok := LookupQueryField(rawOnly)
		if !ok || field.LegacyHourly {
			t.Fatalf("hourly summary cannot reconstruct %s", rawOnly)
		}
	}
	for _, summary := range []string{"exporter", "src_addr", "dst_addr", "src_prefix", "transport", "bytes_scaled"} {
		field, ok := LookupQueryField(summary)
		if !ok || !field.LegacyHourly {
			t.Fatalf("missing supported summary field %s", summary)
		}
	}
}
