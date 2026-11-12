// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tags"
)

func TestIncidentCustomerPrefixCitationsKeepClosestSubjectAndTenant(t *testing.T) {
	contextID := uuid.NewString()
	for _, tenant := range []string{uuid.NewString(), uuid.NewString()} {
		broad, empty, duplicate, duplicate2 := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
		prefixes := []tags.PrefixProjection{}
		for _, row := range []struct{ id, network, value string }{{broad, "10.0.0.0/24", "owned-" + tenant}, {empty, "10.0.0.0/25", ""}, {duplicate, "10.0.0.128/26", "ambiguous"}, {duplicate2, "10.0.0.128/26", "ambiguous"}} {
			values := map[string]string{}
			if row.value != "" {
				values["customer"] = row.value
			}
			prefixes = append(prefixes, tags.PrefixProjection{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, ID: row.id, Network: netip.MustParsePrefix(row.network), Values: values})
		}
		data, err := NewTagQueryData(tenant, 1, []tags.Definition{{TenantID: tenant, ID: uuid.NewString(), Key: "customer"}}, []tags.ExporterProjection{{Exporter: "192.0.2.1", ContextID: contextID}}, 1<<20, TagQuerySources{Context: t.Context(), Prefixes: prefixes})
		if err != nil {
			t.Fatal(err)
		}
		row := Row{TenantID: tenant, Exporter: "192.0.2.1", SrcAddr: "10.0.0.1", DstAddr: "10.0.0.129"}
		if out, err := data.IncidentCustomerPrefixes(row, contextID, "customer"); err != nil || len(out) != 0 {
			t.Fatal("empty/ambiguous closest subject fell back to a broader customer", out, err)
		}
		row.SrcAddr, row.DstAddr = "10.0.0.200", "10.0.0.201"
		out, err := data.IncidentCustomerPrefixes(row, contextID, "customer")
		if err != nil || len(out) != 1 || out[0].PrefixID != broad || out[0].Value != "owned-"+tenant {
			t.Fatal("one winning customer prefix lost provenance or multiplied source/destination", out, err)
		}
		if out, err := data.IncidentCustomerPrefixes(row, uuid.NewString(), "customer"); err == nil || out != nil {
			t.Fatal("original owner selected another routing context", out, err)
		}
		row.TenantID = uuid.NewString()
		if out, err := data.IncidentCustomerPrefixes(row, contextID, "customer"); err == nil || out != nil {
			t.Fatal("tenant replacement disclosed customer prefix metadata", out, err)
		}
	}
}
