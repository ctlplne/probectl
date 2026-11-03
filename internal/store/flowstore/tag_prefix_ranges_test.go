// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"testing"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tags"
)

func prefixOracle(inputs []tags.PrefixProjection, contextID string, address netip.Addr) string {
	address = address.Unmap()
	bits, count, value := -1, 0, ""
	for _, input := range inputs {
		if input.ContextID != contextID || !input.Network.Contains(address) || input.Network.Bits() < bits {
			continue
		}
		if input.Network.Bits() > bits {
			bits, count, value = input.Network.Bits(), 0, input.Values["customer"]
		}
		count++
	}
	if count != 1 {
		return ""
	}
	return value
}

func TestPrefixTagsMatchIndependentClosestSubjectOracle(t *testing.T) {
	tenant, other, contextID, otherContext := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	definitions := []tags.Definition{{TenantID: tenant, ID: uuid.NewString(), Key: "customer"}}
	var inputs []tags.PrefixProjection
	add := func(scope, network, value string) {
		values := map[string]string{}
		if value != "" {
			values["customer"] = value
		}
		inputs = append(inputs, tags.PrefixProjection{Scope: tags.Scope{TenantID: tenant, ContextID: scope}, ID: uuid.NewString(), Network: netip.MustParsePrefix(network), Values: values})
	}
	for _, row := range [][2]string{{"0.0.0.0/0", "broad"}, {"10.0.0.0/24", "site"}, {"10.0.0.32/27", "customer"}, {"10.0.0.64/26", ""}, {"10.0.0.80/28", "specific"}, {"10.0.0.128/25", "equal"}, {"10.0.0.128/25", "equal"}, {"10.0.0.200/32", "host"}, {"::/0", "v6-broad"}, {"2001:db8::/120", "v6-site"}, {"2001:db8::10/124", ""}, {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "last"}} {
		add(contextID, row[0], row[1])
	}
	add(otherContext, "10.0.0.0/24", "other-context")
	roots := []tags.ExporterProjection{{Exporter: "192.0.2.10", ContextID: contextID, Values: map[string]string{"customer": "root"}}, {Exporter: "192.0.2.20", ContextID: otherContext}}
	data, err := NewTagQueryData(tenant, 1, definitions, roots, 1<<20, TagQuerySources{Context: t.Context(), Prefixes: inputs})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		for _, address := range []string{fmt.Sprintf("10.0.0.%d", i), fmt.Sprintf("::ffff:10.0.0.%d", i), fmt.Sprintf("2001:db8::%x", i)} {
			for _, root := range roots {
				row := Row{TenantID: tenant, AgentID: other, Exporter: root.Exporter, SrcAddr: address, DstAddr: address}
				want := prefixOracle(inputs, root.ContextID, netip.MustParseAddr(address))
				for _, side := range []string{"src_prefix", "dst_prefix"} {
					got, err := data.valueForRow(row, side+".customer")
					if err != nil || got != want {
						t.Fatalf("%s %s selected %q, want %q: %v", root.ContextID, address, got, want, err)
					}
				}
			}
		}
	}
	for _, address := range []string{"0.0.0.0", "255.255.255.255", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		row := Row{TenantID: tenant, Exporter: "::ffff:192.0.2.10", SrcAddr: address}
		if got, err := data.valueForRow(row, "src_prefix.customer"); err != nil || got != prefixOracle(inputs, contextID, netip.MustParseAddr(address)) {
			t.Fatal("address extremum or mapped exporter changed prefix selection")
		}
	}
	for _, address := range []string{"", "not-an-address", "fe80::1%en0"} {
		if got, err := data.valueForRow(Row{TenantID: tenant, Exporter: "192.0.2.10", SrcAddr: address}, "src_prefix.customer"); err != nil || got != "" {
			t.Fatal("invalid address matched a default prefix")
		}
	}
	if got, err := data.valueForRow(Row{TenantID: tenant, Exporter: "192.0.2.99", SrcAddr: "10.0.0.200"}, "src_prefix.customer"); err != nil || got != "" {
		t.Fatal("unowned exporter selected context metadata")
	}
	if _, err := data.valueForRow(Row{TenantID: other, Exporter: "192.0.2.10", SrcAddr: "10.0.0.200"}, "src_prefix.customer"); !errors.Is(err, ErrTagQueryScope) {
		t.Fatal("foreign tenant selected prefix metadata")
	}
	for _, ranges := range data.prefixes {
		for i, span := range ranges {
			if span.start.compare(span.end) > 0 || i > 0 && ranges[i-1].end.compare(span.start) >= 0 {
				t.Fatal("compiled prefix intervals can fan out a flow")
			}
		}
	}
	inputs[0].Values["customer"] = "mutated"
	if got, _ := data.valueForRow(Row{TenantID: tenant, Exporter: "192.0.2.10", SrcAddr: "203.0.113.1"}, "src_prefix.customer"); got != "broad" {
		t.Fatal("caller mutated immutable prefix values")
	}
	encoded, err := data.externalPrefixRows(t.Context(), tenant, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	foundMax := false
	for {
		var row map[string]any
		err := decoder.Decode(&row)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if row["prefix_tenant"] != tenant {
			t.Fatal("external prefixes crossed tenant scope")
		}
		if end, ok := row["prefix_end"].(json.Number); ok && end.String() == "340282366920938463463374607431768211455" {
			foundMax = true
		}
	}
	if !foundMax {
		t.Fatal("UInt128 maximum lost exact JSON numeric transport")
	}
}

func TestPrefixTagInputsFailClosedOnScopeBudgetAndCancellation(t *testing.T) {
	tenant, contextID := uuid.NewString(), uuid.NewString()
	definitions := []tags.Definition{{TenantID: tenant, ID: uuid.NewString(), Key: "customer"}}
	root := []tags.ExporterProjection{{Exporter: "192.0.2.10", ContextID: contextID}}
	input := tags.PrefixProjection{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, ID: uuid.NewString(), Network: netip.MustParsePrefix("10.0.0.0/24"), Values: map[string]string{"customer": "owned"}}
	for name, alter := range map[string]func(*tags.PrefixProjection){
		"foreign tenant":     func(p *tags.PrefixProjection) { p.TenantID = uuid.NewString() },
		"unowned context":    func(p *tags.PrefixProjection) { p.ContextID = uuid.NewString() },
		"missing identity":   func(p *tags.PrefixProjection) { p.ID = "" },
		"unmasked network":   func(p *tags.PrefixProjection) { p.Network = netip.MustParsePrefix("10.0.0.1/24") },
		"unknown definition": func(p *tags.PrefixProjection) { p.Values = map[string]string{"unknown": "value"} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := input
			alter(&changed)
			if _, err := NewTagQueryData(tenant, 1, definitions, root, 1<<20, TagQuerySources{Prefixes: []tags.PrefixProjection{changed}}); !errors.Is(err, ErrTagQueryScope) {
				t.Fatalf("invalid prefix authority accepted: %v", err)
			}
		})
	}
	if _, err := NewTagQueryData(tenant, 1, definitions, root, 1<<20, TagQuerySources{Prefixes: []tags.PrefixProjection{input, input}}); !errors.Is(err, ErrTagQueryScope) {
		t.Fatal("repeated canonical subject accepted")
	}
	if _, err := NewTagQueryData(tenant, 1, definitions, root, 1024, TagQuerySources{Prefixes: []tags.PrefixProjection{input}}); !errors.Is(err, ErrExplorerBudget) {
		t.Fatal("prefix compilation escaped shared memory budget")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := NewTagQueryData(tenant, 1, definitions, root, 1<<20, TagQuerySources{Context: ctx, Prefixes: []tags.PrefixProjection{input}}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled prefix build returned authority")
	}
	data, err := NewTagQueryData(tenant, 1, definitions, root, 1<<20, TagQuerySources{Prefixes: []tags.PrefixProjection{input}})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := data.valueForRow(Row{TenantID: tenant, Exporter: "192.0.2.10", SrcAddr: "10.0.1.1"}, "src_prefix.customer"); err != nil || got != "" {
		t.Fatal("range hole reused a preceding prefix")
	}
	if _, err := data.externalPrefixRows(ctx, tenant, 1<<20); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled prefix serialization returned values")
	}
}

func TestPrefixTagCompilerRetainsTwentyFiveThousandSubjects(t *testing.T) {
	tenant, contextID := uuid.NewString(), uuid.NewString()
	definitions := []tags.Definition{{TenantID: tenant, ID: uuid.NewString(), Key: "customer"}}
	inputs := make([]tags.PrefixProjection, 25000)
	for i := range inputs {
		address := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		inputs[i] = tags.PrefixProjection{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, ID: uuid.NewString(), Network: netip.PrefixFrom(address, 32), Values: map[string]string{"customer": "p" + strconv.Itoa(i)}}
	}
	data, err := NewTagQueryData(tenant, 1, definitions, []tags.ExporterProjection{{Exporter: "192.0.2.10", ContextID: contextID}}, 64<<20, TagQuerySources{Context: t.Context(), Prefixes: inputs})
	if err != nil {
		t.Fatalf("standing prefix cardinality was narrowed: %v", err)
	}
	if len(data.prefixes[tagPrefixGroup{contextID, 4}]) != len(inputs) {
		t.Fatal("compiler dropped canonical prefix subjects")
	}
	for _, i := range []int{0, 12345, 24999} {
		row := Row{TenantID: tenant, Exporter: "192.0.2.10", SrcAddr: inputs[i].Network.Addr().String()}
		if got, err := data.valueForRow(row, "src_prefix.customer"); err != nil || got != "p"+strconv.Itoa(i) {
			t.Fatal("large prefix catalog lost an exact subject")
		}
	}
	vocabulary, err := data.Vocabulary(tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := vocabulary.Lookup("tag.src_prefix.customer"); !ok {
		t.Fatal("large catalog lost its explicit query field")
	}
}
