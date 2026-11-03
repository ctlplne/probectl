// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"encoding/json"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

func TestTagResultPreservesOwnedIdentityAcrossFrozenRoundTrip(t *testing.T) {
	a, b, definitionID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	memory := NewMemory()
	for i, tenant := range []string{a, b} {
		if err := memory.Insert(t.Context(), []Row{{TenantID: tenant, Exporter: "192.0.2.10", AgentID: "untrusted", TS: at, BytesScaled: uint64(100 + i*800), PacketsScaled: 1}}); err != nil {
			t.Fatal(err)
		}
	}
	for i, tenant := range []string{a, b} {
		definitions := []tags.Definition{{TenantID: tenant, ID: definitionID, Key: "customer"}}
		data, err := NewTagQueryData(tenant, 9007199254740993, definitions, []tags.ExporterProjection{{Exporter: "192.0.2.10", Values: map[string]string{"customer": tenant}}}, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		result, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: tenant, Tags: data, Plan: flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"tag.customer"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}})
		if err != nil {
			t.Fatal(err)
		}
		if result.Totals["bytes:total"] != []string{"100", "900"}[i] || len(result.Rows) != 1 || result.Rows[0].Group["tag.customer"] != tenant {
			t.Fatal("same exporter/definition identity crossed tenant results")
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var frozen PlanResult
		if err := json.Unmarshal(raw, &frozen); err != nil {
			t.Fatal(err)
		}
		// Current definitions can change after materialization; output needs
		// the original exact identity, without a new metadata read.
		definitions[0].Key = "renamed"
		vocabulary, err := frozen.OutputVocabulary(tenant)
		field, ok := vocabulary.Lookup("tag.customer")
		if err != nil || !ok || field.TagID != definitionID || frozen.TagRevision != 9007199254740993 || frozen.TagTenantID != tenant {
			t.Fatalf("frozen output lost original tenant/definition/revision: %v", err)
		}
		if _, ok := vocabulary.Lookup("tag.renamed"); ok {
			t.Fatal("current rename changed frozen output")
		}
		other := b
		if tenant == b {
			other = a
		}
		if _, err := frozen.OutputVocabulary(other); !errors.Is(err, ErrTagQueryScope) {
			t.Fatal("foreign actor accepted an owned result descriptor")
		}
		testTagResultIdentityTampering(t, frozen, tenant)
	}
}

func testTagResultIdentityTampering(t *testing.T, source PlanResult, tenant string) {
	t.Helper()
	for name, change := range map[string]func(*PlanResult){
		"missing revision":      func(r *PlanResult) { r.TagRevision = 0 },
		"missing scope":         func(r *PlanResult) { r.TagTenantID = "" },
		"missing binding":       func(r *PlanResult) { delete(r.TagIDs, "tag.customer") },
		"extra binding":         func(r *PlanResult) { r.TagIDs["tag.extra"] = uuid.NewString() },
		"malformed ID":          func(r *PlanResult) { r.TagIDs["tag.customer"] = "not-an-id" },
		"conflicting qualifier": func(r *PlanResult) { r.TagIDs["tag.device.customer"] = uuid.NewString() },
		"unknown namespace":     func(r *PlanResult) { r.TagIDs["tag.sql.customer"] = uuid.NewString() },
		"old unbound result":    func(r *PlanResult) { r.TagIDs = nil; r.TagTenantID = ""; r.TagRevision = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			result := source
			result.TagIDs = maps.Clone(source.TagIDs)
			change(&result)
			if _, err := result.OutputVocabulary(tenant); !errors.Is(err, ErrTagQueryScope) {
				t.Fatalf("invalid output identity accepted: %v", err)
			}
		})
	}
}
