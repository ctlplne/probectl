// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
)

func TestEffectiveTagProjectionOmitsRawFactsAndExactExporterIdentity(t *testing.T) {
	for _, kind := range []string{"device", "interface", "prefix", "agent", "test", "exporter"} {
		out := projectSubjectTags(store.ResolvedTagSubject{Scope: tags.Scope{TenantID: "private-tenant", ContextID: "owned-context"},
			Kind: kind, ID: "private-encoded-target", Revision: 9007199254740993, AsOf: time.Unix(1, 0),
			Items: []tags.Resolved{{TagID: "tag", Key: "customer", Value: "gold", Source: "manual", SourceID: "private-source-lineage"}}})
		body, err := json.Marshal(out)
		if err != nil || out.TagRevision != "9007199254740993" || out.AsOf != "1970-01-01T00:00:01Z" || len(out.Items) != 1 {
			t.Fatalf("curated projection lost exact revision, time or tags: %s %v", body, err)
		}
		if strings.Contains(string(body), "private-tenant") || strings.Contains(string(body), "private-source-lineage") ||
			(kind == "exporter" && strings.Contains(string(body), "private-encoded-target")) {
			t.Fatal("effective-tag response disclosed private provenance")
		}
		if kind != "exporter" && out.TargetID != "private-encoded-target" {
			t.Fatal("canonical subject reference was lost")
		}
	}
}

func TestEffectiveTagQueryRejectsFactsTenantHintsAndDuplicateFields(t *testing.T) {
	for _, raw := range []string{
		"target_kind=device&target_kind=prefix", "target_kind=device&target_id=", "tenant_id=foreign", "sys_name=forged", "address=10.2.0.1", "limit=0",
	} {
		if _, err := tagSubjectQuery(mustTagQuery(t, raw)); err == nil {
			t.Fatalf("untrusted or ambiguous query admitted: %s", raw)
		}
	}
}

func mustTagQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	values, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	return values
}
