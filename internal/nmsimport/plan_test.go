// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizePlanPageKeepsUnmappedObjectsWithoutSourceSecrets(t *testing.T) {
	const raw = `{"zabbix_export":{"version":"7.4","host_groups":[{"uuid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"Routers"}],"hosts":[{"host":"r1","name":"Router 1","groups":[{"name":"Routers"}],"interfaces":[{"ip":"10.42.0.1","default":"1","useip":"1"}],"items":[{"key":"private.item","triggers":[{"expression":"SECRET-PREDICATE"}]}],"macros":[{"macro":"{$PASSWORD}","value":"SECRET-MACRO"}]}]}}`
	snapshot, err := parseZabbixHosts(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	const tenantA = "00000000-0000-4000-8000-000000000001"
	const tenantB = "00000000-0000-4000-8000-000000000002"
	const routingContext = "00000000-0000-4000-8000-000000000003"
	const generation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	a, err := normalizePlanPage(tenantA, routingContext, "lab", generation, Zabbix, snapshot, 10)
	if err != nil || len(a) != 5 {
		t.Fatalf("normalize = %v, %d rows", err, len(a))
	}
	if a[0].ObjectKind != "group" || a[1].ObjectKind != "device" ||
		a[2].ObjectKind != "membership" || a[3].ObjectKind != "poll_setting" ||
		a[4].ObjectKind != "alert_rule" {
		t.Fatalf("unexpected plan row kinds: %+v", a)
	}
	if a[2].ExternalID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:r1" || !a[2].ReviewOnly {
		t.Fatalf("Zabbix membership lost its exact review-only source pair: %+v", a[2])
	}
	for i := 3; i <= 4; i++ {
		if a[i].RowNumber != int64(10+i) || !a[i].ReviewOnly ||
			a[i].ParentID != "r1" ||
			!strings.HasPrefix(a[i].ExternalID, "unmapped-") || len(a[i].ExternalID) != len("unmapped-")+32 {
			t.Fatalf("missing source UUID became an apply candidate or raw ID: %+v", a[i])
		}
	}
	if a[3].ExternalID == a[4].ExternalID {
		t.Fatal("unmapped item and trigger share a review key")
	}
	b, err := normalizePlanPage(tenantB, routingContext, "lab", generation, Zabbix, snapshot, 10)
	if err != nil || b[3].ExternalID == a[3].ExternalID {
		t.Fatal("review key is not tenant bound")
	}
	encoded, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET-PREDICATE", "SECRET-MACRO", "{$PASSWORD}", "private.item"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("normalized plan echoed source-only content: %s", secret)
		}
	}
}

func TestNormalizePlanPageRejectsUnsafeOrAmbiguousRows(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000001"
	const routingContext = "00000000-0000-4000-8000-000000000003"
	const generation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	base := Snapshot{Source: LibreNMS, Rows: []Row{{Kind: "device", ExternalID: "17", Label: "router", Address: "10.42.0.1"}}}
	for name, candidate := range map[string]Snapshot{
		"duplicate ID": {Source: LibreNMS, Rows: []Row{
			{Kind: "device", ExternalID: "17", Label: "router", Address: "10.42.0.1"},
			{Kind: "device", ExternalID: "17", Label: "router", Address: "10.42.0.1"}}},
		"raw reason": {Source: LibreNMS, Rows: []Row{{Kind: "device", ExternalID: "17", Label: "router", Address: "10.42.0.1",
			UnmappedCodes: []string{"credential=secret"}}}},
		"control label":       {Source: LibreNMS, Rows: []Row{{Kind: "device", ExternalID: "17", Label: "a\nb", Address: "10.42.0.1"}}},
		"missing required ID": {Source: LibreNMS, Rows: []Row{{Kind: "device", ExternalID: "", Label: "router", Address: "10.42.0.1"}}},
		"noncanonical group": {Source: Zabbix, Rows: []Row{{Kind: "device", ExternalID: "r1", Label: "router", Address: "10.42.0.1",
			GroupIDs: []string{"SECRET-GROUP"}}}},
		"URL hostname": {Source: PRTG, Rows: []Row{{Kind: "device", ExternalID: "17", Label: "router",
			Hostname: "https://example.test/secret"}}},
		"silent missing address":    {Source: LibreNMS, Rows: []Row{{Kind: "device", ExternalID: "17", Label: "router"}}},
		"nonnumeric foreign parent": {Source: LibreNMS, Rows: []Row{{Kind: "poll_item", ExternalID: "17", ParentID: "router-name", UnmappedCodes: []string{"poll_item_unmapped"}}}},
		"Zabbix device parent":      {Source: Zabbix, Rows: []Row{{Kind: "device", ExternalID: "r1", Label: "router", Address: "10.42.0.1", ParentID: "other-host"}}},
	} {
		if _, err := normalizePlanPage(tenant, routingContext, "lab", generation, candidate.Source, candidate, 0); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	if _, err := normalizePlanPage(tenant, routingContext, "lab", "bad", LibreNMS, base, 0); err == nil {
		t.Fatal("accepted unbound generation hash")
	}
	if _, err := normalizePlanPage("not-a-tenant", routingContext, "lab", generation, LibreNMS, base, 0); err == nil {
		t.Fatal("accepted invalid tenant scope")
	}
	if _, err := normalizePlanPage(tenant, routingContext, "https://nms/?token=secret", generation, LibreNMS, base, 0); err == nil {
		t.Fatal("accepted a credential-shaped source instance reference")
	}
	if _, err := normalizePlanPage(tenant, routingContext, "lab", generation, Zabbix, base, 0); err == nil {
		t.Fatal("accepted a snapshot under another configured source kind")
	}
}

func TestNormalizeLibreNMSMembershipIsScopedReviewOnly(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000001"
	const routingContext = "00000000-0000-4000-8000-000000000003"
	const generation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	base := Row{Kind: "membership", ExternalID: "7:11", UnmappedCodes: []string{"group_unmapped"}}
	snapshot := Snapshot{Source: LibreNMS, Rows: []Row{base}}
	rows, err := normalizePlanPage(tenant, routingContext, "lab", generation, LibreNMS, snapshot, 4)
	if err != nil || len(rows) != 1 || rows[0].ObjectKind != "membership" ||
		rows[0].ExternalID != "7:11" || rows[0].RowNumber != 4 || !rows[0].ReviewOnly {
		t.Fatalf("membership must stay scoped and inert: rows=%+v err=%v", rows, err)
	}
	for _, id := range []string{"", "0:11", "07:11", "7:0", "7:011", "7:11:12", "7:secret"} {
		candidate := base
		candidate.ExternalID = id
		if _, err := normalizePlanPage(tenant, routingContext, "lab", generation,
			LibreNMS, Snapshot{Source: LibreNMS, Rows: []Row{candidate}}, 4); err == nil {
			t.Errorf("accepted invalid membership identity %q", id)
		}
	}
	for name, mutate := range map[string]func(*Row){
		"source data": func(r *Row) { r.Label = "secret" },
		"address":     func(r *Row) { r.Address = "10.0.0.1" },
		"actionable":  func(r *Row) { r.UnmappedCodes = nil },
	} {
		candidate := base
		mutate(&candidate)
		if _, err := normalizePlanPage(tenant, routingContext, "lab", generation,
			LibreNMS, Snapshot{Source: LibreNMS, Rows: []Row{candidate}}, 4); err == nil {
			t.Errorf("accepted %s in membership", name)
		}
	}
	if _, err := normalizePlanPage(tenant, routingContext, "lab", generation,
		Zabbix, Snapshot{Source: Zabbix, Rows: []Row{base}}, 4); err == nil {
		t.Fatal("accepted LibreNMS membership under another source kind")
	}
}

func TestNormalizeZabbixMembershipRequiresExactSourcePair(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000001"
	const routingContext = "00000000-0000-4000-8000-000000000003"
	const generation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	base := Row{Kind: "membership", ExternalID: "748ad4d098d447d492bb935c907f652f:edge:r1",
		UnmappedCodes: []string{"group_unmapped"}}
	rows, err := normalizePlanPage(tenant, routingContext, "lab", generation, Zabbix,
		Snapshot{Source: Zabbix, Rows: []Row{base}}, 0)
	if err != nil || len(rows) != 1 || rows[0].ExternalID != base.ExternalID ||
		!rows[0].ReviewOnly {
		t.Fatalf("Zabbix membership must remain an exact reviewed pair: %+v err=%v", rows, err)
	}
	for _, id := range []string{
		"7:11", "748ad4d098d447d492bb935c907f652f:",
		"748ad4d098d447d492bb935c907f652f: edge-r1",
		"748ad4d098d447d492bb935c907f652f:edge\nr1",
		"748AD4D098D447D492BB935C907F652F:edge-r1",
	} {
		candidate := base
		candidate.ExternalID = id
		if _, err := normalizePlanPage(tenant, routingContext, "lab", generation,
			Zabbix, Snapshot{Source: Zabbix, Rows: []Row{candidate}}, 0); err == nil {
			t.Errorf("accepted invalid Zabbix member pair %q", id)
		}
	}
	if _, err := normalizePlanPage(tenant, routingContext, "lab", generation,
		LibreNMS, Snapshot{Source: LibreNMS, Rows: []Row{base}}, 0); err == nil {
		t.Fatal("accepted Zabbix member pair under LibreNMS source")
	}
}
