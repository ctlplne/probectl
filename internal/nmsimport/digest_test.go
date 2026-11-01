// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import "testing"

func TestPlanDigestBindsScopeOrderAndNormalizedContent(t *testing.T) {
	const tenantA = "00000000-0000-4000-8000-000000000001"
	const tenantB = "00000000-0000-4000-8000-000000000002"
	const routingContext = "00000000-0000-4000-8000-000000000003"
	const generation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	page := []planRow{
		{RowNumber: 0, ObjectKind: "device", ExternalID: "17", Label: "Router 1", Address: "10.42.0.1"},
		{RowNumber: 1, ObjectKind: "group", ExternalID: "5", Label: "WAN", ReviewOnly: true,
			UnmappedCodes: []string{"membership_not_captured"}},
	}
	newDigest := func(t *testing.T, tenant, instance string, policy int) *planDigest {
		t.Helper()
		d, err := newPlanDigest(tenant, routingContext, instance, generation, LibreNMS, policy)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	all := newDigest(t, tenantA, "lab", 1)
	if err := all.appendPage(page); err != nil {
		t.Fatal(err)
	}
	want, err := all.hexSum()
	if err != nil || len(want) != 64 {
		t.Fatalf("plan hash = %q, %v", want, err)
	}
	streamed := newDigest(t, tenantA, "lab", 1)
	if err := streamed.appendPage(page[:1]); err != nil {
		t.Fatal(err)
	}
	if err := streamed.appendPage(page[1:]); err != nil {
		t.Fatal(err)
	}
	if got, _ := streamed.hexSum(); got != want {
		t.Fatalf("page boundary changed plan hash: %q != %q", got, want)
	}
	changed := append([]planRow(nil), page...)
	changed[1].Label = "WAN 2"
	reordered := []planRow{page[1], page[0]}
	reordered[0].RowNumber, reordered[1].RowNumber = 0, 1
	for name, tc := range map[string]struct {
		tenant, instance string
		policy           int
		rows             []planRow
	}{
		"tenant":   {tenantB, "lab", 1, page},
		"instance": {tenantA, "other", 1, page},
		"policy":   {tenantA, "lab", 2, page},
		"content":  {tenantA, "lab", 1, changed},
		"order":    {tenantA, "lab", 1, reordered},
	} {
		t.Run(name, func(t *testing.T) {
			d := newDigest(t, tc.tenant, tc.instance, tc.policy)
			if err := d.appendPage(tc.rows); err != nil {
				t.Fatal(err)
			}
			if got, _ := d.hexSum(); got == want {
				t.Fatal("different plan shared a digest")
			}
		})
	}
	before, _ := streamed.hexSum()
	if err := streamed.appendPage([]planRow{{RowNumber: 3, ObjectKind: "device", ExternalID: "99"}}); err == nil {
		t.Fatal("accepted a missing global row number")
	}
	if after, _ := streamed.hexSum(); after != before {
		t.Fatal("failed page changed committed digest")
	}
}

func TestPlanDigestRejectsUnboundHeader(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000001"
	const routingContext = "00000000-0000-4000-8000-000000000003"
	const generation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []struct {
		tenant, context, instance, generation string
		source                                Kind
		policy                                int
	}{
		{"missing", routingContext, "lab", generation, LibreNMS, 1},
		{tenant, "missing", "lab", generation, LibreNMS, 1},
		{tenant, routingContext, "https://nms", generation, LibreNMS, 1},
		{tenant, routingContext, "lab", "not-a-hash", LibreNMS, 1},
		{tenant, routingContext, "lab", generation, "unknown", 1},
		{tenant, routingContext, "lab", generation, LibreNMS, 0},
	} {
		if _, err := newPlanDigest(tc.tenant, tc.context, tc.instance, tc.generation, tc.source, tc.policy); err == nil {
			t.Fatalf("accepted unbound plan header: %+v", tc)
		}
	}
}

func TestNormalizedPageHashBindsRetryIdentity(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000001"
	const context = "00000000-0000-4000-8000-000000000003"
	const generation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rows := []planRow{{RowNumber: 2, ObjectKind: "device", ExternalID: "17", Label: "Router 1"}}
	hash := func(tenantID, resource string, pageNumber, firstRow int64, data []planRow) (string, error) {
		return normalizedPageHash(tenantID, context, "lab", generation, LibreNMS, 1,
			resource, pageNumber, firstRow, data)
	}
	want, err := hash(tenant, "devices", 1, 2, rows)
	if err != nil || len(want) != 64 {
		t.Fatalf("page receipt = %q, %v", want, err)
	}
	if retry, err := hash(tenant, "devices", 1, 2, rows); err != nil || retry != want {
		t.Fatalf("exact retry changed receipt: %q, %v", retry, err)
	}
	changed := []planRow{{RowNumber: 2, ObjectKind: "device", ExternalID: "17", Label: "Router 2"}}
	for name, candidate := range map[string]struct {
		tenant, resource string
		page, firstRow   int64
		rows             []planRow
	}{
		"tenant":  {"00000000-0000-4000-8000-000000000002", "devices", 1, 2, rows},
		"page":    {tenant, "devices", 2, 2, rows},
		"content": {tenant, "devices", 1, 2, changed},
		"empty":   {tenant, "devices", 1, 2, nil},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := hash(candidate.tenant, candidate.resource, candidate.page, candidate.firstRow, candidate.rows)
			if err != nil || got == want {
				t.Fatalf("different page shared receipt: %q, %v", got, err)
			}
		})
	}
	if _, err := hash(tenant, "rules", 1, 2, rows); err != nil {
		t.Fatalf("valid LibreNMS resource refused: %v", err)
	}
	for _, invalid := range []struct {
		resource string
		page     int64
		firstRow int64
		rows     []planRow
	}{
		{"hosts", 1, 2, rows},
		{"devices", -1, 2, rows},
		{"devices", 1, -1, rows},
		{"devices", 1, 2, []planRow{{RowNumber: 3, ObjectKind: "device", ExternalID: "17"}}},
	} {
		if _, err := hash(tenant, invalid.resource, invalid.page, invalid.firstRow, invalid.rows); err == nil {
			t.Fatalf("accepted invalid page receipt: %+v", invalid)
		}
	}
}
