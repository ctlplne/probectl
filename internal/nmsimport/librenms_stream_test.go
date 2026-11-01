// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestLibreNMSUnpagedDeviceStreamEmitsBoundedRedactedPages(t *testing.T) {
	var source strings.Builder
	source.WriteString(`{"status":"ok","devices":[`)
	for i := range maxCaptureRowsPerPage + 1 {
		if i > 0 {
			source.WriteByte(',')
		}
		fmt.Fprintf(&source, `{"device_id":%d,"display":"Edge %d","ip":"10.0.0.1","location_id":5,"community":"source-only-secret"}`,
			i+1, i+1)
	}
	fmt.Fprintf(&source, `],"count":%d}`, maxCaptureRowsPerPage+1)
	var pages []int
	var first, last Row
	err := streamLibreNMSDevices(strings.NewReader(source.String()), func(page Snapshot) error {
		pages = append(pages, len(page.Rows))
		if page.Source != LibreNMS || len(page.Rows) > maxCaptureRowsPerPage {
			t.Fatal("stream emitted an invalid capture page")
		}
		if len(pages) == 1 {
			first = page.Rows[0]
		}
		last = page.Rows[len(page.Rows)-1]
		wire, err := json.Marshal(page)
		if err != nil {
			return err
		}
		if strings.Contains(string(wire), "source-only-secret") {
			t.Fatal("source credential escaped into capture page")
		}
		return nil
	})
	if err != nil || len(pages) != 2 || pages[0] != maxCaptureRowsPerPage || pages[1] != 1 ||
		first.ExternalID != "1" || last.ExternalID != fmt.Sprint(maxCaptureRowsPerPage+1) {
		t.Fatalf("unpaged source lost or capped devices: pages=%v first=%+v last=%+v err=%v",
			pages, first, last, err)
	}
}

func TestLibreNMSUnpagedLocationStreamEmitsBoundedUnassignedSites(t *testing.T) {
	var source strings.Builder
	source.WriteString(`{"status":"ok","locations":[`)
	for i := range maxCaptureRowsPerPage + 1 {
		if i > 0 {
			source.WriteByte(',')
		}
		fmt.Fprintf(&source, `{"id":%d,"location":"Site %d","notes":"source-only-secret"}`,
			i+1, i+1)
	}
	fmt.Fprintf(&source, `],"count":%d}`, maxCaptureRowsPerPage+1)
	var pages []int
	var last Row
	err := streamLibreNMSLocations(strings.NewReader(source.String()), func(page Snapshot) error {
		pages = append(pages, len(page.Rows))
		if page.Source != LibreNMS || len(page.Rows) > maxCaptureRowsPerPage {
			t.Fatal("location stream emitted an invalid capture page")
		}
		last = page.Rows[len(page.Rows)-1]
		wire, err := json.Marshal(page)
		if err != nil {
			return err
		}
		if strings.Contains(string(wire), "source-only-secret") {
			t.Fatal("source location metadata escaped into capture page")
		}
		return nil
	})
	if err != nil || len(pages) != 2 || pages[0] != maxCaptureRowsPerPage || pages[1] != 1 ||
		last.Kind != "site" || last.ExternalID != fmt.Sprint(maxCaptureRowsPerPage+1) ||
		last.Label != fmt.Sprintf("Site %d", maxCaptureRowsPerPage+1) {
		t.Fatalf("unpaged locations lost or capped site candidates: pages=%v last=%+v err=%v",
			pages, last, err)
	}
	for _, raw := range []string{
		`{"status":"ok","locations":[{"id":1,"location":"West"}],"count":2}`,
		`{"status":"ok","locations":[{"id":1},{"id":"01"}]}`,
		`{"status":"error","locations":[]}`,
	} {
		if err := streamLibreNMSLocations(strings.NewReader(raw), func(Snapshot) error { return nil }); !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("invalid location stream accepted: %q: %v", raw, err)
		}
	}
}

func TestLibreNMSGroupAndRuleStreamsKeepOnlyReviewFields(t *testing.T) {
	var groups strings.Builder
	groups.WriteString(`[{"status":"ok","message":"source-only-message","groups":[`)
	for i := range maxCaptureRowsPerPage + 1 {
		if i > 0 {
			groups.WriteByte(',')
		}
		fmt.Fprintf(&groups, `{"id":%d,"name":"Group %d","pattern":"source-only-predicate","desc":"source-only-description"}`,
			i+1, i+1)
	}
	fmt.Fprintf(&groups, `],"count":%d}]`, maxCaptureRowsPerPage+1)
	var pages []int
	err := streamLibreNMSGroups(strings.NewReader(groups.String()), func(page Snapshot) error {
		pages = append(pages, len(page.Rows))
		for _, row := range page.Rows {
			if row.Kind != "group" || !strings.Contains(strings.Join(row.UnmappedCodes, ","), "membership_not_captured") ||
				!strings.Contains(strings.Join(row.UnmappedCodes, ","), "dynamic_predicate_unmapped") {
				t.Fatalf("group lost review-only status: %+v", row)
			}
		}
		wire, err := json.Marshal(page)
		if err != nil {
			return err
		}
		if strings.Contains(string(wire), "source-only-") {
			t.Fatal("group source predicate or description escaped into capture")
		}
		return nil
	})
	if err != nil || len(pages) != 2 || pages[0] != maxCaptureRowsPerPage || pages[1] != 1 {
		t.Fatalf("unpaged group inventory was capped or malformed: pages=%v err=%v", pages, err)
	}
	rules := `{"status":"ok","message":"source-only-message","count":1,"rules":[{"id":"7","name":"Edge alert","severity":"critical","rule":"source-only-expression","operations":[{"transports":[{"text":"source-only-secret"}]}]}]}`
	var rulePage Snapshot
	if err := streamLibreNMSRules(strings.NewReader(rules), func(page Snapshot) error {
		rulePage = page
		return nil
	}); err != nil || len(rulePage.Rows) != 1 {
		t.Fatalf("rule stream failed: page=%+v err=%v", rulePage, err)
	}
	rule := rulePage.Rows[0]
	if rule.Kind != "rule" || rule.ExternalID != "7" || rule.Severity != "critical" ||
		!strings.Contains(strings.Join(rule.UnmappedCodes, ","), "expression_unmapped") ||
		!strings.Contains(strings.Join(rule.UnmappedCodes, ","), "delivery_unmapped") {
		t.Fatalf("rule lost review-only status: %+v", rule)
	}
	wire, err := json.Marshal(rulePage)
	if err != nil || strings.Contains(string(wire), "source-only-") {
		t.Fatalf("rule source expression or transport escaped into capture: err=%v", err)
	}
}

func TestLibreNMSGroupAndRuleStreamsRejectPartialEnvelope(t *testing.T) {
	for _, raw := range []string{
		`[{"status":"ok","groups":[]},{"status":"ok","groups":[]}]`,
		`{"status":"ok","groups":[]}`,
		`[{"status":"ok","groups":[{"id":1},{"id":"01"}]}]`,
		`[{"status":"ok","groups":[],"count":1}]`,
	} {
		if err := streamLibreNMSGroups(strings.NewReader(raw), func(Snapshot) error { return nil }); !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("partial group envelope accepted: %q: %v", raw, err)
		}
	}
	for _, raw := range []string{
		`{"status":"ok","rules":[{"id":1}],"count":2}`,
		`{"status":"ok","rules":[{"id":1},{"id":"01"}]}`,
		`{"status":"error","rules":[]}`,
	} {
		if err := streamLibreNMSRules(strings.NewReader(raw), func(Snapshot) error { return nil }); !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("partial rule envelope accepted: %q: %v", raw, err)
		}
	}
}

func TestLibreNMSGroupMembershipStreamKeepsEveryEdgeWithoutSourceData(t *testing.T) {
	var source strings.Builder
	source.WriteString(`[{"status":"ok","message":"source-only-message","devices":[`)
	for i := range maxCaptureRowsPerPage + 1 {
		if i > 0 {
			source.WriteByte(',')
		}
		fmt.Fprintf(&source, `{"device_id":%d,"community":"source-only-secret"}`, i+1)
	}
	fmt.Fprintf(&source, `],"count":%d}]`, maxCaptureRowsPerPage+1)
	var pages []int
	var last Row
	err := streamLibreNMSGroupMembers(strings.NewReader(source.String()), "7", func(page Snapshot) error {
		pages = append(pages, len(page.Rows))
		last = page.Rows[len(page.Rows)-1]
		wire, err := json.Marshal(page)
		if err != nil {
			return err
		}
		if strings.Contains(string(wire), "source-only-") {
			t.Fatal("membership source message or device credential escaped into capture")
		}
		for _, row := range page.Rows {
			if row.Kind != "membership" || len(row.UnmappedCodes) != 1 || row.UnmappedCodes[0] != "group_unmapped" {
				t.Fatalf("member must remain a separate review candidate: %+v", row)
			}
		}
		return nil
	})
	if err != nil || len(pages) != 2 || pages[0] != maxCaptureRowsPerPage || pages[1] != 1 ||
		last.ExternalID != fmt.Sprintf("7:%d", maxCaptureRowsPerPage+1) {
		t.Fatalf("group membership was capped or lost its parent: pages=%v last=%+v err=%v", pages, last, err)
	}
	for _, groupID := range []string{"", "0", "07", "-7", "7/other"} {
		if err := streamLibreNMSGroupMembers(strings.NewReader(`[{"status":"ok","devices":[]}]`),
			groupID, func(Snapshot) error { return nil }); !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("noncanonical group ID %q accepted: %v", groupID, err)
		}
	}
	for _, raw := range []string{
		`[{"status":"ok","devices":[{"device_id":1}],"count":2}]`,
		`[{"status":"ok","devices":[{"device_id":1},{"device_id":"01"}]}]`,
		`[{"status":"ok","devices":[{"device_id":0}]}]`,
		`{"status":"ok","devices":[]}`,
	} {
		if err := streamLibreNMSGroupMembers(strings.NewReader(raw), "7",
			func(Snapshot) error { return nil }); !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("invalid membership response accepted: %q: %v", raw, err)
		}
	}
}

func TestLibreNMSUnpagedStreamRefusesIncompleteOrChangedSource(t *testing.T) {
	for _, raw := range []string{
		`{"status":"ok","devices":[{"device_id":1}],"count":2}`,
		`{"status":"error","devices":[]}`,
		`{"status":"ok","devices":[{"device_id":1},{"device_id":"01"}]}`,
		`{"status":"ok","devices":[]} {"extra":true}`,
		`{"devices":[]}`,
		`{"status":"ok","devices":[{"device_id":1}`,
	} {
		if err := streamLibreNMSDevices(strings.NewReader(raw), func(Snapshot) error { return nil }); !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("invalid stream accepted: %q: %v", raw, err)
		}
	}
	badUTF8 := append([]byte(`{"status":"ok","devices":[{"device_id":1,"display":"`), 0xff)
	badUTF8 = append(badUTF8, []byte(`"}]}`)...)
	if err := streamLibreNMSDevices(strings.NewReader(string(badUTF8)), func(Snapshot) error { return nil }); !errors.Is(err, ErrInvalidPage) {
		t.Fatalf("invalid UTF-8 source accepted: %v", err)
	}
	denied := errors.New("capture transaction denied")
	if err := streamLibreNMSDevices(strings.NewReader(`{"status":"ok","devices":[{"device_id":1}]}`),
		func(Snapshot) error { return denied }); !errors.Is(err, denied) {
		t.Fatalf("capture callback failure was hidden: %v", err)
	}
	var emptyPages int
	if err := streamLibreNMSDevices(strings.NewReader(`{"status":"ok","devices":[],"count":0}`),
		func(page Snapshot) error {
			emptyPages++
			if len(page.Rows) != 0 {
				return errors.New("empty source emitted a row")
			}
			return nil
		}); err != nil || emptyPages != 1 {
		t.Fatalf("empty source needs one zero-row receipt: pages=%d err=%v", emptyPages, err)
	}
}

func TestLibreNMSStreamValueBudgetRefusesOversizeObject(t *testing.T) {
	r := &captureValueReader{reader: strings.NewReader("abcdef"), remaining: 3}
	buf := make([]byte, 8)
	if n, err := r.Read(buf); err != nil || n != 3 {
		t.Fatalf("value read crossed budget: n=%d err=%v", n, err)
	}
	if n, err := r.Read(buf); n != 0 || !errors.Is(err, ErrInvalidPage) {
		t.Fatalf("oversize value was accepted: n=%d err=%v", n, err)
	}
}
