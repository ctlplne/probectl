// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	coreaudit "github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/license"
)

type auditPage struct {
	Items []coreaudit.Event `json:"items"`
	Next  int64             `json:"next"`
	Order string            `json:"order"`
}

// TestProviderAuditStreamIsReadableByAdmins (DPR-037): an MSP admin can page
// the plane's own activity log — oldest-first with a cursor, newest-first for
// an activity view, filtered by action — and reading it never appends to it.
// A non-admin operator is refused.
func TestProviderAuditStreamIsReadableByAdmins(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	token := f.bootstrapAndLoginFast(t)
	for _, slug := range []string{"acme", "globex"} {
		rec := f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants",
			map[string]any{"slug": slug, "name": strings.ToUpper(slug)})
		if rec.Code != http.StatusCreated {
			t.Fatalf("provision %s: %d %s", slug, rec.Code, rec.Body.String())
		}
	}
	before := len(f.audit.events)
	if before == 0 {
		t.Fatal("provisioning must have recorded provider audit events")
	}

	rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/audit?limit=1000", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list audit: %d %s", rec.Code, rec.Body.String())
	}
	var page auditPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != before || page.Order != "asc" || page.Next != int64(before) {
		t.Fatalf("asc page: %d items (want %d), order %q, next %d", len(page.Items), before, page.Order, page.Next)
	}
	for i := 1; i < len(page.Items); i++ {
		if page.Items[i].Seq <= page.Items[i-1].Seq {
			t.Fatalf("asc page is not ordered by seq at %d", i)
		}
	}
	if len(f.audit.events) != before {
		t.Fatalf("reading the stream appended %d rows to it", len(f.audit.events)-before)
	}

	// Cursor: the page after the first event holds everything but that event.
	rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/audit?after=1&limit=1000", nil)
	mustDecode(t, rec, &page)
	if len(page.Items) != before-1 || page.Items[0].Seq != 2 {
		t.Fatalf("after=1: %d items, first seq %d", len(page.Items), page.Items[0].Seq)
	}

	// Newest-first activity view: the last thing that happened comes first.
	rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/audit?order=desc&limit=2", nil)
	mustDecode(t, rec, &page)
	if page.Order != "desc" || len(page.Items) != 2 || page.Items[0].Seq != int64(before) || page.Items[1].Seq != int64(before-1) {
		t.Fatalf("desc page: order %q, seqs %v", page.Order, []int64{page.Items[0].Seq, page.Items[1].Seq})
	}
	if page.Next != int64(before-1) {
		t.Fatalf("desc next = %d, want %d (cursor for the older page)", page.Next, before-1)
	}
	rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/audit?order=desc&before=2", nil)
	mustDecode(t, rec, &page)
	if len(page.Items) != 1 || page.Items[0].Seq != 1 {
		t.Fatalf("before=2: want only seq 1, got %d items", len(page.Items))
	}

	// Filter by action substring, case-insensitively.
	rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/audit?action=TENANT_PROVISION&limit=1000", nil)
	mustDecode(t, rec, &page)
	if len(page.Items) == 0 {
		t.Fatal("action filter must match the provisioning events")
	}
	for _, e := range page.Items {
		if !strings.Contains(e.Action, "tenant_provision") {
			t.Fatalf("filter leaked action %q", e.Action)
		}
	}

	// Malformed cursors are a 400, not a silent default.
	rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/audit?after=-3", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("after=-3: %d %s", rec.Code, rec.Body.String())
	}

	// A non-admin operator gets no governance view.
	op, err := f.store.CreateOperator(context.Background(),
		Operator{Email: "noc@msp.example", Name: "NOC", Role: RoleOperator, Status: "disabled"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	noc := f.activateAndIssue(t, op)
	rec = f.doAuthed(t, noc, http.MethodGet, "/provider/v1/audit", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator role reading the audit stream: %d %s", rec.Code, rec.Body.String())
	}
	if rec = doReq(f.h, newReq(http.MethodGet, "/provider/v1/audit", nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", rec.Code)
	}
}

// TestProviderAuditReadWithoutAReaderIsAnHonest503 keeps a sink without a
// read side (failingAudit) from masquerading as an empty stream.
func TestProviderAuditReadWithoutAReaderIsAnHonest503(t *testing.T) {
	svc, err := NewService(NewMemStore(), failingAudit{}, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour), fakeTelemetry{}, testEnvelope(t), 4*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ListAudit(context.Background(), 0, 10, coreaudit.Filter{}, false); err != ErrAuditReadUnavailable {
		t.Fatalf("err = %v, want ErrAuditReadUnavailable", err)
	}
}
