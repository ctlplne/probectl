// SPDX-License-Identifier: LicenseRef-probectl-TBD

package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProjectErasedSubjectsRedactsStructuredAuditFields(t *testing.T) {
	tenantID := "tenant-a"
	subject := "Alice@example.com"
	erased := map[string]struct{}{SubjectErasureHash(tenantID, subject): {}}
	ev := Event{
		Seq:      7,
		Actor:    "alice@example.com",
		Action:   "directory.provision",
		Target:   "alice@example.com",
		PrevHash: "prev",
		Hash:     "hash",
		Data: map[string]any{
			"user_name": "alice@example.com",
			"nested": map[string]any{
				"owner": "Alice@example.com",
			},
			"members": []any{"bob@example.com", "alice@example.com"},
		},
	}

	got := projectErasedSubjects(ev, tenantID, erased)
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "alice@example.com") {
		t.Fatalf("projected audit event still contains erased subject: %s", raw)
	}
	if got.Actor != erasedSubjectValue || got.Target != erasedSubjectValue {
		t.Fatalf("actor/target not redacted: actor=%q target=%q", got.Actor, got.Target)
	}
	if got.Seq != ev.Seq || got.PrevHash != ev.PrevHash || got.Hash != ev.Hash {
		t.Fatalf("projection must preserve chain fields: got %#v want seq/hash from %#v", got, ev)
	}
	if got.Data[privacyMetaKey] == nil {
		t.Fatalf("projection marker missing from data: %#v", got.Data)
	}
}

func TestMinimizeEventForWORMDropsRawActorTargetAndData(t *testing.T) {
	ev := Event{
		Seq:      1,
		Actor:    "operator@example.com",
		Action:   "breakglass.grant",
		Target:   "tenant:alice@example.com",
		PrevHash: "",
		Hash:     "hash-1",
		Data:     map[string]any{"email": "alice@example.com", "reason": "support"},
	}

	got := minimizeEventForWORM(ev)
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ToLower(string(raw))
	for _, secret := range []string{"operator@example.com", "alice@example.com", "support"} {
		if strings.Contains(s, secret) {
			t.Fatalf("WORM projection leaked %q in %s", secret, raw)
		}
	}
	if got.Action != ev.Action || got.Seq != ev.Seq || got.PrevHash != ev.PrevHash || got.Hash != ev.Hash {
		t.Fatalf("WORM projection must preserve action and chain fields: got %#v want %#v", got, ev)
	}
}
