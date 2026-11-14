// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/change"
)

func TestOwnedRoutingNativeMetadataKeepsExactOriginalsAndClosedFields(t *testing.T) {
	const id = "40000000-0000-4004-8000-abcdefabcdef"
	reference := change.RouteReference{Version: 1, ContextID: id, RouterID: id, BaseContextID: id, BaseRouterID: id, ViewID: id, Generation: id, Sequence: "9007199254740993", UpdateIndex: 3, BatchDigest: strings.Repeat("a1", 32), ObservedAt: time.Date(2026, 11, 14, 1, 2, 3, 123456789, time.UTC), View: "loc_rib", Action: "selected_route_update", AFI: 1, SAFI: 1, HasPathID: true, PathID: 0, PriorPresent: true, PathChanged: true}
	body, err := nativeRoutingChangeReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	redacted := ai.RedactTextForTenant(string(body), ai.DefaultRedaction, id)
	var got change.RouteReference
	if err := json.Unmarshal([]byte(redacted), &got); err != nil || got != reference {
		t.Fatal("full native redaction corrupted authorized closed routing metadata", err, redacted)
	}
	rows := ai.SanitizeRow(ai.DomainEvents, ai.Row{"routing": &reference, "raw_pdu": "private sender bytes"})
	if rows["routing"] == nil || rows["raw_pdu"] != nil {
		t.Fatal("routing metadata broke the shared field allow-list")
	}
	if rows := ai.SanitizeRow(ai.DomainEvents, ai.Row{"routing": map[string]any{"password": "private", "router_id": id}}); rows["routing"] != nil {
		t.Fatal("unchecked sender map escaped inside routing metadata")
	}
	invalid := reference
	invalid.Sequence = "a phone number 1234567890123"
	if _, err := nativeRoutingChangeReference(invalid); err == nil {
		t.Fatal("unvalidated arbitrary text obtained structural redaction protection")
	}
}

func TestNativeChangeCursorSurvivesFullRedactionWithoutGrantingAuthority(t *testing.T) {
	cursor := changeTimelineCursor{Version: 1, From: time.Unix(0, 0).UTC(), To: time.Date(2026, 11, 14, 2, 0, 0, 0, time.UTC), Before: time.Date(2026, 11, 14, 1, 0, 0, 0, time.UTC), ID: "40000000-0000-4004-8000-123456789012"}
	body, err := json.Marshal(cursor)
	if err != nil {
		t.Fatal(err)
	}
	original := base64.RawURLEncoding.EncodeToString(body)
	encoded, err := nativeChangeTimelineCursor(original)
	if err != nil {
		t.Fatal(err)
	}
	var actual string
	if err := json.Unmarshal([]byte(ai.RedactTextForTenant(string(encoded), ai.DefaultRedaction, cursor.ID)), &actual); err != nil || actual != original {
		t.Fatal("native redaction changed a generated continuation", err)
	}
	decoded, err := decodeChangeTimelineCursor(actual)
	if err != nil || decoded != cursor {
		t.Fatal("continuation changed its exact window/order", err)
	}
	if _, err := nativeChangeTimelineCursor("password=private sender text"); err == nil {
		t.Fatal("arbitrary caller text acquired cursor redaction protection")
	}
}
