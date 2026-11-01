// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestLibreNMSPagePreservesSourceIDWithoutCredentialOrContext(t *testing.T) {
	page := `{"status":"ok","count":2,"devices":[
		{"device_id":"17","hostname":"edge-r1","display":"Edge R1","ip":"10.0.0.1","location_id":null,"community":"secret-community-123"},
		{"device_id":18,"hostname":"edge-r2","ip":"10.0.0.2","location_id":5,"authpass":"secret-auth-456"}
	]}`
	got, err := ParseLibreNMSDevices(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 2 || got.Rows[0].ExternalID != "17" || got.Rows[1].ExternalID != "18" ||
		got.Rows[0].Address != "10.0.0.1" || got.Rows[1].LocationID != "5" {
		t.Fatalf("source identities lost: %+v", got.Rows)
	}
	if !contains(got.Rows[0].UnmappedCodes, "site_unmapped") {
		t.Fatalf("missing site must remain explicitly unmapped: %+v", got.Rows[0])
	}
	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-community-123", "secret-auth-456", "tenant_id", "context_id", "agent_id"} {
		if strings.Contains(string(wire), forbidden) {
			t.Fatalf("unsafe field %q escaped into preview", forbidden)
		}
	}
}

func TestZabbixExportKeepsGroupUUIDAndListsNestedUnmappedTrigger(t *testing.T) {
	page := `{"zabbix_export":{"version":"7.4","host_groups":[{"uuid":"group-uuid-1","name":"WAN"}],
	"hosts":[{"host":"edge-r1","name":"Edge R1","groups":[{"name":"WAN"}],
	"interfaces":[{"ip":"10.0.0.1","interface_ref":"if1"}],
	"macros":[{"macro":"{$SNMP_COMMUNITY}","value":"secret-macro-123"}],
	"items":[{"uuid":"item-uuid-1","key":"if.in","delay":"30s",
	"triggers":[{"uuid":"trigger-uuid-1","name":"Down","expression":"secret-expression-456","url":"https://secret.invalid/hook"}]}]}]}}`
	got, err := ParseZabbixHosts(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "7.4" || len(got.Rows) != 4 {
		t.Fatalf("expected group, host, item and trigger rows: %+v", got)
	}
	if got.Rows[0].ExternalID != "group-uuid-1" || got.Rows[1].ExternalID != "edge-r1" ||
		got.Rows[1].Address != "10.0.0.1" || len(got.Rows[1].GroupIDs) != 1 ||
		got.Rows[1].GroupIDs[0] != "group-uuid-1" || got.Rows[3].ExternalID != "trigger-uuid-1" ||
		!contains(got.Rows[3].UnmappedCodes, "expression_unmapped") {
		t.Fatalf("documented identity or unmapped status lost: %+v", got.Rows)
	}
	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-macro-123", "secret-expression-456", "https://secret.invalid/hook", "{$SNMP_COMMUNITY}"} {
		if strings.Contains(string(wire), forbidden) {
			t.Fatalf("unsafe source field %q escaped into preview", forbidden)
		}
	}
}

func TestMalformedSourcePageFailsWithoutEchoingInput(t *testing.T) {
	for _, page := range []string{
		`{"status":"error","message":"secret-token-123","devices":[]}`,
		`{"status":"ok","devices":[{"device_id":0,"community":"secret-token-123"}]}`,
		`{"status":"ok","devices":[]}{"extra":"secret-token-123"}`,
	} {
		_, err := ParseLibreNMSDevices(strings.NewReader(page))
		if !errors.Is(err, ErrInvalidPage) || strings.Contains(err.Error(), "secret-token-123") {
			t.Fatalf("invalid source page must fail closed without echo: %v", err)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
