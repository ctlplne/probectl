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
	got, err := parseLibreNMSDevices(strings.NewReader(page))
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

func TestLibreNMSLocationsBecomeUnassignedSitesWithoutSourceMetadata(t *testing.T) {
	page := `{"status":"ok","locations":[
		{"id":"5","location":"West DC","lat":"12.3","lng":"45.6","notes":"secret-note-123"},
		{"id":6,"location":"\n"}],"count":2}`
	got, err := parseLibreNMSLocations(strings.NewReader(page))
	if err != nil || len(got.Rows) != 2 || got.Rows[0].Kind != "site" ||
		got.Rows[0].ExternalID != "5" || got.Rows[0].Label != "West DC" ||
		got.Rows[1].ExternalID != "6" || !contains(got.Rows[1].UnmappedCodes, "missing_safe_label") {
		t.Fatalf("location source identity or unmapped label lost: %+v err=%v", got, err)
	}
	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-note-123", "12.3", "45.6", "context_id", "tenant_id"} {
		if strings.Contains(string(wire), forbidden) {
			t.Fatalf("source metadata %q escaped into site candidate", forbidden)
		}
	}
	for _, invalid := range []string{
		`{"status":"error","locations":[]}`,
		`{"status":"ok","locations":[{"id":5,"location":"a"},{"id":"05","location":"b"}]}`,
		`{"status":"ok","locations":[{"id":5,"location":"a"}],"count":2}`,
	} {
		if _, err := parseLibreNMSLocations(strings.NewReader(invalid)); !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("invalid location list accepted: %v", err)
		}
	}
}

func TestZabbixExportKeepsGroupUUIDAndListsNestedUnmappedTrigger(t *testing.T) {
	page := `{"zabbix_export":{"version":"7.4","host_groups":[{"uuid":"748ad4d098d447d492bb935c907f652f","name":"WAN"}],
	"hosts":[{"host":"edge-r1","name":"Edge R1","groups":[{"name":"WAN"}],
	"interfaces":[{"ip":"10.0.0.1","interface_ref":"if1"}],
	"macros":[{"macro":"{$SNMP_COMMUNITY}","value":"secret-macro-123"}],
	"items":[{"uuid":"11111111222233334444555555555555","key":"if.in","delay":"30s",
	"triggers":[{"uuid":"aaaaaaaabbbbccccddddffffffffffff","name":"Down","expression":"secret-expression-456","url":"https://secret.invalid/hook"}]}]}]}}`
	got, err := parseZabbixHosts(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "7.4" || len(got.Rows) != 5 {
		t.Fatalf("expected group, host, member, item and trigger rows: %+v", got)
	}
	if got.Rows[0].ExternalID != "748ad4d098d447d492bb935c907f652f" || got.Rows[1].ExternalID != "edge-r1" ||
		got.Rows[1].Address != "10.0.0.1" || len(got.Rows[1].GroupIDs) != 1 ||
		got.Rows[1].GroupIDs[0] != "748ad4d098d447d492bb935c907f652f" ||
		got.Rows[2].Kind != "membership" ||
		got.Rows[2].ExternalID != "748ad4d098d447d492bb935c907f652f:edge-r1" ||
		!contains(got.Rows[2].UnmappedCodes, "group_unmapped") ||
		got.Rows[4].ExternalID != "aaaaaaaabbbbccccddddffffffffffff" ||
		got.Rows[3].PollSeconds != 30 ||
		got.Rows[3].ParentID != "edge-r1" || got.Rows[4].ParentID != "edge-r1" ||
		!contains(got.Rows[4].UnmappedCodes, "expression_unmapped") {
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

func TestLibreNMSGroupAndRulePagesKeepIDsWithoutExecutingSourcePolicy(t *testing.T) {
	groups := `{"status":"ok","count":2,"groups":[
		{"id":"7","name":"Edge routers","pattern":"%devices.status = 1 && secret-pattern-123"},
		{"id":8,"name":"Core switches","pattern":""}
	]}`
	gotGroups, err := parseLibreNMSGroups(strings.NewReader(groups))
	if err != nil {
		t.Fatal(err)
	}
	if len(gotGroups.Rows) != 2 || gotGroups.Rows[0].ExternalID != "7" || gotGroups.Rows[1].ExternalID != "8" ||
		!contains(gotGroups.Rows[0].UnmappedCodes, "dynamic_predicate_unmapped") ||
		!contains(gotGroups.Rows[1].UnmappedCodes, "membership_not_captured") {
		t.Fatalf("group identity or unmapped policy lost: %+v", gotGroups.Rows)
	}
	rules := `{"status":"ok","count":2,"rules":[
		{"id":"31","name":"Interface down","severity":"critical","rule":"secret-expression-456",
		 "alert_operation_id":12,"operations":[{"transports":[{"text":"https://secret.invalid/hook"}]}]},
		{"id":32,"name":"Unknown priority","severity":"emergency","rule":"secret-expression-789"}
	]}`
	gotRules, err := parseLibreNMSRules(strings.NewReader(rules))
	if err != nil {
		t.Fatal(err)
	}
	if len(gotRules.Rows) != 2 || gotRules.Rows[0].ExternalID != "31" || gotRules.Rows[1].ExternalID != "32" ||
		gotRules.Rows[0].Severity != "critical" ||
		!contains(gotRules.Rows[0].UnmappedCodes, "expression_unmapped") ||
		!contains(gotRules.Rows[0].UnmappedCodes, "delivery_unmapped") ||
		!contains(gotRules.Rows[1].UnmappedCodes, "severity_unmapped") {
		t.Fatalf("rule identity or unmapped policy lost: %+v", gotRules.Rows)
	}
	for _, snapshot := range []Snapshot{gotGroups, gotRules} {
		wire, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"secret-pattern-123", "secret-expression-456", "secret-expression-789", "https://secret.invalid/hook"} {
			if strings.Contains(string(wire), forbidden) {
				t.Fatalf("source expression or delivery target %q escaped into preview", forbidden)
			}
		}
	}
}

func TestLibreNMSGroupAndRulePagesRejectMissingAndDuplicateIdentity(t *testing.T) {
	for _, raw := range []string{
		`{"status":"ok","groups":[{"id":1,"name":"a"},{"id":"1","name":"b"}]}`,
		`{"status":"ok","groups":[{"name":"a"}]}`,
		`{"status":"ok","rules":[{"id":1,"name":"a"},{"id":"1","name":"b"}]}`,
		`{"status":"ok","rules":[{"name":"a"}]}`,
	} {
		var err error
		if strings.Contains(raw, `"groups"`) {
			_, err = parseLibreNMSGroups(strings.NewReader(raw))
		} else {
			_, err = parseLibreNMSRules(strings.NewReader(raw))
		}
		if !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("invalid source identity accepted: %v", err)
		}
	}
}

func TestMalformedSourcePageFailsWithoutEchoingInput(t *testing.T) {
	for _, page := range []string{
		`{"status":"error","message":"secret-token-123","devices":[]}`,
		`{"status":"ok","devices":[{"device_id":0,"community":"secret-token-123"}]}`,
		`{"status":"ok","devices":[{"device_id":17},{"device_id":"017"}]}`,
		`{"status":"ok","devices":[]}{"extra":"secret-token-123"}`,
	} {
		_, err := parseLibreNMSDevices(strings.NewReader(page))
		if !errors.Is(err, ErrInvalidPage) || strings.Contains(err.Error(), "secret-token-123") {
			t.Fatalf("invalid source page must fail closed without echo: %v", err)
		}
	}
	badUTF8 := append([]byte(`{"status":"ok","devices":[{"device_id":1,"display":"`), 0xff)
	badUTF8 = append(badUTF8, []byte(`"}]}`)...)
	if _, err := parseLibreNMSDevices(strings.NewReader(string(badUTF8))); !errors.Is(err, ErrInvalidPage) {
		t.Fatalf("lossy UTF-8 source accepted: %v", err)
	}
}

func TestZabbixExportRejectsAmbiguousSourceKeys(t *testing.T) {
	for _, raw := range []string{
		`{"zabbix_export":{"version":"7.4","host_groups":[{"uuid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"A"},{"uuid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"B"}],"hosts":[]}}`,
		`{"zabbix_export":{"version":"7.4","host_groups":[],"hosts":[{"host":"edge"},{"host":"edge"}]}}`,
		`{"zabbix_export":{"version":"7.4","host_groups":[{"uuid":"secret-token-123","name":"A"}],"hosts":[]}}`,
		`{"zabbix_export":{"version":"7.4","host_groups":[{"uuid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"A"}],"hosts":[{"host":"edge","groups":[{"name":"A"},{"name":"A"}]}]}}`,
	} {
		_, err := parseZabbixHosts(strings.NewReader(raw))
		if !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("ambiguous import identity accepted: %v", err)
		}
	}
}

func TestZabbixUnknownHostGroupCannotCreateMembership(t *testing.T) {
	const raw = `{"zabbix_export":{"version":"7.4","host_groups":[],"hosts":[{"host":"edge","groups":[{"name":"unknown"}],"interfaces":[{"ip":"10.0.0.1"}]}]}}`
	got, err := parseZabbixHosts(strings.NewReader(raw))
	if err != nil || len(got.Rows) != 1 || got.Rows[0].Kind != "device" ||
		len(got.Rows[0].GroupIDs) != 0 ||
		!contains(got.Rows[0].UnmappedCodes, "group_unmapped") {
		t.Fatalf("unknown group silently selected a destination: %+v err=%v", got, err)
	}
}

func TestZabbixInvalidNestedUUIDsStayUnmappedWithoutEcho(t *testing.T) {
	raw := `{"zabbix_export":{"version":"7.4","host_groups":[],"hosts":[{"host":"edge",
		"items":[{"uuid":"secret-item-id-123","delay":"{$SECRET_DELAY}","triggers":[{"uuid":"secret-trigger-id-456","expression":"secret-expression-789"}]}]}]}}`
	got, err := parseZabbixHosts(strings.NewReader(raw))
	if err != nil || len(got.Rows) != 3 || got.Rows[1].ExternalID != "" || got.Rows[2].ExternalID != "" ||
		!contains(got.Rows[1].UnmappedCodes, "item_id_unavailable") ||
		!contains(got.Rows[1].UnmappedCodes, "poll_interval_unmapped") || got.Rows[1].PollSeconds != 0 ||
		!contains(got.Rows[2].UnmappedCodes, "trigger_id_unavailable") {
		t.Fatalf("invalid nested UUID was not held unmapped: %+v, %v", got, err)
	}
	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-item-id-123", "secret-trigger-id-456", "secret-expression-789", "{$SECRET_DELAY}"} {
		if strings.Contains(string(wire), secret) {
			t.Fatalf("invalid source UUID or expression %q escaped into preview", secret)
		}
	}
}

func TestZabbixHostItemWithoutUUIDUsesOpaqueStableKey(t *testing.T) {
	item := `{"key":"ifOperStatus.1[{$SECRET_MACRO}]","type":"SNMP_AGENT","delay":"15s"}`
	page := func(host, item string) string {
		return `{"zabbix_export":{"version":"7.4","host_groups":[],"hosts":[{"host":"` + host + `","items":[` + item + `]}]}}`
	}
	first, err := parseZabbixHosts(strings.NewReader(page("edge-r1", item)))
	if err != nil || len(first.Rows) != 2 || !contains(first.Rows[1].UnmappedCodes, "poll_proposal") ||
		len(first.Rows[1].ExternalID) != 32 || safeZabbixUUID(first.Rows[1].ExternalID) != first.Rows[1].ExternalID {
		t.Fatalf("host item key did not yield a bounded poll proposal: %+v, %v", first, err)
	}
	second, err := parseZabbixHosts(strings.NewReader(page("edge-r1", item)))
	otherHost, hostErr := parseZabbixHosts(strings.NewReader(page("edge-r2", item)))
	otherKey, keyErr := parseZabbixHosts(strings.NewReader(page("edge-r1", strings.Replace(item, "ifOperStatus.1", "ifOperStatus.2", 1))))
	if err != nil || hostErr != nil || keyErr != nil ||
		first.Rows[1].ExternalID != second.Rows[1].ExternalID ||
		first.Rows[1].ExternalID == otherHost.Rows[1].ExternalID ||
		first.Rows[1].ExternalID == otherKey.Rows[1].ExternalID {
		t.Fatal("opaque item identity is not stable and source scoped")
	}
	wire, err := json.Marshal(first)
	if err != nil || strings.Contains(string(wire), "SECRET_MACRO") || strings.Contains(string(wire), "ifOperStatus.1") {
		t.Fatalf("host item key escaped into preview: %s, %v", wire, err)
	}
	invalid, err := parseZabbixHosts(strings.NewReader(page("edge-r1", strings.Replace(item, `"key":`, `"uuid":"malformed","key":`, 1))))
	if err != nil || !contains(invalid.Rows[1].UnmappedCodes, "item_id_unavailable") {
		t.Fatalf("malformed explicit UUID should fail closed: %+v, %v", invalid, err)
	}
}

func TestZabbixLiteralPollIntervalKeepsOnlyBoundedSeconds(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int64
	}{
		{"30", 30}, {"30s", 30}, {"2m", 120}, {"1h", 3600},
		{"1d", 86400}, {"1w", 604800}, {"0", 0}, {"2w", 0},
		{"{$DELAY}", 0}, {"1h;wd1-5h9-18", 0}, {"-1", 0},
		{"999999999999999999999999s", 0},
	} {
		if got := safeZabbixLiteralSeconds(tc.raw); got != tc.want {
			t.Errorf("delay %q: got %d seconds, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestZabbixSNMPItemEligibilityReasonsStayFixed(t *testing.T) {
	for _, tc := range []struct {
		name, item                  string
		transport, status, proposal bool
	}{
		{"supported", `{"uuid":"11111111222233334444555555555555","type":"SNMP_AGENT","status":"ENABLED","delay":"90s"}`, false, false, true},
		{"numeric enums", `{"uuid":"11111111222233334444555555555555","type":20,"status":0,"delay":"90s"}`, false, false, true},
		{"documented enabled default", `{"uuid":"11111111222233334444555555555555","type":"SNMP_AGENT","delay":"90s"}`, false, false, true},
		{"other transport", `{"uuid":"11111111222233334444555555555555","type":"ZABBIX_PASSIVE","delay":"90s"}`, true, false, false},
		{"disabled", `{"uuid":"11111111222233334444555555555555","type":"SNMP_AGENT","status":"DISABLED","delay":"90s"}`, false, true, false},
		{"unknown input", `{"uuid":"11111111222233334444555555555555","type":"secret-transport","status":"secret-status","delay":"90s"}`, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := `{"zabbix_export":{"version":"7.4","host_groups":[],"hosts":[{"host":"edge-r1","interfaces":[{"ip":"10.0.0.1"}],"items":[` + tc.item + `]}]}}`
			got, err := parseZabbixHosts(strings.NewReader(payload))
			if err != nil || len(got.Rows) != 2 {
				t.Fatalf("parse item: %+v err=%v", got, err)
			}
			codes := got.Rows[1].UnmappedCodes
			if contains(codes, "poll_transport_unmapped") != tc.transport ||
				contains(codes, "poll_status_unmapped") != tc.status ||
				contains(codes, "poll_proposal") != tc.proposal ||
				contains(codes, "poll_item_unmapped") == tc.proposal ||
				got.Rows[1].PollSeconds != 90 {
				t.Fatalf("fixed eligibility reasons lost: %+v", got.Rows[1])
			}
			wire, err := json.Marshal(got)
			if err != nil || strings.Contains(string(wire), "secret-transport") ||
				strings.Contains(string(wire), "secret-status") {
				t.Fatalf("source enum escaped into preview: %s err=%v", wire, err)
			}
		})
	}
}

func TestZabbixHostPollCadenceConflictIsVisible(t *testing.T) {
	first := `{"uuid":"11111111222233334444555555555555","type":"SNMP_AGENT","status":"ENABLED","delay":"90s"}`
	for _, tc := range []struct {
		name, second                  string
		firstConflict, secondConflict bool
	}{
		{"matching SNMP", `{"uuid":"22222222333344445555666666666666","type":"SNMP_AGENT","status":"ENABLED","delay":"90s"}`, false, false},
		{"different SNMP", `{"uuid":"22222222333344445555666666666666","type":"SNMP_AGENT","status":"ENABLED","delay":"60s"}`, true, true},
		{"macro SNMP", `{"uuid":"22222222333344445555666666666666","type":"SNMP_AGENT","status":"ENABLED","delay":"{$DELAY}"}`, true, false},
		{"non-SNMP item", `{"uuid":"22222222333344445555666666666666","type":"ZABBIX_PASSIVE","status":"ENABLED","delay":"60s"}`, false, false},
		{"disabled SNMP", `{"uuid":"22222222333344445555666666666666","type":"SNMP_AGENT","status":"DISABLED","delay":"60s"}`, false, false},
		{"omitted SNMP status defaults enabled", `{"uuid":"22222222333344445555666666666666","type":"SNMP_AGENT","delay":"60s"}`, true, true},
		{"unknown SNMP status", `{"uuid":"22222222333344445555666666666666","type":"SNMP_AGENT","status":"SURPRISE","delay":"60s"}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := `{"zabbix_export":{"version":"7.4","host_groups":[],"hosts":[{"host":"edge-r1","interfaces":[{"ip":"10.0.0.1"}],"items":[` + first + `,` + tc.second + `]}]}}`
			got, err := parseZabbixHosts(strings.NewReader(payload))
			if err != nil || len(got.Rows) != 3 {
				t.Fatalf("parse host cadence: %+v err=%v", got, err)
			}
			if contains(got.Rows[1].UnmappedCodes, "poll_cadence_conflict") != tc.firstConflict ||
				contains(got.Rows[2].UnmappedCodes, "poll_cadence_conflict") != tc.secondConflict {
				t.Fatalf("host cadence conflict classification: first=%+v second=%+v",
					got.Rows[1], got.Rows[2])
			}
		})
	}
}

func TestZabbixSNMPCadenceRespectsDeviceAgentBounds(t *testing.T) {
	for _, tc := range []struct {
		delay string
		want  int64
	}{
		{"14s", 14},
		{"25h", 90000},
	} {
		t.Run(tc.delay, func(t *testing.T) {
			payload := `{"zabbix_export":{"version":"7.4","host_groups":[],"hosts":[{"host":"edge-r1","interfaces":[{"ip":"10.0.0.1"}],"items":[{"uuid":"11111111222233334444555555555555","type":"SNMP_AGENT","status":"ENABLED","delay":"` + tc.delay + `"}]}]}}`
			got, err := parseZabbixHosts(strings.NewReader(payload))
			if err != nil || len(got.Rows) != 2 ||
				got.Rows[1].PollSeconds != tc.want ||
				!contains(got.Rows[1].UnmappedCodes, "poll_interval_unmapped") {
				t.Fatalf("out-of-range source cadence became eligible: %+v err=%v", got, err)
			}
		})
	}
}

func TestSafeAddressRejectsZoneAndCanonicalizesMappedIPv4(t *testing.T) {
	for input, want := range map[string]string{
		"fe80::1%en0":      "",
		"::ffff:10.42.0.1": "10.42.0.1",
		"10.42.0.1":        "10.42.0.1",
	} {
		if got := safeAddress(input); got != want {
			t.Errorf("safeAddress(%q) = %q, want %q", input, got, want)
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
