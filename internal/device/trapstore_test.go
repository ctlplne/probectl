// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
)

func validTrapRecord() TrapRecord {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	return TrapRecord{
		TenantID: "tenant-a", AgentID: "agent-1", DeviceAddress: "10.0.0.1",
		SourceAddress: "10.0.0.1", AuthPrincipal: "core-sw1", Version: "snmpv2c",
		Kind: "snmp.trap.link_down", Severity: "warning", TrapOID: oidSNMPLinkDown,
		VarBinds: []TrapVarBind{
			{OID: oidSNMPTrapOID0, Type: "ObjectIdentifier", Value: oidSNMPLinkDown},
			{OID: oidIfIndex + ".2", Type: "Integer", Value: "2"},
		},
		Fingerprint: "00ff00ff00ff00ff", ObservedAt: now, ReceivedAt: now,
	}
}

func TestValidateTrapRecordAcceptsAnAuthenticatedTrap(t *testing.T) {
	got, err := ValidateTrapRecord(validTrapRecord())
	if err != nil {
		t.Fatal(err)
	}
	if got.TrapName != "linkDown" || got.VarBindsTruncated || len(got.VarBinds) != 2 {
		t.Fatalf("validated = %+v", got)
	}
}

func TestValidateTrapRecordRefusesBrokenIdentity(t *testing.T) {
	cases := map[string]func(*TrapRecord){
		"no tenant":         func(r *TrapRecord) { r.TenantID = "" },
		"no agent":          func(r *TrapRecord) { r.AgentID = " " },
		"long agent":        func(r *TrapRecord) { r.AgentID = strings.Repeat("a", 129) },
		"no device":         func(r *TrapRecord) { r.DeviceAddress = "" },
		"control in device": func(r *TrapRecord) { r.DeviceAddress = "10.0.0\x01.1" },
		"long principal":    func(r *TrapRecord) { r.AuthPrincipal = strings.Repeat("u", 256) },
		"no fingerprint":    func(r *TrapRecord) { r.Fingerprint = "" },
		"long fingerprint":  func(r *TrapRecord) { r.Fingerprint = strings.Repeat("f", 65) },
		"bad version":       func(r *TrapRecord) { r.Version = "snmpv9" },
		"foreign kind":      func(r *TrapRecord) { r.Kind = "syslog.message" },
		"non-numeric oid":   func(r *TrapRecord) { r.TrapOID = ".1.3.6.x" },
		"empty oid arc":     func(r *TrapRecord) { r.TrapOID = ".1..3" },
		"long oid":          func(r *TrapRecord) { r.TrapOID = "." + strings.Repeat("1.", 200) + "1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rec := validTrapRecord()
			mutate(&rec)
			if _, err := ValidateTrapRecord(rec); !errors.Is(err, ErrInvalidTrapRecord) {
				t.Fatalf("ValidateTrapRecord(%s) = %v, want ErrInvalidTrapRecord", name, err)
			}
		})
	}
}

func TestValidateTrapRecordBoundsUntrustedVarBinds(t *testing.T) {
	rec := validTrapRecord()
	rec.VarBinds = nil
	for i := 0; i < MaxTrapVarBinds+10; i++ {
		rec.VarBinds = append(rec.VarBinds, TrapVarBind{OID: ".1.3.6.1.4.1.9.9.1", Type: "OctetString", Value: "v"})
	}
	got, err := ValidateTrapRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.VarBinds) != MaxTrapVarBinds || !got.VarBindsTruncated {
		t.Fatalf("varbinds = %d truncated=%v, want %d truncated", len(got.VarBinds), got.VarBindsTruncated, MaxTrapVarBinds)
	}

	rec = validTrapRecord()
	rec.VarBinds = []TrapVarBind{
		{OID: ".1.3.6.1.2.1.2.2.1.6.2", Type: "OctetString", Value: "\x00\x1b\x21\xff\xfe\x01"}, // a MAC
		{OID: ".1.3.6.1.2.1.31.1.1.1.18.2", Type: "OctetString", Value: strings.Repeat("é", MaxTrapVarBindValueBytes)},
		{OID: "not-an-oid", Type: "Integer", Value: "1"},
		{OID: ".1.3.6.1.4.1.1", Type: strings.Repeat("T", 40), Value: "x"},
	}
	got, err = ValidateTrapRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.VarBinds) != 3 || !got.VarBindsTruncated {
		t.Fatalf("varbinds = %+v truncated=%v, want the malformed OID dropped", got.VarBinds, got.VarBindsTruncated)
	}
	if got.VarBinds[0].Value != "0x001b21fffe01" {
		t.Fatalf("binary octet string stored as %q, want hex", got.VarBinds[0].Value)
	}
	if v := got.VarBinds[1].Value; len(v) > MaxTrapVarBindValueBytes || !utf8.ValidString(v) {
		t.Fatalf("long value kept %d bytes (valid UTF-8 %v), want <= %d", len(v), utf8.ValidString(v), MaxTrapVarBindValueBytes)
	}
	if got.VarBinds[2].Type != "Unknown" {
		t.Fatalf("oversized type kept as %q", got.VarBinds[2].Type)
	}
}

func TestValidateTrapRecordNormalizes(t *testing.T) {
	rec := validTrapRecord()
	rec.TrapOID = "1.3.6.1.6.3.1.1.5.4"
	rec.Severity = "panic"
	rec.Kind = ""
	rec.ObservedAt = time.Time{}
	got, err := ValidateTrapRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if got.TrapOID != oidSNMPLinkUp || got.TrapName != "linkUp" || got.Severity != "info" ||
		got.Kind != "snmp.trap" || !got.ObservedAt.Equal(rec.ReceivedAt) {
		t.Fatalf("normalized = %+v", got)
	}
}

func TestTrapRecordFromProtoCarriesNoCredentialField(t *testing.T) {
	rec := TrapRecordFromProto(&devicev1.DeviceTrapEvent{
		TenantId: "t", AgentId: "a", DeviceAddress: "d", AuthPrincipal: "acme-ro",
		Varbinds: []*devicev1.DeviceTrapVarBind{{Oid: ".1.3", Type: "Integer", Value: "1"}},
	})
	if rec.AuthPrincipal != "acme-ro" || len(rec.VarBinds) != 1 || rec.VarBinds[0].OID != ".1.3" {
		t.Fatalf("record = %+v", rec)
	}
}

func TestTrapNames(t *testing.T) {
	for oid, want := range map[string]string{
		oidSNMPColdStart: "coldStart", oidSNMPWarmStart: "warmStart", "1.3.6.1.6.3.1.1.5.3": "linkDown",
		oidSNMPLinkUp: "linkUp", oidSNMPAuthFailure: "authenticationFailure", ".1.3.6.1.4.1.9.0.1": "",
	} {
		if got := TrapName(oid); got != want {
			t.Errorf("TrapName(%s) = %q, want %q", oid, got, want)
		}
	}
	if NormalizeTrapOID(" 1.3.6 ") != ".1.3.6" || NormalizeTrapOID("") != "" {
		t.Fatal("NormalizeTrapOID")
	}
}
