// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"errors"
	"testing"
	"time"
)

const (
	redTenant  = "11111111-1111-4111-8111-111111111111"
	blueTenant = "22222222-2222-4222-8222-222222222222"
	siteA      = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	siteB      = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	routerA    = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	routerB    = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
)

func routerClaim(scope Scope, source, evidenceID, entityID string) Claim {
	kind := DeviceTarget
	switch source {
	case "flow":
		kind = FlowExporter
	case "path":
		kind = PathAgent
	case "bmp":
		kind = BMPPeer
	}
	return Claim{
		Scope: scope, Alias: AliasKey{Kind: AddressAlias, Value: "10.20.0.1"},
		EntityID: entityID, EntityKind: Device, EvidenceID: evidenceID,
		Source: source, SourceRef: source + ":router",
		SourceKey:  SourceKey{AgentID: source + "-collector", Kind: kind, SourceRef: "10.20.0.1"},
		ObservedAt: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
	}
}

func TestResolveOneRouterAcrossFourPlaneEvidenceRows(t *testing.T) {
	scope := Scope{TenantID: redTenant, ContextID: siteA}
	claims := []Claim{
		routerClaim(scope, "snmp", "00000000-0000-4000-8000-000000000001", routerA),
		routerClaim(scope, "flow", "00000000-0000-4000-8000-000000000002", routerA),
		routerClaim(scope, "path", "00000000-0000-4000-8000-000000000003", routerA),
		routerClaim(scope, "bmp", "00000000-0000-4000-8000-000000000004", routerA),
	}
	claims[1].SupportEvidenceID = claims[0].EvidenceID
	claims[3].SupportEvidenceID = claims[0].EvidenceID
	got, err := Resolve(scope, AliasKey{Kind: AddressAlias, Value: "::ffff:10.20.0.1"}, claims)
	if err != nil || got.Status != Resolved || got.EntityID != routerA || len(got.Candidates) != 4 {
		t.Fatalf("one scoped router did not retain four provenance rows: %+v %v", got, err)
	}
	for i, source := range []string{"snmp", "flow", "path", "bmp"} {
		if got.Candidates[i].Source != source {
			t.Fatalf("provenance changed order or vanished: %+v", got.Candidates)
		}
	}
	if got.Candidates[1].SupportEvidenceID != claims[0].EvidenceID ||
		got.Candidates[3].SupportEvidenceID != claims[0].EvidenceID {
		t.Fatal("inferred flow/BMP candidates lost their exact SNMP support row")
	}
}

func TestResolveRefusesCrossTenantAndCrossContextSamePrivateAddress(t *testing.T) {
	red := Scope{TenantID: redTenant, ContextID: siteA}
	for name, other := range map[string]Scope{
		"another tenant":   {TenantID: blueTenant, ContextID: siteA},
		"another VRF/site": {TenantID: redTenant, ContextID: siteB},
	} {
		t.Run(name, func(t *testing.T) {
			claim := routerClaim(other, "snmp", "00000000-0000-4000-8000-000000000005", routerB)
			got, err := Resolve(red, AliasKey{Kind: AddressAlias, Value: "10.20.0.1"}, []Claim{claim})
			if !errors.Is(err, ErrScopeMismatch) || got.EntityID != "" || len(got.Candidates) != 0 {
				t.Fatalf("foreign candidate became a local identity: %+v %v", got, err)
			}
		})
	}
	if _, err := Resolve(Scope{TenantID: redTenant}, AliasKey{Kind: AddressAlias, Value: "10.20.0.1"}, nil); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("missing routing context enabled a global address lookup: %v", err)
	}
}

func TestResolveRefusesForgedInferredSupportOnSNMPClaim(t *testing.T) {
	scope := Scope{TenantID: redTenant, ContextID: siteA}
	claim := routerClaim(scope, "snmp", "00000000-0000-4000-8000-000000000011", routerA)
	claim.SupportEvidenceID = "00000000-0000-4000-8000-000000000012"
	if _, err := Resolve(scope, claim.Alias, []Claim{claim}); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("SNMP claim carried an inferred support pointer: %v", err)
	}
}

func TestResolveShowsConflictWithoutChoosingAnEntity(t *testing.T) {
	scope := Scope{TenantID: redTenant, ContextID: siteA}
	claims := []Claim{
		routerClaim(scope, "snmp", "00000000-0000-4000-8000-000000000006", routerB),
		routerClaim(scope, "flow", "00000000-0000-4000-8000-000000000007", routerA),
	}
	got, err := Resolve(scope, AliasKey{Kind: AddressAlias, Value: "10.20.0.1"}, claims)
	if err != nil || got.Status != Conflict || got.EntityID != "" || len(got.Candidates) != 2 {
		t.Fatalf("competing device claims were silently merged: %+v %v", got, err)
	}
	if got.Candidates[0].EntityID != routerA || got.Candidates[1].EntityID != routerB {
		t.Fatalf("conflict order is unstable: %+v", got.Candidates)
	}
	unseen, err := Resolve(scope, AliasKey{Kind: AddressAlias, Value: "10.20.0.2"}, nil)
	if err != nil || unseen.Status != Unresolved || unseen.EntityID != "" {
		t.Fatalf("absent evidence manufactured identity: %+v %v", unseen, err)
	}
}

func TestResolveRejectsWrongAliasAndForgedEvidence(t *testing.T) {
	scope := Scope{TenantID: redTenant, ContextID: siteA}
	base := routerClaim(scope, "snmp", "00000000-0000-4000-8000-000000000008", routerA)
	for name, mutate := range map[string]func(*Claim){
		"wrong address":             func(c *Claim) { c.Alias.Value = "10.20.0.2" },
		"invalid entity":            func(c *Claim) { c.EntityID = "not-a-uuid" },
		"invalid evidence":          func(c *Claim) { c.EvidenceID = "not-a-uuid" },
		"missing source":            func(c *Claim) { c.Source = "" },
		"missing source reference":  func(c *Claim) { c.SourceRef = "" },
		"missing source assignment": func(c *Claim) { c.SourceKey.AgentID = "" },
		"missing time":              func(c *Claim) { c.ObservedAt = time.Time{} },
		"unknown kind":              func(c *Claim) { c.EntityKind = "router-maybe" },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if got, err := Resolve(scope, base.Alias, []Claim{c}); err == nil || got.EntityID != "" {
				t.Fatalf("invalid claim was accepted: %+v %v", got, err)
			}
		})
	}
	second := routerClaim(scope, "flow", base.EvidenceID, routerB)
	if _, err := Resolve(scope, base.Alias, []Claim{base, second}); !errors.Is(err, ErrConflictingEvidence) {
		t.Fatalf("one evidence ID pointed to two entities: %v", err)
	}
}

func TestAliasNormalizationPreservesTypedSourceIdentity(t *testing.T) {
	for _, tc := range []struct {
		in   AliasKey
		want string
	}{
		{AliasKey{Kind: AddressAlias, Value: " ::ffff:192.0.2.7 "}, "192.0.2.7"},
		{AliasKey{Kind: PrefixAlias, Value: "10.20.3.7/24"}, "10.20.3.0/24"},
		{AliasKey{Kind: SNMPDeviceAlias, Value: "  Agent-A:7 "}, "Agent-A:7"},
		{AliasKey{Kind: SNMPInterfaceAlias, Value: " 4294967295 "}, "4294967295"},
	} {
		got, err := tc.in.Normalize()
		if err != nil || got.Value != tc.want {
			t.Fatalf("typed alias normalized incorrectly: %+v %v", got, err)
		}
	}
	for _, key := range []AliasKey{
		{Kind: AddressAlias, Value: "10.20.0.1%en0"},
		{Kind: PrefixAlias, Value: "not-a-prefix"},
		{Kind: SNMPDeviceAlias, Value: "line\nbreak"},
		{Kind: SNMPInterfaceAlias, Value: "0"},
		{Kind: SNMPInterfaceAlias, Value: "007"},
		{Kind: SNMPInterfaceAlias, Value: "4294967296"},
		{Kind: "raw-sql", Value: "10.20.0.1"},
	} {
		if _, err := key.Normalize(); !errors.Is(err, ErrInvalidAlias) {
			t.Fatalf("untrusted alias accepted: %+v %v", key, err)
		}
	}
	if SNMPDeviceAlias == FlowExporterAlias {
		t.Fatal("source-local identity types collapsed")
	}
}
