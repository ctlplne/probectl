// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package incident

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

type identityMemoryStore struct {
	*MemoryStore
	lookup func(AuthenticatedIdentitySource, Signal) (IdentityResolution, error)
}

func (m *identityMemoryStore) ResolveSignalIdentity(_ context.Context,
	source AuthenticatedIdentitySource, sig Signal) (IdentityResolution, error) {
	return m.lookup(source, sig)
}

func identitySource(tenant, agent string) AuthenticatedIdentitySource {
	return AuthenticatedIdentitySource{tenantID: tenant, agentID: agent,
		sourceKind: "device_target", sourceRef: "10.42.0.1", certificateSerial: "ab1234"}
}

func TestAuthenticatedIdentitySourceRequiresVerifiedEvidencePlane(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000101"
	uri, err := url.Parse(crypto.EntitySPIFFEID(tenant, "collector-a"))
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{Raw: []byte{1, 2, 3}, URIs: []*url.URL{uri},
		SerialNumber: big.NewInt(123), NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour)}
	state := tls.ConnectionState{HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}}}
	got, err := AuthenticatedSourceFromTLS(state, "device_target", "10.42.0.1")
	if err != nil || got.TenantID() != tenant || got.AgentID() != "collector-a" ||
		got.CertificateSerial() != "7b" {
		t.Fatalf("verified entity peer: %+v %v", got, err)
	}
	noChain := state
	noChain.VerifiedChains = nil
	if _, err := AuthenticatedSourceFromTLS(noChain, "device_target", "10.42.0.1"); err == nil {
		t.Fatal("unverified TLS peer constructed an identity source")
	}
	agentURI, err := url.Parse(crypto.AgentSPIFFEID(tenant, "collector-a"))
	if err != nil {
		t.Fatal(err)
	}
	agentLeaf := *leaf
	agentLeaf.URIs = []*url.URL{agentURI}
	agentLeaf.Raw = []byte{4, 5, 6}
	state.PeerCertificates, state.VerifiedChains = []*x509.Certificate{&agentLeaf}, [][]*x509.Certificate{{&agentLeaf}}
	if _, err := AuthenticatedSourceFromTLS(state, "device_target", "10.42.0.1"); err == nil {
		t.Fatal("agent-plane credential constructed an entity evidence source")
	}
	leaf.NotAfter = time.Now().Add(-time.Second)
	state.PeerCertificates, state.VerifiedChains = []*x509.Certificate{leaf}, [][]*x509.Certificate{{leaf}}
	if _, err := AuthenticatedSourceFromTLS(state, "device_target", "10.42.0.1"); err == nil {
		t.Fatal("expired evidence certificate constructed an identity source")
	}
}

func TestVerifiedEntityCorrelationSeparatesReusedPrivateAddress(t *testing.T) {
	store := &identityMemoryStore{MemoryStore: NewMemoryStore(),
		lookup: func(source AuthenticatedIdentitySource, _ Signal) (IdentityResolution, error) {
			if source.AgentID() == "red-other-vrf" {
				return IdentityResolution{ContextID: "red-vrf-b", EntityID: "device-b"}, nil
			}
			if source.TenantID() == "blue" {
				return IdentityResolution{ContextID: "blue-vrf", EntityID: "blue-device"}, nil
			}
			return IdentityResolution{ContextID: "red-vrf-a", EntityID: "device-a"}, nil
		}}
	c := NewCorrelator(store, 5*time.Minute, discard())
	makeSignal := func(tenant, plane, target string, at time.Time) Signal {
		return Signal{TenantID: tenant, Plane: plane, Kind: "fault", Target: target,
			OccurredAt: at}
	}
	first, err := c.IngestAuthenticated(context.Background(),
		makeSignal("red", "device", "10.42.0.1", t0), identitySource("red", "red-snmp"))
	if err != nil {
		t.Fatal(err)
	}
	joined, err := c.IngestAuthenticated(context.Background(),
		makeSignal("red", "flow", "10.42.0.254", t0.Add(time.Second)),
		identitySource("red", "red-flow"))
	if err != nil || joined.ID != first.ID || joined.SignalCount != 2 ||
		joined.Signals[1].Attributes["correlation.rule"] != "verified_entity_context_v1" {
		t.Fatalf("different raw targets with one verified device must group: %+v %v", joined, err)
	}
	otherVRF, err := c.IngestAuthenticated(context.Background(),
		makeSignal("red", "device", "10.42.0.1", t0.Add(2*time.Second)),
		identitySource("red", "red-other-vrf"))
	if err != nil || otherVRF.ID == first.ID {
		t.Fatalf("same private IP crossed red VRFs: %+v %v", otherVRF, err)
	}
	otherTenant, err := c.IngestAuthenticated(context.Background(),
		makeSignal("blue", "device", "10.42.0.1", t0.Add(3*time.Second)),
		identitySource("blue", "blue-snmp"))
	if err != nil || otherTenant.ID == first.ID || store.Len() != 3 {
		t.Fatalf("same private IP crossed tenants: %+v %v", otherTenant, err)
	}
}

func TestAuthenticatedLookupFailureCannotFallBackToRawAddress(t *testing.T) {
	store := &identityMemoryStore{MemoryStore: NewMemoryStore(),
		lookup: func(_ AuthenticatedIdentitySource, sig Signal) (IdentityResolution, error) {
			if sig.Kind == "lookup-error" {
				return IdentityResolution{}, errors.New("registry unavailable")
			}
			return IdentityResolution{ContextID: "red-vrf", EntityID: "device-a"}, nil
		}}
	c := NewCorrelator(store, time.Minute, discard())
	raw, err := c.Ingest(context.Background(), Signal{TenantID: "red", Plane: "bgp",
		Kind: "raw", Target: "10.42.0.1", OccurredAt: t0})
	if err != nil {
		t.Fatal(err)
	}
	unavailable, err := c.IngestAuthenticated(context.Background(), Signal{TenantID: "red",
		Plane: "device", Kind: "lookup-error", Target: "10.42.0.1",
		OccurredAt: t0.Add(time.Second)}, identitySource("red", "red-snmp"))
	if err != nil || unavailable.ID == raw.ID || !unavailable.IdentityLookupAttempted ||
		unavailable.IdentityContextID != "" ||
		unavailable.Signals[0].Attributes["correlation.rule"] != "identity_unresolved_v1" {
		t.Fatalf("failed lookup fell back to raw incident: %+v %v", unavailable, err)
	}
	verified, err := c.IngestAuthenticated(context.Background(), Signal{TenantID: "red",
		Plane: "device", Kind: "resolved", Target: "10.42.0.1",
		OccurredAt: t0.Add(2 * time.Second)}, identitySource("red", "red-snmp"))
	if err != nil || verified.ID == raw.ID || verified.ID == unavailable.ID ||
		verified.IdentityContextID != "red-vrf" || verified.IdentityEntityID != "device-a" {
		t.Fatalf("verified signal joined an unresolved/raw incident: %+v %v", verified, err)
	}
}

func TestCallerCannotStampCorrelationIdentity(t *testing.T) {
	store := NewMemoryStore()
	c := NewCorrelator(store, time.Minute, discard())
	first, err := c.Ingest(context.Background(), Signal{TenantID: "red", Plane: "device",
		Target: "10.42.0.1", OccurredAt: t0,
		IdentityLookupAttempted: true, IdentityContextID: "forged-vrf", IdentityEntityID: "forged-device"})
	if err != nil || first.IdentityLookupAttempted || first.IdentityContextID != "" {
		t.Fatalf("caller stamped a verified identity: %+v %v", first, err)
	}
	second, err := c.Ingest(context.Background(), Signal{TenantID: "red", Plane: "flow",
		Target: "10.42.0.254", OccurredAt: t0.Add(time.Second),
		Attributes: map[string]string{"entity_id": "forged-device", "context_id": "forged-vrf"}})
	if err != nil || second.ID == first.ID {
		t.Fatalf("free-form attributes forced an identity match: %+v %v", second, err)
	}
	if _, err := c.IngestAuthenticated(context.Background(), Signal{TenantID: "red",
		Target: "10.42.0.1"}, identitySource("blue", "blue-snmp")); err == nil {
		t.Fatal("cross-tenant authenticated source was accepted")
	}
}

func TestDeletedEntityContextTombstoneNeverUsesRawAddress(t *testing.T) {
	inc := &Incident{TenantID: "red", Status: StatusOpen, Target: "10.42.0.1",
		StartedAt: t0, LastSeenAt: t0, IdentityLookupAttempted: true,
		IdentityContextID: "red-vrf"} // entity_id cleared by the FK on deletion
	for _, sig := range []Signal{
		{TenantID: "red", Target: "10.42.0.1", OccurredAt: t0.Add(time.Second)},
		{TenantID: "red", Target: "10.42.0.1", OccurredAt: t0.Add(time.Second),
			IdentityLookupAttempted: true, IdentityContextID: "red-vrf",
			IdentityEntityID: "replacement-device"},
	} {
		if related(inc, sig, time.Minute) {
			t.Fatalf("deleted entity tombstone reused raw address or new entity: %+v", sig)
		}
	}
}

func TestVerifiedCorrelationOverrideDoesNotMatchReusedAddressInAnotherVRF(t *testing.T) {
	override := CorrelationOverride{TenantID: "red", Plane: "device", Kind: "fault",
		Target: "10.42.0.1", Active: true, IdentityLookupAttempted: true,
		IdentityContextID: "vrf-a", IdentityEntityID: "router-a"}
	same := Signal{TenantID: "red", Plane: "device", Kind: "fault",
		Target: "10.42.0.1", IdentityLookupAttempted: true,
		IdentityContextID: "vrf-a", IdentityEntityID: "router-a"}
	if !override.Matches(same) {
		t.Fatal("verified override no longer matched its exact canonical signal")
	}
	for _, other := range []Signal{
		{TenantID: "red", Plane: "device", Kind: "fault", Target: "10.42.0.1",
			IdentityLookupAttempted: true, IdentityContextID: "vrf-b", IdentityEntityID: "router-b"},
		{TenantID: "red", Plane: "device", Kind: "fault", Target: "10.42.0.1"},
		{TenantID: "blue", Plane: "device", Kind: "fault", Target: "10.42.0.1",
			IdentityLookupAttempted: true, IdentityContextID: "vrf-a", IdentityEntityID: "router-a"},
	} {
		if override.Matches(other) {
			t.Fatalf("verified override crossed its tenant/context/authority: %+v", other)
		}
	}
	override.IdentityEntityID = "" // FK tombstone after canonical deletion
	same.IdentityEntityID = ""
	if override.Matches(same) {
		t.Fatal("deleted-entity override matched an unrelated unresolved signal")
	}
}
