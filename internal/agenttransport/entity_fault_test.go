// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestFaultAdapterRequiresLiveVerifiedEvidenceSender(t *testing.T) {
	const tenant, agent = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	ca, err := crypto.GenerateCA("fault-evidence", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := ca.IssueClientCert(agent, crypto.EntitySPIFFEID(tenant, agent), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafFromPEM(t, cert)
	identity, err := crypto.EntitySPIFFEIDFromCert(leaf)
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}}}
	ctx := func(state tls.ConnectionState) context.Context {
		return peer.NewContext(context.Background(), &peer.Peer{
			AuthInfo: credentials.TLSInfo{State: state}})
	}
	item := &agentv1.EntityFaultObservation{
		ObservationId: "55e143c5-c63c-4e0e-974a-f29631bb5233",
		SourceKind:    "device_target", ConfiguredRef: "10.42.0.1",
		TargetAddress: "10.42.0.1", Kind: "device.poll_failed",
		ObservedUnixNanos: time.Now().UnixNano(),
	}
	valid, err := validateEntityFaults(ctx(state), identity, []*agentv1.EntityFaultObservation{item})
	if err != nil || len(valid) != 1 || valid[0].source.TenantID() != tenant ||
		valid[0].source.AgentID() != agent || valid[0].signal.TenantID != tenant ||
		valid[0].signal.Target != "10.42.0.1" {
		t.Fatalf("verified fault sender/target lost: %+v %v", valid, err)
	}
	unverified := state
	unverified.VerifiedChains = nil
	if _, err := validateEntityFaults(ctx(unverified), identity, []*agentv1.EntityFaultObservation{item}); err == nil {
		t.Fatal("unverified gRPC peer authored an incident fault")
	}
	forged := proto.Clone(item).(*agentv1.EntityFaultObservation)
	forged.ConfiguredRef = "10.42.0.2"
	if _, err := validateEntityFaults(ctx(state), identity, []*agentv1.EntityFaultObservation{forged}); err == nil {
		t.Fatal("configured source selected another device fault target")
	}
	wrongTenant := identity
	wrongTenant.TenantID = "33333333-3333-4333-8333-333333333333"
	if _, err := validateEntityFaults(ctx(state), wrongTenant, []*agentv1.EntityFaultObservation{item}); err == nil {
		t.Fatal("request-path tenant disagreed with mTLS sender")
	}
	if _, err := validateEntityFaults(ctx(state), identity,
		[]*agentv1.EntityFaultObservation{item, item}); err == nil {
		t.Fatal("same fault UUID appeared twice in one batch before any write")
	}
}
