// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Actual issued evidence mTLS and app-role Postgres/RLS, with modeled original
// flow dimensions. Absent exporter ownership is deliberately unavailable, never
// a real sender/current-RIB/flow pipeline or positive route-attachment claim.
func TestFlowRoutingWitnessRealMTLSKeepsTenantFirstReceiptAndCurrentSender(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	server := startTestServer(ctx, t, pool)
	type lane struct {
		tenant, agent string
		client        *agent.EvidenceClient
		capture       *agentv1.FlowRoutingCapture
	}
	var lanes []lane
	raw := &agentv1.FlowRoutingWitness{RawDigest: make([]byte, 32), ExporterAddress: "192.0.2.1", SourceAddress: "203.0.113.1", DestinationAddress: "2001:db8::1", FlowProtocol: "ipfix", ObservationDomain: ^uint32(0)}
	raw.RawDigest[31] = 1
	for _, suffix := range []string{"a", "b"} {
		agentID := newUUID(t)
		tenant, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("flow-witness-wire-%s-%d", suffix, time.Now().UnixNano()), suffix)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
				t.Error(err)
			}
		})
		var cert, key []byte
		for _, uri := range []string{crypto.AgentSPIFFEID(tenant.ID, agentID), crypto.EntitySPIFFEID(tenant.ID, agentID)} {
			cert, key, err = server.ca.IssueClientCert(agentID, uri, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(cert)
			if block == nil {
				t.Fatal("QA certificate missing")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.NewAgentIdentities(pool).Record(ctx, tenant.ID, agentID, uri, leaf.SerialNumber.Text(16), leaf.NotAfter, ""); err != nil {
				t.Fatal(err)
			}
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := (store.Agents{}).Register(ctx, sc, agentID, "flow-witness", "10.2.0.99", "fixture", crypto.AgentSPIFFEID(tenant.ID, agentID), nil)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		client, err := agent.DialEntityEvidence(server.addr, writeTemp(t, dir, "evidence.crt", cert), writeTemp(t, dir, "evidence.key", key), server.caFile, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		captures, err := client.SubmitFlowRouting(ctx, []*agentv1.FlowRoutingWitness{raw})
		if err != nil || len(captures) != 1 {
			t.Fatal("issued flow witness did not retain a scoped first receipt", err)
		}
		retry, err := client.SubmitFlowRouting(ctx, []*agentv1.FlowRoutingWitness{raw})
		if err != nil || len(retry) != 1 || !bytes.Equal(retry[0].Key, captures[0].Key) || retry[0].CapturedUnixNanos != captures[0].CapturedUnixNanos {
			t.Fatal("real evidence retry changed its first routing capture", err)
		}
		if err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var role, outcome string
			var clock int64
			var payloads int
			err := sc.Q.QueryRow(ctx, `SELECT current_user,outcome,captured_at_unix_nanos,(SELECT count(*) FROM bgp_flow_capture_payloads WHERE tenant_id=$1) FROM bgp_flow_capture_receipts WHERE tenant_id=$1 AND flow_key=$2`, tenant.ID, captures[0].Key).Scan(&role, &outcome, &clock, &payloads)
			if err == nil && (role != tenancy.AppRole || outcome != "unavailable" || clock != captures[0].CapturedUnixNanos || payloads != 0) {
				t.Fatal("unowned real witness invented a route or bypassed app-role storage", role, outcome, payloads)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		lanes = append(lanes, lane{tenant.ID, agentID, client, captures[0]})
	}
	if bytes.Equal(lanes[0].capture.Key, lanes[1].capture.Key) {
		t.Fatal("same raw digest/tuple crossed certified tenant scope")
	}
	if err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(lanes[0].tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		var foreign int
		err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_flow_capture_receipts WHERE flow_key=$1`, lanes[1].capture.Key).Scan(&foreign)
		if err == nil && foreign != 0 {
			t.Fatal("app-role RLS exposed foreign routing witness")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// A CA-valid new serial is not the exact issued sender credential.
	cert, key, err := server.ca.IssueClientCert(lanes[0].agent, crypto.EntitySPIFFEID(lanes[0].tenant, lanes[0].agent), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	unissued, err := agent.DialEntityEvidence(server.addr, writeTemp(t, dir, "unissued.crt", cert), writeTemp(t, dir, "unissued.key", key), server.caFile, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unissued.Close() })
	if captures, err := unissued.SubmitFlowRouting(ctx, []*agentv1.FlowRoutingWitness{raw}); err == nil || captures != nil {
		t.Fatal("unissued evidence serial reached a routing witness")
	}
	if _, _, err := store.NewAgentIdentities(pool).RevokeAgent(ctx, lanes[0].tenant, lanes[0].agent, "operator-test"); err != nil {
		t.Fatal(err)
	}
	if captures, err := lanes[0].client.SubmitFlowRouting(ctx, []*agentv1.FlowRoutingWitness{raw}); err == nil || captures != nil {
		t.Fatal("revoked evidence connection retained witness access")
	}
	if captures, err := lanes[1].client.SubmitFlowRouting(ctx, []*agentv1.FlowRoutingWitness{raw}); err != nil || len(captures) != 1 || !bytes.Equal(captures[0].Key, lanes[1].capture.Key) {
		t.Fatal("sibling sender inherited another tenant's revocation", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tenants SET status='offboarding' WHERE id=$1`, lanes[1].tenant); err != nil {
		t.Fatal(err)
	}
	if captures, err := lanes[1].client.SubmitFlowRouting(ctx, []*agentv1.FlowRoutingWitness{raw}); err == nil || captures != nil {
		t.Fatal("offboarding evidence sender read an existing routing witness")
	}
}
