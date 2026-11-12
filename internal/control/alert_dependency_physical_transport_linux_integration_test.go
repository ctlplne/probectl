// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package control

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport"
)

type dependencyPhysicalTransport struct {
	ca                *crypto.CA
	addr, caFile      string
	certFile, keyFile string
}

func dependencyPhysicalFile(t *testing.T, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startDependencyPhysicalTransport(t *testing.T, d *dependencyRoutingFixture) dependencyPhysicalTransport {
	t.Helper()
	ca, err := crypto.GenerateCA("probectl-dependency-lab", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	transport := dependencyPhysicalTransport{ca: ca, caFile: dependencyPhysicalFile(t, "ca.pem", ca.CertPEM()),
		certFile: dependencyPhysicalFile(t, "server.pem", cert), keyFile: dependencyPhysicalFile(t, "server.key", key)}
	server, err := agenttransport.New(transport.certFile, transport.keyFile, transport.caFile, d.f.pool, bus.NewMemory(), nil, d.f.server.log)
	if err != nil {
		t.Fatal(err)
	}
	server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	transport.addr = listener.Addr().String()
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.ServeListener(ctx, listener) }()
	t.Cleanup(func() { stop(); <-done })
	return transport
}

func (transport dependencyPhysicalTransport) sender(t *testing.T, d *dependencyRoutingFixture, tenant string) *agent.EvidenceClient {
	t.Helper()
	sender := d.graphs[tenant].Nodes[0].AgentID
	identity := crypto.EntitySPIFFEID(tenant, sender)
	cert, key, err := transport.ca.IssueClientCert(sender, identity, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(cert)
	if block == nil {
		t.Fatal("issued sender certificate is absent")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serial := leaf.SerialNumber.Text(16)
	if err := store.NewAgentIdentities(d.f.pool).Record(t.Context(), tenant, sender, identity, serial, leaf.NotAfter, ""); err != nil {
		t.Fatal(err)
	}
	d.serials[tenant] = serial
	client, err := agent.DialEntityEvidence(transport.addr, dependencyPhysicalFile(t, "sender.pem", cert), dependencyPhysicalFile(t, "sender.key", key), transport.caFile, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func (transport dependencyPhysicalTransport) mail(t *testing.T) (*testsupport.SMTPServer, alert.MailSender) {
	t.Helper()
	serverTLS, err := crypto.ServerTLSConfig(transport.certFile, transport.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := crypto.HardenedClientTLSConfigWithCAFile(transport.caFile)
	if err != nil {
		t.Fatal(err)
	}
	relay := testsupport.StartSMTPServer(t, serverTLS, "", "")
	return relay, alert.NewSMTPSender(relay.Addr, "probectl@example.test", nil, alert.SMTPStartTLS, clientTLS)
}

func dependencyPhysicalDefinitions(t *testing.T, d *dependencyRoutingFixture, tenant string) []testspec.ExecutableDefinition {
	t.Helper()
	ids := []string{d.graphs[tenant].Nodes[0].TestID, d.graphs[tenant].Nodes[1].TestID, gouuid.NewString()}
	definitions := make([]testspec.ExecutableDefinition, len(ids))
	d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target,interval_seconds,timeout_seconds,params,enabled)
			VALUES($1,$2,'Independent physical ICMP','icmp','192.0.2.3',30,2,'{"allow_private_targets":"true","count":"1"}',true)`, tenant, ids[2]); err != nil {
			return err
		}
		for i, id := range ids {
			var params []byte
			definition := &definitions[i]
			if err := sc.Q.QueryRow(ctx, `SELECT id::text,type,target,interval_seconds,timeout_seconds,params FROM tests WHERE tenant_id=$1 AND id=$2`, tenant, id).
				Scan(&definition.ID, &definition.Type, &definition.Target, &definition.IntervalSeconds, &definition.TimeoutSeconds, &params); err != nil {
				return err
			}
			if err := json.Unmarshal(params, &definition.Params); err != nil {
				return err
			}
		}
		// The physical proof cannot borrow the routing fixture's modeled loss
		// samples or preexisting upstream incident to manufacture its result.
		if _, err := sc.Q.Exec(ctx, `DELETE FROM entity_evidence WHERE tenant_id=$1 AND agent_id=$2`, tenant, d.graphs[tenant].Nodes[0].AgentID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `DELETE FROM incidents WHERE tenant_id=$1 AND id=$2`, tenant, d.cases[tenant])
		return err
	})
	return definitions
}

func sampleDependencyPhysical(t *testing.T, d *dependencyRoutingFixture, tenant string, ns string, definitions []testspec.ExecutableDefinition, client *agent.EvidenceClient, writer tsdb.Writer) {
	t.Helper()
	sender := d.graphs[tenant].Nodes[0].AgentID
	for i, definition := range definitions {
		value := collectDependencyPhysical(t, ns, definition)
		m := value.Measurement
		if i < len(d.graphs[tenant].Nodes) {
			digest, err := testspec.DefinitionHash(definition)
			if err != nil {
				t.Fatal(err)
			}
			claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: sender, Kind: entity.PathAgent, SourceRef: definition.ID},
				Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: m.TargetIP}, SourceRef: "icmp:configured-test", ObservedAt: m.CompletedAt,
				ICMP: &entity.ICMPMeasurement{Version: 1, DefinitionHash: digest, StartedAt: m.StartedAt, CompletedAt: m.CompletedAt,
					Requested: uint32(m.Expected), Attempted: uint32(m.Attempted), Transmitted: uint32(m.Transmitted), Replies: uint32(m.Replies), SendErrors: uint32(m.SendErrors),
					ReadComplete: m.ReadComplete, Canceled: m.Canceled, IOFailed: m.IOFailed, Responders: m.Responders}}
			claim, err = claim.Normalize(time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if accepted, unresolved, err := client.Submit(t.Context(), []entity.Observation{claim}); err != nil || accepted != 1 || unresolved != 0 {
				t.Fatal("real physical sender evidence was refused", accepted, unresolved, err)
			}
		}
		success := float64(0)
		if value.Result.Success {
			success = 1
		}
		row := tsdb.Series{Metric: d.rules[tenant].Metric, Value: success, TimeMillis: m.CompletedAt.UnixMilli(),
			Labels: map[string]string{"tenant_id": tenant, "agent_id": sender, "test_id": definition.ID, "server_address": definition.Target}}
		if err := writer.Write(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), []tsdb.Series{row}); err != nil {
			t.Fatal(err)
		}
	}
}
