// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func faultReceiptTestSource(t *testing.T, tenant, agent string) incident.AuthenticatedIdentitySource {
	t.Helper()
	uri, err := url.Parse(crypto.EntitySPIFFEID(tenant, agent))
	if err != nil {
		t.Fatal(err)
	}
	serialID := uuid.New()
	leaf := &x509.Certificate{Raw: []byte(tenant + agent), URIs: []*url.URL{uri},
		SerialNumber: new(big.Int).SetBytes(serialID[:]), NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour)}
	source, err := incident.AuthenticatedSourceFromTLS(tls.ConnectionState{
		HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains: [][]*x509.Certificate{{leaf}},
	}, "device_target", "10.42.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func bindFaultReceiptTestSource(t *testing.T, db *store.DB, tenant, agent string) {
	t.Helper()
	contextID := uuid.NewString()
	err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)),
		db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
			(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
			VALUES ($1,$2,$3,$4,'fault-site','fault-vrf')`,
				tenant, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
			(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
				tenant, agent, contextID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id)
			VALUES ($1,$2,'device_target','10.42.0.1',$3)`,
				tenant, agent, contextID)
			return err
		})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFaultReceiptSurvivesResolutionAndBindsTenant(t *testing.T) {
	_, db := setupAPIServerWithLatest(t, nil)
	a, b := freshTenant(t, db, "fault-receipt-a"), freshTenant(t, db, "fault-receipt-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove fault receipt tenants: %v", err)
		}
	})
	id := uuid.NewString()
	ats := make(map[string]time.Time)
	signal := func(tenant string) incident.Signal {
		return incident.Signal{TenantID: tenant, Plane: "device", Kind: "device.poll_failed",
			Severity: incident.SeverityWarning, Title: "SNMP device poll failed",
			Target: "10.42.0.1", OccurredAt: ats[tenant],
			Attributes: map[string]string{entity.AttrFaultObservationID: id,
				entity.AttrFaultKind:  "device.poll_failed",
				entity.AttrSourceKind: "device_target",
				"probectl.agent.id":   "agent-a", "probectl.tenant.id": tenant,
				"probectl.device.address": "10.42.0.1"}}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	firstCorrelator := BuildCorrelator(db.Pool(), time.Minute, log)
	sourceA := faultReceiptTestSource(t, a, "agent-a")
	if err := store.NewAgentIdentities(db.Pool()).Record(context.Background(), a,
		"agent-a", crypto.EntitySPIFFEID(a, "agent-a"), sourceA.CertificateSerial(),
		time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	var beforeAssignment time.Time
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(a)),
		db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&beforeAssignment)
		}); err != nil {
		t.Fatal(err)
	}
	bindFaultReceiptTestSource(t, db, a, "agent-a")
	ats[a] = time.Now().Add(time.Millisecond).UTC().Truncate(time.Microsecond)
	beforeID := uuid.NewString()
	before := signal(a)
	before.OccurredAt = beforeAssignment
	before.Attributes[entity.AttrFaultObservationID] = beforeID
	if _, err := firstCorrelator.IngestAuthenticatedFault(context.Background(),
		before, sourceA, beforeID); !errors.Is(err, incident.ErrFaultSourceInactive) {
		t.Fatalf("later source assignment authorized an earlier fault: %v", err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(a)),
		db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			var receipts int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_fault_receipts`).Scan(&receipts); err != nil {
				return err
			}
			if receipts != 0 {
				t.Errorf("pre-assignment fault wrote %d receipts", receipts)
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	first, err := firstCorrelator.IngestAuthenticatedFault(context.Background(), signal(a), sourceA, id)
	if err != nil || first == nil || first.SignalCount != 1 {
		t.Fatalf("first durable fault: %+v %v", first, err)
	}
	preIssueID := uuid.NewString()
	preIssue := signal(a)
	preIssue.OccurredAt = ats[a].Add(-time.Hour)
	preIssue.Attributes[entity.AttrFaultObservationID] = preIssueID
	if _, err := firstCorrelator.IngestAuthenticatedFault(context.Background(),
		preIssue, sourceA, preIssueID); !errors.Is(err, incident.ErrFaultIdentityInactive) {
		t.Fatalf("certificate issued after fault authenticated old observation: %v", err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(a)),
		db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := (store.Incidents{}).Resolve(ctx, sc, first.ID)
			return err
		}); err != nil {
		t.Fatal(err)
	}
	notifications := 0
	restarted := BuildCorrelator(db.Pool(), time.Minute, log,
		incident.WithObserver(func(context.Context, *incident.Incident, bool) { notifications++ }))
	replayed, err := restarted.IngestAuthenticatedFault(context.Background(), signal(a), sourceA, id)
	if err != nil || replayed == nil || replayed.ID != first.ID ||
		replayed.SignalCount != 1 || replayed.Status != incident.StatusResolved || notifications != 0 {
		t.Fatalf("resolved fault replay opened/notified again: %+v %v notifications=%d",
			replayed, err, notifications)
	}
	changed := signal(a)
	changed.Target = "10.42.0.2"
	if _, err := restarted.IngestAuthenticatedFault(context.Background(), changed, sourceA, id); !errors.Is(err, incident.ErrFaultObservationConflict) {
		t.Fatalf("conflicting reuse of fault UUID = %v", err)
	}
	sourceB := faultReceiptTestSource(t, b, "agent-a")
	if err := store.NewAgentIdentities(db.Pool()).Record(context.Background(), b,
		"agent-a", crypto.EntitySPIFFEID(b, "agent-a"), sourceB.CertificateSerial(),
		time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	bindFaultReceiptTestSource(t, db, b, "agent-a")
	ats[b] = time.Now().Add(time.Millisecond).UTC().Truncate(time.Microsecond)
	foreign, err := restarted.IngestAuthenticatedFault(context.Background(), signal(b), sourceB, id)
	if err != nil || foreign == nil || foreign.ID == first.ID {
		t.Fatalf("tenant B replayed tenant A receipt: %+v %v", foreign, err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(a)),
		db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_fault_receipts
				(tenant_id,agent_id,observation_id,source_kind,source_ref,payload_fingerprint,incident_id)
				VALUES ($1,'agent-x',$2,'device_target','10.42.0.1',$3,$4)`,
				a, uuid.NewString(), signal(a).Fingerprint(), foreign.ID)
			return err
		}); err == nil {
		t.Fatal("fault receipt referenced another tenant's incident")
	}
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(a)),
		db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE agent_identities
			SET revoked_at=clock_timestamp(),revoked_by='operator'
			WHERE tenant_id=$1 AND agent_id='agent-a' AND serial=$2`,
				a, sourceA.CertificateSerial())
			return err
		}); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.IngestAuthenticatedFault(context.Background(),
		signal(a), sourceA, id); !errors.Is(err, incident.ErrFaultIdentityInactive) {
		t.Fatalf("revoked evidence SVID replayed or opened a fault: %v", err)
	}
}
