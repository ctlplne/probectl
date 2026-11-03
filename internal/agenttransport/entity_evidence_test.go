// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/metrics"
)

func TestEntityEvidenceByteAdmissionIsTenantScopedAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	if (&service{}).admitEntityEvidence(ctx, "tenant-a", 1, 1) {
		t.Fatal("missing byte admission accepted evidence")
	}
	policy := fairness.DefaultPolicy()
	policy.IngestBytesPerSec = 32
	policy.BurstSeconds = 1
	svc := &service{fairness: fairness.NewGate(policy, nil)}
	// Existing ingest admission permits one whole batch while tokens are
	// positive, then charges its entire debt. Preserve that contract rather
	// than silently imposing a smaller per-batch address limit.
	if !svc.admitEntityEvidence(ctx, "tenant-a", 1, 1<<20) {
		t.Fatal("evidence lost whole-batch ingest admission")
	}
	if svc.admitEntityEvidence(ctx, "tenant-a", 1, 1) {
		t.Fatal("another observation bypassed unpaid byte debt")
	}
	if !svc.fairness.AdmitN(ctx, "tenant-a", fairness.MeterBytes, 32) {
		t.Fatal("evidence consumed raw payload byte credits")
	}
	if !svc.admitEntityEvidence(ctx, "tenant-b", 1, 16) {
		t.Fatal("another tenant inherited exhausted byte admission")
	}
	for _, row := range []struct {
		tenant       string
		count, bytes int
	}{{"", 1, 1}, {"tenant-a", 0, 1}, {"tenant-a", 1, 0}} {
		if svc.admitEntityEvidence(ctx, row.tenant, row.count, row.bytes) {
			t.Fatal("invalid evidence accounting admitted")
		}
	}
}

// The same TLS listener admits the evidence plane, but its credential cannot
// call any existing agent or L7 RPC. Other planes cannot enter the new writer.
func TestEntityEvidenceCredentialIsRestrictedToItsRPC(t *testing.T) {
	ca, err := crypto.GenerateCA("entity-rpc-plane", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const tenant, agent = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	for _, tc := range []struct {
		name, uri string
		want      codes.Code
	}{
		{"entity", crypto.EntitySPIFFEID(tenant, agent), codes.Unavailable},
		{"agent", crypto.AgentSPIFFEID(tenant, agent), codes.Unauthenticated},
		{"ebpf", crypto.EBPFSPIFFEID(tenant, agent), codes.Unauthenticated},
		{"bmp", crypto.BMPSPIFFEID(tenant, agent), codes.Unauthenticated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, _, err := ca.IssueClientCert(agent, tc.uri, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			ctx := peerContextForLeaf(leafFromPEM(t, cert))
			svc := &service{}
			reg := metrics.New("test", "test")
			(&Server{svc: svc}).WithMetrics(reg)
			if _, err := svc.SubmitEntityEvidence(ctx, &agentv1.SubmitEntityEvidenceRequest{}); status.Code(err) != tc.want {
				t.Fatalf("SubmitEntityEvidence = %v, want %s", err, tc.want)
			}
			if got := svc.entityEvidenceBatches["rejected"].Value(); got != 1 {
				t.Fatalf("rejected evidence batch counter = %d, want 1", got)
			}
			rec := httptest.NewRecorder()
			reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			body := rec.Body.String()
			if !strings.Contains(body, `probectl_entity_evidence_batches_total{outcome="rejected"} 1`) ||
				strings.Contains(body, tenant) || strings.Contains(body, agent) {
				t.Fatalf("evidence metrics lost fixed-outcome privacy: %s", body)
			}
			if tc.name != "entity" {
				return
			}
			if _, err := svc.Register(ctx, &agentv1.RegisterRequest{}); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("entity identity entered Register: %v", err)
			}
			if _, err := svc.Heartbeat(ctx, &agentv1.HeartbeatRequest{}); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("entity identity entered Heartbeat: %v", err)
			}
			if _, err := svc.FetchL7Policy(ctx, &agentv1.FetchL7PolicyRequest{}); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("entity identity entered L7 policy: %v", err)
			}
		})
	}
}
