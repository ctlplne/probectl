// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func auditActions(t *testing.T, db *store.DB, tenant, action string) []audit.Event {
	t.Helper()
	var events []audit.Event
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), db.Pool(),
		func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			events, err = audit.ListFiltered(ctx, sc, 0, 50, audit.Filter{Action: action})
			return err
		}); err != nil {
		t.Fatalf("list audit %s: %v", action, err)
	}
	return events
}

// D-43: the tenant's L7 capture redaction floor persists on its governance row,
// stays inside the tenant (RLS), is audited OLD/NEW on the tenant's own chain,
// and survives a provider-plane policy write untouched — the provider cannot
// loosen (or reset) a tenant's capture redaction.
func TestGovernanceL7FloorRealStack(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	policies := govern.NewPolicyStore(db.Pool())
	srv.WithGovernance(policies)
	h := srv.Handler()
	ctx := context.Background()
	tenantA := freshTenant(t, db, "l7floor-a")
	tenantB := freshTenant(t, db, "l7floor-b")

	if rec := apiReq(t, h, http.MethodPut, "/v1/governance/policy", tenantA,
		map[string]any{"l7_capture_redaction": "headers"}); rec.Code != http.StatusOK {
		t.Fatalf("PUT headers opt-in: %d %s", rec.Code, rec.Body)
	}
	for tenant, want := range map[string]string{tenantA: "headers", tenantB: "metadata"} {
		floor, err := policies.L7CaptureFloor(ctx, tenant, false)
		if err != nil || floor != want {
			t.Fatalf("floor(%s) = %q, %v; want %q", tenant, floor, err, want)
		}
	}
	if floor, _ := policies.L7CaptureFloor(ctx, tenantA, true); floor != "metadata" {
		t.Fatalf("regulated floor = %q, want metadata whatever the row says", floor)
	}
	events := auditActions(t, db, tenantA, governancePolicyAuditAction)
	if len(events) != 1 || events[0].Data["l7_capture_redaction"] != "headers" || events[0].Data["prior_l7_capture_redaction"] != "metadata" {
		t.Fatalf("governance audit = %+v", events)
	}

	// The provider plane writes the row through UpsertPolicyTx (ee/governance).
	if err := tenancy.InProvider(ctx, db.Pool(), func(ctx context.Context, q tenancy.Querier) error {
		return govern.UpsertPolicyTx(ctx, q, tenantA, govern.Policy{AIRemoteEgress: true, L7CaptureRedaction: "full"}, "provider-op")
	}); err != nil {
		t.Fatalf("provider upsert: %v", err)
	}
	if floor, _ := policies.L7CaptureFloor(ctx, tenantA, false); floor != "headers" {
		t.Fatalf("a provider write changed the tenant's L7 floor to %q", floor)
	}
}

// D-43 addendum (a): the agent's posture lands on its registry row, the first
// consented report and every mode change append agent.l7_capture.posture to
// the tenant's chain (a re-report of the same posture does not), another
// tenant's agent cannot be written, and the agent detail view shows it.
func TestAgentL7PostureRealStack(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	h := srv.Handler()
	ctx := context.Background()
	tenantA := freshTenant(t, db, "l7posture-a")
	tenantB := freshTenant(t, db, "l7posture-b")
	agentA, agentB := uuid(t), uuid(t)
	for tenant, agent := range map[string]string{tenantA: agentA, tenantB: agentB} {
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := (store.Agents{}).Register(ctx, sc, agent, "ebpf-"+agent[:8], "node", "", crypto.AgentSPIFFEID(tenant, agent), []string{"collector", "ebpf"})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	policy := agenttransport.NewL7Policy(db.Pool(), false)
	consented := store.L7CapturePosture{Enabled: true, ConsentTenant: tenantA, Scope: []string{"exe:/opt/app/bin/api"},
		RedactionMode: "metadata", EffectiveMode: "metadata", RedactionFloor: "metadata", Active: true, State: "capturing", ReportedAt: time.Now().UTC()}
	if changed, err := policy.RecordPosture(ctx, tenantA, agentA, consented); err != nil || !changed {
		t.Fatalf("first report: changed=%v err=%v", changed, err)
	}
	again := consented
	again.ReportedAt = again.ReportedAt.Add(time.Minute)
	if changed, err := policy.RecordPosture(ctx, tenantA, agentA, again); err != nil || changed {
		t.Fatalf("re-report: changed=%v err=%v", changed, err)
	}
	refused := consented
	refused.RedactionMode, refused.EffectiveMode, refused.Active, refused.State = "headers", "", false, "refused_floor"
	if _, err := policy.RecordPosture(ctx, tenantA, agentA, refused); err != nil {
		t.Fatal(err)
	}
	events := auditActions(t, db, tenantA, agenttransport.L7PostureAuditAction)
	if len(events) != 2 || events[0].Actor != "agent:"+agentA || events[0].Data["first_report"] != true ||
		events[1].Data["prior_redaction_mode"] != "metadata" || events[1].Data["state"] != "refused_floor" {
		t.Fatalf("posture audit = %+v", events)
	}
	// RLS: tenant A's identity cannot write tenant B's agent row.
	if _, err := policy.RecordPosture(ctx, tenantA, agentB, consented); err == nil {
		t.Fatal("tenant A recorded a posture on tenant B's agent")
	} else if de, ok := apierror.As(err); !ok || de.Kind != apierror.KindNotFound {
		t.Fatalf("cross-tenant record error = %v, want NotFound", err)
	}
	if n := len(auditActions(t, db, tenantB, agenttransport.L7PostureAuditAction)); n != 0 {
		t.Fatalf("tenant B chain carries %d posture events", n)
	}

	rec := apiReq(t, h, http.MethodGet, "/v1/agents/"+agentA, tenantA, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET agent: %d %s", rec.Code, rec.Body)
	}
	var view struct {
		L7 *store.L7CapturePosture `json:"l7_capture_posture"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil || view.L7 == nil || view.L7.State != "refused_floor" || view.L7.RedactionMode != "headers" {
		t.Fatalf("agent detail posture = %+v (%v): %s", view.L7, err, rec.Body)
	}
}

// Refinement 3's identity: an eBPF collector registered with a CSR gets an
// agent-plane SVID bound to its own collector agent_id, so the policy it
// fetches and the records it publishes name the same registry row, and its
// collector capabilities survive.
func TestEBPFCollectorRegistrationIssuesAgentChannelSVID(t *testing.T) {
	db := changeDB(t)
	svc := collectorEnrollService(t, db)
	tenant := freshTenant(t, db, "ebpf-svid")
	srv := New(&config.Config{AuthMode: "dev"}, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil)
	srv.SetEnrollService(svc)
	h := srv.Handler()
	token, _, err := svc.MintToken(context.Background(), tenant, "", "ebpf-node", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, _, err := crypto.CreateCSR("ebpf-node")
	if err != nil {
		t.Fatal(err)
	}
	rec := apiReq(t, h, http.MethodPost, "/v1/collectors/register", tenant, map[string]any{
		"token": token, "plane": "ebpf", "hostname": "ebpf-node", "csr_pem": string(csr),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d %s", rec.Code, rec.Body)
	}
	var out collectorRegistrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.SVID == nil || out.SVID.SPIFFEID != crypto.AgentSPIFFEID(tenant, out.AgentID) || out.SVID.Plane != "agent" {
		t.Fatalf("eBPF collector SVID = %+v, want the agent-plane identity of %s", out.SVID, out.AgentID)
	}
	var a *store.Agent
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		var e error
		a, e = (store.Agents{}).Get(ctx, sc, out.AgentID)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if len(a.Capabilities) != 2 || a.Capabilities[0] != "collector" || a.Capabilities[1] != "ebpf" {
		t.Fatalf("collector capabilities = %v", a.Capabilities)
	}
}
