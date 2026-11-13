// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

func TestIncidentVerdictJoinsIndependentHTTPSOriginalsWithinTheirTenant(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	seedInterfaceRoleMCPConsent(f)
	for lane, tenant := range f.tenants {
		id := gouuid.NewString()
		definitions := make([]testspec.ExecutableDefinition, 2)
		agents, serials := make([]string, 2), make([]string, 2)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permIncidentRead, permTestRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted) VALUES($1,$2,'HTTPS original verdict',$3,$4,true)`, tenant, id, f.contextID, f.routerID)
			return err
		})
		for i := range definitions {
			agents[i], serials[i] = gouuid.NewString(), strings.ReplaceAll(gouuid.NewString(), "-", "")
			definitions[i] = testspec.ExecutableDefinition{ID: gouuid.NewString(), Type: "http", Target: "https://service.example/health", IntervalSeconds: 30, TimeoutSeconds: 2, Params: map[string]string{}}
			definition, agent := definitions[i], agents[i]
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				if _, err := (store.Agents{}).Register(ctx, sc, agent, "verdict HTTPS "+agent, "127.0.0.1", "fixture", crypto.AgentSPIFFEID(tenant, agent), nil); err != nil {
					return err
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target,interval_seconds,timeout_seconds,params,enabled) VALUES($1,$2,'HTTPS source','http',$3,30,2,'{}',true)`, tenant, definition.ID, definition.Target); err != nil {
					return err
				}
				registry := store.NewEntityRegistry(f.pool)
				if err := registry.AssignPathTestContext(ctx, sc, definition.ID, f.contextID); err != nil {
					return err
				}
				return registry.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: agent, Kind: entity.PathAgent, SourceRef: definition.ID}, f.contextID, f.routerID)
			})
			if err := store.NewAgentIdentities(f.pool).Record(t.Context(), tenant, agent, crypto.EntitySPIFFEID(tenant, agent), serials[i], time.Now().Add(time.Hour), ""); err != nil {
				t.Fatal(err)
			}
		}
		at := f.observedAt(tenant)
		for i, definition := range definitions {
			digest, err := testspec.DefinitionHash(definition)
			if err != nil {
				t.Fatal(err)
			}
			status, success := 503, false
			if lane == 1 {
				status, success = 200, true
			}
			claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: agents[i], Kind: entity.PathAgent, SourceRef: definition.ID}, Alias: entity.AliasKey{Kind: entity.ConfiguredTestAlias, Value: definition.ID}, SourceRef: "probe:configured-test", ObservedAt: at.Add(time.Microsecond),
				Outcome: &entity.ProbeOutcome{Version: 2, DefinitionHash: digest, CanaryType: "http", StartedAt: at, CompletedAt: at.Add(time.Microsecond), Success: success, HTTPResponse: &entity.ProbeHTTPResponse{StatusCode: status, TLSVerified: true, SameOrigin: true}}}
			receipt, err := store.NewEntityRegistry(f.pool).WriteEvidenceBatchReceipt(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), agents[i], serials[i], []entity.Observation{claim})
			if err != nil || receipt.Accepted != 1 || receipt.Unresolved != 0 {
				t.Fatal("original configured HTTPS response was not retained", receipt, err)
			}
		}
		var actor *auth.Principal
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err == nil {
				actor = auth.ClonePrincipal(current.principal)
			}
			return err
		})
		input := incident.VerdictInput{From: at.Add(-time.Microsecond), To: at.Add(2 * time.Microsecond)}
		got, err := f.server.computeIncidentVerdict(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), actor, id, input.From, input.To, 128<<20)
		want := incident.FaultRemoteService
		if lane == 1 {
			want = incident.FaultUnknown
		}
		if err != nil || got.Domain != want {
			t.Fatal("joined HTTPS source verdict changed tenant or domain", got.Domain, want, err)
		}
		var citations []incident.VerdictCitation
		for _, hypothesis := range got.Hypotheses {
			if hypothesis.Domain == incident.FaultRemoteService {
				citations = hypothesis.For
				if lane == 1 {
					citations = hypothesis.Against
				}
			}
		}
		if len(citations) != 2 || citations[0].AgentID == citations[1].AgentID {
			t.Fatal("complete independent original responses were lost", len(citations))
		}
		proveIncidentVerdictServedReaders(t, f, tenant, id, input, got)
		proveIncidentVerdictSignedExport(t, f, tenant, id, input, got)
	}
	// Storage, signing and served readers are real; configured observations
	// and identities here are modeled. Physical HTTP/mTLS fault proof remains.
}
